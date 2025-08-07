#!/bin/sh

: > /etc/fck-nat.conf
echo "eni_id=${TERRAFORM_ENI_ID}" >> /etc/fck-nat.conf
echo "eip_id=${TERRAFORM_EIP_ID}" >> /etc/fck-nat.conf
echo "cwagent_enabled=${TERRAFORM_CWAGENT_ENABLED}" >> /etc/fck-nat.conf
echo "cwagent_cfg_param_name=${TERRAFORM_CWAGENT_CFG_PARAM_NAME}" >> /etc/fck-nat.conf

# Configure iptables to drop inbound connections not matching VPC CIDR
# This helps avoid conntrack limitations when using security groups
if [ -n "${TERRAFORM_VPC_CIDR}" ]; then
    # Drop all inbound traffic by default
    iptables -P INPUT DROP

    # Allow loopback traffic
    iptables -A INPUT -i lo -j ACCEPT

    # Drop invalid packets early
    iptables -A INPUT -m state --state INVALID -j DROP

    # Allow established and related connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Drop packets with suspicious TCP flags (port scans)
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

    # Protect against SYN floods
    iptables -A INPUT -p tcp --syn -m limit --limit 5/second --limit-burst 10 -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP

    # Limit concurrent connections per source IP
    iptables -A INPUT -p tcp -m connlimit --connlimit-above 100 -j REJECT --reject-with tcp-reset

    # Allow all inbound traffic from VPC CIDR
    iptables -A INPUT -s ${TERRAFORM_VPC_CIDR} -j ACCEPT

    # Allow DHCP responses (UDP port 68)
    iptables -A INPUT -p udp --dport 68 -j ACCEPT

    # Allow DNS responses (UDP and TCP port 53) - for DNS resolution
    iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
    iptables -A INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT

    # Allow NTP responses (UDP port 123) - for time synchronization
    iptables -A INPUT -p udp --sport 123 -m state --state ESTABLISHED -j ACCEPT

    # Allow HTTPS responses (TCP port 443) - for AWS API calls, package updates, metadata service
    iptables -A INPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

    # Allow HTTP responses (TCP port 80) - for package updates and metadata service
    iptables -A INPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

    # Allow AWS metadata service (169.254.169.254)
    iptables -A INPUT -s 169.254.169.254 -j ACCEPT

    # Allow ICMP for network diagnostics (ping, MTU discovery) with rate limiting
    iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type parameter-problem -j ACCEPT
    # Rate limit ICMP echo requests to prevent ping floods
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/second --limit-burst 10 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

    # Log dropped packets (rate limited to avoid log flooding)
    # iptables -N LOGGING 2>/dev/null || true
    # iptables -A INPUT -j LOGGING
    # iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
    # iptables -A LOGGING -j DROP

    # Save iptables rules to persist across reboots
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

    # Configure FORWARD chain rules for NAT instance
    # MSS Clamping to prevent fragmentation issues
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

    # Rate limit forwarded connections (supports 120k packets/minute baseline)
    iptables -A FORWARD -m limit --limit 2000/second --limit-burst 4000 -j ACCEPT
    iptables -A FORWARD -m limit --limit 10/second -j LOG --log-prefix "Forward-Dropped: " --log-level 4
    iptables -A FORWARD -j DROP

    # Block spoofed addresses from external interface (assuming eth0 is external)
    # Insert anti-spoofing rules before the rate limiting rules
    
    # First, accept traffic from VPC CIDR (legitimate traffic)
    iptables -I FORWARD 1 -i eth0 -s ${TERRAFORM_VPC_CIDR} -j ACCEPT
    
    # Then block all RFC1918 and special-use addresses from external interface
    # These shouldn't appear as source addresses from the internet
    iptables -I FORWARD 2 -i eth0 -s 10.0.0.0/8 -j DROP      # RFC1918 Class A
    iptables -I FORWARD 3 -i eth0 -s 172.16.0.0/12 -j DROP   # RFC1918 Class B
    iptables -I FORWARD 4 -i eth0 -s 192.168.0.0/16 -j DROP  # RFC1918 Class C
    iptables -I FORWARD 5 -i eth0 -s 127.0.0.0/8 -j DROP     # Loopback
    iptables -I FORWARD 6 -i eth0 -s 169.254.0.0/16 -j DROP  # Link-local
    iptables -I FORWARD 7 -i eth0 -s 224.0.0.0/4 -j DROP     # Multicast
    iptables -I FORWARD 8 -i eth0 -s 240.0.0.0/4 -j DROP     # Reserved
    iptables -I FORWARD 9 -i eth0 -s 0.0.0.0/8 -j DROP       # Invalid/reserved

    # For systems using iptables-persistent
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
    fi
fi

# Configure ip6tables for IPv6 traffic if VPC has IPv6 CIDR
if [ -n "${TERRAFORM_VPC_IPV6_CIDR}" ]; then
    # Drop all inbound IPv6 traffic by default
    ip6tables -P INPUT DROP

    # Allow loopback traffic
    ip6tables -A INPUT -i lo -j ACCEPT

    # Drop invalid IPv6 packets early
    ip6tables -A INPUT -m state --state INVALID -j DROP

    # Allow established and related connections
    ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Drop packets with routing header type 0 (deprecated and dangerous)
    ip6tables -A INPUT -m rt --rt-type 0 -j DROP

    # Allow all inbound traffic from VPC IPv6 CIDR
    ip6tables -A INPUT -s ${TERRAFORM_VPC_IPV6_CIDR} -j ACCEPT

    # Allow DHCPv6 responses (UDP ports 546 and 547)
    ip6tables -A INPUT -p udp --dport 546 -j ACCEPT
    ip6tables -A INPUT -p udp --dport 547 -j ACCEPT

    # Allow DNS responses (UDP and TCP port 53) - for DNS resolution
    ip6tables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
    ip6tables -A INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT

    # Allow NTP responses (UDP port 123) - for time synchronization
    ip6tables -A INPUT -p udp --sport 123 -m state --state ESTABLISHED -j ACCEPT

    # Allow HTTPS responses (TCP port 443) - for AWS API calls, package updates
    ip6tables -A INPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

    # Allow HTTP responses (TCP port 80) - for package updates
    ip6tables -A INPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

    # Allow AWS metadata service IPv6 (fd00:ec2::254)
    ip6tables -A INPUT -s fd00:ec2::254 -j ACCEPT

    # Allow ICMPv6 for network diagnostics and IPv6 functionality
    # Essential ICMPv6 types for IPv6 to function properly
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type destination-unreachable -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type packet-too-big -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type time-exceeded -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type parameter-problem -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type echo-reply -j ACCEPT
    # Rate limit ICMPv6 echo requests to prevent ping floods
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type echo-request -m limit --limit 5/second --limit-burst 10 -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type echo-request -j DROP
    # Neighbor Discovery Protocol (essential for IPv6)
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type router-solicitation -j ACCEPT
    # Router advertisements with hop limit 255 (RFC 4861 requirement)
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type router-advertisement -m hl --hl-eq 255 -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type router-advertisement -j DROP
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type neighbor-solicitation -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type neighbor-advertisement -j ACCEPT

    # Log dropped IPv6 packets (rate limited to avoid log flooding)
    # ip6tables -N LOGGING 2>/dev/null || true
    # ip6tables -A INPUT -j LOGGING
    # ip6tables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IP6Tables-Dropped: " --log-level 4
    # ip6tables -A LOGGING -j DROP

    # Configure IPv6 FORWARD chain rules for NAT instance
    # MSS Clamping for IPv6 to prevent fragmentation issues
    ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

    # Rate limit forwarded IPv6 connections (supports 120k packets/minute baseline)
    ip6tables -A FORWARD -m limit --limit 2000/second --limit-burst 4000 -j ACCEPT
    ip6tables -A FORWARD -m limit --limit 10/second -j LOG --log-prefix "IPv6-Forward-Dropped: " --log-level 4
    ip6tables -A FORWARD -j DROP

    # Block spoofed IPv6 addresses from external interface (assuming eth0 is external)
    # Insert anti-spoofing rules before the rate limiting rules
    
    # First, accept traffic from VPC IPv6 CIDR (legitimate traffic)
    ip6tables -I FORWARD 1 -i eth0 -s ${TERRAFORM_VPC_IPV6_CIDR} -j ACCEPT
    
    # Then block special-use and reserved IPv6 addresses from external interface
    # These shouldn't appear as source addresses from the internet
    ip6tables -I FORWARD 2 -i eth0 -s ::1/128 -j DROP           # Loopback
    ip6tables -I FORWARD 3 -i eth0 -s ::/128 -j DROP            # Unspecified
    ip6tables -I FORWARD 4 -i eth0 -s ::ffff:0:0/96 -j DROP     # IPv4-mapped
    ip6tables -I FORWARD 5 -i eth0 -s fe80::/10 -j DROP         # Link-local
    ip6tables -I FORWARD 6 -i eth0 -s fc00::/7 -j DROP          # Unique local (ULA)
    ip6tables -I FORWARD 7 -i eth0 -s ff00::/8 -j DROP          # Multicast
    ip6tables -I FORWARD 8 -i eth0 -s 2001:db8::/32 -j DROP     # Documentation
    ip6tables -I FORWARD 9 -i eth0 -s 2001::/32 -j DROP         # Teredo tunneling
    ip6tables -I FORWARD 10 -i eth0 -s 2002::/16 -j DROP        # 6to4 tunneling
    ip6tables -I FORWARD 11 -i eth0 -s fec0::/10 -j DROP        # Site-local (deprecated)

    # Save ip6tables rules to persist across reboots
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

    # For systems using iptables-persistent
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
    fi
fi

service fck-nat restart
