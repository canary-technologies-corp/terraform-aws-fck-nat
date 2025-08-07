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

    # Allow established and related connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

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

    # Allow ICMP for network diagnostics (ping, MTU discovery)
    iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type parameter-problem -j ACCEPT

    # Save iptables rules to persist across reboots
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

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

    # Allow established and related connections
    ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

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
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type echo-reply -j ACCEPT
    # Neighbor Discovery Protocol (essential for IPv6)
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type router-solicitation -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type router-advertisement -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type neighbor-solicitation -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp --icmpv6-type neighbor-advertisement -j ACCEPT

    # Save ip6tables rules to persist across reboots
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

    # For systems using iptables-persistent
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
    fi
fi

service fck-nat restart
