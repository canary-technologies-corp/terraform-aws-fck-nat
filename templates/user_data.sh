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

service fck-nat restart
