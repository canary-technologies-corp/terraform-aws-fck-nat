#!/bin/bash

: > /etc/fck-nat.conf
echo "eni_id=${TERRAFORM_ENI_ID}" >> /etc/fck-nat.conf
echo "eip_id=${TERRAFORM_EIP_ID}" >> /etc/fck-nat.conf
echo "cwagent_enabled=${TERRAFORM_CWAGENT_ENABLED}" >> /etc/fck-nat.conf
echo "cwagent_cfg_param_name=${TERRAFORM_CWAGENT_CFG_PARAM_NAME}" >> /etc/fck-nat.conf

# Configure iptables to allow traffic from VPC CIDR only
if [[ -n "${TERRAFORM_VPC_CIDR}" ]]; then
    # Allow all inbound traffic from VPC CIDR
    iptables -A INPUT -s ${TERRAFORM_VPC_CIDR} -j ACCEPT

    # Save iptables rules to persist across reboots
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

    # For systems using iptables-persistent
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
    fi
fi

# Configure ip6tables for IPv6 traffic if VPC has IPv6 CIDR
if [[ -n "${TERRAFORM_VPC_IPV6_CIDR}" ]]; then
    # Allow all inbound traffic from VPC IPv6 CIDR
    ip6tables -A INPUT -s ${TERRAFORM_VPC_IPV6_CIDR} -j ACCEPT

    # Save ip6tables rules to persist across reboots
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

    # For systems using iptables-persistent
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
    fi
fi

# Install Datadog agent
# Retrieve API key from AWS Secrets Manager
export DD_API_KEY=$(aws secretsmanager get-secret-value --secret-id ${TERRAFORM_DATADOG_SECRET_NAME} --query 'SecretString' --output text | jq -r '.${TERRAFORM_DATADOG_SECRET_KEY}')

# Install Datadog agent if API key is retrieved successfully
if [[ -n "$DD_API_KEY" ]]; then
    DD_API_KEY="$DD_API_KEY" \
    DD_SITE="datadoghq.com" \
    bash -c "$(curl -L https://install.datadoghq.com/scripts/install_script_agent7.sh)"
else
    echo "Failed to retrieve Datadog API key from Secrets Manager"
fi

service fck-nat restart
service datadog-agent restart
