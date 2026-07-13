#!/bin/bash

# Enable IPv4 forwarding on the host
sysctl -w net.ipv4.ip_forward=1

# 1. Create a NAT table for IPv4
nft add table ip nat

# 2. Create a postrouting chain for source NAT (masquerading)
# nft add chain ip nat postrouting '{ type nat hook postrouting priority srcnat; }'
nft add chain ip nat postrouting '{ type nat hook postrouting priority 100; policy accept; }'

# 3. Add a rule to masquerade traffic coming from the VM's subnet
nft add rule ip nat postrouting ip saddr 192.168.4.0/24 masquerade
