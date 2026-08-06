#!/bin/bash

# Enable IPv4 forwarding on the host
sudo sysctl -w net.ipv4.ip_forward=1

# 1. Create a NAT table for IPv4
sudo nft add table ip nat

# 2. Create a postrouting chain for source NAT (masquerading)
# nft add chain ip nat postrouting '{ type nat hook postrouting priority srcnat; }'
sudo nft add chain ip nat postrouting '{ type nat hook postrouting priority 100; policy accept; }'

# 3. Add a rule to masquerade traffic coming from the VM's subnet
sudo nft add rule ip nat postrouting ip saddr 192.168.4.0/24 masquerade

# 4. Run on the host if development is inside a Qemu VM (i.e. Motor OS VM is nested)
# sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
