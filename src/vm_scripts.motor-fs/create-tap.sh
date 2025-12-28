#!/bin/sh

sudo ip tuntap add mode tap moto-tap
sudo ip addr add 192.168.4.1/24 dev moto-tap
sudo ip link set moto-tap up

