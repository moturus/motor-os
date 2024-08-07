# Changelog

All notable changes to this project will be documented in this file.

## 2024-07-06

Motor OS [web site](https://motor-os.org) is now served from inside
a couple of Motor OS VMs (proxied via Cloudflare).

## 2024-07-04

TLS/HTTPS serving implemented.

## 2024-06-30

`ss` command implemented.

## 2024-05-08

The serving side of TCP stack seems to be robust now: rnetbench
multithreaded host-guest test with the guest serving has been running
for a week now.

Throughput is also quite decent (about 10Gbps in alioth and CHV,
a bit less in qemu).

## 2024-04-30

`top` command implemented.

## 2024-04-13

The throughput of a single TCP stream is now about 300 MiB/sec
(an approximately ~20x improvement from what it was in January 2024).
