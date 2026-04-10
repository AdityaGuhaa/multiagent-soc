#!/bin/bash
echo "Clearing all test iptables rules..."
iptables -D INPUT -s 45.33.32.156 -j DROP 2>/dev/null
iptables -D INPUT -s 185.220.101.45 -j DROP 2>/dev/null
iptables -D INPUT -s 198.51.100.23 -j DROP 2>/dev/null
iptables -D INPUT -s 203.0.113.99 -j DROP 2>/dev/null
iptables -D INPUT -s 91.121.87.123 -j DROP 2>/dev/null
iptables -D INPUT -s 176.9.15.200 -j DROP 2>/dev/null
iptables -D INPUT -s 109.201.133.195 -j DROP 2>/dev/null
iptables -D INPUT -s 192.168.1.100 -j DROP 2>/dev/null
iptables -D INPUT -s 192.168.1.101 -j DROP 2>/dev/null
iptables -D INPUT -s 192.168.1.102 -j DROP 2>/dev/null
echo "Done. Restart main.py now to reset detection engine memory."
