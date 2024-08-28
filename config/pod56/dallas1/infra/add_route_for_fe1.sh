route add -net 10.131.128.96/29 gw 11.0.4.254
route add -net 10.131.144.96/29 gw 11.0.4.254
route add -net 6.192.32.0/20 gw 11.20.1.101
route add -net 6.192.64.0/20 gw 11.20.1.102
route add -host 10.131.128.136/32 gw 11.0.4.254
route add -host 10.131.128.136/32 gw 11.0.4.254
route add -host 10.131.144.136/32 gw 11.0.4.254
route add -host 10.131.144.136/32 gw 11.0.4.254
route add -net 8.140.32.0/20 gw 11.20.1.101
route add -net 8.140.64.0/20 gw 11.20.1.102
route add -net 106.2.0.64/27 gw 11.0.2.254
route add -net 106.2.0.96/27 gw 11.0.2.254


/sbin/sysctl -w net.ipv4.ip_forward=1
