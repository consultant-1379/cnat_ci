#!/usr/bin/env bash
set -uex

### PCG 1.19 EP3 workaround for performance affected by Linux kernel feature THP (Transparent Huge Pages)
### This WA is only applied for CCD 2.24, 2.25 and 2.26
# update proactiveness
cat << EOF >> /etc/sysctl.conf
vm.compaction_proactiveness = 0
EOF

# update ptes
cat << EOF >> /root/ptes_update.sh
echo 127 > /sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none
EOF
chmod +x /root/ptes_update.sh

# create auto start service for ptes updating
cat << EOF >> /etc/systemd/system/ptes_update.service
[Unit]
Description=Update max_ptes_none
Before=containerd.service
[Service]
Type=oneshot
ExecStart=/bin/bash -c "/root/ptes_update.sh"
[Install]
WantedBy=multi-user.target
EOF
systemctl enable ptes_update.service
systemctl start ptes_update.service
