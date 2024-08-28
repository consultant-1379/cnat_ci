#!/usr/bin/env bash
set -uex
echo -e "Adding Target Solution Dual-mode 5GC Self-signed RootCA"
rootca_file=/etc/pki/trust/anchors/tsdm5gc-self-signed-rootca.crt
cat <<EOF > $rootca_file
-----BEGIN CERTIFICATE-----
MIIGCTCCA/GgAwIBAgIBADANBgkqhkiG9w0BAQsFADCBnjELMAkGA1UEBhMCU0Ux
EjAQBgNVBAgMCVN0b2NraG9sbTESMBAGA1UEBwwJU3RvY2tob2xtMREwDwYDVQQK
DAhFcmljc3NvbjEVMBMGA1UECwwMUEMgU29sdXRpb25zMRgwFgYDVQQDDA9UZWFt
Qmx1ZXNSb290Q0ExIzAhBgkqhkiG9w0BCQEWFGtlbi5zaGlAZXJpY3Nzb24uY29t
MB4XDTIwMTEwMjA5MzMxNloXDTQwMTAyODA5MzMxNlowgZ4xCzAJBgNVBAYTAlNF
MRIwEAYDVQQIDAlTdG9ja2hvbG0xEjAQBgNVBAcMCVN0b2NraG9sbTERMA8GA1UE
CgwIRXJpY3Nzb24xFTATBgNVBAsMDFBDIFNvbHV0aW9uczEYMBYGA1UEAwwPVGVh
bUJsdWVzUm9vdENBMSMwIQYJKoZIhvcNAQkBFhRrZW4uc2hpQGVyaWNzc29uLmNv
bTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALpFSt2RPftYwPHaaX0O
li/g52VnHmyACmG1egnPA4efRptfFqsm9lHH2byigSech+zfLXCarVErdu1/yvRG
zYaLgH/76XtOVXpGYa3aXBksBbkTnIRmgtq11iIdOKXUrVbVt4HZ20EJxrFrMs9n
mxy7dvhWM1KrSVSUqN840DSWJxeFWWgEZ7vTgRhnuAD2FUqsZ6CRvt2iL31ZNIco
dqOUQF9chZLWgprEDgRmJD4oLjVoWe0kS/zRR2G3GB9J28xs9ZjSp38CtTgqBzyv
gWua4Im5KyFIJUeH4a9NRYZWry6I9sxAzIYVt7ki3TAP+K2YsGg9dD1GwKDR+5Zy
7EVuri9hqR5YFrvvdNAjWrJvymQXaDdmXUGa7Og8p9IzM+lNL86dDf3BsyeqHJrq
m31OMHM3MCVfc0zUu96LnLj2wqTdKa7MaWyfA7KO38wIACBvO/SNCCzCXpADJRED
A3n219y6QxmM+DH35XVBTvJkM5UxPHoa8rhZsuLhobIyNU/Kuk6JAm/lueYzOG9k
lLmaaSasdlNJ/Pqf4MBOB1UKPVsJsravFaQ7BmOLp3R0XyhoNrnmd/OOxU6r1TH1
wh5vx2CAOO4tujvnihgeADU8yQdwDKBkOtjjV0TdY0MFxecLowtmEnrKfIO9kSS3
tpnAgdBgfq7eOYvsrKw31AqxAgMBAAGjUDBOMB0GA1UdDgQWBBTqkIEarX28jATB
MBsv/Vse5jCebDAfBgNVHSMEGDAWgBTqkIEarX28jATBMBsv/Vse5jCebDAMBgNV
HRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQB73tG3G1mZt93j5MoRXimsB6sO
q47A/lZiyJKqJiLIeSq1V8GOPwqfQyNAe40inhLWHYky5rPfhhXw+FlyW4zotv7W
ZygTjtCwa7EbawUMOoG9YcMhK9NZx/EoPT0cs4BK6UvajpH28Kl5+fyvSLN5ZY7K
arBIMUWNVs7m3O9e5doLx6e98soj2U5PkGq1AB2xgwX7F0spIj3Yg3WS4C5z5KkF
b1cviVgHuFnxJNGu5nY+h08+i5cZNu/Uc1M9pkYthlfnhpyPlONxD9rTpDm5LEkU
3af9zyqwJuuunWDJMfKKZGPB5BCgfM6hBw4D3iLWTWxrHfjNghNVqCh6K+L+GdfD
hzT/LVSHW/bOjHh+wAVGFcFxxXedXxq/prj1ZwflPI7XvxuCwj1EVA630FIBSC6/
xWq8mHoECXXp839Gccd3tmeauELrchkty6OaBpwHg/dB44GEByJz/T+lbLIOZLXd
K+kpgaN4TmA5wtlQPMq0HQLvEax+cCUYtE78QSe+86mV/2Q1EeJNEesT7p5C2U4c
aQZbPQ6YgvRZtvPD/3CrQS9CD0DJwaCrj2dEISb4lEj/fz5wlLETyS7X/0KYUMKR
UmqyKwz2Zs9jM7By0HxM1i+0f/ovMDuKuQ6IQTROEu0TZZVH6KRsDuujv+/VJ2Nb
szlrRw3la1H71eU9UQ==
-----END CERTIFICATE-----
EOF
chmod 400 $rootca_file

cat << EOF > apparmor-docker-pcc
#include <tunables/global>

profile docker-pcc flags=(attach_disconnected,mediate_deleted) {
    #include <abstractions/base>
    network,
    capability,
    file,
    mount,
    umount,
    ptrace peer=@{profile_name},
}
EOF

mv apparmor-docker-pcc /etc/apparmor.d/
systemctl restart apparmor

function load_kernel_module() {
    for m in $@; do
    modprobe $m && echo $m >> /etc/modules-load.d/dm5gc_nfvi_preload.conf
    done
}
load_kernel_module ip6table_mangle fou

# adjust kernel parameters for DM 5GC CNFs
cat << EOF >> /etc/sysctl.conf
## update to kernel parameters required by Search Engine
vm.max_map_count = 262144
EOF
sysctl -p

# Add static routes for NeLS
nels_ip="10.155.142.68/32"
gw_ip=$(grep "registry.eccd.local" /etc/hosts | cut -d' ' -f1)
cat << EOF >> /etc/sysconfig/network/ifroute-eth0
## NeLS static route
${nels_ip} ${gw_ip} - -
EOF
