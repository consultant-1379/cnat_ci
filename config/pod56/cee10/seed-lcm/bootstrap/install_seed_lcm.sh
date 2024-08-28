#!/bin/bash
# shellcheck disable=SC2086

set -o errexit
set -o nounset
set -o pipefail

unset LC_ALL
export LANG=en_US.UTF-8
[[ ${LANGUAGE:-} ]] && LANGUAGE=en_US

VM_NAME=CEE_LCM

CEE_BASE=cee-CXC1737883_8
HOST_OS=cee-host-os-CXC1742929_8
PORTAL=cee-portal-CXC1742933_8
DIR=$(dirname "$(readlink --canonicalize-existing "$0")")
CONFIG_YAML=$DIR/seed_lcm_config.yaml
ISO=
HOST_OS_ISO=
URIS=()
ANSIBLE_VERBOSITY=${ANSIBLE_VERBOSITY:-2}
PREFER_IPV4=false
SILENT_ANSIBLE='&>/dev/null'

readonly REQUIRED_PACKAGES_SUSE=(libvirt \
                                 libvirt-client \
                                 libvirt-daemon \
                                 libvirt-daemon-driver-qemu \
                                 openssh \
                                 qemu-kvm \
                                 qemu-tools \
                                 wget)
readonly REQUIRED_PACKAGES_UBUNTU_COMMON=(openssh-client \
                                          qemu-utils \
                                          qemu-system-x86 \
                                          qemu-kvm \
                                          vlan \
                                          wget)
readonly -A REQUIRED_PACKAGES_UBUNTU_LIBVIRT=([xenial]="libvirt-bin" \
                                              [trusty]="libvirt-bin" \
                                              [bionic]="libvirt-bin" \
                                              [focal]="libvirt-daemon \
                                                       libvirt-clients \
                                                       libvirt-daemon-system")


info() {
    local script; script=$(basename "$0")
    logger -s -t "$script.info" -p syslog.info "$*"
}

error() {
    local script; script=$(basename "$0")
    logger -s -t "$script.error" -p syslog.err "$*"
    exit 1
}

# Get IP from CIDR. If IP is the just the "the network" this will
# return that network address.
# E.g.:
# 192.168.0.0/16 -> 192.168.0.0
# 192.168.1.2/16 -> 192.168.1.2
# fd3d:3609:1c3d::11/64 -> fd3d:3609:1c3d::11
cidr2ip() {
   echo ${1%%\/*}
}

# Get prefix length from CIDR.
# E.g.:
# 192.168.0.0/16 -> 16
# 192.168.1.2/16 -> 16
# fd3d:3609:1c3d::11/64 -> 64
cidr2prefixlen() {
   echo ${1##*\/}
}

# Expand an IPv6 address,
# E.g.:
# fd3d:3609:1c3d::19 -> fd3d:3609:1c3d:0:0:0:0:19
expandipv6() {
    local ip=$1
    local i n_col
    n_col=$(echo $ip | awk -F: '{print NF-1}')
    local res=""
    local i=1
    local cnt=0
    while ((cnt < 8)); do
        local pip
        pip=$(echo $ip | awk -F: "{print \$$i}")
        ((++i))
        if [[ -z $pip ]]; then
            j=$((8 - n_col))
            while ((j--)); do
                res="$res:0"
                ((++cnt))
            done
            continue
        else
            res="$res:$pip"
        fi
        ((++cnt))
    done
    # Remove the initial :
    echo ${res#\:}
}

# Get netmask from CIDR NB! IPv4 only
# E.g.:
# 192.168.1.2/16 -> 255.255.0.0
# 192.168.0.0/16 -> 255.255.0.0
cidr2mask() {
   local prefix ip mask
   prefix=$(cidr2prefixlen $1)
   mask=$((0xffffffff ^ ((1 << (32 - prefix)) - 1)))
   echo $(((mask >> 24) & 0xff)).$(((mask >> 16) & 0xff)).$(((mask >> 8) & 0xff)).$((mask & 0xff))
}

cidr2mask6() {
   local prefix ip mask
   prefix=$(cidr2prefixlen $1)
   mask=$(( 0xffffffffffffffff ^ ((1 << (32 - prefix)) - 1) ))
   echo $(((mask >> 24) & 0xff)).$(((mask >> 16) & 0xff)).$(((mask >> 8) & 0xff)).$((mask & 0xff))
}

# Get host identifer from CIDR. NB! IPv4 only
# E.g.:
# 192.168.0.0/16 -> 0.0.0.0
# 192.168.1.2/16 -> 0.0.1.2
cidr2host() {
    local ip; ip=$(cidr2ip $1)
    local mask; mask=$(cidr2mask $1)

    local res=""
    local i
    for i in {1..4}; do
        local pip pmask
        pip=$(echo $ip | awk -F\. "{print \$$i}")
        pmask=$(echo $mask | awk -F\. "{print \$$i}")
        res="$res.$((pip & ~pmask))"
    done
    # Remove the initial .
    echo ${res#\.}
}

# cidr2host for IPv6, does not "compress" the result
cidr2host6() {
    local ip; ip=$(expandipv6 "$(cidr2ip $1)")
    local prefix; prefix=$(cidr2prefixlen $1)
    local res=""
    local i
    for i in {1..8}; do
        local pip pmask
        pip=0x$(echo $ip | awk -F: "{print \$$i}")
        if ((prefix > 15)); then
            pmask=0xffff
            ((prefix -= 16))
        elif ((prefix == 0)); then
            pmask=0x0
        else
            pmask=$(( 0xffff ^ ((1 << (16 - prefix)) - 1) ))
            prefix=0
        fi
        oct=$(printf %x $((pip & ~pmask)))
        res="$res:$oct"
    done
    # Remove the initial :
    echo ${res#\:}
}

# Get network address from CIDR, NB! IPv4 only
# E.g.
# 192.168.1.2/16 -> 192.168.0.0
# 192.168.0.0/16 -> 192.168.0.0
cidr2net() {
    local ip; ip=$(cidr2ip $1)
    local mask; mask=$(cidr2mask $1)

    local res=""
    local i
    for i in {1..4}; do
        local pip pmask
        pip=$(echo $ip | awk -F\. "{print \$$i}")
        pmask=$(echo $mask | awk -F\. "{print \$$i}")
        res="$res.$((pip & pmask))"
    done
    # Remove the initial .
    echo ${res#\.}
}

# cidr2net for IPv6, does not "compress" the result
cidr2net6() {
    local ip; ip=$(expandipv6 "$(cidr2ip $1)")
    local prefix; prefix=$(cidr2prefixlen $1)

    local res=""
    local i
    for i in {1..8}; do
        local pip pmask
        pip=0x$(echo $ip | awk -F: "{print \$$i}")
        if ((prefix > 15)); then
            pmask=0xffff
            ((prefix -= 16))
        elif ((prefix == 0)); then
            pmask=0x0
        else
            pmask=$(( 0xffff ^ ((1 << (16 - prefix)) - 1) ))
            prefix=0
        fi
        oct=$(printf %x $((pip & pmask)))
        res="$res:$oct"
    done
    # Remove the initial :
    echo ${res#\:}
}

# Strip away comments unless inside quotes in the seed_yaml
strip_comments() {
sed -e "
1 {
  /^#!/ {
    p
  }
}

/^[\t\ ]*#/d

/\.*#.*/ {
  /[\x22\x27].*#.*[\x22\x27]/ !{
    :regular_loop
      s/\(.*\)*[^\]#.*/\1/
    t regular_loop
  }
  /[\x22\x27].*#.*[\x22\x27]/ {
    :special_loop
      s/\([\x22\x27].*#.*[^\x22\x27]\)#.*/\1/
    t special_loop
  }
  /\\#/ {
    :second_special_loop
      s/\(.*\\#.*[^\]\)#.*/\1/
    t second_special_loop
  }
}" $CONFIG_YAML
}

get_key_val() {
    local key="$1"
    local val
    # Allow spaces in value even if no explicit quoting is used but remove
    # leading and trailing spaces. It is a YAML file
    val="$(strip_comments | grep -E "^[[:space:]]*$key": | \
           sed -e 's/\r$//' -e 's/^.*'$key': *//' | \
           xargs)" || true
    [[ $val ]] || return 1
    echo "$val"
}

get_nested_key_val() {
    local key1="$1"
    local key2="$2"

    # Allow spaces in value even if no explicit quoting is used but remove
    # leading and trailing spaces. It is a YAML file
    val=$(strip_comments | sed -n "/^$key1:/",'/^[a-z]/{//!p}' | \
          grep -E "^[[:space:]]+$key2": | \
          sed -e 's/^.*'"${key2}"': *//' | xargs) || true

    [[ $val ]] || return 1
    echo "$val"
}

get_nested_key_list() {
    local key1="$1"
    local key2="$2"

    # Allow spaces in value even if no explicit quoting is used but remove
    # leading and trailing spaces. It is a YAML file
    val=$(strip_comments | sed -n "/^$key1:/",'/^[a-z]/{//!p}' | \
          sed -n "/^[[:space:]][[:space:]]*$key2:/",'/^[a-z]/{//!p}' | \
          sed -e 's/-//' | xargs) || true
    [[ $val ]] || return 1
    echo "$val"
}

verify_required_packages() {
    info "Verifying that all needed packages are installed"
    DISTRIBUTION=
    if grep -qw SUSE /proc/version; then
         grep -w VERSION= /etc/os-release | grep -qw 15 || \
            error "Only SLES 15 or OpenSUSE Leap 15 is supported"
        verify_required_packages_suse
        DISTRIBUTION=SUSE
    elif grep -qw Ubuntu /proc/version; then
        local rel; rel=$(awk -F= /DISTRIB_CODENAME/'{print $2}' /etc/lsb-release)
        [[ "xenial trusty bionic focal" =~ $rel ]] || \
            error "Only Ubuntu 14.04, 16.04, 18.04, or 20.04 is supported"
        verify_required_packages_ubuntu $rel
        DISTRIBUTION=UBUNTU
    else
        #error "Unsupported OS (must be Ubuntu or SLES/OpenSUSE)"
	:
    fi
}

set_globals() {
    BASE_DIR=$HOME/lcm_vms/$VM_NAME
    DATA_DISK=$BASE_DIR/data.qcow2
    CONFIG_DISK=$BASE_DIR/config.img
    INITRD=$BASE_DIR/initrd
    LINUX=$BASE_DIR/linux

    local lcm_ctrl_cidr
    lcm_ctrl_cidr=$(get_nested_key_val lcm_ctrl_sp cidr) || \
        error "CIDR for lcm_ctrl_sp missing in $CONFIG_YAML"
    [[ $(cidr2ip $lcm_ctrl_cidr) != "$lcm_ctrl_cidr" ]] || \
        error "The IP for lcm_ctrl_sp should be given in CIDR format," \
              "i.e. as dotted IP-address/prefixlen"
    lcm_ctrl_cidr=${lcm_ctrl_cidr,,}
    LCM_CIDR=$lcm_ctrl_cidr
    IPV6="false" # Needed as string in autoyast XML
    [[ $LCM_CIDR =~ : ]] && IPV6="true"
    LCM_CTRL_IP=$(cidr2ip $LCM_CIDR) || \
        error "Failed to extract IP from $LCM_CIDR"
    LCT_CIDR=
    LCT_CIDR=$(get_key_val lct_cidr) || LCT_CIDR=
    [[ -z $LCT_CIDR || $(cidr2ip $LCT_CIDR) != "$LCT_CIDR" ]] || \
        error "The IP for lct_cidr should be given in CIDR format," \
              "i.e. as dotted IP-address/prefixlen"

    local lcm_om_cidr
    lcm_om_cidr=$(get_nested_key_val lcm_om_sp cidr) || \
        info "CIDR for lcm_om_sp(optional) missing in $CONFIG_YAML" \
             "configures seedVM without lcm_om_sp network"
    LCM_OM_IP=
    if [[ $lcm_om_cidr ]]; then
        [[ $(cidr2ip $lcm_om_cidr) != "$lcm_om_cidr" ]] || \
            error "The IP for lcm_om_sp should be given in CIDR format," \
                  "i.e. as dotted IP-address/prefixlen"
        lcm_om_cidr=${lcm_om_cidr,,}
        IPV6="false" # Needed as string in autoyast XML
        [[ $lcm_om_cidr =~ : ]] && IPV6="true"
        LCM_OM_IP=$(cidr2ip $lcm_om_cidr) || \
            error "Failed to extract IP from $lcm_om_cidr"
    fi
    LCM_API_CLIENT_PASSWORD=$(get_key_val lcmApiInternalClientPassword) || LCM_API_CLIENT_PASSWORD=

    DISABLE_INTERNAL_PKI=$(get_key_val disableInternalPKI) || DISABLE_INTERNAL_PKI=
    PKI_CACERT_EXPIRY=$(get_key_val cacertExpiry) || PKI_CACERT_EXPIRY=1825
    PKI_CERT_EXPIRY=$(get_key_val certExpiry) || PKI_CERT_EXPIRY=730

    CEEINFRA_USER=ceeinfra
    CEEINFRA_PASSWORD=$(get_key_val ceeinfraPassword) || \
        error "ceeinfraPassword key missing in $CONFIG_YAML"
    get_ssh_key

    export ANSIBLE_VERBOSITY
}

verify_required_packages_suse() {
    local pk
    for pk in "${REQUIRED_PACKAGES_SUSE[@]}"; do
        rpm -q "$pk" &>/dev/null || \
            error "Required package not found: $pk. Required packages are:" \
                  "${REQUIRED_PACKAGES_SUSE[*]}"
    done
}

verify_required_packages_ubuntu() {
    rel=$1
    local pk
    for pk in "${REQUIRED_PACKAGES_UBUNTU_COMMON[@]}"; do
        dpkg -s "$pk" 2>/dev/null | grep "^Status:" | \
                                    grep -qw "install ok installed" || \
            error "Required package not found: $pk. Required packages are:" \
                  "${REQUIRED_PACKAGES_UBUNTU_COMMON[*]}" \
                  "$(echo ${REQUIRED_PACKAGES_UBUNTU_LIBVIRT[$rel]} | xargs)"
    done
    for pk in ${REQUIRED_PACKAGES_UBUNTU_LIBVIRT[$rel]}; do
        dpkg -s "$pk" 2>/dev/null | grep "^Status:" | \
                                    grep -qw "install ok installed" || \
            error "Required package not found: $pk. Required packages are:" \
                  "${REQUIRED_PACKAGES_UBUNTU_COMMON[*]}" \
                  "$(echo ${REQUIRED_PACKAGES_UBUNTU_LIBVIRT[$rel]} | xargs)"
    done
}

check_files(){
    [[ $ISO ]] || error "Failed to determine ISO-file to use"
    [[ -e $ISO ]] || error "$ISO is missing"
    [[ ! -d $ISO ]] || error "ISO is missing, determined path ended up with $ISO"
    [[ -e $CONFIG_YAML ]] || error "$CONFIG_YAML is missing"
    [[ $HOST_OS_ISO ]] || return 0
    [[ -e $HOST_OS_ISO ]] || error "$HOST_OS_ISO is missing"
    [[ ! -d $HOST_OS_ISO ]] || error "HOST_OS_ISO is missing, determined path ended up with $HOST_OS_ISO"
}

create_autoyast() {
    local file_name=$1

    local hostname domain timezone
    local lcm_ctrl_gw
    local cee_ctrl_cidr cee_ctrl_vlan
    local oobm_ctrl_cidr oobm_ctrl_vlan
    local lcm_om_cidr lcm_om_br lcm_om_bond lcm_om_gw
    local lcm_om_cidr_ipv4="" lcm_om_br_ipv4 lcm_om_bond_ipv4 LCM_OM_GW_IPV4=

    local ceeinfra_uid=1000
    local ceeinfra_gid=1000
    local ceeinfra_group=ceeinfra
    local sudo_gid=999

    [[ $CEEINFRA_PASSWORD ]] || \
        error "Password must be specified for $CEEINFRA_USER in $CONFIG_YAML"
    hostname=$(get_key_val hostname) || hostname=lcm_vm
    domain=$(get_key_val domain) || domain=cee.tld
    timezone=$(get_key_val timezone) || timezone=UTC

    local lcm_ctrl_br
    lcm_ctrl_br=$(get_nested_key_val lcm_ctrl_sp hostBridge) || \
        error "Name of bridge for lcm_ctrl_sp needs to be specified in $CONFIG_YAML"

    lcm_ctrl_gw=$(get_nested_key_val lcm_ctrl_sp gateway) || lcm_ctrl_gw=

    if [[ -z ${CI_PROXY:-} ]]; then
        local lcm_net cidr net
        if [[ $LCM_CIDR =~ : ]]; then
            lcm_net=$(cidr2net6 $LCM_CIDR)
            cidr=$(ip addr show $lcm_ctrl_br | grep -w inet6 | \
                   grep -v "scope link" | awk '{print $2}') || true
            [[ $cidr ]] || \
                error "The $lcm_ctrl_br bridge/interface needs to have an" \
                      "IPv6 address in the $lcm_net/$(cidr2prefixlen $LCM_CIDR)" \
                      "network"
            net=$(cidr2net6 $cidr)
            [[ $net == "$lcm_net" ]] || \
                error "The $lcm_ctrl_br bridge/interface needs to have an" \
                      "IPv6 address in the $lcm_net network. The current is" \
                      "in $net"
            [[ $(cidr2host6 $LCM_CIDR) != $(cidr2host6 $cidr) ]] || \
                error "The LCM IPv6 address in the lcm_ctrl_sp is already" \
                      "used on the $lcm_ctrl_br bridge/interface"
        else
            lcm_net=$(cidr2net $LCM_CIDR)
            cidr=$(ip addr show $lcm_ctrl_br | grep -w inet | \
                   awk '{print $2}') || true
            [[ $cidr ]] || \
                error "The $lcm_ctrl_br bridge/interface needs to have an" \
                      "IP address in the $lcm_net/$(cidr2prefixlen $LCM_CIDR)" \
                      "network"
            net=$(cidr2net $cidr)
            [[ $net == "$lcm_net" ]] || \
                error "The $lcm_ctrl_br bridge/interface needs to have" \
                      "an IP in the $lcm_net network. The current is in $net"
            [[ $(cidr2host $LCM_CIDR) != $(cidr2host $cidr) ]] || \
                error "The LCM IP address in the lcm_ctrl_sp is already used" \
                      "on the $lcm_ctrl_br bridge/interface"
        fi
    fi
    cee_ctrl_cidr=$(get_nested_key_val cee_ctrl_sp cidr) || \
        error "CIDR for cee_ctrl_sp missing in $CONFIG_YAML"
    cee_ctrl_vlan=$(get_nested_key_val cee_ctrl_sp segmentationId) || \
        error "segmentationId (VLAN id) for cee_ctrl_sp missing in" \
              "$CONFIG_YAML"
    [[ $(cidr2ip $cee_ctrl_cidr) != "$cee_ctrl_cidr" ]] || \
        error "The IP for cee_ctrl_sp should be given in CIDR format," \
              "i.e. as dotted IP-address/prefixlen"
    oobm_ctrl_cidr=$(get_nested_key_val oobm_ctrl_sp cidr) || oobm_ctrl_cidr=
    oobm_ctrl_vlan=$(get_nested_key_val oobm_ctrl_sp segmentationId) || true
    [[ -z $oobm_ctrl_cidr || $(cidr2ip $oobm_ctrl_cidr) != "$oobm_ctrl_cidr" ]] || \
        error "The IP for oobm_ctrl_sp should be given in CIDR format," \
              "i.e. as dotted IP-address/prefixlen"
    lcm_om_cidr=$(get_nested_key_val lcm_om_sp cidr) || lcm_om_cidr=
    lcm_om_br=$(get_nested_key_val lcm_om_sp hostBridge) || lcm_om_br=
    lcm_om_bond=$(get_nested_key_val lcm_om_sp hostBond) || lcm_om_bond=
    lcm_om_gw=$(get_nested_key_val lcm_om_sp gateway) || lcm_om_gw=
    if [[ ${IPV6:-} == "true" ]]; then
        lcm_om_cidr_ipv4=$(get_nested_key_val lcm_om_sp_ipv4 cidr) || lcm_om_cidr_ipv4=
        lcm_om_br_ipv4=$(get_nested_key_val lcm_om_sp_ipv4 hostBridge) || lcm_om_br_ipv4=
        lcm_om_bond_ipv4=$(get_nested_key_val lcm_om_sp_ipv4 hostBond) || lcm_om_bond_ipv4=
        LCM_OM_GW_IPV4=$(get_nested_key_val lcm_om_sp_ipv4 gateway) || LCM_OM_GW_IPV4=
        if [[ ${LCM_OM_GW_IPV4:-} ]]; then
            [[ ${lcm_om_cidr_ipv4:-} ]] || \
                error "Cannot specify gw for cee_om_sp_ipv4 if no cidr is defined"
        fi
    fi

    local oobm_interface=
    if [[ ${oobm_ctrl_cidr:-} ]]; then
        [[ ${oobm_ctrl_vlan:-} ]] || \
           error "When oobm_ctrl_sp is defined the segmentationId (VLAN)" \
                 "must also be defined"
        oobm_interface="
      <interface>
        <bootproto>static</bootproto>
        <device>eth0.$oobm_ctrl_vlan</device>
        <etherdevice>eth0</etherdevice>
        <firewall>no</firewall>
        <ipaddr>$oobm_ctrl_cidr</ipaddr>
        <startmode>onboot</startmode>
        <usercontrol>no</usercontrol>
      </interface>"
    fi
    local lcm_route=
    if [[ ${lcm_om_gw:-} ]]; then
        [[ ${lcm_om_cidr:-} ]] || \
            error "Cannot specify gw for cee_om_sp if no cidr is defined"
        lcm_route="
      <routes config:type=\"list\">
        <route>
          <destination>default</destination>
          <device>eth1</device>
          <gateway>$lcm_om_gw</gateway>
        </route>
      </routes>"
    elif [[ ${lcm_ctrl_gw:-} ]]; then
        lcm_route="
      <routes config:type=\"list\">
        <route>
          <destination>default</destination>
          <device>eth0</device>
          <gateway>$lcm_ctrl_gw</gateway>
        </route>
      </routes>"
    fi
    local lcm_om_interface="" lcm_om_interface2=
    if [[ ${lcm_om_cidr:-} ]]; then
        [[ $(cidr2ip $lcm_om_cidr) != "$lcm_om_cidr" ]] || \
            error "The IP for lcm_om_sp should be given in CIDR format," \
                  "i.e. as dotted IP-address/prefixlen"
        [[ ${lcm_om_br:-} || ${lcm_om_bond:-} ]] || \
           error "When lcm_om_sp is defined the hostBridge or hostBond" \
                 "must also be defined"
        [[ ${lcm_om_bond:-} && ${lcm_om_br:-} ]] && \
           error "When lcm_om_sp is defined not both hostBrige and hostBond" \
                 "can be defined"
        lcm_om_interface="
      <interface>
        <bootproto>static</bootproto>
        <device>eth1</device>
        <firewall>no</firewall>
        <ipaddr>$lcm_om_cidr</ipaddr>
        <startmode>onboot</startmode>
        <usercontrol>no</usercontrol>
      </interface>"
        if [[ ${lcm_om_cidr_ipv4:-} ]]; then
            [[ $(cidr2ip $lcm_om_cidr_ipv4) != "$lcm_om_cidr_ipv4" ]] || \
                error "The IP for lcm_om_sp_ipv4 should be given in CIDR format," \
                      "i.e. as dotted IP-address/prefixlen"
            [[ ${lcm_om_br_ipv4:-} || ${lcm_om_bond_ipv4:-} ]] || \
               error "When lcm_om_sp_ipv4 is defined the hostBridge or hostBond" \
                     "must also be defined"
            [[ ${lcm_om_bond_ipv4:-} && ${lcm_om_br_ipv4:-} ]] && \
               error "When lcm_om_sp_ipv4 is defined not both hostBrige and hostBond" \
                     "can be defined"
            lcm_om_interface2="
      <interface>
        <bootproto>static</bootproto>
        <device>eth2</device>
        <firewall>no</firewall>
        <ipaddr>$lcm_om_cidr_ipv4</ipaddr>
        <startmode>onboot</startmode>
        <usercontrol>no</usercontrol>
      </interface>"
        fi
    fi
    local lct_alias=
    if [[ ${LCT_CIDR:-} ]]; then
        # ipaddr has to be in upper case for the alias to work, really!
        lct_alias="
        <aliases>
          <alias0>
            <IPADDR>$LCT_CIDR</IPADDR>
          </alias0>
        </aliases>"
    fi
    local dns_servers dns=
    dns_servers=$(get_nested_key_list lcm_om_sp externalDnsServers) || dns_servers=
    if [[ ${CI_PROXY:-} && -z $dns_servers ]] && get_nested_key_list lcm_ctrl_sp gateway &>/dev/null; then
        dns_servers=$(get_nested_key_list lcm_ctrl_sp externalDnsServers) || dns_servers=
    fi
    if [[ $dns_servers ]]; then
        dns="
      <resolv_conf_policy>auto</resolv_conf_policy>
      <nameservers config:type='list'>"
      local i
      for i in $dns_servers; do
          dns+="<nameserver>$i</nameserver>"
      done
      dns+="</nameservers>"
    fi

    local tmp number version info
    tmp=$(sed -n '/^product:/,/^[a-z]/{//!p}' ${ISO%iso}yaml)
    version=$(awk '/version:/{print $2}' <<< "$tmp")
    info=$(awk '/buildInfo:/{print $2}' <<< "$tmp")
    number=${CEE_BASE#cee-}
    CEE_INFRA_ORCHESTATOR=$number-$version-$info

    cat >"$file_name" <<EOF
<?xml version="1.0"?>
<!DOCTYPE profile>
<profile
     xmlns="http://www.suse.com/1.0/yast2ns"
     xmlns:config="http://www.suse.com/1.0/configns">
  <deploy_image>
    <image_installation config:type="boolean">false</image_installation>
  </deploy_image>
  <language>
    <language>en_US</language>
  </language>
  <keyboard>
    <keymap>english-us</keymap>
  </keyboard>
  <timezone>
    <hwclock>UTC</hwclock>
    <timezone>$timezone</timezone>
  </timezone>
  <bootloader>
    <global>
      <terminal>console</terminal>
      <timeout config:type="integer">5</timeout>
    </global>
  </bootloader>
  <general>
    <mode>
      <confirm config:type="boolean">false</confirm>
      <final_halt config:type="boolean">false</final_halt>
      <final_reboot config:type="boolean">false</final_reboot>
      <halt config:type="boolean">true</halt>
      <second_stage config:type="boolean">false</second_stage>
    </mode>
    <signature-handling>
      <accept_file_without_checksum config:type="boolean">true</accept_file_without_checksum>
      <accept_non_trusted_gpg_key config:type="boolean">true</accept_non_trusted_gpg_key>
      <accept_unknown_gpg_key config:type="boolean">true</accept_unknown_gpg_key>
      <accept_unsigned_file config:type="boolean">true</accept_unsigned_file>
      <accept_verification_failed config:type="boolean">false</accept_verification_failed>
      <import_gpg_key config:type="boolean">false</import_gpg_key>
    </signature-handling>
    <storage>
      <start_multipath config:type="boolean">true</start_multipath>
    </storage>
  </general>
  <software>
    <products config:type="list">
      <product>SLES</product>
    </products>
    <packages config:type="list">
      <package>aaa_base-extras</package>
      <package>adjtimex</package>
      <package>ansible</package>
      <package>ansible-collections</package>
      <package>apache2-mod_wsgi-python3</package>
      <package>apache2</package>
      <package>apparmor-profiles</package>
      <package>audit</package>
      <package>autoyast2-installation</package>
      <package>bash-completion</package>
      <package>btrfsmaintenance</package>
      <package>bzip2</package>
      <package>cee-lcm</package>
      <package>cee-ansible-$CEE_INFRA_ORCHESTATOR</package>
      <package>cee-config-model</package>
      <package>cee-registry</package>
      <package>chrony</package>
      <package>createrepo_c</package>
      <package>docker</package>
      <package>docker-bash-completion</package>
      <package>firewalld</package>
      <package>git-core</package>
      <package>hostname</package>
      <package>iputils</package>
      <package>kernel-firmware</package>
      <package>less</package>
      <package>lsof</package>
      <package>mlocate</package>
      <package>netcat-openbsd</package>
      <package>oobm-tools</package>
      <package>parted</package>
      <package>python3-Cheetah3</package>
      <package>python3-keystonemiddleware</package>
      <package>python3-kolla-ansible</package>
      <package>python3-netaddr</package>
      <package>python3-passlib</package>
      <package>python3-pbr</package>
      <package>python3-requests</package>
      <package>python3-simplejson</package>
      <package>rsync</package>
      <package>screen</package>
      <package>shim</package>
      <package>sudo</package>
      <package>suse-build-key</package>
      <package>syslinux</package>
      <package>systemd-coredump</package>
      <package>terminfo</package>
      <package>terminfo-screen</package>
      <package>traceroute</package>
      <package>util-linux</package>
      <package>vim</package>
      <package>vim-data</package>
      <package>xinetd</package>
      <package>yast2-network</package>
      <package>yast2-ntp-client</package>
    </packages>
  </software>
  <add-on>
    <add_on_products config:type="list">
      <listentry>
        <name>cee-host-os</name>
        <media_url><![CDATA[cd:///?devices=/dev/sr1]]></media_url>
        <alias>cee-host-os</alias>
        <product_dir>/cee/repos/cee-host-os/</product_dir>
        <ask_on_error config:type="boolean">true</ask_on_error>
      </listentry>
      <listentry>
        <name>cee-infa</name>
        <media_url><![CDATA[cd:///?devices=/dev/sr0]]></media_url>
        <alias>cee-infra</alias>
        <product_dir>/cee/repos/cee-infra/</product_dir>
        <ask_on_error config:type="boolean">true</ask_on_error>
      </listentry>
      <listentry>
        <name>cee-infa</name>
        <media_url><![CDATA[cd:///?devices=/dev/sr0]]></media_url>
        <alias>cee-infra-orchestrator</alias>
        <product_dir>/cee/repos/cee-infra-orchestrator/</product_dir>
        <ask_on_error config:type="boolean">true</ask_on_error>
      </listentry>
      <listentry>
        <name>cee-host-extras</name>
        <media_url><![CDATA[cd:///?devices=/dev/sr1]]></media_url>
        <alias>cee-host-extras</alias>
        <product_dir>/cee/repos/cee-host-extras/</product_dir>
        <ask_on_error config:type="boolean">true</ask_on_error>
      </listentry>
    </add_on_products>
  </add-on>
  <services-manager>
    <default_target>multi-user</default_target>
    <services>
      <enable config:type="list">
        <service>apache2</service>
        <service>chronyd</service>
        <service>docker</service>
        <service>sshd</service>
      </enable>
      <disable config:type="list">
        <service>firewalld</service>
      </disable>
    </services>
  </services-manager>
  <kdump>
    <add_crash_kernel config:type="boolean">true</add_crash_kernel>
    <crash_kernel config:type="list">
      <listentry>256M</listentry>
    </crash_kernel>
  </kdump>
  <partitioning config:type="list">
    <drive>
      <device>/dev/vda</device>
      <initialize config:type="boolean">true</initialize>
      <use>all</use>
      <disklabel>gpt</disklabel>
      <partitions config:type="list">
        <partition>
          <filesystem config:type="symbol">swap</filesystem>
          <size>4G</size>
          <mount>swap</mount>
        </partition>
        <partition>
          <filesystem config:type="symbol">ext4</filesystem>
          <size>10G</size>
          <mount>/var/lib/docker</mount>
        </partition>
        <partition>
          <filesystem config:type="symbol">btrfs</filesystem>
          <size>max</size>
          <mount>/</mount>
        </partition>
      </partitions>
    </drive>
  </partitioning>
  <networking>
    <dns>
      <domain>$domain</domain>
      <hostname>$hostname.$domain</hostname>
      $dns
    </dns>
    <interfaces config:type="list">
      <interface>
        <bootproto>static</bootproto>
        <device>eth0</device>
        <firewall>no</firewall>
        <ipaddr>$LCM_CIDR</ipaddr>
        <startmode>onboot</startmode>
        <usercontrol>no</usercontrol>
        $lct_alias
      </interface>
      <interface>
        <bootproto>static</bootproto>
        <device>eth0.$cee_ctrl_vlan</device>
        <etherdevice>eth0</etherdevice>
        <firewall>no</firewall>
        <ipaddr>$cee_ctrl_cidr</ipaddr>
        <startmode>onboot</startmode>
        <usercontrol>no</usercontrol>
      </interface>
      $oobm_interface
      $lcm_om_interface
      $lcm_om_interface2
    </interfaces>
    <ipv6 config:type="boolean">$IPV6</ipv6>
    <keep_install_network config:type="boolean">false</keep_install_network>
    <managed config:type="boolean">false</managed>
    <routing>
      <ipv4_forward config:type="boolean">false</ipv4_forward>
      <ipv6_forward config:type="boolean">false</ipv6_forward>
      $lcm_route
    </routing>
  </networking>
  <ntp-client>
    <ntp_policy>auto</ntp_policy>
    <ntp_sync>systemd</ntp_sync>
    <ntp_servers config:type="list">
      <ntp_server>
        <address>opensuse.pool.ntp.org</address>
        <iburst config:type="boolean">true</iburst>
        <offline config:type="boolean">false</offline>
      </ntp_server>
    </ntp_servers>
  </ntp-client>
  <host>
    <hosts config:type="list">
      <hosts_entry>
        <host_address>$LCM_CTRL_IP</host_address>
        <names config:type="list">
          <name>$hostname.$domain $hostname</name>
        </names>
      </hosts_entry>
    </hosts>
  </host>
  <groups config:type="list">
    <group>
      <groupname>sudo</groupname>
      <gid>$sudo_gid</gid>
      <userlist>$CEEINFRA_USER</userlist>
    </group>
    <group>
      <groupname>$ceeinfra_group</groupname>
      <gid>$ceeinfra_gid</gid>
      <userlist>$CEEINFRA_USER</userlist>
    </group>
  </groups>
  <users config:type="list">
    <user>
      <username>$CEEINFRA_USER</username>
      <uid>$ceeinfra_uid</uid>
      <gid>$ceeinfra_gid</gid>
      <user_password>$CEEINFRA_PASSWORD</user_password>
      <encrypted config:type="boolean">false</encrypted>
      <home>/home/$CEEINFRA_USER</home>
      <authorized_keys config:type="list">
        <authorized_key>$KEY</authorized_key>
      </authorized_keys>
    </user>
    <user>
      <username>root</username>
      <encrypted config:type="boolean">false</encrypted>
      <home>/root</home>
      <authorized_keys config:type="list">
        <authorized_key>$KEY</authorized_key>
      </authorized_keys>
    </user>
  </users>
  <scripts>
    <chroot-scripts config:type="list">
      <script>
        <chrooted config:type="boolean">true</chrooted>
        <filename>init.sh</filename>
        <notification>Executing bootstrap of CEE seed LCM VM...</notification>
        <source><![CDATA[
#!/bin/sh
sed -i -e 's/^#local/local/' /etc/chrony.conf
mkdir -p /var/log/cee
touch /var/log/cee/ansible.log
chmod 0640 /var/log/cee/ansible.log
chown $CEEINFRA_USER:$ceeinfra_group /var/log/cee/ansible.log
sed -i -e 's|#log_path.*|log_path = /var/log/cee/ansible.log|' /etc/ansible/ansible.cfg
echo "$LCM_CTRL_IP      docker-registry.$domain" >>/etc/hosts
echo "$LCM_CTRL_IP      cee-repo.$domain" >>/etc/hosts
mkdir -p /etc/sudoers.d
chmod 0750 /etc/sudoers.d
echo '$CEEINFRA_USER ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/90-cee-lcm
chmod 0440 /etc/sudoers.d/90-cee-lcm
echo 'syntax off' >/root/.vimrc
cp /root/.vimrc /home/$CEEINFRA_USER
# The uid/gid is not honoured at all times, ensure proper ownership
chown -R $CEEINFRA_USER:$ceeinfra_group /home/$CEEINFRA_USER /var/log/cee
mkdir -p --mode=0755 /var/lib/cee/main /var/lib/cee/main/system
chown -R $CEEINFRA_USER:$ceeinfra_group /var/lib/cee/main
# WA the alias is not set in SP2...
if [ $LCT_CIDR ]; then
  if ! grep -q $LCT_CIDR /etc/sysconfig/network/ifcfg-eth0; then
    echo "IPADDR_1='$LCT_CIDR'" >>/etc/sysconfig/network/ifcfg-eth0
  fi
fi
# If dual stack add the IPv4 route
if [ ${LCM_OM_GW_IPV4:-} ]; then
  echo "default $LCM_OM_GW_IPV4 - eth2" >/etc/sysconfig/network/ifroute-eth2
fi
mount -o loop,ro /dev/sr0 /mnt
mkdir -p /srv/www/cee
cp -r /mnt/cee/* /srv/www/cee/
umount /mnt
mount -o loop,ro /dev/sr1 /mnt
cp -r /mnt/cee/* /srv/www/cee/
umount /mnt
]]>
        </source>
      </script>
    </chroot-scripts>
    <init-scripts config:type="list">
      <script>
        <filename>postinit.sh</filename>
        <source><![CDATA[
#!/bin/sh
zypper removerepo -all
# Running the ansible playbooks as part of the post init scripts does not work
# as all services are not really up and running yet. The ansible spawnng of
# local ssh sessions complain on ssh and pam stuf and takes for ever to run
# We'll run them via ssh instead when the system is really up
echo '[search]' >>/root/.zypper.conf
echo 'runSearchPackages = never' >>/root/.zypper.conf
]]>
        </source>
      </script>
    </init-scripts>
  </scripts>
</profile>
EOF
}

get_ssh_key() {
    if [[ ! -d $HOME/.ssh ]]; then
        mkdir -p $HOME/.ssh
        ssh-keygen -t rsa -f $HOME/.ssh/id_rsa -q -P ""
    elif [[ -e $HOME/.ssh/id_rsa && ! -e $HOME/.ssh/id_rsa.pub ]]; then
        ssh-keygen -y -f $HOME/.ssh/id_rsa > $HOME/.ssh/id_rsa.pub
    elif [[ ! -e $HOME/.ssh/id_rsa ]]; then
        ssh-keygen -t rsa -f $HOME/.ssh/id_rsa -q -P ""
    fi
    # If we run the script w/ sudo, then on at least Ubuntu, the $HOME will be
    # the the real user's $HOME. But when we at the end do ssh it will look in
    # root's home for the keys. So explicitly state to use the real user's ssh
    # identity
    local id_file=$HOME/.ssh/id_rsa
    KEY=$(cat $HOME/.ssh/id_rsa.pub)
    SSH_OPTS="-o PreferredAuthentications=publickey \
              -o StrictHostKeyChecking=no \
              -o UserKnownHostsFile=/dev/null \
              -o IdentitiesOnly=yes \
              -o ConnectTimeout=15 \
              -i $id_file"
}

usage() {
    echo "Usage: $0 [--artifact <uri> [<uri> ...] [--vm-name VM_NAME]" \
         "[--iso ISO] [--host-os-iso ISO] [--config CONFIG]"
    exit 1
}

parse_commandline() {
    local trace=false
    while [[ ${1:-} ]]; do
        case "$1" in
        -v | --vm-name)
            shift
            (($# > 0)) || usage
            VM_NAME="$1"
            ;;
        -i | --iso)
            shift
            (($# > 0)) || usage
            ISO=$(readlink --canonicalize "$1") || \
                error "Can't read file $1"
            ;;
        --host-os-iso)
            shift
            (($# > 0)) || usage
            HOST_OS_ISO=$(readlink --canonicalize "$1") || \
                error "Can't read file $1"
            ;;
        -c | --config)
            shift
            (($# > 0)) || usage
            CONFIG_YAML=$(readlink --canonicalize "$1") || \
                error "Can't read file $1"
            ;;
        -a | --artifact)
            shift
            (($# > 0)) || usage
            while [[ ${1:-} ]]; do
                [[ $1 =~ ^- ]] && continue 2 # Outer while-loop to process arg
                if ! [[ $1 =~ ^http || $1 =~ ^ftp ]]; then
                   [[ -e ${1#file:} ]] || error "No tar-file found at $1"
                fi
                [[ "$1" != *$CEE_BASE* ]] || \
                   error "The CEE Base artifact, $1, should not be included in the list of artifacts"
                URIS+=("$1")
                shift
            done
            # We consume all unless additional parameter is found above
            break
            ;;
        -h | --help)
            usage
            ;;
        -p | --prefer-ipv4)
            PREFER_IPV4=true
            ;;
        --verbose)
            ANSIBLE_VERBOSITY=3
            ;;
        -d | --debug)
            SILENT_ANSIBLE=
            ;;
        -x | --trace)
            trace=true
            ;;
        *)
            usage
            ;;
        esac
        shift
    done
    if [[ -z $ISO ]]; then
        ISO=$(ls "$(dirname $DIR)/$CEE_BASE"*.iso 2>/dev/null) || true
    fi

    if [[ -z $HOST_OS_ISO ]]; then
        HOST_OS_ISO=$(ls "$(dirname $DIR)/$HOST_OS"*.iso 2>/dev/null) || true
    fi
    $trace && set -o xtrace
    return 0
}

check_prerequisites(){
    check_files
    verify_required_packages
}

handle_host_os_artifact() {
    [[ $HOST_OS_ISO ]] && return 0

    local tmp uri prefer_ipv4=
    # Magic issues on Ubuntu having ISOs in /tmp so just place it where the
    # CEE base ISO has been downloaded
    tmp=$(dirname $ISO)
    [[ $IPV6 == true ]] && $PREFER_IPV4 && prefer_ipv4="--prefer-family=IPv4"
    for uri in "${URIS[@]:-}"; do
        [[ "$uri" == *$HOST_OS* ]] || continue
        local -a res
        local iso="" meta="" f
        if [[ $uri =~ ^http || $uri =~ ^ftp ]]; then
            info "Downloading and unpacking host OS artifact $uri"
            mapfile -t res < <(wget -q $prefer_ipv4 $uri -O - | tar -C $tmp -zxvf - 2>/dev/null || \
                               wget -q $prefer_ipv4 $uri -O - | tar -C $tmp -xvf - 2>&1) || \
                error "Failed to download/extract $uri: ${res[*]}"
        else
            info "Unpacking host OS artifact $uri"
            # shellcheck disable=SC2002
            mapfile -t res < <(cat ${uri#file:} | tar -C $tmp -zxvf - 2>/dev/null || \
                               cat ${uri#file:} | tar -C $tmp -xvf - 2>&1) || \
                error "Failed to extract $uri: ${res[*]}"
        fi
        local f
        for f in "${res[@]}"; do
            [[ $f == *iso ]] && iso=$f
        done
        [[ $iso ]] || error "Failed to find iso in $uri"
        HOST_OS_ISO=$tmp/$iso
        break
    done
    [[ $HOST_OS_ISO ]] || error "Host OS artifact is missing in list of artifacts"
    [[ -e $HOST_OS_ISO ]] || error "$HOST_OS_ISO is missing"

    # Remove the host OS from the artifacts, keeping any spaces
    res=("${URIS[@]}")
    URIS=()
    for uri in "${res[@]}"; do
        [[ "$uri" == *$HOST_OS* ]] && continue
        URIS+=("$uri")
    done
}

cleanup_previous(){
    info "Cleaning up from any previous run"
    local res
    if virsh list | grep -qw $VM_NAME; then
        res=$(virsh destroy "$VM_NAME" 2>&1) ||
              error "Failed to destroy old $VM_NAME: \"$res\""
    fi
    if virsh list --all | grep -qw "$VM_NAME"; then
        res=$(virsh undefine "$VM_NAME" 2>&1) ||
              error "Failed to undefine old $VM_NAME: \"$res\""
    fi
    rm -rf $BASE_DIR
    info "Previous seed LCM VM cleaned up"
}

create_disks(){
    info "Creating configuration files for seed LCM VM"
    # The path must be searchable by qemu. Explicitly fix that since we
    # might be running with root's HOME which will not be searchable by
    # default. We're on the kickstart server so we should be able to
    # allow this for the initital deployment
    local umask; umask=$(umask)
    umask 0022 &>/dev/null || true
    local mnt; mnt=$BASE_DIR/mnt
    mkdir -p $mnt
    umask $umask &>/dev/null || true
    local i=${BASE_DIR%\/*}
    while [[ $i ]]; do
        chmod +x $i
        i=${i%\/*}
    done

    local disk_size
    disk_size=$(get_key_val disk) || \
        error "disk key missing in $CONFIG_YAML"
    [[ $disk_size ]] || \
        error "Size of diskimage for seed LCM VM not specified in $CONFIG_YAML"

    # LABEL Used in autoyast
    LABEL=cee-config
    local qcow2_prealloc="-o preallocation=falloc"
    local raw_prealloc="-o preallocation=full"
    local res
    if ! qemu-img create -f qcow2 -o? | grep -qw falloc; then
        info "WARNING: old qemu-img, preallocation=falloc cannot be used." \
             "Falling back to preallocation=metadata"
        qcow2_prealloc="-o preallocation=metadata"
        raw_prealloc=""
    fi
    res=$(qemu-img create -f qcow2 $qcow2_prealloc $DATA_DISK $disk_size 2>&1) || error "$res"
    res=$(qemu-img create -f raw $raw_prealloc $CONFIG_DISK 10M 2>&1) || error "$res"
    res=$(mkfs -t ext2 -m 0 -F $CONFIG_DISK 2>&1) || error "$res"
    res=$(e2label $CONFIG_DISK $LABEL 2>&1) || error "$res"
    fsck.ext2 -y $CONFIG_DISK &>/dev/null || true

    local autoyast; autoyast=$(mktemp)
    create_autoyast "$autoyast"
    mount -o loop,rw $CONFIG_DISK $mnt || error "Failed to loop mount $CONFIG_DISK"
    cp $autoyast $mnt/autoyast.xml
    umount $mnt
    rm -f $autoyast

    mount -o loop,ro $ISO $mnt || error "Failed to loop mount $ISO"
    cp $mnt/boot/x86_64/loader/initrd $INITRD
    cp $mnt/boot/x86_64/loader/linux $LINUX
    umount $mnt
}

create_xml() {
    local file_name=$1
    local machine=
    if [[ $DISTRIBUTION == SUSE ]]; then
        machine=q35
    elif [[ $DISTRIBUTION == UBUNTU ]]; then
        machine=$(grep ^DISTRIB_CODENAME /etc/lsb-release | \
                  sed 's/^.*DISTRIB_CODENAME=//' | xargs) || true
        [[ $machine ]] || machine=xenial
        machine=pc-i440fx-$machine
    fi

    local lcm_ctrl_br lcm_om_br lcm_om_bond lcm_om_br_ipv4 lcm_om_bond_ipv4 memory vcpus
    lcm_ctrl_br=$(get_nested_key_val lcm_ctrl_sp hostBridge) || \
        error "Name of bridge for lcm_ctrl_sp needs to be specified in $CONFIG_YAML"
    lcm_om_br=$(get_nested_key_val lcm_om_sp hostBridge) || lcm_om_br=
    lcm_om_bond=$(get_nested_key_val lcm_om_sp hostBond) || lcm_om_bond=
    lcm_om_br_ipv4=$(get_nested_key_val lcm_om_sp_ipv4 hostBridge) || lcm_om_br_ipv4=
    lcm_om_bond_ipv4=$(get_nested_key_val lcm_om_sp_ipv4 hostBond) || lcm_om_bond_ipv4=
    memory=$(get_key_val memory) || \
        error "memory key missing in $CONFIG_YAML"
    vcpus=$(get_key_val vcpus) || \
        error "vcpus key missing in $CONFIG_YAML"
    [[ $memory ]] || \
        error "Reserved memory for seed LCM VM not specified in $CONFIG_YAML"
    [[ $vcpus ]] || \
        error "Number of vCPUs for seed LCM VM not specified in $CONFIG_YAML"

    local interface dev_name=${VM_NAME:0:10}
    # CI Hook
    if [[ ${CI_PROXY:-} ]]; then
       if [[ ${IPV6:-} == "true" ]]; then
        interface="
    <interface type='network'>
      <source network='$lcm_ctrl_br'/>
      <model type='e1000'/>
    </interface>"
       else
        interface="
    <interface type='network'>
      <source network='$lcm_ctrl_br'/>
      <model type='rtl8139'/>
    </interface>"
       fi
    else
        interface="
    <interface type='bridge'>
      <source bridge='$lcm_ctrl_br'/>
      <target dev='${dev_name}_eth0'/>
      <model type='virtio'/>
    </interface>"
    fi
    local om_sp_interface=
    if [[ ${lcm_om_br:-} ]]; then
        om_sp_interface="
    <interface type='bridge'>
      <source bridge='$lcm_om_br'/>
      <target dev='${dev_name}_eth1'/>
      <model type='virtio'/>
    </interface>"
    elif [[ ${lcm_om_bond:-} ]]; then
        om_sp_interface="
    <interface type='direct'>
      <source dev='$lcm_om_bond' mode='bridge'/>
      <target dev='${dev_name}_eth1'/>
      <model type='virtio'/>
    </interface>"
    fi
    local om_sp_interface2=
    if [[ $om_sp_interface ]]; then
        if [[ ${lcm_om_br_ipv4:-} ]]; then
            om_sp_interface2="
    <interface type='bridge'>
      <source bridge='$lcm_om_br_ipv4'/>
      <target dev='${dev_name}_eth2'/>
      <model type='virtio'/>
    </interface>"
        elif [[ ${lcm_om_bond_ipv4:-} ]]; then
            om_sp_interface2="
    <interface type='direct'>
      <source dev='$lcm_om_bond_ipv4' mode='bridge'/>
      <target dev='${dev_name}_eth2'/>
      <model type='virtio'/>
    </interface>"
        fi
    fi

    cat >"$file_name" <<EOF
<domain type='kvm'>
  <name>$VM_NAME</name>
  <metadata>
    <libosinfo:libosinfo xmlns:libosinfo='http://libosinfo.org/xmlns/libvirt/domain/1.0'>
      <libosinfo:os id='http://suse.com/sle/15.3'/>
    </libosinfo:libosinfo>
  </metadata>
  <memory unit='MiB'>$memory</memory>
  <vcpu placement='static'>$vcpus</vcpu>
  <os>
    <type arch='x86_64' machine='$machine'>hvm</type>
    <kernel>$LINUX</kernel>
    <initrd>$INITRD</initrd>
    <cmdline>autoyast=label://$LABEL/autoyast.xml nomodeset console=tty0 console=ttyS0,115200</cmdline>
    <boot dev='cdrom'/>
    <boot dev='hd'/>
    <bios useserial='yes'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='host-passthrough'>
  </cpu>
  <clock offset='utc'>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='hpet' present='no'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>coredump-restart</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none' io='native'/>
      <source file='$DATA_DISK'/>
      <target dev='vda' bus='virtio'/>
      <alias name='virtio-disk0'/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw'/>
      <source file='$CONFIG_DISK'/>
      <target dev='vdb' bus='virtio'/>
      <alias name='virtio-disk1'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='$ISO'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
      <alias name='ide0-0-0'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='$HOST_OS_ISO'/>
      <target dev='sdb' bus='sata'/>
      <readonly/>
      <alias name='ide1-0-0'/>
    </disk>
    "$interface"
    "$om_sp_interface"
    "$om_sp_interface2"
    <console type='pty' tty='/dev/pts/0'>
      <source path='/dev/pts/0'/>
      <target type='serial' port='0'/>
    </console>
    <graphics type='vnc' autoport='yes' listen='127.0.0.1'/>
    <video>
      <model type='cirrus'/>
    </video>
    <memballoon model='virtio'>
    </memballoon>
  </devices>
</domain>
EOF
}

wait_for_first_step() {
    info "Waiting for seed LCM VM to shutdown after its first installation" \
         "step. This typically takes 5-15 minutes"
    local install_timeout=$((25 * 60))
    local slp=10
    local to=$((install_timeout / slp))
    local i
    for ((i = 0; i < to; ++i)); do
        virsh list | grep -qw "$VM_NAME" || return 0
        sleep $slp
    done
    error "First installation step of seed LCM VM failed, we timed out after" \
          "$((install_timeout/60)) minutes"
}

wait_for_restart() {
    info "Waiting for seed LCM VM to become reachable again"
    local poll_timeout=$((10 * 60))
    local slp=10
    local to=$((poll_timeout / slp))
    local i
    local -a ssh_cmd
    read -r -a ssh_cmd <<<"ssh $SSH_OPTS"
    # CI Hook
    [[ ${CI_PROXY:-} ]] && ssh_cmd+=(-o) && ssh_cmd+=("$CI_PROXY")
    ssh_cmd+=("$CEEINFRA_USER@$LCM_CTRL_IP")
    for ((i = 0; i < to; ++i)); do
        sleep $slp
        if "${ssh_cmd[@]}" "/bin/echo" &>/dev/null; then
            info "Seed LCM VM is reachable again"
            return 0
        fi
    done
    error "Seed LCM VM failed to start"
}

post_install_steps() {
    local -a scp_cmd ssh_cmd
    read -r -a scp_cmd <<<"scp $SSH_OPTS"
    read -r -a ssh_cmd <<<"ssh -q $SSH_OPTS"
    local domain; domain=$(get_key_val domain) || domain=cee.tld
    local hostname; hostname=$(get_key_val hostname) || hostname=lcm_vm

    # CI Hooks
    [[ ${CI_PROXY:-} ]] && scp_cmd+=(-o) && scp_cmd+=("$CI_PROXY")
    [[ ${CI_PROXY:-} ]] && ssh_cmd+=(-o) && ssh_cmd+=("$CI_PROXY")

    ssh_cmd+=("$CEEINFRA_USER@$LCM_CTRL_IP")
    ssh_cmd+=(--)
    ssh_cmd+=("ANSIBLE_VERBOSITY=$ANSIBLE_VERBOSITY")

    info "Starting post installation steps"
    local src; src=$(dirname $ISO)/templates
    local target=/opt/cee
    if [[ -d $src ]]; then
        "${scp_cmd[@]}" -r "$src" $CEEINFRA_USER@"[$LCM_CTRL_IP]:" &>/dev/null || \
            error "Failed to copy config templates to $VM_NAME"
        "${ssh_cmd[@]}" "sudo mv ~$CEEINFRA_USER/templates $target" || \
            error "Failed to move the templates to $target"
    fi

    ejbca_image="cee/{{ kolla_base_distro }}-binary-ejbca-server:$(awk '/tag:/ && image ~ /ejbca-server_image/ {print $2} {image=$0}' "${ISO%iso}yaml")"
    cmpclient_image="cee/{{ kolla_base_distro }}-binary-cmpclient:$(awk '/tag:/ && image ~ /cmpclient_image/ {print $2} {image=$0}' "${ISO%iso}yaml")"
    local seed_inventory_fn=/var/lib/cee/main/seed_inventory.yml
    local host_seed_inventory_file; host_seed_inventory_file=$(mktemp)
    cat >$host_seed_inventory_file <<EOF
all:
  hosts:
    localhost:
      ansible_connection: local
      ansible_host: '$LCM_CTRL_IP'
  children:
    portal_hosts:
      hosts:
        localhost:
    cee-lcm:
      hosts:
        localhost:
      vars:
        lcm_api_auth_strategy: 'none'
    lcm_hosts:
      hosts:
        localhost:
      vars:
        max_job_task_parallelism: "{{ ansible_processor_vcpus }}"
        ansible_max_forks: 100
    cmpclient:
      hosts:
        localhost:
      vars:
        cmp_alias_name: "{{ cmp_aliases[0]['name'] }}"
        cmpclient_image_full: "{{ docker_registry }}/$cmpclient_image"
        pki_bind_dir: "/var/lib/pki"
        pki_truststore_name: truststore
        ejbca_port: "{{ ejbca_http_port }}"
        pki_cert_expiry_days: $PKI_CERT_EXPIRY
    ejbca:
      hosts:
        localhost:
      vars:
        ejbca_image_full: "{{ docker_registry }}/$ejbca_image"
        # Ejbca template configuration requires the rsyslog port
        rsyslog_log_local_port: 20513
        ejbca_http_port: 9080
        ejbca_https_port: 9443
        ejbca_mgmt_http_port: 9990
        ejbca_ajp_port: 8009
        ejbca_custom_end_entity_profile_name: "CEE_EE_v1"
        ejbca_custom_certificate_profile_names: "CEE_SERVER_v1,CEE_ENDUSER_v1,CEE_ENDUSER_SERVER_v1"
        ejbca_txn_recovery_port: 4712
        ejbca_txn_status_mgmt_port: 4713
        ejbca_remoting_port: 4447
        # Prevent to run DB creation using toolbox.
        use_preconfigured_databases: true
        enable_ejbca: True
        ejbca_vip_address: "{{ kolla_internal_vip_address | put_address_in_context('url') }}"
        ejbca_bind_address_public: "{{ kolla_internal_vip_address | put_address_in_context('url') }}"
        ejbca_access_url: "http://{{ kolla_internal_vip_address | put_address_in_context('url') }}:{{ ejbca_http_port }}/ejbca"
        ejbca_java_options: "-Xms1024m -Xmx1024m -XX:MetaspaceSize=256m -XX:MaxMetaspaceSize=256m -Djboss.modules.system.pkgs=\$JBOSS_MODULES_SYSTEM_PKGS -Djava.awt.headless=true"
        valid_days: "$PKI_CACERT_EXPIRY"
        internal_pki: {
          "cmpclient": {
            "ca_certificates": [
              "internal_pki_management",
            ],
            "cert_directory": "cmpclient",
            "identities": [
              {
                "ca": "internal_pki_management",
                "certificate_profile": "CEE_ENDUSER_v1",
                "name": "ejbca-wsdl-client",
                "subject": "CN=ejbca-wsdl-client",
                "owner": "42490",
                "group": "42490",
              }
            ],
            "role": "cmpclient"
          }
        }
        internal_pki_ca: {
          authentication_code: "null",
          dn: "CN=internal_pki_management",
          ejbca_access_url: "{{ ejbca_access_url }}",
          ejbca_ca_name: "internal_pki_management",
          key_algorithm: "RSA",
          key_specification: "4096",
          name: "internal_pki_management",
          signing_algorithm: "SHA512WithRSA",
          state: "present",
          valid_days: "{{ valid_days }}"}
        certificate_authorities:
          - {
            "authentication_code": "null",
            "dn": "CN=Ericsson CEE CA, OU=CEE, O=Ericsson AB",
            "ejbca_access_url": "{{ ejbca_access_url }}",
            "ejbca_ca_name": "internal_pki_management",
            "key_algorithm": "RSA",
            "key_specification": "4096",
            "name": "ericsson_cee_ca",
            "signing_algorithm": "SHA512WithRSA",
            "state": "present",
            "valid_days": "{{ valid_days }}"
          }
          - {
            "authentication_code": "null",
            "dn": "CN=infrastructure",
            "ejbca_access_url": "{{ ejbca_access_url }}",
            "ejbca_ca_name": "internal_pki_management",
            "key_algorithm": "RSA",
            "key_specification": "4096",
            "name": "infrastructure",
            "sign_ca_name": "ericsson_cee_ca",
            "signing_algorithm": "SHA512WithRSA",
            "state": "present",
            "valid_days": "{{ valid_days }}"
          }
          - {
            "authentication_code": "null",
            "dn": "CN=openstack",
            "ejbca_access_url": "{{ ejbca_access_url }}",
            "ejbca_ca_name": "internal_pki_management",
            "key_algorithm": "RSA",
            "key_specification": "4096",
            "name": "openstack",
            "sign_ca_name": "ericsson_cee_ca",
            "signing_algorithm": "SHA512WithRSA",
            "state": "present",
            "valid_days": "{{ valid_days }}"
          }
          - {
            "authentication_code": "null",
            "dn": "CN=vnc",
            "ejbca_access_url": "{{ ejbca_access_url }}",
            "ejbca_ca_name": "internal_pki_management",
            "key_algorithm": "RSA",
            "key_specification": "4096",
            "name": "vnc",
            "sign_ca_name": "ericsson_cee_ca",
            "signing_algorithm": "SHA512WithRSA",
            "state": "present",
            "valid_days": "{{ valid_days }}"
          }

        cmp_aliases:
          - {state: "present",
             name: "default",
             operation_mode: "client",
             allow_update_with_same_key: "true",
             authentication_module: "EndEntityCertificate;DnPartPwd",
             authentication_parameters: "-;pseudonym",
             allow_automatic_key_update: "false",
             response_protection: "signature",
             allow_server_gen_keys: "false",
             extract_username_component: "givenName"}
    lcm_seed_hosts:
      hosts:
        localhost:
  vars:
    backup_db_user: 'backup_db_user'
    backup_db_password: ''
    backup_db_address: ''
    backup_db_name: 'backup_schema'
    ceeinfra_group_name: "$CEEINFRA_USER"
    ceeinfra_home_dir: "/home/$CEEINFRA_USER"
    ceeinfra_user_name: "$CEEINFRA_USER"
    default_project_domain_name: Default
    default_user_domain_name: Default
    host_username: "$CEEINFRA_USER"
    interface_addresses:
      control: "$LCM_CTRL_IP"
    keystone_admin_listen_port: 35357
    keystone_admin_url: ''
    keystone_internal_url: ''
    kolla_internal_vip_address: "$LCM_CTRL_IP"
    cee_lcm_orchestrator_port: 8281
    lcm_api_auth_url: 'nothing'
    lcm_api_external_address_on_seed: "$LCM_OM_IP"
    lcm_api_internal_vip_address: "$LCM_CTRL_IP"
    lcm_api_port: 8081
    lcm_api_version: 1
    lcm_api_limits:
      server_backend_timeout: 594
      max_total_connections: 30
      server_timeout: 595
      server_fin_timeout: 4
      tunnel_timeout: 60
    my_dns_config:
      domain: "$domain"
      search: []
      servers: []
    openstack_region_name: 'NONE'
    portal_haproxy_config_keystone_subpath: identity
    portal_haproxy_config_lcm_api_subpath: lcm_'api'
    portal_haproxy_config_portal_subpath: 'portal'
    portal_lcm_api_port: 8081
    portal_lcm_api_url: "http://{{ '$LCM_CTRL_IP' | ipwrap }}"
    portal_listen_host: "$LCM_CTRL_IP"
    portal_listen_host_external: "$LCM_OM_IP"
    portal_port: 8080
    enable_container_healthchecks: yes
    default_container_healthcheck_interval: 30
    default_container_healthcheck_retries: 3
    default_container_healthcheck_start_period: 5
    default_container_healthcheck_timeout: 30
    api_interface_address: "{{ portal_listen_host }}"
    portal_listen_port: "{{ portal_port }}"
    legaltext:
      local: "Unauthorized access is strictly prohibited!"
      remote: "Unauthorized access is strictly prohibited!"
    scheduler_db_user: 'fake'
    scheduler_db_password: 'fake'
    scheduler_db_host: 'fake'
    scheduler_db_port: 'fake'
    system_name: 'seed'
    hostname: "$hostname"
    hostname_full: "$hostname.$domain"
    cluster_name: 'seed'
    data_collections_root_dir: /var/lib/cee/collections

    # Internal PKI common
    ipki_trust_store_dir: "/var/lib/ipki_trust_store/bootstrap"

    # DB
    database_address: "{{ interface_addresses.control }}"
    database_port: 3306
    database_user: "seed-admin"
    mysql_socket: "/var/run/mysql/mysql.sock"
    lcm_database_password: "$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)"

    # Registry
    docker_registry_port: 5500
    docker_registry: "docker-registry.{{ my_dns_config.domain }}:{{ docker_registry_port }}"

    # Kolla
    kolla_base_distro: "sles"
    config_strategy: "COPY_ALWAYS"
    config_owner_group: root
    config_owner_user: root
    container_config_directory: "/var/lib/kolla/config_files"
    default_container_dimensions: {}
    default_extra_volumes: []
    node_config_directory: "/etc/kolla"
    docker_common_options: {
      environment: {
        KOLLA_CONFIG_STRATEGY: "{{ config_strategy }}"
      },
      restart_policy: "unless-stopped",
      restart_retries: 10,
      graceful_timeout: 60,
      client_timeout: 120
    }

EOF
    "${scp_cmd[@]}" "$host_seed_inventory_file" $CEEINFRA_USER@"[$LCM_CTRL_IP]:$seed_inventory_fn" &>/dev/null ||
        error "Failed to copy seed LCM inventory"
    rm -f "$host_seed_inventory_file"

    local seed_kolla_password_path=/var/lib/cee/main/seed_passwords.yml
    local host_kolla_password_path; host_kolla_password_path=$(mktemp)
    cat >$host_kolla_password_path <<EOF
database_password: "$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)"
ejbca_ra_password: "$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)"
ejbca_adm_password: "$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)"
ejbca_user_password: "$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)"
ejbca_database_password: "$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)"
ejbca_password: "$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)"
pki_ee_cmpclient_password: "$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)"
EOF
    [[ "$LCM_API_CLIENT_PASSWORD" ]] &&
        printf 'lcm_api_internal_client_password: %q\n' "$LCM_API_CLIENT_PASSWORD" >>$host_kolla_password_path
    "${scp_cmd[@]}" "$host_kolla_password_path" $CEEINFRA_USER@"[$LCM_CTRL_IP]:$seed_kolla_password_path" &>/dev/null ||
        error "Failed to copy kolla passwords file"
    rm -f "$host_kolla_password_path"

    src=/opt/cee/source/$CEE_INFRA_ORCHESTATOR/ansible
    kolla_ansible_src=/opt/cee/source/$CEE_INFRA_ORCHESTATOR/kolla-ansible/ansible

    info "Initial preparation of seed LCM VM"
    local tmp
    "${ssh_cmd[@]}" "ansible-playbook $src/seedvm-setup.yml \
                                      -i $seed_inventory_fn" $SILENT_ANSIBLE || \
        error "Failed in post installation step 'setup journald'"

    "${ssh_cmd[@]}" "ansible-playbook $src/seedvm-docker.yml \
                                      -i $seed_inventory_fn \
                                      -e cee_action=deploy" $SILENT_ANSIBLE || \
        error "Failed in post installation step 'setup Docker and Docker registry services'"

    info "Importing repositories and infra Kolla images." \
         "This takes at least approximately 10-25 minutes"
    local artifact
    for artifact in ${HOST_OS_ISO%iso} ${ISO%iso}; do
        "${scp_cmd[@]}" "${artifact}yaml" $CEEINFRA_USER@"[$LCM_CTRL_IP]":/tmp >&/dev/null || \
            error "Failed copy ${artifact}yaml to $VM_NAME"

        "${ssh_cmd[@]}" "ansible-playbook $src/cee-artifacts.yml \
                                         -i $seed_inventory_fn \
                                         -e type=directory \
                                         -e metadata_uri=file:///tmp/$(basename ${artifact}yaml) \
                                         -e artifact_uri=file:///srv/www \
                                         -e cee_action=import" $SILENT_ANSIBLE || \
            error "Failed in post installation step 'import repo metadata'"
        "${ssh_cmd[@]}" "rm -f /tmp/$(basename ${artifact}yaml)"
        local number version info product name
        tmp=$(sed -n '/^product:/,/^[a-z]/{//!p}' ${artifact}yaml)
        number=$(echo "$tmp" | grep number: | sed -e 's/^.*number: *//' -e 's/ //g' -e 's|/|_|')
        version=$(awk '/version:/{print $2}' <<< "$tmp")
        info=$(awk '/buildInfo:/{print $2}' <<< "$tmp")
        product="$number-$version-$info"
        tmp=$(sed -n '/^repositories:/,/^[a-z]/{//!p}' ${artifact}yaml)
        if [[ $artifact == "${HOST_OS_ISO%iso}" ]]; then
            # Add the Host OS repos to zypper
            for name in $(echo "$tmp" | awk '/name:/{print $NF}' | xargs); do
                "${ssh_cmd[@]}" "sudo zypper addrepo --no-gpgcheck --refresh dir:/srv/www/repos/$product/$name $name" >&/dev/null || \
                    error "Failed adding host OS repo $name"
            done
        elif [[ $artifact == "${ISO%iso}" ]]; then
            # Add the cee-infra repo to zypper
            # NB! XXX Hard coded cee-infra knowledge
            "${ssh_cmd[@]}" "sudo zypper addrepo --no-gpgcheck --refresh dir:/srv/www/repos/$product/cee-infra cee-infra" >&/dev/null || \
                error "Failed adding host cee-infra repo"
            "${ssh_cmd[@]}" "cd /opt/cee/source; sudo ln -s $CEE_INFRA_ORCHESTATOR/ansible .; sudo ln -s $CEE_INFRA_ORCHESTATOR/kolla-ansible ." || \
                error "Failed adding orchestrator soft links"
        fi
    done
    [[ $(dirname $HOST_OS_ISO) != $(dirname $ISO) ]] && rm -rf "$(dirname $HOST_OS_ISO)"
    # We don't need this anylonger since the import is done
    "${ssh_cmd[@]}" "sudo rm -rf /srv/www/cee"

    info "Initializing CEE LCM components"
    "${ssh_cmd[@]}" "ansible-playbook $src/initialize-cee.yml \
                                     -i $seed_inventory_fn \
                                     -l localhost \
                                     -e cee_action=deploy" $SILENT_ANSIBLE || \
        error "Failed in post installation step 'initialize CEE'"

    local uri portal_tag="" portal_ver="" prefer_ipv4=
    [[ $IPV6 == true ]] && $PREFER_IPV4 && prefer_ipv4="--prefer-family=IPv4"
    for uri in "${URIS[@]:-}"; do
        [[ $uri ]] || continue
        local -a res
        local iso="" meta="" f
        if [[ $uri =~ ^http || $uri =~ ^ftp ]]; then
            info "Downloading, copying, unpacking, and importing $uri"
            mapfile -t res < <(wget -q $prefer_ipv4 $uri -O - | "${ssh_cmd[@]}" "tar -C /tmp -zxvf - 2>/dev/null" || \
                               wget -q $prefer_ipv4 $uri -O - | "${ssh_cmd[@]}" "tar -C /tmp -xvf - 2>&1") || \
                error "Failed to download/extract $uri: ${res[*]}"
        else
            info "Copying, unpacking, and importing $uri"
            # shellcheck disable=SC2002
            mapfile -t res < <(cat ${uri#file:} | "${ssh_cmd[@]}" "tar -C /tmp -zxvf - 2>/dev/null" || \
                               cat ${uri#file:} | "${ssh_cmd[@]}" "tar -C /tmp -xvf - 2>&1") || \
                error "Failed to extract $uri: ${res[*]}"
        fi
        for f in "${res[@]}"; do
            [[ $f == *iso ]] && iso=$f
            [[ $f == *yaml ]] && meta=$f
            [[ $f == *yml ]] && meta=$f
        done
        [[ $iso ]] || error "Failed to find iso in $uri"
        [[ $meta ]] || error "Failed to metadata in $uri"
        local art; art=$(basename $uri)
        if [[ $art =~ $PORTAL ]]; then
            tmp=$("${ssh_cmd[@]}" "sed -n '/^services:/,/^[a-z]/{//!p}' /tmp/$meta")
            portal_tag=$(awk '/tag:/{print $2}' <<< "$tmp" | sort -u)
            tmp=$("${ssh_cmd[@]}" "sed -n '/^product:/,/^[a-z]/{//!p}' /tmp/$meta")
            portal_ver=$(awk '/version:/{print $2}' <<< "$tmp")
            portal_ver=$portal_ver-$(awk '/buildInfo:/{print $2}' <<< "$tmp")
        fi
        "${ssh_cmd[@]}" "ansible-playbook $src/cee-artifacts.yml \
                                         -i $seed_inventory_fn \
                                         -e type=iso \
                                         -e artifact_uri=file:///tmp/$iso \
                                         -e metadata_uri=file:///tmp/$meta \
                                         -e cee_action=import" $SILENT_ANSIBLE || \
            error "Failed to import $art artifact"
        info "$art imported successfully"
        "${ssh_cmd[@]}" "rm -f /tmp/$iso /tmp/$meta"
    done

    info "Install RDBMS"
    "${ssh_cmd[@]}" "ansible-playbook $src/install-seed-db.yml \
                                      -i $seed_inventory_fn \
                                      -e @$seed_kolla_password_path" $SILENT_ANSIBLE || \
        error "Failed in post installation step 'Database installation'"

    info "Configure LCM database"
    "${ssh_cmd[@]}" "ansible-playbook $src/lcm-db.yml \
                                      -i $seed_inventory_fn" $SILENT_ANSIBLE || \
        error "Failed in post installation step 'LCM database configuration'"

    if [[ ${DISABLE_INTERNAL_PKI,,} != "true" ]]; then
        info "Install internal PKI"
        "${ssh_cmd[@]}" "ansible-playbook $src/install-seed-ca.yml \
                                          -i $seed_inventory_fn \
                                          -e @$seed_kolla_password_path \
                                          -e kolla_action=deploy \
                                          -M $kolla_ansible_src/library/" $SILENT_ANSIBLE || \
            error "Internal PKI installation failed!"
    fi

    for uri in "${URIS[@]:-}"; do
        [[ $uri ]] || continue
        local art; art=$(basename $uri)
        [[ $art =~ $PORTAL ]] || continue
        info "Deploying CEE Portal"
        local path=${PORTAL#cee-portal-}
        path=/opt/cee/source/$path-$portal_ver/ansible
        "${ssh_cmd[@]}" \
            "ANSIBLE_LIBRARY=$kolla_ansible_src/library \
             ANSIBLE_FILTER_PLUGINS=$kolla_ansible_src/filter_plugins \
                 ansible-playbook $path/cee_portal.yml \
                                  -i $seed_inventory_fn \
                                  -e portal_tag=$portal_tag \
                                  -e my_path=$src \
                                  -e kolla_action=deploy" $SILENT_ANSIBLE || \
            error "Failed in post installation step 'deploy Portal'"
    done

    # We're now done, then there should be no authorized keys left
    "${ssh_cmd[@]}" "rm -f .ssh/authorized_keys && sudo rm -f /root/.ssh/authorized_keys" || true
    info "Post installation steps completed on seed LCM VM"
}

deploy_vm() {
    info "Starting installation of the seed LCM VM"
    local xml; xml=$(mktemp)
    create_xml "$xml"

    local res
    res=$(virsh define "$xml" 2>&1) || \
        error "Failed to define $VM_NAME: \"$res\""

    res=$(virsh autostart --disable $VM_NAME 2>&1) || \
        error "Failed to disable autostart of $VM_NAME"

    res=$(virsh start "$VM_NAME" 2>&1) || \
        error "Failed to start $VM_NAME: \"$res\""

    wait_for_first_step

    virsh dumpxml --inactive --security-info "$VM_NAME" >"$xml"
    sed -i -e "/<boot dev='cdrom'/d" \
           -e "/<kernel>/d" \
           -e "/<initrd>/d" \
           -e "/<cmdline>autoyast/d" \
           -e '/^[[:blank:]]*<disk type=/,/<\/disk>/{H;/<\/disk>/!d;s/.*//;x;'"/${CONFIG_DISK////\\/}/"'d;s/.//;}' \
           -e '/^[[:blank:]]*<disk type=.*cdrom.*/,/<\/disk>/d' $xml || \
        error "Failed to update $VM_NAME xml"

    res=$(virsh define "$xml" 2>&1) || \
        error "Failed to update $VM_NAME definition: \"$res\""
    rm -f "$xml"

    info "First install step finished." \
         "Restarting the seed LCM VM to complete installation"
    sleep 5

    [[ $(dirname $HOST_OS_ISO) != $(dirname $ISO) ]] && rm -f $HOST_OS_ISO

    virsh start "$VM_NAME" &>/dev/null || true

    if [[ ${CI_PROXY:-} && ${IPV6:-} == true ]]; then
        # WA Set promisc mode on the macvtap interface for IPv6 to work
        local lcm_ctrl_br; lcm_ctrl_br=$(get_nested_key_val lcm_ctrl_sp hostBridge)
        res=$(ip link | grep $lcm_ctrl_br | \
              awk -F"[ @]" '/macvtap/{print $2}') || error "$res"
        [[ $res ]] || error "Failed to find macvtap interface for $lcm_ctrl_br"
        res=$(ip link set dev $res promisc on) || error "$res"
    fi

    if ! wait_for_restart; then
        error "Seed LCM VM failed to come back online"
    fi
}

main() {
    info "Starting Seed LCM VM installation"

    parse_commandline "$@"
    (($(id -u) == 0)) || error "You need to be root to execute $0"

    check_prerequisites
    set_globals
    handle_host_os_artifact
    cleanup_previous
    create_disks
    deploy_vm
    post_install_steps

    info "Seed LCM VM installation successfully completed"
}

main "$@"
