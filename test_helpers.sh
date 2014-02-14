#!/bin/bash
#
# Copyright (c) 2011-2013 PLUMgrid, http://plumgrid.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

verlte() {
  [ "$1" = "`echo -e "$1\n$2" | sort -V | head -n1`" ]
}

if verlte `uname -r` 3.6.0
then
 USE_VCMD=1
else
 USE_VCMD=0
fi

function tap_add() {
#  sudo ip tuntap add dev $1 mode tap user $USER
  sudo tunctl -t $1
  sudo ifconfig $1 up
}

function tap_del() {
#  sudo ip tuntap del dev $1 mode tap
  sudo tunctl -d $1
}
function delete_temp_dir() {
    dir_name=$1
    if [[ "${dir_name:0:5}" == "/tmp/" ]] ; then
        rm -rf ${dir_name}
    fi
}

function create_temp_dir() {
    result=$(mktemp -d /tmp/test_XXXXXX)
    chmod 0777 $result
}
# ns_create('/tmp/test_xxxx', 'ns0')
function ns_create() {
    dir=$1
    name=$2
    if [ $USE_VCMD == 1 ]; then
      sudo vnoded -c ${dir}/${name}.ctl -l ${dir}/${name}.log -p ${dir}/${name}.pid > /dev/null
    else
      sudo ip netns add ${name}
    fi
}
# ns_create_ifc('/tmp/test_xxxx','ns0', 'eth0')
function ns_create_ifc() {
    dir=$1
    name=$2
    ifc=$3
    # create a veth with one end on the smart edge side called <namespace>.<ifcname>.se
    # the other end connected to the VM <namespace>.<ifcname>.vm
    sudo ip link add name ${name}.${ifc}.se type veth peer name ${name}.${ifc}.vm
    if [ $USE_VCMD == 1 ]; then
      sudo ip link set ${name}.${ifc}.vm netns `cat ${dir}/${name}.pid`
    else
      sudo ip link set ${name}.${ifc}.vm netns ${name}
    fi

    if [ $USE_VCMD == 1 ]; then
      /usr/sbin/vcmd -c ${dir}/${name}.ctl -- ip link set ${name}.${ifc}.vm name ${ifc}
    else
      sudo ip netns exec ${name} ip link set ${name}.${ifc}.vm name ${ifc}
    fi

    if [ $USE_VCMD == 1 ]; then
      /usr/sbin/vcmd -c ${dir}/${name}.ctl -- /sbin/sysctl -q -w net.ipv6.conf.${ifc}.disable_ipv6=1
    else
      sudo ip netns exec ${name} /sbin/sysctl -q -w net.ipv6.conf.${ifc}.disable_ipv6=1
    fi

    sudo ip link set ${name}.${ifc}.se up

    if [ $USE_VCMD == 1 ]; then
      /usr/sbin/vcmd -c ${dir}/${name}.ctl -- ip link set ${ifc} up
    else
      sudo ip netns exec ${name} ip link set ${ifc} up
    fi
}

function tap_cleanall() {
  #ip tuntap not supported for rhel
  #taps=$(ip tap show | grep -v '^vnet' | grep -v '^virbr' | grep -v '^tun' | cut -d: -f1)
  taps=$(ls /sys/class/net)
  for t in $taps; do
    if [[ -f "/sys/class/net/$t/tun_flags" ]] ; then
      tap_del $t
    fi
  done

  links=$(ip link | awk '{if (substr($0,1,1)!=" ") print substr($2,1,length($2)-1)}')
  for link in $links; do
    # ignore lines that refer to the loopback interface, to Ethernet interfaces,
    # to IPv6 interfaces, or to "tun" interfaces (used by OpenVPN)
    if [[ ! "$link" == lo && ! "$link" == eth* && ! "$link" == sit* \
        && ! "$link" == tun*  && ! "$link" == bond* && ! "$link" == rename* \
        && ! "$link" == virbr* && ! "$link" == vnet* && ! "$link" == *@eth* && ! "$link" == wlan* ]]; then
      sudo ifconfig $link down
      sudo ip link del dev $link
    fi
  done

  if [ $USE_VCMD == 0 ]; then
    netnss=$(sudo ip netns list)
    for n in $netnss; do
      sudo ip netns del $n
    done
  fi
}

# ns_run_cmd '/tmp/test_xxxx' 'ns0' 'ifconfig eth0' -q
# -q = runs the cmd quietly (optional)
function ns_run_cmd() {
    dir=$1
    name=$2
    cmd=$3
  if [ $USE_VCMD == 1 ]; then
    if [[ $4 == "-q" ]]; then
      result=$(/usr/sbin/vcmd -q -c ${dir}/${name}.ctl -- ${cmd})
    else
      result=$(/usr/sbin/vcmd -c ${dir}/${name}.ctl -- ${cmd})
    fi
  else
    result=$(sudo ip netns exec ${name} ${cmd})
  fi
}
function ns_run_cmd_2() {
    dir=$1
    name=$2
    cmd=$3
  if [ $USE_VCMD == 1 ]; then
    /usr/sbin/vcmd -c ${dir}/${name}.ctl -- ${cmd}
  else
    sudo ip netns exec ${name} ${cmd}
  fi
}

function quit() {
  # reset the EXIT handler to avoid infinite loops
  trap - EXIT
  tap_cleanall

  if [ $USE_VCMD == 1 ]; then
    sudo pkill -9 vcmd
    sudo pkill -9 vnoded
  fi

  if [ $USE_VCMD == 1 ]; then
    delete_temp_dir $TMP_DIR
  fi

  sudo pkill -9 -f iperf

#  sudo rmmod openvswitch
  exit $1
}

trap "echo ' Test killed by SIGINT'; quit 2" SIGINT
trap "echo ' Test killed by SIGTERM'; quit 3" SIGTERM
# trap unmanaged shell quits
trap "retval=$?; echo ' Unmanaged test exit trapped'; quit $retval" EXIT

#  sudo modprobe openvswitch

if [ $USE_VCMD == 1 ]; then
  create_temp_dir
  TMP_DIR=$result
else
  TMP_DIR="/tmp/none"
fi

