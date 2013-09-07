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

function tap_add() {
  sudo ip tuntap add dev $1 mode tap user $USER
  sudo ifconfig $1 up
}

function tap_del() {
  sudo ip tuntap del dev $1 mode tap
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
    sudo vnoded -c ${dir}/${name}.ctl -l ${dir}/${name}.log -p ${dir}/${name}.pid > /dev/null
}
# ns_create_ifc('/tmp/test_xxxx','ns0', 'eth0')
function ns_create_ifc() {
    dir=$1
    name=$2
    ifc=$3
    # create a veth with one end on the smart edge side called <namespace>.<ifcname>.se
    # the other end connected to the VM <namespace>.<ifcname>.vm
    sudo ip link add name ${name}.${ifc}.se type veth peer name ${name}.${ifc}.vm
    sudo ip link set ${name}.${ifc}.vm netns `cat ${dir}/${name}.pid`
    /usr/sbin/vcmd -c ${dir}/${name}.ctl -- ip link set ${name}.${ifc}.vm name ${ifc}
    /usr/sbin/vcmd -c ${dir}/${name}.ctl -- /sbin/sysctl -q -w net.ipv6.conf.${ifc}.disable_ipv6=1
    sudo ip link set ${name}.${ifc}.se up
    /usr/sbin/vcmd -c ${dir}/${name}.ctl -- ip link set ${ifc} up
}

function tap_cleanall() {
  taps=$(ip tap show | grep -v '^vnet' | grep -v '^virbr' | grep -v '^tun' | cut -d: -f1)
  for t in $taps; do
    tap_del $t
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
}

# ns_run_cmd '/tmp/test_xxxx' 'ns0' 'ifconfig eth0' -q
# -q = runs the cmd quietly (optional)
function ns_run_cmd() {
    dir=$1
    name=$2
    cmd=$3
    if [[ $4 == "-q" ]]; then
      result=$(/usr/sbin/vcmd -q -c ${dir}/${name}.ctl -- ${cmd})
    else
      result=$(/usr/sbin/vcmd -c ${dir}/${name}.ctl -- ${cmd})
    fi
}
function ns_run_cmd_2() {
    dir=$1
    name=$2
    cmd=$3
    /usr/sbin/vcmd -c ${dir}/${name}.ctl -- ${cmd}
}

function quit() {
  # reset the EXIT handler to avoid infinite loops
  trap - EXIT
  tap_cleanall
  delete_temp_dir $TMP_DIR
  sudo rmmod openvswitch
  exit $1
}

trap "echo ' Test killed by SIGINT'; quit 2" SIGINT
trap "echo ' Test killed by SIGTERM'; quit 3" SIGTERM
# trap unmanaged shell quits
trap "retval=$?; echo ' Unmanaged test exit trapped'; quit $retval" EXIT

sudo modprobe openvswitch

create_temp_dir
TMP_DIR=$result

