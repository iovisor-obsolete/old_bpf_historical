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

###############################################################################
# TEST OVERVIEW
# -------------
# Tests distributed L2 learning switch functionality defining a Topology with
# two switches connected through Linux bridge and kernel vxlan/gre drivers.
#
#
# TEST TOPOLOGY
# -------------
#
#             +---Linux Bridge---+
#             |                  |
#        ns1.eth1.se        ns1.eth1.se
#             |                  |
#      +-NS1--+------+    +-NS2--+------+
#      |      |      |    |      |      |
#      |  vxlan/gre  |    |  vxlan/gre  |
#      |      |      |    |      |      |
#      |     eth1    |    |     eth1    |
#      |      |      |    |      |      |
#      |     L2LS    |    |     L2LS    |
#      |      |      |    |      |      |
#      |    hook0    |    |    hook0    |
#      |      |      |    |      |      |
#      |     eth0    |    |     eth0    |
#      +-------------+    +-------------+
#
###############################################################################

ENCAP=gre
GSO=on

for arg in "$@"; do
  case "$arg" in
    encap=*) ENCAP=${arg:6}
      ;;
    gso=*) GSO=${arg:4}
      ;;
  esac
done

. test_helpers.sh

echo Using ${ENCAP} encap

for DP in `seq 1 2`
do
  ns_create ${TMP_DIR} ns$DP
  ns_run_cmd ${TMP_DIR} ns$DP "ip link add name eth0 type veth peer name hook0"
  ns_run_cmd ${TMP_DIR} ns$DP "ifconfig eth0 10.1.1.$DP/24 up"
  ns_run_cmd ${TMP_DIR} ns$DP "ifconfig hook0 0 up"
  ns_create_ifc ${TMP_DIR} ns$DP eth1
  ns_run_cmd ${TMP_DIR} ns$DP "ifconfig eth1 10.1.2.$DP/24 mtu 1550 up"
#  ns_run_cmd ${TMP_DIR} ns$DP "ethtool -K eth0 gso off tso off ufo off"
done

sudo brctl addbr nsbridge
sudo ifconfig nsbridge up
sudo ifconfig ns1.eth1.se mtu 1550 up
sudo ifconfig ns2.eth1.se mtu 1550 up
sudo brctl addif nsbridge ns1.eth1.se
sudo brctl addif nsbridge ns2.eth1.se
if [ $GSO != "on" ]; then
  sudo ethtool -K ns1.eth1.se gso off tso off ufo off
  sudo ethtool -K ns2.eth1.se gso off tso off ufo off
fi

for DP in `seq 1 2`
do
  ns_run_cmd ${TMP_DIR} ns$DP "./l2ls-ctl addbr"
  ns_run_cmd ${TMP_DIR} ns$DP "./l2ls-ctl addif hook0"
done
ns_run_cmd ${TMP_DIR} ns1 "./l2ls-ctl addtun ${ENCAP} 10.1.2.2 1"
ns_run_cmd ${TMP_DIR} ns2 "./l2ls-ctl addtun ${ENCAP} 10.1.2.1 1"

ns_run_cmd ${TMP_DIR} ns1 "iperf -s" &
sleep 0.2

echo "Starting iperf through BPF mini bridge"
ns_run_cmd_2 ${TMP_DIR} ns2 "iperf -c 10.1.1.1 -i 5 -t 10"
ns_run_cmd_2 ${TMP_DIR} ns2 "./l2ls-ctl showmac"

sudo ifconfig nsbridge down
sudo brctl delbr nsbridge

quit 0
