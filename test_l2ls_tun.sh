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

ENCAP=vxlan

for arg in "$@"; do
  case "$arg" in
    encap=*) ENCAP=${arg:6}
      ;;
  esac
done

. test_helpers.sh

echo ${TMP_DIR}
echo ${ENCAP}

for DP in `seq 1 2`
do
  ns_create ${TMP_DIR} ns$DP
  ns_run_cmd ${TMP_DIR} ns$DP "ip link add name eth0 type veth peer name hook0"
  ns_run_cmd ${TMP_DIR} ns$DP "ifconfig eth0 10.1.1.$DP/24 up"
  ns_run_cmd ${TMP_DIR} ns$DP "ifconfig hook0 0 up"
  ns_create_ifc ${TMP_DIR} ns$DP eth1
  ns_run_cmd ${TMP_DIR} ns$DP "ifconfig eth1 10.1.2.$DP/24 mtu 1550 up"
done

sudo brctl addbr nsbridge
sudo ifconfig nsbridge up
sudo ifconfig ns1.eth1.se mtu 1550 up
sudo ifconfig ns2.eth1.se mtu 1550 up
sudo brctl addif nsbridge ns1.eth1.se
sudo brctl addif nsbridge ns2.eth1.se

for DP in `seq 1 2`
do
/usr/sbin/vcmd -c ${TMP_DIR}/ns$DP.ctl -- ./l2ls-ctl addbr
ns_run_cmd ${TMP_DIR} ns$DP "./l2ls-ctl addif hook0"
done
ns_run_cmd ${TMP_DIR} ns1 "./l2ls-ctl addtun ${ENCAP} 10.1.2.2 1"
ns_run_cmd ${TMP_DIR} ns2 "./l2ls-ctl addtun ${ENCAP} 10.1.2.1 1"
sleep 0.2

ns_run_cmd ${TMP_DIR} ns1 "iperf -s" &
sleep 0.2

echo "Starting iperf through BPF mini bridge"
ns_run_cmd_2 ${TMP_DIR} ns2 "iperf -c 10.1.1.1 -i 5 -t 10"
ns_run_cmd_2 ${TMP_DIR} ns2 "./l2ls-ctl showmac"

quit 0
