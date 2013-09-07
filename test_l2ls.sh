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
# Tests L2 learning switch functionality defining a Topology with two Linux
# namespaces connected by a switch.
#
#
# TEST TOPOLOGY
# -------------
#
#             +-------L2LS-------+
#             |                  |
#        ns1.eth0.se        ns1.eth0.se
#             |                  |
#      +-NS1--+------+    +-NS2--+------+
#      |      |      |    |      |      |
#      |     eth0    |    |     eth0    |
#      +-------------+    +-------------+
#
###############################################################################

. test_helpers.sh

for DP in `seq 1 2`
do
  ns_create ${TMP_DIR} ns$DP
  ns_create_ifc ${TMP_DIR} ns$DP eth0
  ns_run_cmd ${TMP_DIR} ns$DP "ifconfig eth0 10.1.1.$DP"
done

ns_run_cmd ${TMP_DIR} ns1 "iperf -s" &
sleep 0.1

sudo ./l2ls-ctl addbr
sudo ./l2ls-ctl addif ns1.eth0.se
sudo ./l2ls-ctl addif ns2.eth0.se

echo "Starting iperf through BPF mini bridge"
ns_run_cmd_2 ${TMP_DIR} ns2 "iperf -c 10.1.1.1 -t 2"
./l2ls-ctl showmac

quit 0
