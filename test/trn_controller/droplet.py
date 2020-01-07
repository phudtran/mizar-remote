# Copyright (c) 2019 The Authors.
#
# Authors: Sherif Abdelwahab <@zasherif>
#          Phu Tran          <@phudtran>
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from test.trn_controller.common import cidr, logger, run_cmd
import os
import docker
import time
import json
from fabric import Connection
from io import BytesIO


class droplet:
    def __init__(self, id, droplet_type='docker', control_ip=None, benchmark=False, phy_itf='eth0'):
        """
        Models a host that runs the transit XDP program. In the
        functional test this is simply a docker container.
        """
        self.id = id
        self.droplet_type = droplet_type
        self.control_ip = control_ip
        self.container = None
        self.ip = None
        self.mac = None
        self.veth_peers = set()
        self.rpc_updates = {}
        self.rpc_deletes = {}
        self.rpc_failures = {}
        self.phy_itf = phy_itf
        self.benchmark = benchmark
        # When droplet is a switch for two different networks in the same vpc
        self.known_nets = set()
        self.vpc_updates = {}
        self.substrate_updates = {}  # When droplet is a host for multiple objects
        self.endpoint_updates = {}  # When droplet is a switch host and ep host
        # We don't need one for net because delete_net takes nip

        if benchmark:
            self.xdp_path = "/trn_xdp/trn_transit_xdp_ebpf.o"
            self.agent_xdp_path = "/trn_xdp/trn_agent_xdp_ebpf.o"
        else:
            self.xdp_path = "/trn_xdp/trn_transit_xdp_ebpf_debug.o"
            self.agent_xdp_path = "/trn_xdp/trn_agent_xdp_ebpf_debug.o"

        # transitd cli commands
        self.conn = Connection(self.id)
        self.phy_itf = phy_itf
        self.benchmark = benchmark

        self.xdp_path = "/trn_xdp/trn_transit_xdp_ebpf_debug.o"
        self.agent_xdp_path = "/trn_xdp/trn_agent_xdp_ebpf_debug.o"

        if benchmark:
            self.xdp_path = "/trn_xdp/trn_transit_xdp_ebpf.o"
            self.agent_xdp_path = "/trn_xdp/trn_agent_xdp_ebpf.o"

        self.pcap_file = "/bpffs/transit_xdp.pcap"
        self.agent_pcap_file = "/bpffs/agent_xdp.pcap"
        self.output_dir = '/mnt/Transit/test/trn_func_tests/output'

        self.tun_bridge = 'br-tun'
        self.int_bridge = 'br-int'
        self.main_bridge = 'br0'

        self.bootstrap()

        sar = f'''bash -c 'sar -o {self.output_dir}/{self.id}_sar.out 1 > /dev/null 2>&1' '''
        if self.benchmark:
            self.run(sar, detach=True)

        # transitd cli commands
        self.trn_cli = f'''/trn_bin/transit -s {self.control_ip}'''
        self.trn_cli_load_transit_xdp = f'''{self.trn_cli} load-transit-xdp -i {self.phy_itf} -j'''
        self.trn_cli_unload_transit_xdp = f'''{self.trn_cli} unload-transit-xdp -i {self.phy_itf} -j'''
        self.trn_cli_update_vpc = f'''{self.trn_cli} update-vpc -i {self.phy_itf} -j'''
        self.trn_cli_get_vpc = f'''{self.trn_cli} get-vpc -i {self.phy_itf} -j'''
        self.trn_cli_delete_vpc = f'''{self.trn_cli} delete-vpc -i {self.phy_itf} -j'''
        self.trn_cli_update_net = f'''{self.trn_cli} update-net -i {self.phy_itf} -j'''
        self.trn_cli_get_net = f'''{self.trn_cli} get-net -i {self.phy_itf} -j'''
        self.trn_cli_delete_net = f'''{self.trn_cli} delete-net -i {self.phy_itf} -j'''
        self.trn_cli_update_ep = f'''{self.trn_cli} update-ep -i {self.phy_itf} -j'''
        self.trn_cli_get_ep = f'''{self.trn_cli} get-ep -i {self.phy_itf} -j'''
        self.trn_cli_delete_ep = f'''{self.trn_cli} delete-ep -i {self.phy_itf} -j'''

        self.trn_cli_load_transit_agent_xdp = f'''{self.trn_cli} load-agent-xdp'''
        self.trn_cli_unload_transit_agent_xdp = f'''{self.trn_cli} unload-agent-xdp'''
        self.trn_cli_update_agent_metadata = f'''{self.trn_cli} update-agent-metadata'''
        self.trn_cli_get_agent_metadata = f'''{self.trn_cli} get-agent-metadata'''
        self.trn_cli_delete_agent_metadata = f'''{self.trn_cli} delete-agent-metadata'''
        self.trn_cli_update_agent_ep = f'''{self.trn_cli} update-agent-ep'''
        self.trn_cli_get_agent_ep = f'''{self.trn_cli} get-agent-ep'''
        self.trn_cli_delete_agent_ep = f'''{self.trn_cli} delete-agent-ep'''

        self.iperf_report = f'''{self.output_dir}/{self.id}_iperf'''

        self.load_transit_xdp()

        if not self.benchmark:
            self.start_pcap()

    def bootstrap(self):
        if self.droplet_type == 'docker':
            self._create_docker_container()
            return

        if self.droplet_type == 'linux':
            self.prepare_remote_host()
            return

        logger.error("Unsupported droplet type!")

    def provision_simple_endpoint(self, ep):
        """
        Creates a veth pair and a namespace for the endpoint and loads
        the transit agent program on the veth peer running in the root
        namespace.
        """
        logger.info(
            "[DROPLET {}]: provision_simple_endpoint {}".format(self.id, ep.ip))

        self._create_veth_pair(ep)
        self.load_transit_agent_xdp(ep.veth_peer)

    def unprovision_simple_endpoint(self, ep):
        """
        Unloads the transit agent program on the veth peer, and
        deletes the veth pair and the namespace for the endpoint
        """
        logger.info(
            "[DROPLET {}]: unprovision_simple_endpoint {}".format(self.id, ep.ip))

        self.unload_transit_agent_xdp(ep.veth_peer)
        self._delete_veth_pair(ep)

    def provision_vxlan_endpoint(self, ep):
        logger.info(
            "[DROPLET {}]: provision_vxlan_endpoint {}".format(self.id, ep.ip))
        self._create_veth_pair(ep)
        return self.ovs_add_port(ep.bridge, ep.veth_peer)

    def wire_bridges(self, ep):
        self.add_bridge(ep.ep_bridge)

        script = (f''' sudo bash -c '\
ip link add {ep.qvb} type veth peer name {ep.qvo} && \
brctl addif {ep.ep_bridge} {ep.qvb} && \
ovs-vsctl add-port {self.int_bridge} {ep.qvo} && \
brctl addif {ep.ep_bridge} {ep.veth_peer} && \
ip link set {ep.qvb} up && \
ip link set {ep.qvo} up && \
iptables -I FORWARD -m physdev --physdev-is-bridged -j ACCEPT' ''')
        self.run(script)

    def create_bridges(self):
        if self.ovs_is_exist(self.tun_bridge):
            return

        # only provision these switches if a vxlan endpoint is created
        script = (f''' sudo bash -c '\
ovs-vsctl add-br {self.int_bridge} && \
ovs-vsctl add-br {self.tun_bridge} && \
ovs-vsctl add-port {self.int_bridge} patch-tun -- set interface patch-tun type=internal && \
ovs-vsctl set interface patch-tun type=patch && \
ovs-vsctl set interface patch-tun options:peer=patch-int && \
ovs-vsctl add-port {self.tun_bridge} patch-int -- set interface patch-int type=internal && \
ovs-vsctl set interface patch-int type=patch && \
ovs-vsctl set interface patch-int options:peer=patch-tun && \
ip link set dev {self.int_bridge} up && \
ip link set dev {self.tun_bridge} up ' ''')
        self.run(script)

    def _create_macvlan_pair(self, ep):
        """
        Creates a veth pair.
        """
        logger.info(
            "[DROPLET {}]: _create_macvlan_pair {}".format(self.id, ep.ip))

        northitf = ep.veth_peer + '_north'
        southitf = ep.veth_peer

        script = (f''' sudo bash -c '\
mkdir -p /tmp/{ep.ns}_{ep.ip} && \
echo {ep.ip} > /tmp/{ep.ns}_{ep.ip}/index.html && \
ip netns add {ep.ns} && \
ip link add {southitf} type veth peer name {northitf} && \
ip link set dev {northitf} up mtu 9000 && \
ip link set dev {southitf} up mtu 9000 && \
ethtool -K {northitf} tso off gso off ufo off && \
ethtool -K {southitf} tso off gso off ufo off && \
ethtool --offload {northitf} rx off tx off && \
ethtool --offload {southitf} rx off tx off && \
sudo ip link add veth0 link {northitf} type macvlan mode passthru && \
ifconfig veth0 hw ether {ep.mac} && \
ip link set veth0 netns {ep.ns} && \
ip netns exec {ep.ns} ip addr add {ep.ip}/{ep.prefixlen} dev veth0 && \
ip netns exec {ep.ns} ip link set dev veth0 up mtu 1500 && \
ip netns exec {ep.ns} sysctl -w net.ipv4.tcp_mtu_probing=2 && \
ip netns exec {ep.ns} route add default gw {ep.gw_ip} &&  \
ip netns exec {ep.ns} ifconfig lo up && \
ip netns exec {ep.ns} ifconfig veth0 hw ether {ep.mac} ' ''')

        self.run(script)
        self.veth_peers.add(ep.veth_peer)

    def _create_veth_pair(self, ep):
        """
        Creates a veth pair. br0 must have been created.
        """
        logger.info(
            "[DROPLET {}]: _create_veth_pair {}".format(self.id, ep.ip))

        script = (f''' sudo bash -c '\
mkdir -p /tmp/{ep.ns}_{ep.ip} && \
echo {ep.ip} > /tmp/{ep.ns}_{ep.ip}/index.html && \
ip netns add {ep.ns} && \
ip link add veth0 type veth peer name {ep.veth_peer} && \
ip link set veth0 netns {ep.ns} && \
ip netns exec {ep.ns} ip addr add {ep.ip}/{ep.prefixlen} dev veth0 && \
ip netns exec {ep.ns} ip link set dev veth0 up && \
ip netns exec {ep.ns} sysctl -w net.ipv4.tcp_mtu_probing=2 && \
ip netns exec {ep.ns} ethtool -K veth0 tso off gso off ufo off && \
ip netns exec {ep.ns} ethtool --offload veth0 rx off tx off && \
ip link set dev {ep.veth_peer} up mtu 9000 && \
ip netns exec {ep.ns} route add default gw {ep.gw_ip} &&  \
ip netns exec {ep.ns} ifconfig lo up &&  \
ip netns exec {ep.ns} ifconfig veth0 hw ether {ep.mac} ' ''')

        self.run(script)
        self.veth_peers.add(ep.veth_peer)

    def _delete_veth_pair(self, ep):
        """
        Deletes a veth pair.
        """
        logger.info(
            "[DROPLET {}]: _delete_veth_pair {}".format(self.id, ep.ip))

        script = (f''' bash -c '\
rm -rf /tmp/{ep.ns}_{ep.ip} &&
ip link delete {ep.veth_peer} && \
ip netns del {ep.ns} \' ''')

        self.run(script)
        self.veth_peers.remove(ep.veth_peer)

    def attach_vm(self, ep):
        logger.info(
            "[DROPLET {}]: attach_vm {}".format(self.id, ep.ip))

        script = (f''' sudo bash -c '\
ip netns exec {ep.ns} brctl addbr br0 && \
ip netns exec {ep.ns} ip tuntap add tap0 mode tap && \
ip netns exec {ep.ns} ip link set dev br0 up && \
ip netns exec {ep.ns} ip link set tap0 up && \
ip netns exec {ep.ns} brctl addif br0 tap0 && \
ip netns exec {ep.ns} brctl addif br0 veth0 && \
ip netns exec {ep.ns} ip link set dev veth0 up mtu 9000 && \
ip netns exec {ep.ns} ip link set dev tap0 up mtu 9000 && \
ip netns exec {ep.ns} ip link set dev br0 up mtu 9000 ' ''')
        self.run(script)

    def load_transit_xdp(self, expect_fail=False):
        log_string = "[DROPLET {}]: load_transit_xdp {}".format(
            self.id, self.ip)
        jsonconf = {
            "xdp_path": self.xdp_path,
            "pcapfile": self.pcap_file
        }
        jsonconf = json.dumps(jsonconf)
        cmd = f'''{self.trn_cli_load_transit_xdp} \'{jsonconf}\' '''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def unload_transit_xdp(self, expect_fail=False):
        log_string = "[DROPLET {}]: unload_transit_xdp {}".format(
            self.id, self.ip)
        jsonconf = '\'{}\''
        cmd = f'''{self.trn_cli_unload_transit_xdp} {jsonconf} '''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def load_transit_agent_xdp(self, itf, expect_fail=False):
        log_string = "[DROPLET {}]: load_transit_agent_xdp {}".format(
            self.id, itf)
        jsonconf = {
            "xdp_path": self.agent_xdp_path,
            "pcapfile": self.agent_pcap_file
        }
        jsonconf = json.dumps(jsonconf)
        self.rpc_updates[("load", itf)] = time.time()
        cmd = f'''{self.trn_cli_load_transit_agent_xdp} -i \'{itf}\' -j \'{jsonconf}\' '''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def unload_transit_agent_xdp(self, itf, expect_fail=False):
        log_string = "[DROPLET {}]: unload_transit_agent_xdp {}".format(
            self.id, itf)
        jsonconf = '\'{}\''
        cmd = f'''{self.trn_cli_unload_transit_agent_xdp} -i \'{itf}\' -j {jsonconf} '''
        self.rpc_deletes[("load", itf)] = time.time()
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def update_vpc(self, vpc, netid, expect_fail=False):
        log_string = "[DROPLET {}]: update_vpc {}".format(
            self.id, vpc.get_tunnel_id())

        jsonconf = {
            "tunnel_id": vpc.get_tunnel_id(),
            "routers_ips": vpc.get_transit_routers_ips()
        }
        jsonconf = json.dumps(jsonconf)
        if netid not in self.known_nets:
            self.known_nets.add(netid)
        cmd = f'''{self.trn_cli_update_vpc} \'{jsonconf}\''''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def get_vpc(self, vpc, expect_fail=False):
        log_string = "[DROPLET {}]: get_vpc {}".format(
            self.id, vpc.get_tunnel_id())
        jsonconf = {
            "tunnel_id": vpc.get_tunnel_id(),
        }
        jsonconf = json.dumps(jsonconf)
        cmd = f'''{self.trn_cli_get_vpc} \'{jsonconf}\''''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def delete_vpc(self, vpc, netid, expect_fail=False):
        log_string = "[DROPLET {}]: delete_vpc {}".format(
            self.id, vpc.get_tunnel_id())
        jsonconf = {
            "tunnel_id": vpc.get_tunnel_id(),
        }
        jsonconf = json.dumps(jsonconf)
        key = ("vpc " + self.phy_itf, jsonconf)
        cmd = f'''{self.trn_cli_delete_vpc} \'{jsonconf}\''''
        if netid in self.known_nets:
            self.known_nets.remove(netid)
        self.vpc_updates[key] = len(self.known_nets)
        self.do_delete_decrement(
            log_string, cmd, expect_fail, key, self.vpc_updates)

    def update_net(self, net, expect_fail=False):
        log_string = "[DROPLET {}]: update_net {}".format(self.id, net.netid)
        jsonconf = {
            "tunnel_id": net.get_tunnel_id(),
            "nip": net.get_nip(),
            "prefixlen": net.get_prefixlen(),
            "switches_ips": net.get_switches_ips()
        }
        jsonconf = json.dumps(jsonconf)
        jsonkey = {
            "tunnel_id": net.get_tunnel_id(),
            "nip": net.get_nip(),
            "prefixlen": net.get_prefixlen(),
        }
        self.rpc_updates[("net " + self.phy_itf,
                          json.dumps(jsonkey))] = time.time()
        cmd = f'''{self.trn_cli_update_net} \'{jsonconf}\''''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def get_net(self, net, expect_fail=False):
        log_string = "[DROPLET {}]: get_net {}".format(self.id, net.netid)
        jsonconf = {
            "tunnel_id": net.get_tunnel_id(),
            "nip": net.get_nip(),
            "prefixlen": net.get_prefixlen(),
        }
        jsonconf = json.dumps(jsonconf)
        cmd = f'''{self.trn_cli_get_net} \'{jsonconf}\''''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def delete_net(self, net, expect_fail=False):
        log_string = "[DROPLET {}]: delete_net {}".format(self.id, net.netid)
        jsonconf = {
            "tunnel_id": net.get_tunnel_id(),
            "nip": net.get_nip(),
            "prefixlen": net.get_prefixlen(),
        }
        jsonconf = json.dumps(jsonconf)
        self.rpc_deletes[("net " + self.phy_itf, jsonconf)] = time.time()
        cmd = f'''{self.trn_cli_delete_net} \'{jsonconf}\''''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def update_ep(self, ep, expect_fail=False):
        if ep.host is not None:
            log_string = "[DROPLET {}]: update_ep {} hosted at {}".format(
                self.id, ep.ip, ep.host.id)
        else:
            log_string = "[DROPLET {}]: update_ep for a phantom ep {}".format(
                self.id, ep.ip)
        peer = ""

        # Only detail veth info if the droplet is also a host
        if (ep.host and self.ip == ep.host.ip):
            peer = ep.get_veth_peer()

        jsonconf = {
            "tunnel_id": ep.get_tunnel_id(),
            "ip": ep.get_ip(),
            "eptype": ep.get_eptype(),
            "mac": ep.get_mac(),
            "veth": ep.get_veth_name(),
            "remote_ips": ep.get_remote_ips(),
            "hosted_iface": peer
        }
        jsonconf = json.dumps(jsonconf)
        jsonkey = {
            "tunnel_id": ep.get_tunnel_id(),
            "ip": ep.get_ip(),
        }
        key = ("ep " + self.phy_itf, json.dumps(jsonkey))
        cmd = f'''{self.trn_cli_update_ep} \'{jsonconf}\''''
        self.do_update_increment(
            log_string, cmd, expect_fail, key, self.endpoint_updates)

    def get_ep(self, ep, agent=False, expect_fail=False):
        jsonconf = {
            "tunnel_id": ep.get_tunnel_id(),
            "ip": ep.get_ip(),
        }
        jsonconf = json.dumps(jsonconf)
        if agent:
            log_string = "[DROPLET {}]: get_agent_ep {} hosted at {}".format(
                self.id, ep.ip, ep.host.id)
            cmd = f'''{self.trn_cli_get_agent_ep} \'{jsonconf}\''''
        else:
            log_string = "[DROPLET {}]: get_ep {} hosted at {}".format(
                self.id, ep.ip, ep.host.id)
            cmd = f'''{self.trn_cli_get_ep} \'{jsonconf}\''''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def delete_ep(self, ep, agent=False, expect_fail=False):

        jsonconf = {
            "tunnel_id": ep.get_tunnel_id(),
            "ip": ep.get_ip(),
        }
        jsonconf = json.dumps(jsonconf)
        if agent:
            log_string = "[DROPLET {}]: delete_agent_ep {} hosted at {}".format(
                self.id, ep.ip, ep.host.id)
            cmd = f'''{self.trn_cli_delete_agent_ep} \'{jsonconf}\''''
            self.exec_cli_rpc(log_string, cmd, expect_fail)
        else:
            cmd = f'''{self.trn_cli_delete_ep} \'{jsonconf}\''''
            key = ("ep " + self.phy_itf, jsonconf)
            if ep.host is not None:
                log_string = "[DROPLET {}]: delete_ep {} hosted at {}".format(
                    self.id, ep.ip, ep.host.id)
            else:
                log_string = "[DROPLET {}]: delete_ep for a phantom ep {}".format(
                    self.id, ep.ip)
            self.do_delete_decrement(
                log_string, cmd, expect_fail, key, self.endpoint_updates)

    def get_agent_ep(self, ep, expect_fail=False):
        self.get_ep(ep, agent=True, expect_fail=expect_fail)

    def delete_agent_ep(self, ep, expect_fail=False):
        self.delete_ep(ep, agent=True, expect_fail=expect_fail)

    def update_substrate_ep(self, droplet, expect_fail=False):
        log_string = "[DROPLET {}]: update_substrate_ep for droplet {}".format(
            self.id, droplet.ip)
        jsonconf = droplet.get_substrate_ep_json()
        jsonkey = {
            "tunnel_id": "0",
            "ip": droplet.ip,
        }
        key = ("ep_substrate " + self.phy_itf,
               json.dumps(jsonkey))
        cmd = f'''{self.trn_cli_update_ep} \'{jsonconf}\''''
        self.do_update_increment(
            log_string, cmd, expect_fail, key, self.substrate_updates)

    def delete_substrate_ep(self, droplet, expect_fail=False):
        log_string = "[DROPLET {}]: delete_substrate_ep for droplet {}".format(
            self.id, droplet.ip)
        jsonconf = droplet.get_substrate_ep_json()
        jsonkey = {
            "tunnel_id": "0",
            "ip": droplet.ip,
        }
        key = ("ep_substrate " + self.phy_itf,
               json.dumps(jsonkey))
        cmd = f'''{self.trn_cli_delete_ep} \'{jsonconf}\''''
        self.do_delete_decrement(
            log_string, cmd, expect_fail, key, self.substrate_updates)

    def update_agent_ep(self, itf, expect_fail=False):
        logger.error(
            "[DROPLET {}]: not implemented, no use case for now!".format(self.id))

    def update_agent_metadata(self, itf, ep, net, expect_fail=False):
        log_string = "[DROPLET {}]: update_agent_metadata on {} for endpoint {}".format(
            self.id, itf, ep.ip)
        jsonconf = {
            "ep": {
                "tunnel_id": ep.get_tunnel_id(),
                "ip": ep.get_ip(),
                "eptype": ep.get_eptype(),
                "mac": ep.get_mac(),
                "veth": ep.get_veth_name(),
                "remote_ips": ep.get_remote_ips(),
                "hosted_iface": self.phy_itf
            },
            "net": {
                "tunnel_id": net.get_tunnel_id(),
                "nip": net.get_nip(),
                "prefixlen": net.get_prefixlen(),
                "switches_ips": net.get_switches_ips()
            },
            "eth": {
                "ip": self.ip,
                "mac": self.mac,
                "iface": self.phy_itf
            }
        }
        jsonconf = json.dumps(jsonconf)
        cmd = f'''{self.trn_cli_update_agent_metadata} -i \'{itf}\' -j \'{jsonconf}\''''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def get_agent_metadata(self, itf, ep, expect_fail=False):
        log_string = "[DROPLET {}]: get_agent_metadata on {} for endpoint {}".format(
            self.id, itf, ep.ip)
        jsonconf = {
            "": "",
        }
        jsonconf = json.dumps(jsonconf)
        cmd = f'''{self.trn_cli_get_agent_metadata} -i \'{itf}\' -j \'{jsonconf}\''''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def delete_agent_metadata(self, itf, ep, expect_fail=False):
        log_string = "[DROPLET {}]: delete_agent_metadata on {} for endpoint {}".format(
            self.id, itf, ep.ip)
        jsonconf = {
            "": "",
        }
        jsonconf = json.dumps(jsonconf)
        cmd = f'''{self.trn_cli_delete_agent_metadata} -i \'{itf}\' -j \'{jsonconf}\''''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def update_agent_substrate_ep(self, itf, droplet, expect_fail=False):
        log_string = "[DROPLET {}]: update_agent_substrate_ep on {} for droplet {}".format(
            self.id, itf, droplet.ip)

        jsonconf = droplet.get_substrate_ep_json()
        cmd = f'''{self.trn_cli_update_agent_ep} -i \'{itf}\' -j \'{jsonconf}\''''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def delete_agent_substrate_ep(self, itf, droplet, expect_fail=False):
        log_string = "[DROPLET {}]: delete_agent_substrate_ep on {} for droplet {}".format(
            self.id, itf, droplet.ip)

        jsonconf = droplet.get_substrate_ep_json()
        cmd = f'''{self.trn_cli_delete_agent_ep} -i \'{itf}\' -j \'{jsonconf}\''''
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def exec_cli_rpc(self, log_string, cmd, expect_fail):
        logger.info(log_string)
        output = self.run(cmd, expect_fail=expect_fail)
        if not expect_fail and output[0] != 0:
            self.rpc_failures[time.time()] = cmd
        return output

    # RPC call is stored as key
    # Will overwrite with latest call if exact same call is made multiple times
    def dump_rpc_calls(self):
        logger.info("{} {}, update commands ran. {}".format(
            '='*20, len(self.rpc_updates.keys()), '='*20))
        for cmd in self.rpc_updates:
            logger.info("[DROPLET {}]: Update command ran: {} at {}".format(
                self.id, cmd, self.rpc_updates[cmd]))
        logger.info("{} {}, delete commands ran. {}".format(
            '='*20, len(self.rpc_deletes.keys()), '='*20))
        for cmd in self.rpc_deletes:
            logger.info("[DROPLET {}]: Delete command ran: {} at {}".format(
                self.id, cmd, self.rpc_deletes[cmd]))

    def add_bridge(self, br):
        logger.info(
            "[DROPLET {}]: Add linux bridge {}".format(self.id, br))
        script = (f''' sudo bash -c '\
brctl addbr {br} && \
ip link set {br} up && \
brctl stp {br} yes' ''')
        self.run(script)

    def bridge_add_itf(self, br, itf):
        logger.info(
            "[DROPLET {}]: bridge_add_itf to {}".format(self.id, br))
        cmd = 'sudo brctl addif {} {}'.format(br, itf)
        self.run(cmd)

    def ovs_add_bridge(self, br):
        logger.info(
            "[DROPLET {}]: Add ovs bridge {}".format(self.id, br))
        script = (f''' sudo bash -c '\
ovs-vsctl add-br {br} && \
ip link set {br} up ' ''')
        self.run(script)

    def ovs_is_exist(self, br):
        cmd = 'sudo ovs-vsctl br-exists {}'.format(br)
        return self.run(cmd)[0] == 0

    def ovs_add_port(self, br, port):
        logger.info(
            "[DROPLET {}]: ovs_add_port to {}".format(self.id, br))
        cmd = 'sudo ovs-vsctl add-port {} {}'.format(br, port)
        self.run(cmd)

        cmd = f'''sudo ovs-vsctl get Interface {port} ofport'''
        return self.run(cmd)[1].rstrip()

    def ovs_add_transit_flow(self, br, in_port, out_port):
        logger.info("[DROPLET {}]: ovs_add_transit_flow {}, {}, {}".format(
            self.id, br, in_port, out_port))
        cmd = f'''sudo ovs-ofctl add-flow {br} priority=50,in_port={in_port},dl_type=0x800,actions=output:{out_port}'''
        self.run(cmd)

        cmd = f'''sudo ovs-ofctl add-flow {br} priority=50,in_port={in_port},dl_type=0x806,actions=output:{out_port}'''
        self.run(cmd)

    def add_vxlan_ofrule(self, br, in_port, out_port, nw_dst):
        cmd = f'''sudo ovs-ofctl add-flow {br} priority=100,in_port={in_port},dl_type=0x800,nw_dst={nw_dst},actions=output:{out_port}'''
        self.run(cmd)

        cmd = f'''sudo ovs-ofctl add-flow {br} priority=100,in_port={in_port},dl_type=0x806,nw_dst={nw_dst},actions=output:{out_port}'''
        self.run(cmd)

    def ovs_create_vxlan_tun_itf(self, br, itf, vxlan_key, remote_ip):
        logger.info(
            "[DROPLET {}]: create_vxlan_tun_itf {}, {}".format(self.id, itf, remote_ip))
        cmd = f'''sudo ovs-vsctl --may-exist \
add-port {br} {itf} \
-- set interface {itf} \
type=vxlan options:remote_ip={remote_ip} \
options:key={vxlan_key}'''
        self.run(cmd)

        cmd = f'''sudo  ovs-vsctl get Interface {itf} ofport'''
        return self.run(cmd)[1].rstrip()

    def ovs_create_geneve_tun_itf(self, br, itf, geneve_key, remote_ip):
        logger.info(
            "[DROPLET {}]: ovs_create_geneve_tun_itf {}, {}".format(self.id, itf, remote_ip))
        cmd = f'''sudo ovs-vsctl --may-exist \
add-port {br} {itf} \
-- set interface {itf} \
type=geneve options:remote_ip={remote_ip} \
options:key={geneve_key}'''
        self.run(cmd)
        cmd = f'''sudo ovs-vsctl get Interface {itf} ofport'''
        return self.run(cmd)[1].rstrip()

    def get_substrate_ep_json(self):
        """
        Get a substrate endpoint data to configure XDP programs to
        send packets to this droplet (no ARP for the moment!)
        """
        jsonconf = {
            "tunnel_id": "0",
            "ip": self.ip,
            "eptype": "0",
            "mac": self.mac,
            "veth": "",
            "remote_ips": [""],
            "hosted_iface": ""
        }
        jsonconf = json.dumps(jsonconf)
        return jsonconf

    def local(self, cmd):
        ret_value = None
        logger.info("[LOCAL {}]: running: {}".format(self.id, cmd))
        try:
            out = run_cmd(cmd)
            ret_value = (out[0], out[1])
            if (ret_value[0] != 0):
                logger.error("[LOCAL {}]: {}".format(self.id, ret_value[1]))

            logger.debug(
                "[LOCAL {}]: running\n    command:\n {}, \n    exit_code: {},\n    output:\n {}".format(self.id, cmd, ret_value[0], ret_value[1]))

            return ret_value
        except Exception as e:
            logger.error("[LOCAL {}]: {}".format(self.id, str(e)))
            return None

    def run(self, cmd, detach=False, expect_fail=False):
        """
        Runs a command directly on the droplet
        """
        if self.droplet_type == 'docker':
            return self._run_docker(cmd, expect_fail, detach)

        if self.droplet_type == 'linux':
            return self._run_linux(cmd, expect_fail, detach)

        logger.error("Unsupported droplet type!")

    def get_file(self, path):
        if self.droplet_type == 'docker':
            return self._get_docker_file(path)

        if self.droplet_type == 'linux':
            return self._get_linux_file(path)

        logger.error("Unsupported droplet type!")

    def _get_docker_file(self, path):
        cmd = f'''cat {path}'''
        out = self.container.exec_run(cmd, detach=False)
        return out.output.decode("utf-8")

    def _get_linux_file(self, path):
        logger.error("[LDROPLET {}]: Fetching file {}".format(self.id, path))
        fd = BytesIO()
        self.conn.get(path, '/tmp/resultdata')
        with open('/tmp/resultdata', 'r') as datfile:
            data = datfile.read()
        return data

    def _run_linux(self, cmd, expect_fail, detach=False):

        ret_value = None

        _cmd = cmd
        if detach:
            _cmd = "nohup {} &> /dev/null &".format(cmd)

        logger.info("[LDROPLET {}]: running: {}".format(self.id, _cmd))

        out = self.conn.run(_cmd, warn=True)
        if not detach:
            ret_value = (out.exited, out.stdout.strip())
        if (not detach and ret_value[0] != 0):
            if not expect_fail:
                logger.error("[LDROPLET {}]: {}".format(self.id, ret_value[1]))
            else:
                logger.info("[LDROPLET {}]: {}".format(self.id, ret_value[1]))

        if not detach:
            logger.debug(
                "[LDROPLET {}]: running\n    command:\n {}, \n    exit_code: {},\n    output:\n {}".format(self.id, _cmd, ret_value[0], ret_value[1]))

        return ret_value

    def _run_docker(self, cmd, expect_fail, detach=False):

        ret_value = None

        out = self.container.exec_run(cmd, detach=detach)
        if not detach:
            ret_value = (out.exit_code, out.output.decode("utf-8"))

        logger.info("[DROPLET {}]: running: {}".format(self.id, cmd))
        if (not detach and ret_value[0] != 0):
            if not expect_fail:
                logger.error("[LDROPLET {}]: {}".format(self.id, ret_value[1]))
            else:
                logger.info("[LDROPLET {}]: {}".format(self.id, ret_value[1]))

        if not detach:
            logger.debug(
                "[DROPLET {}]: running\n    command:\n {}, \n    exit_code: {},\n    output:\n {}".format(self.id, cmd, ret_value[0], ret_value[1]))

        return ret_value

    def _collect_logs(self):
        cmd = f'''
cp /var/log/syslog /trn_test_out/syslog_{self.ip}
        '''
        self.run(cmd)

    def _create_docker_container(self):
        """ Create and initialize a docker container.
        Assumes "buildbox:v2" image exist and setup on host
        """
        cwd = os.getcwd()

        # get a docker client
        docker_client = docker.from_env()
        docker_image = "buildbox:v2"
        mount_pnt = docker.types.Mount("/mnt/Transit",
                                       cwd,
                                       type='bind')

        mount_modules = docker.types.Mount("/lib/modules",
                                           "/lib/modules",
                                           type='bind')

        # Create the contrainer in previlaged mode
        container = docker_client.containers.create(
            docker_image, '/bin/bash', tty=True,
            stdin_open=True, auto_remove=False, mounts=[mount_pnt, mount_modules],
            privileged=True, cap_add=["SYS_PTRACE"],
            security_opt=["seccomp=unconfined"])
        container.start()
        container.reload()

        self.container = container
        self.ip = self.container.attrs['NetworkSettings']['IPAddress']
        self.mac = self.container.attrs['NetworkSettings']['MacAddress']
        self.control_ip = self.ip

        self._init_droplet()

    def start_pcap(self):
        # Start a pcap to collect packets on eth0
        cmd = f''' bash -c \
'(/mnt/Transit/tools/xdpcap /bpffs/{self.phy_itf}_transit_pcap \
/trn_test_out/\
droplet_{self.ip}.pcap >/dev/null 2>&1 &\
)' '''
        self.run(cmd)

    def delete_container(self):
        if self.container:
            self.container.stop()
            self.container.remove()

    def __del__(self):
        self.unload_transit_xdp()
        self.run("killall5 -2")
        time.sleep(1)
        if 'NOCLEANUP' in os.environ:
            return
        self.delete_container()

    def prepare_remote_host(self):
        self.conn = Connection(self.id)
        self.run("sudo ln -snf ~/Mizar /mnt/Transit")
        self.mac = self.run(
            "cat /sys/class/net/{}/address".format(self.phy_itf))[1]
        first_cmd = "/sbin/ip -o -4 addr list {}".format(self.phy_itf)
        self.ip = self.run(first_cmd + " | awk '{print $4}' | cut -d/ -f1")[1]
        logger.info("MAC: {}, IP: {}".format(self.mac, self.ip))
        self._init_droplet()

    def _init_droplet(self):

        # Restart dependancy services
        self.run("sudo /etc/init.d/rpcbind restart")
        self.run("sudo /etc/init.d/rsyslog restart")
        self.run("sudo ip link set dev {} up mtu 9000".format(self.phy_itf))

        # We may need ovs for compatability tests
        self.run("sudo /etc/init.d/openvswitch-switch restart")

        # Create simlinks
        self.run("sudo ln -snf /mnt/Transit/build/bin /trn_bin")
        self.run("sudo ln -snf /mnt/Transit/build/xdp /trn_xdp")
        self.run("sudo ln -snf /sys/fs/bpf /bpffs")
        self.run("sudo ln -snf /mnt/Transit/test/trn_func_tests/output /trn_test_out")

        # Run the transitd in the background
        self.run("sudo /trn_bin/transitd ", detach=True)

        # Enable debug and tracing for the kernel
        self.enable_kernel_tracing()

        # Enable core dumps (just in case!!)
        cmd = "echo '/mnt/Transit/core/core_{}_%e.%p' |\
sudo tee -a /proc/sys/kernel/core_pattern ".format(self.ip)
        self.run(cmd)

    def enable_kernel_tracing(self):
        if self.benchmark:
            return

        if self.droplet_type == 'linux':
            self.run(
                "if mount | grep /sys/kernel/debug > /dev/null; then true; else sudo mount -t debugfs debugfs /sys/kernel/debug; fi")
        elif self.droplet_type == 'docker':
            self.run("mount -t debugfs debugfs /sys/kernel/debug")

        self.run("echo 1 | sudo tee -a /sys/kernel/debug/tracing/tracing_on")

    def delete_self(self):
        # Nothing to do for a running host
        # Cleaning only for containers for now!
        if self.droplet_type == 'linux':
            return

        print("Cleaning\n\n")

        self.unload_transit_xdp()
        self.run("killall5 -2")
        time.sleep(1)
        if 'NOCLEANUP' in os.environ:
            return

        self.delete_container()

    def clear_update_call_state(self):
        self.rpc_updates = {}

    def do_delete_decrement(self, log_string, cmd, expect_fail, key, update_counts):
        if update_counts[key] > 0:
            update_counts[key] -= 1
            if update_counts[key] == 0:
                self.rpc_deletes[key] = time.time()
                self.exec_cli_rpc(log_string, cmd, expect_fail)

    def do_update_increment(self, log_string, cmd, expect_fail, key, update_counts):
        if key in update_counts.keys():
            update_counts[key] += 1
        else:
            update_counts[key] = 1
        self.rpc_updates[key] = time.time()
        self.exec_cli_rpc(log_string, cmd, expect_fail)

    def do_iperf_serve(self, report_suffix='', affinity='1', args=''):
        report = f'''{self.iperf_report}_{report_suffix}'''
        cmd = f'''bash -c '(iperf -s {args} > {report})' '''
        self.run(cmd, detach=True)
        # wait for server to start
        time.sleep(1)

    def do_iperf_stop(self):
        time.sleep(1)
        cmd = 'sudo killall -9 iperf'
        return self.run(cmd)

    def do_iperf_client(self, ip, report_suffix='', affinity='1', args=''):
        report = f'''{self.iperf_report}_{report_suffix}_client'''
        cmd = f'''bash -c '(taskset -c {affinity} iperf -c {ip} {args} > {report})' '''
        return self.run(cmd)

    def stop_sar_process(self):
        cmd = 'sudo killall -9 sar'
        return self.run(cmd)

    def do_collect_mem_stats(self):
        memfile = f'''{self.output_dir}/{self.id}_sar.mem'''
        cmd = f'''bash -c '(sar -r -f {self.output_dir}/{self.id}_sar.out > {memfile})' '''
        self.run(cmd)
        return self.get_file(memfile)

    def do_collect_cpu_stats(self):
        cpufile = f'''{self.output_dir}/{self.id}_sar.cpu'''
        cmd = f'''bash -c '(sar -u -f {self.output_dir}/{self.id}_sar.out > {cpufile})' '''
        self.run(cmd)
        return self.get_file(cpufile)

    def dump_num_calls(self):
        for cmd in self.vpc_updates:
            logger.info("[DROPLET {}]: vpc_updates commands ran: {}  {}".format(
                self.id, cmd, self.vpc_updates[cmd]))
        for cmd in self.substrate_updates:
            logger.info("[DROPLET {}]: substrate_updates commands ran: {}  {}".format(
                self.id, cmd, self.substrate_updates[cmd]))
        for cmd in self.endpoint_updates:
            logger.info("[DROPLET {}]: endpoint_updates commands ran: {}  {}".format(
                self.id, cmd, self.endpoint_updates[cmd]))
