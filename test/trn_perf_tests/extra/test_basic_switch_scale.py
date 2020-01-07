# Copyright (c) 2019 The Authors.
#
# Authors: Sherif Abdelwahab <@zasherif>
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from test.trn_controller.controller import controller
from test.trn_controller.droplet import droplet
from test.trn_controller.common import cidr
from test.trn_func_tests.helper import *
import unittest
from time import sleep
import datetime


class test_switch_local(unittest.TestCase):

    def setUp(self):
        # Testing the following basic scenario
        # +-------------------------+       +-------------------------+
        # |           left          |       |   right (and switch)    |
        # | +--------+   +--------+ |       | +--------+   +--------+ |
        # | |  ns0   |   |  ns2   | |       | |  ns1   |   |  ns3   | |
        # | |        |   |        | |       | |        |   |        | |
        # | +--------+   +--------+ |       | +--------+   +--------+ |
        # | | veth0  |   | veth0  | |       | | veth0  |   | veth0  | |
        # | |10.0.0.1|   |10.0.0.3| |       | |10.0.0.2|   |10.0.0.4| |
        # | +--------+   +--------+ |       | +--------+   +--------+ |
        # |      |            |     |       |      |            |     |
        # |      |            |     |       |      |            |     |
        # |      |            |     |       |      |            |     |
        # | +--------+   +--------+ |       | +--------+   +--------+ |
        # | |Transit |   |Transit | |       | |Transit |   |Transit | |
        # | | Agent  |   | Agent  | |       | | Agent  |   | Agent  | |
        # | | peer0  |   | peer2  | |       | | peer1  |   | peer3  | |
        # | +--------+   +--------+ |       | +--------+   +--------+ |
        # +-------------------------+       +-------------------------+
        # |       Transit XDP       |       |       Transit XDP       |
        # |          eth0           |       |  eth0 (Switch is here)  |
        # +-------------------------+       +-------------------------+

        n_switches = 10
        self.droplets = {
            "d1": droplet("d1", droplet_type="linux", control_ip='10.0.0.194', benchmark=True, phy_itf='eth0'),
            # "d2": droplet("d2", droplet_type="linux", control_ip='10.0.0.92', benchmark=True, phy_itf='eth0'),
            # "d3": droplet("d3", droplet_type="linux", control_ip='10.0.0.62', benchmark=True, phy_itf='eth0'),
            # "d4": droplet("d4", droplet_type="linux", control_ip='10.0.0.183', benchmark=True, phy_itf='eth0'),
            # "d5": droplet("d5", droplet_type="linux", control_ip='10.0.0.89', benchmark=True, phy_itf='eth0'),
            # "d6": droplet("d6", droplet_type="linux", control_ip='10.0.0.215', benchmark=True, phy_itf='eth0'),
            # "d7": droplet("d7", droplet_type="linux", control_ip='10.0.0.145', benchmark=True, phy_itf='eth0'),
            # "d8": droplet("d8", droplet_type="linux", control_ip='10.0.0.97', benchmark=True, phy_itf='eth0'),
            # "d9": droplet("d9", droplet_type="linux", control_ip='10.0.0.9', benchmark=True, phy_itf='eth0'),
            # "d10": droplet("d10", droplet_type="linux", control_ip='10.0.0.151', benchmark=True, phy_itf='eth0'),
            "d11": droplet("d11", droplet_type="linux", control_ip='10.0.0.181', benchmark=True, phy_itf='eth0'),
            "d12": droplet("d12", droplet_type="linux", control_ip='10.0.0.204', benchmark=True, phy_itf='eth0'),
        }
        c = controller(self.droplets)

        switches = []
        # for i in range(1,n_switches):
        #    name = "d" + str(i)
        #    switches.append(name)
        switches.append("d1")
        # switches.append("d2")
        # switches.append("d3")
        # switches.append("d4")
        # switches.append("d5")
        # switches.append("d6")
        # switches.append("d7")
        # switches.append("d8")
        # switches.append("d9")
        # switches.append("d10")
        c.create_vpc(3, cidr("16", "10.0.0.0"), [])
        net = c.create_network(3, 1, cidr("16", "10.0.0.0"), switches)

        self.endpoints = []

        n_endpoints = 10

        start = datetime.datetime.now()
        for i in range(2, n_endpoints, 2):
            c.create_simple_endpoint(3, 1, "10.0.0." + str(i), "d11")
            c.create_simple_endpoint(3, 1, "10.0.0." + str(i + 1), "d12")
        end = datetime.datetime.now()

        t = end - start
        a = t * 1.0 / n_endpoints

        print("################# Provisioned in: {}, avg: {}".format(t, a))

    def tearDown(self):
        sleep(1)
        pass

    def test_switch_local(self):
        pass
