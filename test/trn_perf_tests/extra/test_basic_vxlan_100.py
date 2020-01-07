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


class test_basic_vxlan_perf(unittest.TestCase):

    def setUp(self):

        self.droplets = {
            "d1": droplet("d1", droplet_type="linux", control_ip='10.0.0.104', benchmark=True, phy_itf='enp2s0f0'),
            "d2": droplet("d2", droplet_type="linux", control_ip='10.0.0.180', benchmark=True, phy_itf='enp2s0f0'),
            "d3": droplet("d3", droplet_type="linux", control_ip='10.0.0.45', benchmark=True, phy_itf='enp2s0f0'),
        }

        c = controller(self.droplets)

        self.endpoints = []

        c.create_vpc(3, cidr("16", "10.0.0.0"), [])
        net = c.create_network(3, 1, cidr("16", "10.0.0.0"), ["d1"])

        for i in range(2, 101):
            c.create_vxlan_endpoint(3, 1, "10.0.0." + str(i), "d2")

    def tearDown(self):
        pass

    def test_basic_vxlan_perf(self):
        pass
