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


class test_basic_switch_perf(unittest.TestCase):

    def setUp(self):

        self.droplets = {
            "d1": droplet("d1", droplet_type="linux", control_ip='10.0.0.104', benchmark=True, phy_itf='eth0'),
            "d2": droplet("d2", droplet_type="linux", control_ip='10.0.0.180', benchmark=True, phy_itf='eth0'),
            "d3": droplet("d3", droplet_type="linux", control_ip='10.0.0.45', benchmark=True, phy_itf='eth0'),
        }

        c = controller(self.droplets)

        self.endpoints = []

        c.create_vpc(3, cidr("16", "10.0.0.0"), [])
        c.create_network(3, 1, cidr("16", "10.0.0.0"), ["d1"])

        self.ep_left = c.create_simple_endpoint(3, 1, "10.0.0.2", "d2")
        self.ep_right = c.create_simple_endpoint(3, 1, "10.0.0.3", "d3")

    def tearDown(self):
        pass

    def test_basic_switch_perf(self):
        logger.info(
            "{} Testing basic switch perf! {}".format('='*20, '='*20))
        do_iperf_common_tests(self, self.ep_left, self.ep_right)
