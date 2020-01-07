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
            "d1": droplet("d1", droplet_type="linux", control_ip='172.31.47.2', phy_itf='ens5'),
            "d2": droplet("d2", droplet_type="linux", control_ip='172.31.35.238', phy_itf='ens5'),
        }

        c = controller(self.droplets)

        c.create_vpc(3, cidr("16", "10.0.0.0"), [])
        net = c.create_network(3, 1, cidr("16", "10.0.0.0"), ["d1"])

        self.ep_left = c.create_simple_endpoint(3, 1, "10.0.0.2", "d1")
        self.ep_right = c.create_simple_endpoint(3, 1, "10.0.0.3",  "d2")
        self.ep_left.host.attach_vm(self.ep_left)

    def tearDown(self):
        pass

    def test_basic_switch_perf(self):
        logger.info(
            "{} Testing basic switch perf! {}".format('='*20, '='*20))

        while True:
            pass


