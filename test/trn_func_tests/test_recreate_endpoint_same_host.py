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

from test.trn_controller.controller import controller
from test.trn_controller.droplet import droplet
from test.trn_controller.common import cidr
from test.trn_func_tests.helper import *
import unittest
from time import sleep


class test_recreate_endpoint_same_host(unittest.TestCase):

    def setUp(self):

        self.droplets = {
            "d1": droplet("d1"),
            "d2": droplet("d2"),
            "switch-1": droplet("switch-1"),
            "router-1": droplet("router-1")
        }

        c = controller(self.droplets)

        # Create two co-hosted VPCs each with one endpoint
        c.create_vpc(3, cidr("16", "10.0.0.0"), ["router-1"])
        c.create_network(3, 10, cidr("24", "10.0.0.0"), ["switch-1"])
        self.ep1 = c.create_simple_endpoint(3, 10, "10.0.0.2", "d1")

        c.create_vpc(4, cidr("16", "20.0.0.0"), ["router-1"])
        c.create_network(4, 20, cidr("24", "20.0.0.0"), ["switch-1"])
        self.ep5 = c.create_simple_endpoint(4, 20, "20.0.0.2", "d1")

        # Delete their networks
        c.delete_network(3, 10)
        c.delete_network(4, 20)

        # Recreate the networks and endpoints
        c.create_network(3, 10, cidr("24", "10.0.0.0"), ["switch-1"])
        c.create_network(4, 20, cidr("24", "20.0.0.0"), ["switch-1"])

        self.ep1 = c.create_simple_endpoint(3, 10, "10.0.0.2", "d1")
        self.ep5 = c.create_simple_endpoint(4, 20, "20.0.0.2", "d1")

        # Delete the VPC
        c.delete_vpc(4)
        c.delete_vpc(3)

    def tearDown(self):
        pass

    def test_recreate_endpoint_same_host(self):
        logger.info(
            "{} Checking for failed RPC calls! {}".format('='*20, '='*20))
        do_validate_delete_test(self, list(self.droplets.values()))
        do_check_failed_rpcs(self, self.droplets.values())
