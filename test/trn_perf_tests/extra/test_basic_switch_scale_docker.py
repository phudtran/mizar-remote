# Copyright (c) 2019 The Authors.
#
# Authors: Sherif Abdelwahab <@zasherif>
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import multiprocessing as mp
from functools import partial
from pathos.multiprocessing import ProcessingPool as Pool
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

        open('/dev/shm/update_ep_times.txt', 'w').close()
        n_switches = 4
        self.droplets = {
            "d0": droplet("d0", benchmark=True),
            "d1": droplet("d1", benchmark=True),
        }
        c = controller(self.droplets)

        switches = []
        for i in range(n_switches - 1):
            name = "d" + str(i+2)
            switches.append(name)
            self.droplets[name] = droplet(
                name, benchmark=True)

        c.create_vpc(3, cidr("16", "10.0.0.0"), [])
        net = c.create_network(3, 1, cidr("16", "10.0.0.0"), switches)

        self.endpoints = []

        n_endpoints = 10

        start = datetime.datetime.now()
        for i in range(2, n_endpoints, 2):
            c.create_simple_endpoint(3, 1, "10.0.0." + str(i), "d0")
            c.create_simple_endpoint(3, 1, "10.0.0." + str(i + 1), "d1")
        end = datetime.datetime.now()

        t = end - start
        a = t * 1.0 / n_endpoints

        print("################# Provisioned in: {}, avg: {}".format(t, a))
        output = open("/dev/shm/update_ep_times.txt", "r")
        updates = output.read().split('###')
        updates.pop(0)
        delta_sum = 0
        for update in updates:
            lines = update.split("\n")
            lines.pop(len(lines) - 1)
            lines.sort()
            first = float(lines[0])
            last = float(lines[len(lines) - 1])
            delta = last - first
            print("delta between each update for every ep " +
                  str(delta) + "seconds")
            delta_sum += delta
        print("Total delta is " + str(delta_sum) + "seconds")

    def tearDown(self):
        do_cleanup(self, self.droplets.values())

    def test_switch_local(self):
        pass
