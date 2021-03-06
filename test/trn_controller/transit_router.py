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

from test.trn_controller.common import logger


class transit_router:
    def __init__(self, droplet):
        self.droplet = droplet
        self.ip = self.droplet.ip
        self.id = droplet.id
        self.networks = {}
        self.known_switches = []

    def update_net(self, net, droplet, add=True):
        """
        Calls an update_net rpc to the transit router's droplet. After
        this the transit router has an updated list of the network's
        transit switch. Also calls update_substrate_endpoint to
        populate the mac addresses of the transit switches' droplets.
        """
        logger.info("[ROUTER {}]: update_net {}".format(self.id, net.netid))
        self.droplet.update_net(net)
        if (add):
            for s in net.transit_switches.values():
                if s.droplet not in self.known_switches:
                    self.droplet.update_substrate_ep(s.droplet)
                    self.known_switches.append(s.droplet)
        # When we update_net but remove a switch.
        else:
            if(self.known_switches):
                self.known_switches.remove(droplet)
                self.droplet.delete_substrate_ep(droplet)

    def delete_net(self, net, net_switches=None):
        """
        Calls a delete_net rpc to the transit router's droplet.
        Also calls delete_substrate_endpoint to
        remove the mac addresses of the transit switches' droplets.
        """
        logger.info("[ROUTER {}]: delete_net {}".format(self.id, net.netid))
        self.droplet.delete_net(net)

        switches = net.transit_switches.values()
        if net_switches is not None:
            switches = net_switches

        # Now delete the mac address of the switches
        for s in switches:
            self.droplet.delete_substrate_ep(s.droplet)
