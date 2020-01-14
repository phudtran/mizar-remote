from test.trn_controller.controller import controller
from test.trn_controller.droplet import droplet
from test.trn_controller.common import cidr
from test.trn_func_tests.helper import *
import unittest
from time import sleep


class test_host_ep(unittest.TestCase):

    def setUp(self):

        self.droplets = {
            "d1": droplet("d1", droplet_type="linux", control_ip='172.31.30.230', benchmark=False, phy_itf='eth0'),
            "d2": droplet("d2", droplet_type="linux", control_ip='172.31.30.6', benchmark=False, phy_itf='eth0'),
            "d3": droplet("d3", droplet_type="linux", control_ip='172.31.29.230', benchmark=False, phy_itf='eth0'),
            "d4": droplet("d4", droplet_type="linux", control_ip='172.31.21.76', benchmark=False, phy_itf='eth0'), }

        c = controller(self.droplets)

        self.endpoints = []

        c.create_vpc(3, cidr("16", "10.0.0.0"), [])
        c.create_network(3, 1, cidr("16", "10.0.0.0"), ["d1"])

        c.create_simple_endpoint(3, 1, "10.0.0.2", "d2")
        c.create_simple_endpoint(3, 1, "10.0.0.3", "d3")
        c.create_host_endpoint(3, 1, "172.31.21.76", "d4")
        while(True):
            sleep(100000)

    def tearDown(self):
        pass

    def test_host_ep(self):
        pass
