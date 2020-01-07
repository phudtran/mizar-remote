# Copyright (c) 2019 The Authors.
#
# Authors: Sherif Abdelwahab  <@zasherif>
#          Haibin Michael Xie <@haibinxie>
#          Phu Tran           <@phudtran>
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from test.trn_controller.common import logger
from time import sleep


def float2(read_in):
    try:
        return float(read_in)
    except ValueError:
        return "Nan"


def do_tcp_perf_test(server_ep, client_ep):
    return _do_tcp_perf_test(server_ep, client_ep)


def do_tcp_host_perf_test(server_ep, client_ep):
    return _do_tcp_perf_test(server_ep, client_ep, True)


def do_udp_perf_test(server_ep, client_ep):
    return _do_udp_perf_test(server_ep, client_ep)


def do_udp_host_perf_test(server_ep, client_ep):
    return _do_udp_perf_test(server_ep, client_ep, True)


def _do_tcp_perf_test(server_ep, client_ep, host=False):
    suffix = 'basic_tcp'

    if host:
        _do_host_perf_test(server_ep, client_ep, suffix=suffix, tcp=True)
        client_iperf_report = f'''{client_ep.host.iperf_report}_{suffix}_client'''
    else:
        _do_perf_test(server_ep, client_ep, suffix=suffix, tcp=True)
        client_iperf_report = f'''{client_ep.iperf_report}_{suffix}_client'''

    dat = client_ep.host.get_file(client_iperf_report)

    dat = dat.splitlines()
    stats = {}
    stats_sum = {}
    for l in dat:
        k = l.split()
        if k[0] != '[SUM]' or len(k) != 9:
            continue
        stats_sum['Transfer_val'] = float2(k[3])
        stats_sum['Transfer_unit'] = k[4]
        stats_sum['Bandwidth_val'] = float2(k[5])
        stats_sum['Bandwidth_unit'] = k[6]
        print(stats_sum)

    for l in dat:
        k = l.split()
        if len(k) != 12 or k[0] == '[SUM]' or k[1] == 'ID]' or k[2] == 'local':
            continue
        stats['Transfer_val'] = float2(k[4])
        stats['Transfer_unit'] = k[5]
        stats['Bandwidth_val'] = float2(k[6])
        stats['Bandwidth_unit'] = k[7]
        stats['RTT_val'] = float2(k[10].split('/')[1])
        stats['RTT_unit'] = k[11]
        print(stats)


def _do_udp_perf_test(server_ep, client_ep, host=False):
    suffix = 'basic_udp'

    if host:
        _do_host_perf_test(server_ep, client_ep, suffix=suffix)
        server_iperf_report = f'''{server_ep.host.iperf_report}_{suffix}'''
    else:
        _do_perf_test(server_ep, client_ep, suffix=suffix)
        server_iperf_report = f'''{server_ep.iperf_report}_{suffix}'''

    dat = server_ep.host.get_file(server_iperf_report)
    dat = dat.splitlines()
    stats = {}
    stats_sum = {}
    for l in dat:
        k = l.split()
        if k[0] != '[SUM]' or len(k) != 9:
            continue
        stats_sum['Transfer_val'] = float2(k[3])
        stats_sum['Transfer_unit'] = k[4]
        stats_sum['Bandwidth_val'] = float2(k[5])
        stats_sum['Bandwidth_unit'] = k[6]
        stats_sum['PPS_val'] = float2(k[7])
        stats_sum['PPS_unit'] = k[8]
        print(stats_sum)
    for l in dat:
        k = l.split()
        print(k)
        if len(k) != 17 or k[0] == '[SUM]' or k[1] == 'ID]':
            continue
        stats['Transfer_val'] = float2(k[4])
        stats['Transfer_unit'] = k[5]
        stats['Bandwidth_val'] = float2(k[6])
        stats['Bandwidth_unit'] = k[7]
        stats['Jitter_val'] = float2(k[8])
        stats['Jitter_unit'] = k[9]
        stats['Lost'] = float2(k[10].split('/')[0])
        stats['Total'] = float2(k[10].split('/')[1])
        stats['Latency_avg'] = float2(k[13].split('/')[0])
        stats['Latency_min'] = float2(k[13].split('/')[1])
        stats['Latency_max'] = float2(k[13].split('/')[2])
        stats['Latency_stdev'] = float2(k[14])
        stats['Latency_unit'] = k[15]
        stats['PPS_val'] = float2(k[16])
        stats['PPS_unit'] = 'pps'
        print(stats)


def _do_perf_test(server_ep, client_ep, suffix='', tcp=False):
    affinity = '0-63'

    args = '-e -i 1 -P 8 -f m'
    cargs = '-e -i 1 -P 8 -f m'

    if not tcp:
        args = '-u -e -i 1 -P 8 -f m'
        cargs = '-u -l 20 -e -i 1 -P 8 -f m'

    server_ep.do_iperf_serve(
        affinity=affinity, args=args, report_suffix=suffix)
    client_ep.do_iperf_client(
        server_ep.ip, report_suffix=suffix, affinity=affinity, args=cargs)
    server_ep.do_iperf_stop()


def _do_host_perf_test(server_ep, client_ep, suffix='', tcp=False):

    affinity = '0-63'

    args = '-e -i 1 -P 8 -f m'
    cargs = '-e -i 1 -P 8 -f m'

    if not tcp:
        args = '-u -e -i 1 -P 8 -f m'
        cargs = '-u -e -i 1 -P 8 -f m'

    # Testing the host itself
    server_ep.host.do_iperf_serve(
        affinity=affinity, args=args, report_suffix=suffix)
    client_ep.host.do_iperf_client(
        server_ep.host.ip, report_suffix=suffix, affinity=affinity, args=cargs)
    server_ep.host.do_iperf_stop()


def do_ping_test(test, ep1, ep2):
    logger.info("Test {}: {} do ping test {}".format(
        type(test).__name__, "="*10, "="*10))
    logger.info("Test: {} can ping {}".format(ep2.ip, ep1.ip))
    exit_code = ep2.do_ping(ep1.ip)[0]
    test.assertEqual(exit_code, 0)

    logger.info("Test: {} can ping {}".format(ep1.ip, ep2.ip))
    exit_code = ep1.do_ping(ep2.ip)[0]
    test.assertEqual(exit_code, 0)


def do_ping_fail_test(test, ep1, ep2, both_ways=True):
    logger.info("Test {}: {} do ping FAIL test {}".format(
        type(test).__name__, "="*10, "="*10))
    logger.info("Test: {} can NOT ping {}".format(ep2.ip, ep1.ip))
    exit_code = ep2.do_ping(ep1.ip)[0]
    test.assertNotEqual(exit_code, 0)
    if both_ways:
        logger.info("Test: {} can NOT ping {}".format(ep1.ip, ep2.ip))
        exit_code = ep1.do_ping(ep2.ip)[0]
        test.assertNotEqual(exit_code, 0)


def do_http_test(test, ep1, ep2):
    logger.info("Test {}: {} do http test {}".format(
        type(test).__name__, "="*10, "="*10))
    ep1.do_httpd()
    ep2.do_httpd()

    logger.info("Test {}: {} can curl http server on {}".format(
        type(test).__name__, ep2.ip, ep1.ip))
    exit_code = ep2.do_curl("http://{}:8000 -Ss -m 1".format(ep1.ip))[0]
    test.assertEqual(exit_code, 0)

    logger.info("Test {}: {} can curl http server on {}".format(
        type(test).__name__, ep1.ip, ep2.ip))
    exit_code = ep1.do_curl("http://{}:8000 -Ss -m 1".format(ep2.ip))[0]
    test.assertEqual(exit_code, 0)


def do_tcp_test(test, ep1, ep2):
    logger.info("Test {}: {} do tcp test {} ".format(
        type(test).__name__, "="*10, "="*10))
    ep1.do_tcp_serve()
    ep2.do_tcp_serve()

    logger.info(
        "Test {}: {} can do a tcp connection to {}".format(type(test).__name__, ep2.ip, ep1.ip))
    ep2.do_tcp_client(ep1.ip)
    exit_code = ep1.do_diff_tcp(ep2, ep1)[0]
    test.assertEqual(exit_code, 0)

    logger.info(
        "Test {}: {} can do a tcp connection to {}".format(type(test).__name__, ep1.ip, ep2.ip))
    ep1.do_tcp_client(ep2.ip)
    exit_code = ep2.do_diff_tcp(ep1, ep2)[0]
    test.assertEqual(exit_code, 0)


def do_udp_test(test, ep1, ep2):
    logger.info("Test {}: {} do udp test {} ".format(
        type(test).__name__, "="*10, "="*10))
    ep1.do_udp_serve()
    ep2.do_udp_serve()

    logger.info(
        "Test {}: {} can do a udp connection to {}".format(type(test).__name__, ep2.ip, ep1.ip))
    ep2.do_udp_client(ep1.ip)
    exit_code = ep1.do_diff_udp(ep2, ep1)[0]
    test.assertEqual(exit_code, 0)

    logger.info(
        "Test {}: {} can do a udp connection to {}".format(type(test).__name__, ep1.ip, ep2.ip))
    ep1.do_udp_client(ep2.ip)
    exit_code = ep2.do_diff_udp(ep1, ep2)[0]
    test.assertEqual(exit_code, 0)


def do_common_tests(test, ep1, ep2):
    do_ping_test(test, ep1, ep2)
    do_http_test(test, ep1, ep2)
    do_tcp_test(test, ep1, ep2)
    do_udp_test(test, ep1, ep2)


def do_common_no_udp_tests(test, ep1, ep2):
    do_ping_test(test, ep1, ep2)
    do_http_test(test, ep1, ep2)
    do_tcp_test(test, ep1, ep2)


def do_long_tcp_test(test, ep1, ep2):

    logger.info("Test {}: {} do long tcp test {} ".format(
        type(test).__name__, "="*10, "="*10))
    ep1.do_tcp_serve()

    logger.info(
        "Test {}: {} can do a long tcp connection to {}, while test changes ".format(type(test).__name__, ep2.ip, ep1.ip))
    check_after = ep2.do_long_tcp_client(ep1.ip)
    test.do_scenario_change()
    sleep(check_after)
    exit_code = ep1.do_diff_tcp(ep2, ep1)[0]
    test.assertEqual(exit_code, 0)

    test.do_scenario_reset()


def do_iperf3_test(test, ep1, ep2, args=''):
    logger.info("Test {}: {} do iperf3 test with args '{}' {}".format(
        type(test).__name__, "="*10, args, "="*10))
    ep2.do_iperf3_server()

    logger.info("Test {}: {} can run perf test against server {}".format(
        type(test).__name__, ep1.ip, ep2.ip))
    exit_code = ep1.do_iperf3_client(ep2.ip, args)
    logger.info("{}".format(exit_code).replace('\\n', '\n'))
    test.assertEqual(exit_code[0], 0)

    return exit_code[1]


def do_iperf_common_tests(test, ep1, ep2):
    do_tcp_perf_test(ep1, ep2)
    do_udp_perf_test(ep1, ep2)
    do_tcp_host_perf_test(ep1, ep2)
    do_udp_host_perf_test(ep1, ep2)


def do_validate_delete_test(test, droplets):
    """
    Validates deletes RPC calls are correctly made after an update.
    * Condition #1: All update calls have a corresponding delete.
    * Condition #2: All delete calls happen AFTER their corresponding update call is made.
    * Condition #3: All corresponding get RPC calls return an error after delete
    """
    exit_code = 0
    for d in droplets:
        for update in d.rpc_updates:
            if update not in d.rpc_deletes.keys():
                exit_code = 1
                logger.error(
                    "[{}]: No corresponding delete call was made for the update. {}".format(d.id, update))
                test.assertEqual(exit_code, 0)
            if d.rpc_updates[update] > d.rpc_deletes[update]:
                exit_code = 1
                logger.error(
                    "[{}]: The following update was made after delete was called. {}".format(d.id, update))
                test.assertEqual(exit_code, 0)
            if do_run_get_rpc_test(test, d, update) == 0:
                exit_code = 1
                logger.error(
                    "[{}]: Get RPC returned a valid object after delete. {}".format(d.id, update))
                test.assertEqual(exit_code, 0)
    test.assertEqual(exit_code, 0)


def do_run_get_rpc_test(test, droplet, call):
    """
    Helper function for verifying delete RPC was successful
    """
    if call[0] == "ep " + droplet.phy_itf or call[0] == "ep_substrate " + droplet.phy_itf:
        log_string = "[DROPLET {}]: Expecting failure for RPC call.".format(
            droplet.id)
        cmd = f'''{droplet.trn_cli_get_ep} \'{call[1]}\''''
        return droplet.exec_cli_rpc(log_string, cmd, True)[0]
    elif call[0] == "net " + droplet.phy_itf:
        log_string = "[DROPLET {}]: Expecting failure for RPC call.".format(
            droplet.id)
        cmd = f'''{droplet.trn_cli_get_net} \'{call[1]}\''''
        return droplet.exec_cli_rpc(log_string, cmd, True)[0]
    elif call[0] == "vpc " + droplet.phy_itf:
        log_string = "[DROPLET {}]: Expecting failure for RPC call.".format(
            droplet.id)
        cmd = f'''{droplet.trn_cli_get_vpc} \'{call[1]}\''''
        return droplet.exec_cli_rpc(log_string, cmd, True)[0]
    elif call[0] == "load":  # We assume agent was loaded and unloaded correctly
        return 1
    else:
        logger.error(
            "[{}]: Unidentified rpc call: {}@{}".format(droplet.id, call[0], call[1]))
        return 0


def do_check_failed_rpcs(test, droplets):
    """
    Checks to see if any RPCs ran on the given list of droplets returned an error.
    """
    exit_code = 0
    logger.info(
        "{} Checking for unexpected failed RPC calls {}".format('='*20, '='*20))
    for d in droplets:
        if len(d.rpc_failures.keys()) > 0:
            exit_code = 1
            for cmd in d.rpc_failures.keys():
                logger.error("[DROPLET {}]: Unexpected failed command ran: {} at {}".format(
                    d.id, d.rpc_failures[cmd], cmd))
            print()
    if exit_code == 0:
        logger.info(
            "{} No failed RPC calls found! {}".format('='*20, '='*20))
    else:
        logger.error(
            "{} Found failed RPC calls! {}".format('='*20, '='*20))
    test.assertEqual(exit_code, 0)


def do_cleanup(test, droplets):
    '''
    Droplets need to be cleaned up in test teardown when doing multiprocessing for
    endpoint creation. Destructor for droplet class will need to be removed.
    '''
    for d in droplets:
        d.delete_self()
