from netaddr import IPAddress
from netaddr import IPNetwork

import os
from shutil import copyfile

from state import ospf_packet
from state import eigrp_packet
from state import user_var

import netifaces

import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)

def tempGetIP():
    dict = netifaces.ifaddresses(user_var.interface)
    for x in dict.get(2):
        y = x.get('addr')
    return f'{y}/32'


def build_ospf_config():

    #tempGetIP()
    #print("debug")

    cidr = IPAddress(ospf_packet.mask).netmask_bits()
    ip_range = IPNetwork(f'{ospf_packet.source_ip}/{str(cidr)}')

    if not os.path.exists(user_var.path):
        print(Fore.YELLOW + Style.BRIGHT + "[-]Provided path does not exist.")
        try:
            os.mkdir(user_var.path)
        except OSError:
            print(
                f"Creation of the path {user_var.path} failed. Could not create configuration files."
            )

            return

    copyfile('daemons', f'{user_var.path}/daemons')

    with open(f'{user_var.path}/ospfd.conf', 'w') as ospfd_config:
        ospfd_config.write('!\n')
        #ospfd_config.write('interface {}\n'.format(user_var.interface))
        #ospfd_config.write(' ip ospf hello-interval {}\n'.format(ospf_packet.hello_interval))
        #ospfd_config.write(' ip ospf dead-interval {}\n'.format(ospf_packet.dead_interval))
        #ospfd_config.write('!\n')
        ospfd_config.write('router ospf\n')
            #ospfd_config.write(' network ' + str(ip_range.network) + '/' + str(cidr) + ' area ' + ospf_packet.area_id + '\n')
        ospfd_config.write(f' network {tempGetIP()} area {ospf_packet.area_id}' + '\n')
        ospfd_config.write('!\n')

        if user_var.inject:
            for ip in user_var.ipaddress:
                ospfd_config.write(f' network {ip}/32' + ' area ' + ospf_packet.area_id + '\n')
            with open(f'{user_var.path}/zebra.conf', 'w') as interface_config:
                interface_config.write('!\n')
                interface_config.write('interface lo\n')
                for ip in user_var.ipaddress:
                    interface_config.write(f' ip address {ip}/32\n')

def build_eigrp_config():

    if not os.path.exists(user_var.path):
        print(Fore.YELLOW + Style.BRIGHT + "[-]Provided path does not exist.")
        try:
            os.mkdir(user_var.path)
        except OSError:
            print(
                f"Creation of the path {user_var.path} failed. Could not create configuration files."
            )

            return

    copyfile('daemons', f'{user_var.path}/daemons')

    with open(f'{user_var.path}/eigrpd.conf', 'w') as eigrpd_config:
        eigrpd_config.write('!\n')
        eigrpd_config.write(f'router eigrp {str(eigrp_packet.asn)}' + '\n')
            #eigrpd_config.write(' network 0.0.0.0/0\n')
        eigrpd_config.write(f' network {tempGetIP()}' + '\n')
        eigrpd_config.write('!\n')

        if user_var.inject:
            for ip in user_var.ipaddress:
                eigrpd_config.write(f' network {ip}/32' + '\n')
            with open(f'{user_var.path}/zebra.conf', 'w') as interface_config:
                interface_config.write('!\n')
                interface_config.write('interface lo\n')
                for ip in user_var.ipaddress:
                    interface_config.write(f' ip address {ip}/32\n')

def build_rip_config():

    if not os.path.exists(user_var.path):
        print(Fore.YELLOW + Style.BRIGHT + "[-]Provided path does not exist.")
        try:
            os.mkdir(user_var.path)
        except OSError:
            print(
                f"Creation of the path {user_var.path} failed. Could not create configuration files."
            )

            return

    copyfile('daemons', f'{user_var.path}/daemons')

    with open(f'{user_var.path}/ripd.conf', 'w') as ripd_config:
        ripd_config.write('!\n')
        ripd_config.write('router rip\n')
            #ripd_config.write(' network 0.0.0.0/0\n')
        ripd_config.write(f' network {tempGetIP()}' + '\n')
        ripd_config.write('!\n')

        if user_var.inject:
            for ip in user_var.ipaddress:
                ripd_config.write(f' network {ip}/32' + '\n')
            with open(f'{user_var.path}/zebra.conf', 'w') as interface_config:
                interface_config.write('!\n')
                interface_config.write('interface lo\n')
                for ip in user_var.ipaddress:
                    interface_config.write(f' ip address {ip}/32\n')