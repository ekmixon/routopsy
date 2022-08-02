import docker
import protocols.vrrp as vrrp
from state import user_var

from state import vulnerable_eigrp_packets
from state import vulnerable_hsrp_packets
from state import vulnerable_ospf_packets
from state import vulnerable_rip_packets
from state import vulnerable_vrrp_packets

import time

global client
client = docker.from_env()

import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)


def stop_and_remove_containers():
    for container in client.containers.list(all=True):
        if 'routopsy-frr' in container.name:
            container.stop()
            container.remove()

        if 'routopsy-peer-frr' in container.name:
            container.stop()
            container.remove() 

        if vrrp.docker_container_name in container.name:
            container.stop()
            container.remove()

def build_and_run_container():

    docker_name = 'routopsy-frr'

    ospf_vulnerable = False
    eigrp_vulnerable = False
    rip_vulnerable = False

    for _ in vulnerable_eigrp_packets:
        eigrp_vulnerable = True

    for _ in vulnerable_ospf_packets:
        ospf_vulnerable = True

    for _ in vulnerable_rip_packets:
        rip_vulnerable = True

    volumes = {
        f'{user_var.path}/daemons': {'bind': '/etc/frr/daemons', 'mode': 'rw'}
    }


    if ospf_vulnerable and 'ospf' in user_var.protocol:
        ospf_volume = {
            f'{user_var.path}/{user_var.target}_ospfd.conf': {
                'bind': '/etc/frr/ospfd.conf',
                'mode': 'rw',
            }
        }

        volumes |= ospf_volume

    if eigrp_vulnerable and 'eigrp' in user_var.protocol:
        eigrp_volume = {
            f'{user_var.path}/{user_var.target}_eigrpd.conf': {
                'bind': '/etc/frr/eigrpd.conf',
                'mode': 'rw',
            }
        }

        volumes |= eigrp_volume

    if rip_vulnerable and 'rip' in user_var.protocol:
        rip_volume = {
            f'{user_var.path}/{user_var.target}_ripd.conf': {
                'bind': '/etc/frr/ripd.conf',
                'mode': 'rw',
            }
        }

        volumes |= rip_volume

    if user_var.inject or user_var.redirect:
        volumes[f'{user_var.path}/{user_var.target}_staticd.conf'] = {
            'bind': '/etc/frr/staticd.conf',
            'mode': 'rw',
        }

        volumes[f'{user_var.path}/{user_var.target}_pbrd.conf'] = {
            'bind': '/etc/frr/pbrd.conf',
            'mode': 'rw',
        }


    if user_var.inject_local or user_var.redirect_local:
        volumes[f'{user_var.path}/{user_var.target}_zebra.conf'] = {
            'bind': '/etc/frr/zebra.conf',
            'mode': 'rw',
        }


    container = client.containers.run('frrouting/frr', name=docker_name, cap_add=\
    ['NET_ADMIN', 'NET_RAW', 'SYS_ADMIN'], detach=True, network='host',\
                          volumes=volumes)

    if 'running' in client.containers.get(docker_name).status: 
        print(
            Fore.CYAN
            + Style.BRIGHT
            + f'[+]Created and running container {container.name}'
        )

    else:
        print(
            f'Created container {container.name}, but something happened and it wont run.'
        )

        print(f'Logs from Docker:\n{client.containers.get(docker_name).logs}')

def build_and_run_peer_container():

    docker_name = 'routopsy-peer-frr'

    volumes = {
        f'{user_var.path}/daemons': {'bind': '/etc/frr/daemons', 'mode': 'rw'}
    }


    volume = None

    if 'ospf' in user_var.protocol:
        volume = {
            f'{user_var.path}/{user_var.target}_peer_ospfd.conf': {
                'bind': '/etc/frr/ospfd.conf',
                'mode': 'rw',
            }
        }

        volumes |= volume

    if 'rip' in user_var.protocol:
        volume = {
            f'{user_var.path}/{user_var.target}_peer_ripd.conf': {
                'bind': '/etc/frr/ripd.conf',
                'mode': 'rw',
            }
        }

        volumes |= volume

    if user_var.inject_local or user_var.redirect_local:
        volumes[f'{user_var.path}/{user_var.target}_peer_staticd.conf'] = {
            'bind': '/etc/frr/staticd.conf',
            'mode': 'rw',
        }


    container = client.containers.run('frrouting/frr', name=docker_name, cap_add=\
    ['NET_ADMIN', 'NET_RAW', 'SYS_ADMIN'], detach=True, volumes=volumes)

    if 'running' in client.containers.get(docker_name).status:
        print(
            Fore.CYAN
            + Style.BRIGHT
            + f'[+]Created and running container {container.name}'
        )

    else:
        print(
            f'Created container {container.name}, but something happened and it wont run.'
        )

        print(f'Logs from Docker:\n{client.containers.get(docker_name).logs}')


def build_and_run_container_vrrp():
    docker_name = vrrp.docker_container_name

    vrrp_vulnerable = True

    for _ in vulnerable_vrrp_packets:
        vrrp_vulnerable = True

    if vrrp_vulnerable:
        volume = {
            f'{user_var.path}/{user_var.target}_keepalived.conf': {
                'bind': '/usr/local/etc/keepalived/keepalived.conf',
                'mode': 'rw',
            }
        }

        container = client.containers.run(vrrp.docker_image, name=vrrp.docker_container_name, cap_add=vrrp.docker_capabilities, detach=True, network='host',volumes=volume)

        if 'running' in client.containers.get(vrrp.docker_container_name).status: 
            print(
                Fore.CYAN
                + Style.BRIGHT
                + f'[+]Created and running container {container.name}'
            )

        else:
            print(
                f'Created container {container.name}, but something happened and it wont run.'
            )

            print(
                f'Logs from Docker:\n{client.containers.get(vrrp.docker_container_name).logs}'
            )


def run_ettercap_container_once():

    docker_name = 'etter'
    volumes = {'/tmp/': {'bind': '/stuff/', 'mode': 'rw'}}
    # volumes = {user_var.path: {'bind': '/stuff/', 'mode': 'rw'}}

    container = client.containers.run('mrecco/ettercap', "-Tqr /stuff/ospf_auth.pcap",
                                      name=docker_name, cap_add=['NET_ADMIN', 'SYS_ADMIN'], detach=True,
                                      volumes=volumes)

    time.sleep(1)
    output = container.logs()
    with open("/tmp/etter_hashes.txt", "w") as outfile:
        # outfile = open('{}/etter_hashes.txt'.format(user_var.path), 'w')

        for line in output.strip().decode().splitlines():
            outfile.write(line)
            outfile.write('\n')

    container.stop()
    container.remove()



