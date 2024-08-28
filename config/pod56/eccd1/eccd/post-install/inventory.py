#!/usr/bin/env python3

"""inventory.py:
@Author: Wallance Hou
@Date: 04/19/2022

CCD custom dynamic inventory script for Ansible, in Python3. Supported CaaS: CNIS, NFVI
Example:
# copy the script to ansible specified inventory directory on CCD director(NFVI) or master(CNIS) node
## Perform the following command to display CCD inventory
    $ python inventory.py --list
OR
    $ ansible-inventory --list
"""

import os
import sys
import argparse
from subprocess import check_output
import re
import shutil
import configparser

try:
    import json
except ImportError:
    import simplejson as json


def _get_ccd_role_data(role, label_key='node-pool'):
    check_label_cmd1 = "kubectl get node -l type=standard 2>/dev/null"
    check_label_cmd2 = "kubectl get node -l type=high-throughput 2>/dev/null"
    if check_output(check_label_cmd1, shell=True) and check_output(check_label_cmd2, shell=True):
        label_key= 'type'
    kube_cmd = "kubectl get node -owide -l node-role.kubernetes.io/%s " \
               "-o=jsonpath='{range .items[*]}{.status.addresses[1].address}" \
               "{\":\"}{.metadata.labels.%s}{\":\"}{.status.addresses[].address}{\"\\n\"}{end}'" % (role, label_key)
    return check_output(kube_cmd, shell=True).decode().splitlines()


def gen_ccd_nodes():
    config = configparser.ConfigParser()
    ibd_inventory = '/mnt/config/inventory/ibd_inventory_file.ini'
    directors = []
    workers = []
    outputs = _get_ccd_role_data('control-plane')
    masters = [(i.split(':')[0], i.split(':')[2]) for i in outputs]
    if os.path.isfile(ibd_inventory):
        with open(ibd_inventory) as f:
            config.read_file(f)
        directors = [(f"director-{index}", ip) for index,ip in enumerate(config['director'].values())]
        for worker in _get_ccd_role_data('worker'):
            name, pool_type, ip = worker.split(':')
            if 'standard' in pool_type:
                pool_type = 'std'
            if 'high-throughput' in pool_type:
                pool_type = 'ht'
            workers.append((pool_type, name, ip))
    else:
        outputs = _get_ccd_role_data('control-plane')
        for worker in  _get_ccd_role_data('worker'):
            name, pool, ip = worker.split(':')
            workers.append((pool, name, ip))
        for worker in  _get_ccd_role_data('worker', label_key='node-pool'):
            name, pool, ip = worker.split(':')
            workers.append((pool, name, ip))
    return directors, masters, workers



class CCDInventory(object):

    def __init__(self):
        self.inventory = {}
        self.args_parser()

        # Called with `--list`.
        if self.args.list:
            self.inventory = self.ccd_inventory()
        # Called with `--host [hostname]`.
        elif self.args.host:
            # Not implemented, since we return _meta info `--list`.
            self.inventory = self.empty_inventory()
        # If no groups or vars are present, return an empty inventory.
        else:
            self.inventory = self.empty_inventory()

        print(json.dumps(self.inventory))

    def gen_hostvars(self, nodes, node_type=None):
        hostvars = {}
        if node_type == 'worker':
            hostvars = {name:{'ansible_host':ip} for _, name,ip in nodes}
        else:
            hostvars = {name:{'ansible_host':ip} for name,ip in nodes}
        return hostvars

    def gen_invhosts(self, nodes, node_type):
        common_vars = {'ansible_python_interpreter': '/usr/bin/python3'}
        invhosts = {node_type: {'vars': common_vars}}
        if node_type == 'worker':
            for worker_type, name, _ in nodes:
                invhosts[node_type].setdefault('hosts', []).append(name)
                # worker type:
                # for nfvi, there are std, ht worker
                # for cnis, there are only pool1, pool2, poolN
                invhosts.setdefault(worker_type, {'vars': common_vars})
                invhosts[worker_type].setdefault('hosts', []).append(name)
        else:
            invhosts[node_type]['hosts'] = [name for name, _ in nodes]
        return invhosts

    def ccd_inventory(self):
        hostvars = {}
        inventory = {
            '_meta': {
                'hostvars': hostvars
            },
        }
        directors, masters, workers = gen_ccd_nodes()
        hostvars.update(self.gen_hostvars(directors))
        hostvars.update(self.gen_hostvars(masters))
        hostvars.update(self.gen_hostvars(workers, node_type='worker'))
        inventory.update(self.gen_invhosts(directors, 'director'))
        inventory.update(self.gen_invhosts(masters, 'master'))
        inventory.update(self.gen_invhosts(workers, 'worker'))

        return inventory
    # return an empty inventory
    def empty_inventory(self):
        return {'_meta': {'hostvars': {}}}

    # read user input
    def args_parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--list', action = 'store_true')
        parser.add_argument('--host', action = 'store')
        self.args = parser.parse_args()


if __name__ == '__main__':
    CCDInventory()
