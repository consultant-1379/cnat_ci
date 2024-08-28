import sys
import re
import os
import yaml
import time
from os.path import join, exists, dirname, abspath, isfile
from shutil import copy
from subprocess import check_call

sys.path.append(dirname(dirname(abspath(__file__))))
from utility import run_cnat, collect_log, checks
from common import ssh
from common.consts import (
    EAGLES_CNAT_ENV_PATH,
    CI_CNAT_ENV_DIR,
    CI_LOG_PATH,
    REPO_PATH
)


def get_batch_cnfs(batch_file):
    with open(batch_file, 'r') as file:
        content = yaml.safe_load(file.read())
    cnfs = []
    for line in content['vnf-info-files']:
        line = line.split('/')
        if line[-1] == 'vnf.yaml':
            cnfs.append(line[-2])
    return cnfs


def prepare_env():
    if isfile(EAGLES_CNAT_ENV_PATH):
        copy(EAGLES_CNAT_ENV_PATH, CI_CNAT_ENV_DIR)
    else:
        raise RuntimeError(f"cnat env file '{EAGLES_CNAT_ENV_PATH}' doesn't exist")


def prepare_log_dir(log_path):
    if not exists(log_path):
        oldmask = os.umask(0)
        os.makedirs(log_path)
        os.umask(oldmask)


def remove_env():
    if isfile(CI_CNAT_ENV_DIR):
        os.remove(CI_CNAT_ENV_DIR)


def chmod_log_files(log_path):
    cmd = "chmod -R 777 " + log_path
    check_call(cmd, shell=True)


"""
About case/suite sequence:
    1. When without any setting, it would run file by file.
       In one file, it would run classes and cases inside class
       from up to down one by one.
    2. When using "@pytest.mark.run(order=)" for class or case,
       it would run all the cases with order first.
       No matter it's in which file and which class,
       the order would be run from small to large in highliest priority.
    3. When using "@pytest.mark.dependency()" for cases,
       it would not change the sequence of case run,
       but would skip the case if the dependence is not passed or not run.
"""


class BasicTest:
    log_path = ''

    @classmethod
    def setup_class(cls):
        cnat_version = run_cnat.get_cnat_version()
        suite_name = re.match(r'Test(.*)Class', cls.__name__).group(1)
        cls.log_path = join(CI_LOG_PATH, "release_" + cnat_version, suite_name)
        prepare_log_dir(cls.log_path)
        prepare_env()

    @classmethod
    def teardown_class(cls):
        chmod_log_files(cls.log_path)
        remove_env()

    def setup_method(self, method):
        """
        log: collect all the logs, for checking and synthesizing. pod56 is just and example, should be set in const.py
        log:
        [
            {
                'cmd': <cmd1>
                'output': ['./cnat_screen.log', './cnat_debug.log'],
                'starting_time': <time1>,
                'source': 'cnat'
            },
            {
                'cmd': <cmd2>
                'output': <cmd output>,
                'starting_time': <time2>,
                'source': 'pod56-eccd1'
            }
        ]
        """
        self.function_name = method.__name__
        self.timestamp = time.strftime('%Y%m%d%H%M%S')
        self.log = []

    def teardown_method(self):
        collect_log.collect_logs(self.log, self.function_name, self.timestamp, self.log_path)

    def update_env(self, updated_dict):
        """
        The check point should follow the structure of env file and should be full block, like:
        {
            "export":{
                "enabled": "true"
                "archive": "false"
                "path": self.log_path
            }
        }
        """
        with open(CI_CNAT_ENV_DIR, 'r') as f:
            content = yaml.safe_load(f.read())
        content.update(updated_dict)
        with open(CI_CNAT_ENV_DIR, 'w') as f:
            f.write(yaml.dump(content))

    def delete_exist_cfggen(self, path):
        os.chdir(path)
        with open('cfggen.yaml', 'r') as f:
            content = yaml.safe_load(f.read())
            for dict in content['files']:
                if isfile(dict['target']):
                    os.remove(dict['target'])

    def check_logs(self, log_type, check_points, **kwargs):
        """
        : param log_type: it could be 'cnat_screen', 'cnat_debug' or the ssh server name like 'pod56-eccd1'
        : param check_point: the check points for the log in dict format, the check points could be writen in regular expression,
            for every cmd, it only could have 2 keys:
            "exist" for expecting the checkpoint should exist
            "absent" for expecting the checkpoint should not exist:
            {
                "cmd1": {
                    "exist": ["check point 1.1", "check point 1.2"],
                    "absent": ["check point 1.3", "check point 1.4"],
                "cmd2": {
                    "exist": ["check point 2.1"]}
                }
            }
        """
        if log_type not in ['cnat_screen', 'cnat_debug']:
            self.run_remote_cmd(log_type, check_points)
        spec_log_path = join(self.log_path, f'{self.function_name}_{self.timestamp}.log')
        try:
            checks.check_log(self.log, log_type, check_points)
        except Exception:
            raise Exception(f"See log for details: {spec_log_path}")

    def run_cnat_cmd(self, cnat_args, env_path=REPO_PATH, **kwargs):
        """
        : param cnat_args: cnat cmd
        : param env_path: the absolute path to run cmd
        """
        starting_time = time.strftime("%Y-%m-%d %H:%M:%S")
        screen_log, debug_log = run_cnat.run_cnat_cmd(cnat_args, self.log_path, self.function_name, env_path)
        self.log.append(
            {
                'cmd': cnat_args,
                'output': [screen_log, debug_log],
                'starting_time': starting_time,
                'source': 'cnat'
            }
        )

    def run_remote_cmd(self, server_name, check_point, **kwargs):
        cmd_list = list(check_point.keys())
        output = ssh.ssh_run_cmd(server_name, cmd_list)
        self.log += output

    def get_package_vnfd(self, cnf_name, cnf_version):
        return run_cnat.get_package_vnfdid(cnf_name, cnf_version)
