import subprocess
import sys
import time
import re
from os.path import join, dirname, abspath
from subprocess import check_call, getoutput
sys.path.append(dirname(dirname(abspath(__file__))))
from common.consts import (
    TEMP_DIR,
    CI_CNAT_ENV_DIR,
    LAB
)


def get_cnat_version():
    cnat_bin = join(TEMP_DIR, 'cnat')
    cmd = f'{cnat_bin} --version | tail -1'
    version = getoutput(cmd)
    return version


def get_package_vnfdid(cnf_name, cnf_version):
    cnat_bin = join(TEMP_DIR, 'cnat')
    cmd = (f'{cnat_bin} -e {LAB} | grep "{cnf_name}" | grep "{cnf_version}" | grep "ONBOARDED" | '
           'awk \'{print $8}\' | tail -1')
    print(f"Executing command: {cmd}")
    output = subprocess.check_output(cmd, shell=True, encoding='utf-8')
    vnfdid = output.strip()
    print(f"Vnfdid: {vnfdid}")
    return vnfdid


def run_cnat_cmd(args, log_path, function_name, running_env_path, is_pre=False):
    cnat_bin = join(TEMP_DIR, 'cnat')
    screen_log_name = function_name + ('_pre' if is_pre else '') + '_cnat_screen_' + time.strftime('%Y%m%d%H%M%S') + '.log'
    screen_log_path = join(log_path, screen_log_name)
    cmd = f'{cnat_bin} {args} --env-file {CI_CNAT_ENV_DIR} --log-dir {log_path} > {screen_log_path}'
    print(f"Running CNAT cmd, could check the state in {screen_log_path}")
    check_call(cmd, shell=True, cwd=running_env_path)
    with open(screen_log_path, 'r') as f:
        debug_log_path = re.search(r'[^\s]*(\.log$)', f.readlines()[-1])
        if debug_log_path == None:
            debug_log_path = ''
        else:
            debug_log_path = debug_log_path.group()
    return screen_log_path, debug_log_path
