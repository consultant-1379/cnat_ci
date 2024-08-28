from os import strerror
import re
import paramiko
import contextlib
import time
import yaml
from .consts import SUT_ADDR, TIMEOUT, SSH_KEY_PATH

def get_access_info(ssh_name):
    with open(SUT_ADDR, 'r') as f:
        content = yaml.safe_load(f.read())
    return {
        'ip': content[ssh_name]['ip'],
        'user': content[ssh_name]['user'],
        'port': content[ssh_name]['port']
    }


def ssh_run_cmd(server_name, cmd_list):
    access_info = get_access_info(server_name)
    private_key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)

    with contextlib.closing(paramiko.SSHClient()) as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            print(f"Connecting to {access_info['ip']}")
            print(f"Username: {access_info['user']}")
            print(f"Port: {access_info['port']}")
            print(f"Key: {SSH_KEY_PATH}")
            print(f"Command: {cmd_list}")
            ssh.connect(access_info['ip'],
                        username=access_info['user'],
                        pkey=private_key,
                        port=access_info['port'])
        except Exception as e:
            raise Exception(f"SSH connection failed: {e}")

        channel = ssh.invoke_shell()
        time.sleep(1)
        output = []
        for cmd in cmd_list:
            starting_time = time.strftime("%Y-%m-%d %H:%M:%S")
            channel.send(cmd+'\n')
            res = ''
            t = 0
            rec = ''
            print(f"{cmd}")
            while t < TIMEOUT*5:
                if channel.recv_ready():
                    rec = channel.recv(1024).decode()
                    time.sleep(0.2)
                    print(rec)
                    res += rec
                elif re.match(f".*{server_name}.*(#|>) ", rec.split('\n')[-1]):
                    break
                else:
                    time.sleep(0.2)
                    t+=1
            output.append(
                {
                    'cmd': cmd,
                    'output': res,
                    'starting_time': starting_time,
                    'source': server_name
                }
            )
    return output
