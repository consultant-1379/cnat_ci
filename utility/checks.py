import sys
import re
from os.path import dirname, abspath
sys.path.append(dirname(dirname(abspath(__file__))))


def check_log(log_list, log_type, check_points):
    '''
    : param log_list: List. It's the same as self.log in test_class.py. pod56 is just and example, should be set in const.py

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

    : param log_type: String. From cnat, log_type is 'cnat_screen' or 'cnat_debug'; From ccd, log_type is like 'pod56_eccd1', 'pod56_pcc1' etc.

    : param check_points: Dict. Dict of key-value map for cmd and the exist or absent checkpoint(s) for the cmd.
        for cnat, like:

        {
            "-e pod56": {
                "exist": ['CCRC.*ONBOARDED.*ENABLED', 'CCRC.*INSTANTIATED.*COMPLETED'],
                "absent": ['ccrc1']
            }
        }

        for ccd, like:
        {
            "kubectl get ns -A": {
                "exist": ['ccsm', 'ccrc'],
                "absent": ['ccdm']
            },
            "kubectl get pods -n ccsm": {
                "exist": ["Running"]
            }
        }

    '''
    for cmd, check_point_dict in list(check_points.items())[::-1]:
        for item in log_list[::-1]:
            if cmd == item['cmd']:
                _check_log_content(log_type, item, check_point_dict)
                break

def _check_log_content(log_type, log_dict, check_point_dict):
    '''
    : param log_dict: Each item from log_list.
    '''
    source = log_dict['source']
    if source == 'cnat':
        log_path = log_dict['output'][0] if log_type == 'cnat_screen' else log_dict['output'][1]
        with open(log_path, 'r') as f:
            log_content = f.read()
    else:
        log_content = log_dict['output']

    for state, check_point_list in check_point_dict.items():
        err = []
        for check_point in check_point_list:
            if (state == 'exist' and not re.search(check_point, log_content)) or (state == 'absent' and re.search(check_point, log_content)):
                err.append(check_point)
        if err:
            if state == 'exist':
                raise Exception(f"Expected check point: {check_point_list}\nNot found in output of '{log_dict['cmd']}' from {log_dict['source']}")
            elif state == 'absent':
                raise Exception(f"Unexpected check point: {err}\nFound in output of '{log_dict['cmd']}' from {log_dict['source']}")