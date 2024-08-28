import os
import time


"""
Save the logs with function name like "<function name>_<log type>.log"
The CNF log and ECCD log file would save as:
  <cmd1>:
  <output1>

  <cmd2>:
  <output2>
"""
def collect_logs(log_list, function_name, timestamp, log_path):
    log_name = f'{function_name}_{timestamp}.log'
    spec_log_path = os.path.join(log_path, log_name)
    content = ''
    for rec in log_list:
        cmd = rec['cmd']
        output = rec['output']
        starting_time = rec['starting_time']
        source = rec['source']
        content += f'{starting_time}[{source}]: {cmd}\n\n'
        if output:
            if source != 'cnat':
                content += f'{output}\n\n'
            else:
                with open(output[0], 'r') as f:
                    content += (f.read())
                os.remove(output[0])
        if rec != log_list[-1]:
            content += '\n\n-----------------------------------------------------------------------------------------------------------------\n\n\n'
    with open(spec_log_path, 'w') as f:
        f.write(content)
