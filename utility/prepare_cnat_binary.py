#!/usr/bin/env python
import os
import sys
import requests
import re
import shutil
import tarfile
from os.path import dirname, abspath, join, isfile
sys.path.append(dirname(dirname(abspath(__file__))))

from common.consts import (
    TEMP_DIR,
    JFROG_ART_API_VALUE,
    BASE_ARTIFACT_URL
)


def get_latest_file_name(response):
    print(f'response: {response}')
    file_list = re.findall(r'[>](.*?)[<]', response.text)
    version_files = [file for file in file_list if re.match(r'cnat-\d+\.\d+\.\d+-.*\.tar\.gz$', file)]
    version_files.sort(key=lambda s: list(map(int, s.split('-')[1].split('.'))))
    return version_files[-1]

def get_cnat_latest_pkg():
    print('Start getting CNAT latest package.')
    response = requests.get(BASE_ARTIFACT_URL, headers={'X-JFrog-Art-Api': JFROG_ART_API_VALUE})
    latest_file = get_latest_file_name(response)

    pkg_output_path = os.path.join(TEMP_DIR, latest_file)
    if os.path.isfile(pkg_output_path):
        print(f"CNAT latest package '{pkg_output_path}' already exists, skip downloading it from artifactory.")
        return pkg_output_path

    # Use wget command to download cnat package
    wget_command = f'wget --header=\'X-JFrog-Art-Api: {JFROG_ART_API_VALUE}\' -P {TEMP_DIR} {BASE_ARTIFACT_URL + latest_file}'

    if os.system(wget_command) != 0:
        sys.exit(f"Failed to run wget command '{wget_command}'.")
    print(f"Download CNAT latest package '{pkg_output_path}' by running wget command '{wget_command}' successfully.")
    return pkg_output_path

def extract_cnat_binary(pkg_path):
    print(f"Start to extract CNAT binary from '{pkg_path}'.")

    if not os.path.isfile(pkg_path):
        sys.exit(f"Failed to extract cnat binary because no file '{pkg_path}'.")

    with tarfile.open(pkg_path, 'r:gz') as tar:
        for member in tar.getmembers():
            if member.name.endswith('cnat'):
                tar.extract(member, path=os.path.dirname(pkg_path))
                cnat_path = os.path.join(os.path.dirname(pkg_path), member.name)
                shutil.move(cnat_path, TEMP_DIR)
                print(f"Extract CNAT binary to '{cnat_path}' successfully.")


if __name__ == '__main__':
    cnat_pkg_path = get_cnat_latest_pkg()
    extract_cnat_binary(cnat_pkg_path)