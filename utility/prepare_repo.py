#!/usr/bin/env python
import os
import sys
from subprocess import check_call
from os.path import dirname, join, abspath

sys.path.append(dirname(dirname(abspath(__file__))))
from common.consts import (
    TEMPLATE_REPO,
    TEMPLATE_REPO_DIR
)


def download_repo(repo_dir, repo_dict):
    giturl = join('https://' + os.getlogin() + '@gerritmirror-direct.sero.gic.ericsson.se', repo_dict['projectName'])
    gitcmd = ['git', 'clone', '--branch', repo_dict['branch'], giturl, repo_dir]
    curr_dir = os.getcwd()
    check_call(gitcmd)
    if repo_dict.get('commitId'):
        os.chdir(repo_dir)
        check_call(['git', 'reset', '--hard', repo_dict['commitId']])
        os.chdir(curr_dir)

if __name__ == '__main__':
    download_repo(TEMPLATE_REPO_DIR, TEMPLATE_REPO)
