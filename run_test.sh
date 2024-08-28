#!/bin/bash

script_path=$(cd $(dirname $0); pwd)
# The TEMP_DIR is also defined in common/consts.py
TEMP_DIR=test_resource
TEMPLATE_REPO_DIR=ts-config
# CNAT Binary file and repos will be saved here.
test_path=$script_path/$TEMP_DIR
mkdir $test_path

./utility/prepare_cnat_binary.py
./utility/prepare_repo.py
template_repo_path=$script_path/$TEMPLATE_REPO_DIR

pytest ./case -vs
rm -rf $test_path
rm -rf $template_repo_path