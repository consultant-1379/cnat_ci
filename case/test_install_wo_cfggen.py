import pytest
import sys
from os.path import dirname, abspath, join
sys.path.append(dirname(dirname(abspath(__file__))))
from utility import test_class
from utility.test_class import BasicTest
from common.consts import (
    REPO_PATH,
    BATCH_FILE,
    LAB,
    CLUSTER,
    INSTANCE,
    KUBECTL,
    CNF1_NAME,
    CNF2_NAME,
    CNF1_VERSION,
    CNF2_VERSION
)


@pytest.fixture()
def args():
    batch_cnfs = test_class.get_batch_cnfs(BATCH_FILE)
    return {'single_cnf': "ccrc", 'batch_cnfs': batch_cnfs}


class TestWithoutCfggenClass(BasicTest):

    # @pytest.mark.skip(reason="no")
    def test_batch_install(self, args):
        batch_cnfs = args['batch_cnfs']
        # step1: update the env file
        env = {
            "export": {
                "enabled": True,
                "archive": False,
                "path": self.log_path
            }
        }
        self.update_env(env)
        # step2: cleanup evnfm by uninstalling all CNFs
        cnf_name = [f'{INSTANCE}-{cnf}1' for cnf in batch_cnfs]
        batch_uninstall = f"-e {LAB} --bu {' '.join(cnf_name)} --cleanup -y -b 2"
        self.run_cnat_cmd(batch_uninstall)
        # step3: check the CNF not instantiated
        show_env = f'-e {LAB}'
        self.run_cnat_cmd(show_env)
        check_point = {
            show_env: {
                "absent": [f'{INSTANCE}-{cnf}1.*INSTANTIATED.*COMPLETED' for cnf in batch_cnfs]
            }
        }
        self.check_logs('cnat_screen', check_point)
        # step4: delete all resources in the target namespace, if no resources exist, also fine
        delete_all_resources = {
            f"{KUBECTL} delete all --all -n {cnf}": {} for cnf in batch_cnfs
        }
        self.check_logs(f'{LAB}-{INSTANCE}', delete_all_resources)
        # step5: remove the namespace, if the ns is not exist, also fine
        remove_ns = {
            f"{KUBECTL} delete ns {cnf}": {} for cnf in batch_cnfs
        }
        self.check_logs(f'{LAB}-{INSTANCE}', remove_ns)
        # step6: run the batch install and check the screen log is as expect
        batch_install = f"-e {LAB} --bi {BATCH_FILE} --no-cfggen"
        self.run_cnat_cmd(batch_install)
        cnf_check = [f'{INSTANCE}-{cnf}1 is installed successfully.' for cnf in batch_cnfs]
        check_res = {
            batch_install: {
                "exist": ['No configuration generation. Local configuration files are used for installation'] + cnf_check
            }
        }
        self.check_logs('cnat_screen', check_res)
        # step7: check the CNF is instantiated
        self.run_cnat_cmd(show_env)
        check_point = {
            show_env: {
                "exist": [f'{INSTANCE}-{cnf}1.*INSTANTIATED.*COMPLETED' for cnf in batch_cnfs]
            }
        }
        self.check_logs('cnat_screen', check_point)

    # @pytest.mark.skip(reason="no")
    def test_batch_uninstall(self, args):
        batch_cnfs = args['batch_cnfs']
        # step1: check the CNF exist
        show_env = f'-e {LAB}'
        self.run_cnat_cmd(show_env)
        check_point = {
            show_env: {
                "exist": [f'{INSTANCE}-{cnf}1' for cnf in batch_cnfs]
            }
        }
        self.check_logs('cnat_screen', check_point)
        # step2: run batch uninstall and check the screen log is as expect
        cnf_name = [f'{INSTANCE}-{cnf}1' for cnf in batch_cnfs]
        batch_uninstall = f"-e {LAB} --bu {' '.join(cnf_name)} --cleanup -y"
        self.run_cnat_cmd(batch_uninstall)
        check_point = {
            batch_uninstall: {
                "exist": [f'{INSTANCE}-{cnf}1 is uninstalled successfully.' for cnf in batch_cnfs]
            }
        }
        self.check_logs('cnat_screen', check_point)
        # step3: check the CNF is terminated from evnfm info
        self.run_cnat_cmd(show_env)
        check_res = {
            show_env: {
                "absent": cnf_name
            }
        }
        self.check_logs('cnat_screen', check_res)
        # step4: check the namespace is deleted
        ssh_cmd = {
            f"{KUBECTL} get ns": {
                "absent": batch_cnfs
            }
        }
        self.check_logs(f'{LAB}-{INSTANCE}', ssh_cmd)

    # @pytest.mark.skip(reason="no")
    def test_single_install(self, args):
        cnf = args['single_cnf']
        # step1: update the env file
        env = {
            "export": {
                "enabled": True,
                "archive": False,
                "path": self.log_path
            }
        }
        self.update_env(env)
        # step2: check the CNF not instantiated
        show_env = f'-e {LAB}'
        self.run_cnat_cmd(show_env)
        check_point = {
            show_env: {
                "absent": [f'{INSTANCE}-{cnf}1.*INSTANTIATED.*COMPLETED']
            }
        }
        self.check_logs('cnat_screen', check_point)
        # step3: check no pod in the target namespace
        check_pod = {
            f'{KUBECTL} get pod -n {cnf}': {"absent": ["NAME"]}
        }
        self.check_logs(f'{LAB}-{INSTANCE}', check_pod)
        # step4: remove the namespace, if the ns is not exist, also fine
        remove_ns = {
            f"{KUBECTL} delete ns {cnf}": {}
        }
        self.check_logs(f'{LAB}-{INSTANCE}', remove_ns)
        # step5: run the single install
        single_install = f'-e {LAB} -i -ng'
        self.run_cnat_cmd(single_install, join(REPO_PATH, f'config/{LAB}/{CLUSTER}/{cnf}'))
        # step6: check the screen log is as expect
        check_res = {
            single_install: {
                "exist": ['No configuration generation. Local configuration files are used for installation',
                          f"'{INSTANCE}-{cnf}1' is installed"]
            }
        }
        self.check_logs('cnat_screen', check_res)
        # step7: check the CNF is instantiated
        self.run_cnat_cmd(show_env)
        check_point = {
            show_env: {
                "exist": [f'{INSTANCE}-{cnf}1.*INSTANTIATED.*COMPLETED']
            }
        }
        self.check_logs('cnat_screen', check_point)

    # @pytest.mark.skip(reason="no")
    def test_single_uninstall(self, args):
        cnf = args['single_cnf']
        # step1: check the CNF exist
        show_env = f'-e {LAB}'
        self.run_cnat_cmd(show_env)
        check_point = {
            show_env: {
                "exist": [f'{INSTANCE}-{cnf}1']
            }
        }
        self.check_logs('cnat_screen', check_point)
        # step2: run single uninstall
        single_uninstall = f"-e {LAB} -t {INSTANCE}-{cnf}1 --cleanup -y"
        self.run_cnat_cmd(single_uninstall)
        check_delete = {
            single_uninstall: {
                "exist": [f"'{INSTANCE}-{cnf}1' is uninstalled"]
            }
        }
        self.check_logs('cnat_screen', check_delete)
        # step4: check the CNF is terminated from evnfm info
        self.run_cnat_cmd(show_env)
        check_res = {
            show_env: {
                "absent": [f'{INSTANCE}-{cnf}1']
            }
        }
        self.check_logs('cnat_screen', check_res)
        # step5: check the namespace is deleted
        ssh_cmd = {
            f"{KUBECTL} get ns": {
                "absent": [cnf]
            }
        }
        self.check_logs(f'{LAB}-{INSTANCE}', ssh_cmd)

    def test_cnf1_delete_package_from_evnfm_with_vnfdid(self):
        # step 1: get the vnfdId from evnfm
        vnfdid = self.get_package_vnfd(f"{CNF1_NAME}", f"{CNF1_VERSION}")
        # step 2: delete the package from evnfm
        delete_package = f'-e {LAB} -dp {vnfdid}'
        self.run_cnat_cmd(delete_package)
        check_delete = {
            delete_package: {
                "exist": ["Package was deleted successfully"]
            }
        }
        self.check_logs('cnat_screen', check_delete)

    def test_cnf2_delete_package_from_evnfm_with_vnfdid(self):
        # step 1: get the vnfdId from evnfm
        vnfdid = self.get_package_vnfd(f"{CNF2_NAME}", f"{CNF2_VERSION}")
        # step 2: delete the package from evnfm
        delete_package = f'-e {LAB} -dp {vnfdid}'
        self.run_cnat_cmd(delete_package)
        check_delete = {
            delete_package: {
                "exist": ["Package was deleted successfully"]
            }
        }
        self.check_logs('cnat_screen', check_delete)