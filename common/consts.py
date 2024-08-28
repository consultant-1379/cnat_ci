from os.path import dirname, abspath, join

REPO_PATH = dirname(dirname(abspath(__file__)))
TEMP_DIR = join(REPO_PATH, 'test_resource')
JFROG_ART_API_VALUE = 'AKCp5ekTAbE7zTjJR5B2bU7vvxgQ7oE4x7uzxZyZqSNcHUkhqNY6Jkmfj6MPvB58fVUUEZEu7'
BASE_ARTIFACT_URL = 'https://arm.sero.gic.ericsson.se/artifactory/proj-pc-cnat-release-generic-local/releases/'
EAGLES_CNAT_ENV_PATH = '/lab/pccc_utils/scripts/Team_Eagles_CNAT_env.yaml'
CI_CNAT_ENV_DIR = join(REPO_PATH, 'cnat_env_test.yaml')
CI_LOG_PATH = '/proj/pdupc-mano/XPT/Team_Eagles/cnat/cnat_ci/'
TEMPLATE_REPO_DIR = join(REPO_PATH, 'ts-config')
TEMPLATE_REPO ={
    "projectName": "5gc_config/ts-config",
    "branch": "master"
}
LAB = 'n182'
CLUSTER = 'eccd2'
INSTANCE = 'vpod2'
SUT_ADDR = f'/lab/pccc_utils/scripts/src/auto_login/node_info/{LAB}-{INSTANCE}.yaml'
TIMEOUT = 120

BATCH_FILE = join(REPO_PATH, 'ci_extra_config/ci-test-batch-install.yaml')
KUBECONFIG = f'/lab/pccc_utils/scripts/kubeconfig/{LAB}-cluster2.config'
KUBECTL = f'kubectl'
# KUBECTL = f'kubectl --kubeconfig {KUBECONFIG}'
SSH_KEY_PATH = f'/lab/pccc_utils/scripts/ssh_key2/{LAB}-{INSTANCE}_key'
CSAR_ARTIFACT_URL = 'https://arm.sero.gic.ericsson.se/artifactory/proj-pc-cloud-drop-generic-local/'
CNF1_CSAR_PATH = join(CSAR_ARTIFACT_URL, 'ccrc/1.14/csar/')
CNF2_CSAR_PATH = join(CSAR_ARTIFACT_URL, 'eric-pc-gateway/R58C/csar/')
CNF1_CSAR_PACKAGE_NAME = 'Ericsson.CCRC.CXP9037716_1_14_4_1.csar'
CNF2_CSAR_PACKAGE_NAME = 'PCG_CXP9041656_1-R58C234.csar'
CNF1_NAME = "CCRC"
CNF2_NAME = "PCG"
CNF1_VERSION = '1.14.4+1'
CNF2_VERSION = 'R58C'
