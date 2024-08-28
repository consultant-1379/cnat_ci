source /lab/pccc_utils/scripts/csdp_python3_venv/bin/activate
REPO_PATH="/home/$USER/git"
CNAT_CI_REPO_PATH="${REPO_PATH}/cnat_ci2"

python3 $REPO_PATH/5gc_sa_pkg/lab/scripts/k8s/ssl_cert_generation/ssl_cert_gen.py --ca-cert=$CNAT_CI_REPO_PATH/cnat_ci/config/certs/RootCA/ca.crt --ca-key=$CNAT_CI_REPO_PATH/cnat_ci/config/certs/RootCA/ca.key --cert-source=$CNAT_CI_REPO_PATH/cnat_ci/config/n182/eccd2/certificates/fivegcCertInfo.yml --certs-dir=$CNAT_CI_REPO_PATH/cnat_ci/config/n182/eccd2/certificates/


