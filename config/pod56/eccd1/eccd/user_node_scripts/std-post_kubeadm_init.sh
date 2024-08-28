#!/usr/bin/env bash
set -uex

## Label the worker nodes for PCC
# ADD LABEL START
echo -e "Adding PCC CNF labels ...."
# set worker nodes count of PC-MM controller or PC-SM controller to 3 when it supports HA
export MM_CONTROLLERS=2
export MM_CTRL_LABEL="pcc-mm-pod=controller"
export MM_NON_CTRL_LABEL="pcc-mm-pod=non-controller"
export SM_CONTROLLERS=2
export SM_CTRL_LABEL="pcc-sm-pod=controller"
export SM_NON_CTRL_LABEL="pcc-sm-pod=non-controller"

get_label_count() {
    LABEL=$1
    COUNT=$(/usr/local/bin/kubectl --kubeconfig /etc/kubernetes/kubelet.conf get node -l ${LABEL} | egrep -v "^NAME" | wc -l)
    echo $COUNT
}

### MAIN
NODE_NAME=$(hostname -s)
if [ $(get_label_count $MM_CTRL_LABEL) -lt $MM_CONTROLLERS ]
then
    /usr/local/bin/kubectl --kubeconfig /etc/kubernetes/kubelet.conf label node $NODE_NAME $MM_CTRL_LABEL
    /usr/local/bin/kubectl --kubeconfig /etc/kubernetes/kubelet.conf label node $NODE_NAME $SM_NON_CTRL_LABEL
elif [ $(get_label_count $SM_CTRL_LABEL) -lt $SM_CONTROLLERS ]
then
    /usr/local/bin/kubectl --kubeconfig /etc/kubernetes/kubelet.conf label node $NODE_NAME $SM_CTRL_LABEL
    /usr/local/bin/kubectl --kubeconfig /etc/kubernetes/kubelet.conf label node $NODE_NAME $MM_NON_CTRL_LABEL
else
    /usr/local/bin/kubectl --kubeconfig /etc/kubernetes/kubelet.conf label node $NODE_NAME $MM_NON_CTRL_LABEL
    /usr/local/bin/kubectl --kubeconfig /etc/kubernetes/kubelet.conf label node $NODE_NAME $SM_NON_CTRL_LABEL
fi
echo -e "END PCC CNF labels"
# ADD LABEL END
