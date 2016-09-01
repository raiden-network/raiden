# Ansible deployment scripts

## Preparation

### Requirements

In this folder, run

    pip install -r requirements.txt

to install ansible and dependent modules.

### AWS ACCESS
Create a file `~/.boto` with contents:


    [Credentials]
    aws_access_key_id = XXXXXXX 
    aws_secret_access_key = yyyyyyyyy 

### raiden private key
Obtain the `raiden.pem` file and place it into `keys/raiden.pem`, then `chmod 600 keys/raiden.pem`.


## Playbooks

### build-ami.yaml

This playbook 
- launches a new ubuntu instance: `-t init`
- installs all dependencies: `-t install_geth,install_raiden`
- prepare the DAG for mining: `-t dag`
- stores the result as a new AMI that can be used for launching a scenario: `-t store_ami`
- terminates the instance: `-t terminate`

#### Usage

    ansible-playbook build-ami.yaml
    # termination can be prevented by defining `keep=True`
    ansible-playbook build-ami.yaml -e "keep=True"
    # to make sure, all amis are deleted, call
    ansible-playbook build-ami.yaml -e "cleanup=True" -t store_ami
    

#### Parameters

See `roles/build-ami/vars/main.yaml`.

### prepare-scenario.yaml

This playbook will 

- start `<number_of_nodes>` `<instance_type>` instances of the `raiden_preinstalled` AMI,
- collect the IPs
- prepare `geth` configurations (
    - `genesis` with `<raiden_per_node>` * `<number_of_nodes>` prefunded accounts
    - `static-bootnodes` for the collected IPs)
- `init`ialize `geth` on all nodes
- create scenario folders for each `<raiden_per_node>` on all nodes containing 
    - `privatekey` + `contract_flags`
    - *#FIXME* `peers`
    - *#FIXME* `scenario_config`
- start `geth` on all nodes
- *#FIXME* create assets from `scenario_config`

### run-scenario.yaml

This playbook
- **#FIXME**

# DEV-notes: 
to use a previously created ami, include
`roles/common/tasks/scenario_ami_id_from_name.yaml` before instance creation and use the fact
`scenario_ami_id` with the `ec2` module for the `image` parameter.
