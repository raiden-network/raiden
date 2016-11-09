# Ansible deployment scripts

## Preparation

### Requirements

In this folder, run

    pip install -r requirements.txt --no-deps

to install ansible and dependent modules.
**NOTE**: the `--no-deps` flag is important, because otherwise it breaks dependencies for `raiden`.

### AWS ACCESS
Create a file `~/.boto` with contents:


    [Credentials]
    aws_access_key_id = XXXXXXX 
    aws_secret_access_key = yyyyyyyyy 

### raiden private key
Obtain the `raiden.pem` file and place it into `keys/raiden.pem`, then `chmod 600 keys/raiden.pem`.


## Playbooks

### build-ami-cpython.yaml / build-ami-pypy.yaml

This playbook 
- launches a new ubuntu instance: `-t init`
- installs all dependencies: `-t install_geth,install_raiden`
- prepare the DAG for mining: `-t dag`
- stores the result as a new AMI that can be used for launching a scenario: `-t store_ami`
- terminates the instance: `-t terminate`

#### Usage

    ansible-playbook build-ami-{version}.yaml
    # termination can be prevented by defining `keep=True`
    ansible-playbook build-ami-{version}.yaml -e "keep=True"
    # to make sure, all amis are deleted, call
    ansible-playbook build-ami-{version}.yaml -e "cleanup=True" -t store_ami
    

#### Parameters

See `roles/build-ami/vars/main.yaml`.

### prepare-scenario.yaml

This playbook will 

- start `<number_of_nodes>` `<instance_type>` instances of the `raiden_preinstalled` AMI,
- collect the IPs
- prepare `geth` configurations (
    - `genesis` with `<raiden_per_node>` * `<number_of_nodes>` prefunded accounts
    - `static-bootnodes` for the collected IPs)
- create scenario folders for each `<raiden_per_node>` on all nodes containing 
    - `privatekey` + `contract_flags`
    - `scenario_config` (`scenario.json`)
- start `geth` on all nodes
- *#FIXME* create assets from `scenario_config`

### run-scenario.yaml

This playbook

- `init`ialize `geth` on all nodes
- updates raiden repository if `force_pull` is set to True
- **#FIXME**

# DEV-notes: 

## User separation
In order to avoid clashes between users, there is the `user_tag` variable. This works as follows:

- add `-e user_tag=myname` to the first call to `prepare-scenario.yaml`
- on later calls and when calling `run-scenario.yaml`, keep using `-e user_tag=myname` and add `--limit
  tag_user_myname`.

Full example:

    ansible-playbook prepare-scenario.yaml -e "number_of_nodes=3 user_tag=peter keep=True"

    ansible-playbook run-scenario.yaml --limit tag_user_peter -e "user_tag=peter keep=True"

    ansible-playbook run-scenario.yaml --limit tag_user_peter -e "user_tag=peter" -t terminate

The yoda'esque duplication of the arguments for `--limit` and `-e user_tag` comes from 
1) the need of having the tag variable available for `ec2_remote_facts` in `roles/scenario/tasks/read_scenario_params.yaml` and
2) `ec2.py` reversing the tag-name (`--limit` works on `ec2.py`)
