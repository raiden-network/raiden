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
- **#FIXME** stores the result as a new AMI that can be used for launching a scenario: `-t store_ami`
- terminates the instance: `-t terminate`

#### Usage

    ansible-playbook build-ami.yaml
    # termination can be prevented by defining `keep=True`
    ansible-playbook build-ami.yaml -e "keep=True"

#### Parameters

See `roles/build-ami/vars/main.yaml`.

### run-scenario.yaml

This playbook
- **#FIXME**
