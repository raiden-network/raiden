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
