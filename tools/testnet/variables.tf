variable "project_name" {
    default = "raiden_testnet"
}

variable "keypair_name" {
    description = "AWS SSH key pair"
    default = "raiden-testnet"
}

variable "cidr_block" {
    default = "10.0.0.0/16"
}

variable "ami_name_filter" {
    default = "ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-*"
}

variable "count_infrastructure" {
    default = 1
}

variable "count_eth" {
    default = 3
}

variable "count_raiden" {
    default = 15
}

variable "instance_role_config" {
    type = "map"
    default = {
        "type_infrastructure" = "t2.small",
        "ip_offset_infrastructure" = 769,
        "volume_size_infrastructure" = 10,

        "type_eth" = "t2.small",
        "ip_offset_eth" = 513
        "volume_size_eth" = 30,

        "type_raiden" = "t2.nano",
        "ip_offset_raiden" = 257,
    }
}
