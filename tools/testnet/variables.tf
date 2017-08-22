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
    default = 100
}

variable "count_raiden_echo" {
    default = 1
}

variable "ip_offset" {
    type = "map"
    default = {
        "infrastructure" = 257,
        "eth" = 513,
        "raiden_echo" = 769,
        "raiden" = 1025
    }
}

variable "instance_type" {
    type = "map"
    default = {
        "infrastructure" = "t2.small",
        "eth" = "t2.small",
        "raiden_echo" = "t2.nano",
        "raiden" = "t2.nano"
    }
}

variable "volume_size" {
    type = "map"
    default = {
        "infrastructure" = 50,
        "eth" = 30,
    }
}
