terraform {
    backend "s3" {
        bucket = "network.raiden.testnet.terraform.state"
        key = "terraform.tfstate"
        region = "us-east-1"
    }
}

provider "aws" {
    region = "us-east-1"
}

resource "aws_vpc" "default" {
    cidr_block = "${var.cidr_block}"
    enable_dns_hostnames = true
    enable_dns_support = true

    tags {
        Name = "${var.project_name}"
    }
}

resource "aws_internet_gateway" "default" {
    vpc_id = "${aws_vpc.default.id}"
}

resource "aws_route" "internet_access" {
    route_table_id = "${aws_vpc.default.main_route_table_id}"
    destination_cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.default.id}"
}

resource "aws_subnet" "default" {
    cidr_block = "${var.cidr_block}"
    vpc_id = "${aws_vpc.default.id}"
    map_public_ip_on_launch = true
}

resource "aws_security_group" "common" {
    name = "${var.project_name}_common"
    vpc_id = "${aws_vpc.default.id}"

    // Allow SSH in
    ingress {
        from_port = 22
        to_port = 22
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    // Allow Debug port in
    ingress {
        from_port = 5555
        to_port = 5555
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    // Allow inter-network in
    ingress {
        from_port = 0
        protocol = "-1"
        to_port = 0
        cidr_blocks = ["${var.cidr_block}"]
    }

    // Allow all out
    egress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
}

resource "aws_security_group" "raiden" {
    name = "${var.project_name}_raiden"
    vpc_id = "${aws_vpc.default.id}"

    // Allow Raiden P2P in
    ingress {
        from_port = 38647
        to_port = 38647
        protocol = "udp"
        cidr_blocks = ["0.0.0.0/0"]
    }
}

resource "aws_security_group" "eth" {
    name = "${var.project_name}_eth"
    vpc_id = "${aws_vpc.default.id}"

    // Allow Eth udp in
    ingress {
        from_port = 30303
        to_port = 30303
        protocol = "udp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    // Allow Eth tcp in
    ingress {
        from_port = 30303
        to_port = 30303
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
}

resource "aws_security_group" "infrastructure" {
    name = "${var.project_name}_infrastructure"
    vpc_id = "${aws_vpc.default.id}"

    // Allow infrastructure http in
    ingress {
        from_port = 80
        protocol = "tcp"
        to_port = 80
        cidr_blocks = ["0.0.0.0/0"]
    }

    // Allow infrastructure https in
    ingress {
        from_port = 443
        protocol = "tcp"
        to_port = 443
        cidr_blocks = ["0.0.0.0/0"]
    }

    // Allow infrastructure[0] OpenVPN in
    ingress {
        from_port = 1194
        protocol = "udp"
        to_port = 1194
        cidr_blocks = ["0.0.0.0/0"]
    }
}

resource "aws_instance" "node_infrastructure" {
    ami = "${data.aws_ami.ubuntu1604.id}"
    instance_type = "${var.instance_type["infrastructure"]}"
    key_name = "${var.keypair_name}"
    vpc_security_group_ids = [
        "${aws_security_group.common.id}",
        "${aws_security_group.infrastructure.id}"
    ]
    subnet_id = "${aws_subnet.default.id}"
    count = "${var.count_infrastructure}"
    private_ip = "${cidrhost(var.cidr_block, count.index + var.ip_offset["infrastructure"])}"

    ebs_block_device {
        device_name = "/dev/xvdb"
        delete_on_termination = false
        volume_size = "${var.volume_size["infrastructure"]}"
        volume_type = "gp2"
    }

    tags {
        Name = "${var.project_name}"
        Role = "infrastructure"
    }

    lifecycle {
        # Don't recreate on newer available ami - use `terraform taint` to force recreation
        ignore_changes = ["ami"]
    }

    connection {
        user = "ubuntu"
        private_key = "${file("keys/id_raiden_testnet")}"
    }

    // Ensure python2 and pip are available for ansible
    provisioner "remote-exec" {
        inline = ["sudo apt-get -qq update && sudo apt-get install -qqy python-minimal python-pip"]
    }
}

resource "aws_instance" "node_eth" {
    ami = "${data.aws_ami.ubuntu1604.id}"
    instance_type = "${var.instance_type["eth"]}"
    key_name = "${var.keypair_name}"
    vpc_security_group_ids = [
        "${aws_security_group.common.id}",
        "${aws_security_group.eth.id}"
    ]
    subnet_id = "${aws_subnet.default.id}"
    count = "${var.count_eth}"
    private_ip = "${cidrhost(var.cidr_block, count.index + var.ip_offset["eth"])}"

    ebs_block_device {
        device_name = "/dev/sdb"
        delete_on_termination = true
        volume_size = "${var.volume_size["eth"]}"
        volume_type = "gp2"
    }

    tags {
        Name = "${var.project_name}"
        Role = "eth"
    }

    lifecycle {
        # Don't recreate on newer available ami - use `terraform taint` to force recreation
        ignore_changes = ["ami"]
    }

    connection {
        user = "ubuntu"
        private_key = "${file("keys/id_raiden_testnet")}"
    }

    // Ensure python2 and pip are available for ansible
    provisioner "remote-exec" {
        inline = ["sudo apt-get -qq update && sudo apt-get install -qqy python-minimal python-pip"]
    }
}

resource "aws_instance" "node_raiden" {
    ami = "${data.aws_ami.ubuntu1604.id}"
    instance_type = "${var.instance_type["raiden"]}"
    key_name = "${var.keypair_name}"
    vpc_security_group_ids = [
        "${aws_security_group.common.id}",
        "${aws_security_group.raiden.id}"
    ]
    subnet_id = "${aws_subnet.default.id}"
    count = "${var.count_raiden}"
    private_ip = "${cidrhost(var.cidr_block, count.index + var.ip_offset["raiden"])}"

    tags {
        Name = "${var.project_name}"
        Role = "raiden"
    }

    lifecycle {
        # Don't recreate on newer available ami - use `terraform taint` to force recreation
        ignore_changes = ["ami"]
    }

    connection {
        user = "ubuntu"
        private_key = "${file("keys/id_raiden_testnet")}"
    }

    // Ensure python2 and pip are available for ansible
    provisioner "remote-exec" {
        inline = ["sudo apt-get -qq update && sudo apt-get install -qqy python-minimal python-pip"]
    }
}

resource "aws_instance" "node_raiden_echo" {
    ami = "${data.aws_ami.ubuntu1604.id}"
    instance_type = "${var.instance_type["raiden_echo"]}"
    key_name = "${var.keypair_name}"
    vpc_security_group_ids = [
        "${aws_security_group.common.id}",
        "${aws_security_group.raiden.id}"
    ]
    subnet_id = "${aws_subnet.default.id}"
    count = "${var.count_raiden_echo}"
    private_ip = "${cidrhost(var.cidr_block, count.index + var.ip_offset["raiden_echo"])}"

    tags {
        Name = "${var.project_name}"
        Role = "raiden"
        Echo = "true"
    }

    lifecycle {
        # Don't recreate on newer available ami - use `terraform taint` to force recreation
        ignore_changes = ["ami"]
    }

    connection {
        user = "ubuntu"
        private_key = "${file("keys/id_raiden_testnet")}"
    }

    // Ensure python2 and pip are available for ansible
    provisioner "remote-exec" {
        inline = ["sudo apt-get -qq update && sudo apt-get install -qqy python-minimal python-pip"]
    }
}
