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

resource "aws_security_group" "default" {
    name = "${var.project_name}"
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

    // Allow Raiden P2P in
    ingress {
        from_port = 40001
        to_port = 40001
        protocol = "udp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    // Allow Eth udp in
    ingress {
        from_port = 30303
        to_port = 30303
        protocol = "udp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    // Allow Eth tcpp in
    ingress {
        from_port = 30303
        to_port = 30303
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

resource "aws_instance" "node_eth" {
    ami = "${data.aws_ami.ubuntu1604.id}"
    instance_type = "${lookup(var.instance_role_config, "type_eth")}"
    key_name = "${var.keypair_name}"
    vpc_security_group_ids = ["${aws_security_group.default.id}"]
    subnet_id = "${aws_subnet.default.id}"
    count = "${var.count_eth}"
    private_ip = "${cidrhost(var.cidr_block, count.index + lookup(var.instance_role_config, "ip_offset_eth"))}"

    ebs_block_device {
        device_name = "/dev/sdb"
        delete_on_termination = true
        volume_size = "${lookup(var.instance_role_config, "volume_size_eth")}"
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
    instance_type = "${lookup(var.instance_role_config, "type_raiden")}"
    key_name = "${var.keypair_name}"
    vpc_security_group_ids = ["${aws_security_group.default.id}"]
    subnet_id = "${aws_subnet.default.id}"
    count = "${var.count_raiden}"
    private_ip = "${cidrhost(var.cidr_block, count.index + lookup(var.instance_role_config, "ip_offset_raiden"))}"

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

