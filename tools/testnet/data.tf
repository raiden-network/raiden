data "aws_ami" "ubuntu1604" {
    most_recent = true

    filter {
        name = "name"
        values = ["${var.ami_name_filter}"]
    }

    filter {
        name = "virtualization-type"
        values = ["hvm"]
    }

    # Canonical
    owners = ["099720109477"]
}
