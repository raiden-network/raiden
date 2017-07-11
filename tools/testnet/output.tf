output "testnet-members-eth" {
    value = ["${aws_instance.node_eth.*.public_ip}"]
}
output "testnet-members-raiden" {
    value = ["${aws_instance.node_raiden.*.public_ip}"]
}
