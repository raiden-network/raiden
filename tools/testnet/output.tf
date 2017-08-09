output "testnet-members-infrastructure" {
    value = ["${aws_instance.node_infrastructure.*.public_ip}"]
}
output "testnet-members-eth" {
    value = ["${aws_instance.node_eth.*.public_ip}"]
}
output "testnet-members-raiden-echo" {
    value = ["${aws_instance.node_raiden_echo.*.public_ip}"]
}
output "testnet-members-raiden" {
    value = ["${aws_instance.node_raiden.*.public_ip}"]
}
