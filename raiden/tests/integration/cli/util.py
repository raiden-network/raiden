def expect_cli_until_acknowledgment(child):
    child.expect("Welcome to Raiden")
    child.expect("Have you read, understood and hereby accept the above")
    child.sendline("y")


def expect_cli_until_account_selection(child):
    expect_cli_until_acknowledgment(child)
    child.expect("The following accounts were found in your machine:")
    child.expect("Select one of them by index to continue: ")
    child.sendline("0")


def expect_cli_successful_connected(child, mode: str):
    child.expect(f"Raiden is running in {mode} mode")
    child.expect("You are connected")
    child.expect("REST API services now available.")


def expect_cli_normal_startup(child, mode: str):
    expect_cli_until_acknowledgment(child)
    expect_cli_successful_connected(child, mode)
