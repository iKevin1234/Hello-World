import csv
import getpass
import re

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)


# ============================================================
# LOAD DEVICES FROM CSV
# ============================================================

def load_devices(filename):

    devices = []

    with open(
        filename,
        "r",
        newline="",
        encoding="utf-8-sig"
    ) as csvfile:

        reader = csv.DictReader(csvfile)

        for row in reader:

            devices.append({
                "hostname": row["hostname"],
                "ip": row["ip"],
            })

    return devices


# ============================================================
# FIND VTY INBOUND ACL
# ============================================================

def find_vty_acl(connection):

    print("\nChecking VTY configuration...")

    vty_config = connection.send_command(
        "show running-config | section ^line vty"
    )

    print("\nVTY configuration:")
    print(vty_config)

    # Find access-class statements applied inbound
    acl_numbers = re.findall(
        r"^\s*access-class\s+(\d+)\s+in\s*$",
        vty_config,
        re.MULTILINE
    )

    # Remove duplicates
    acl_numbers = list(dict.fromkeys(acl_numbers))

    if not acl_numbers:

        print(
            "\nWARNING: No inbound VTY access-class found."
        )

        return None

    # Multiple different inbound ACLs = do not guess
    if len(acl_numbers) > 1:

        print(
            "\nWARNING: Multiple inbound VTY ACLs found:"
        )

        for acl in acl_numbers:
            print(f"  ACL {acl}")

        print(
            "\nDevice will be skipped to prevent "
            "modifying the wrong ACL."
        )

        return None

    acl_number = acl_numbers[0]

    print(
        f"\nFound VTY inbound ACL: {acl_number}"
    )

    return acl_number


# ============================================================
# DETERMINE ACL TYPE
# ============================================================

def determine_acl_type(connection, acl_number):

    print(
        f"\nChecking ACL {acl_number}..."
    )

    output = connection.send_command(
        f"show access-lists {acl_number}"
    )

    print(output)

    if "Standard IP access list" in output:

        print(
            f"\nACL {acl_number} is a STANDARD ACL."
        )

        return "standard"

    elif "Extended IP access list" in output:

        print(
            f"\nACL {acl_number} is an EXTENDED ACL."
        )

        return "extended"

    else:

        print(
            f"\nWARNING: Could not determine "
            f"the type of ACL {acl_number}."
        )

        return None


# ============================================================
# CHECK IF ACE ALREADY EXISTS
# ============================================================

def ace_exists(connection, acl_number):

    output = connection.send_command(
        f"show access-lists {acl_number}"
    )

    # Look for an ACE containing 1.1.1.1
    if re.search(
        r"\bpermit\s+1\.1\.1\.1\b",
        output
    ):

        return True

    return False


# ============================================================
# CONFIGURE ACL
# ============================================================

def configure_acl(connection, acl_number):

    print()
    print("=" * 60)
    print("APPLYING ACL CONFIGURATION")
    print("=" * 60)

    commands = [
        f"ip access-list standard {acl_number}",
        "permit 1.1.1.1 log",
        "exit",
        f"ip access-list resequence {acl_number} 10 10",
    ]

    print("\nCommands being sent:")

    for command in commands:
        print(f"  {command}")

    output = connection.send_config_set(
        commands
    )

    print("\nConfiguration output:")
    print(output)

    return output


# ============================================================
# VERIFY ACL
# ============================================================

def verify_acl(connection, acl_number):

    print()
    print("=" * 60)
    print("POST-CHANGE VERIFICATION")
    print("=" * 60)

    output = connection.send_command(
        f"show access-lists {acl_number}"
    )

    print(output)

    if re.search(
        r"\bpermit\s+1\.1\.1\.1\b",
        output
    ):

        print(
            "\nSUCCESS: permit 1.1.1.1 was found."
        )

        return True

    print(
        "\nERROR: permit 1.1.1.1 was NOT found."
    )

    return False


# ============================================================
# PROCESS DEVICE
# ============================================================

def process_device(device, username, password):

    hostname = device["hostname"]
    ip = device["ip"]

    print()
    print("=" * 70)
    print(f"DEVICE: {hostname}")
    print(f"IP:     {ip}")
    print("=" * 70)

    cisco_device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
    }

    try:

        # ----------------------------------------------------
        # CONNECT
        # ----------------------------------------------------

        print("\nConnecting...")

        connection = ConnectHandler(
            **cisco_device
        )

        print(
            f"Successfully connected to {hostname}"
        )

        # ----------------------------------------------------
        # FIND VTY ACL
        # ----------------------------------------------------

        acl_number = find_vty_acl(
            connection
        )

        if acl_number is None:

            connection.disconnect()

            return False

        # ----------------------------------------------------
        # DETERMINE ACL TYPE
        # ----------------------------------------------------

        acl_type = determine_acl_type(
            connection,
            acl_number
        )

        if acl_type != "standard":

            print(
                "\nSAFETY STOP:"
            )

            print(
                f"ACL {acl_number} is not a standard ACL."
            )

            print(
                "This script will NOT modify it."
            )

            connection.disconnect()

            return False

        # ----------------------------------------------------
        # SHOW CURRENT ACL
        # ----------------------------------------------------

        print()
        print("=" * 60)
        print(f"CURRENT ACL {acl_number}")
        print("=" * 60)

        current_acl = connection.send_command(
            f"show access-lists {acl_number}"
        )

        print(current_acl)

        # ----------------------------------------------------
        # CHECK IF ACE ALREADY EXISTS
        # ----------------------------------------------------

        if ace_exists(
            connection,
            acl_number
        ):

            print()
            print(
                "INFO: permit 1.1.1.1 already exists."
            )

            print(
                "No configuration change is necessary."
            )

            connection.disconnect()

            return True

        # ----------------------------------------------------
        # PREVIEW
        # ----------------------------------------------------

        print()
        print("=" * 60)
        print("CHANGE PREVIEW")
        print("=" * 60)

        print(
            f"\nDevice: {hostname}"
        )

        print(
            f"IP: {ip}"
        )

        print(
            f"VTY ACL: {acl_number}"
        )

        print(
            "\nThe following configuration will be applied:"
        )

        print()
        print(
            f"ip access-list standard {acl_number}"
        )

        print(
            "permit 1.1.1.1 log"
        )

        print(
            "exit"
        )

        print(
            f"ip access-list resequence {acl_number} 10 10"
        )

        # ----------------------------------------------------
        # CONFIRM
        # ----------------------------------------------------

        confirmation = input(
            "\nApply this change? "
            "Type YES to continue: "
        )

        if confirmation != "YES":

            print(
                "\nChange cancelled."
            )

            connection.disconnect()

            return False

        # ----------------------------------------------------
        # APPLY CONFIGURATION
        # ----------------------------------------------------

        configure_acl(
            connection,
            acl_number
        )

        # ----------------------------------------------------
        # VERIFY
        # ----------------------------------------------------

        success = verify_acl(
            connection,
            acl_number
        )

        # ----------------------------------------------------
        # DISCONNECT
        # ----------------------------------------------------

        connection.disconnect()

        print(
            f"\nDisconnected from {hostname}"
        )

        return success

    except NetmikoAuthenticationException:

        print(
            f"\nERROR: Authentication failed "
            f"for {hostname}"
        )

        return False

    except NetmikoTimeoutException:

        print(
            f"\nERROR: Connection timeout "
            f"for {hostname}"
        )

        return False

    except Exception as error:

        print(
            f"\nERROR on {hostname}: {error}"
        )

        return False


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("Cisco IOS VTY ACL Automation")
    print("=" * 70)

    username = input(
        "TACACS Username: "
    )

    password = getpass.getpass(
        "TACACS Password: "
    )

    devices = load_devices(
        "devices.csv"
    )

    print()
    print(
        f"Loaded {len(devices)} devices "
        f"from devices.csv"
    )

    successful = 0
    failed = 0

    for device in devices:

        result = process_device(
            device,
            username,
            password
        )

        if result:

            successful += 1

        else:

            failed += 1

    print()
    print("=" * 70)
    print("AUTOMATION SUMMARY")
    print("=" * 70)

    print(
        f"Successful: {successful}"
    )

    print(
        f"Failed:     {failed}"
    )


if __name__ == "__main__":

    main()