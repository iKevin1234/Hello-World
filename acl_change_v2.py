import csv
import getpass
import re
import subprocess
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)


# ============================================================
# GLOBAL SETTINGS
# ============================================================

REPORT_DIR = Path("reports")

REPORT_DIR.mkdir(exist_ok=True)

timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")

REPORT_FILE = REPORT_DIR / f"acl_change_{timestamp}.csv"


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
                "hostname": row["hostname"].strip(),
                "ip": row["ip"].strip(),
            })

    return devices


# ============================================================
# PING DEVICE
# ============================================================

def ping_device(ip):

    print(f"\nPinging {ip}...")

    try:

        result = subprocess.run(
            [
                "ping",
                "-n",
                "1",
                "-w",
                "1000",
                ip
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if result.returncode == 0:

            print(
                f"PING SUCCESS: {ip} is reachable"
            )

            return True, ""

        print(
            f"PING FAILED: {ip} did not respond"
        )

        return False, "Ping timeout"

    except Exception as error:

        print(
            f"PING ERROR for {ip}: {error}"
        )

        return False, str(error)


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

    acl_numbers = re.findall(
        r"^\s*access-class\s+(\d+)\s+in\s*$",
        vty_config,
        re.MULTILINE
    )

    acl_numbers = list(dict.fromkeys(acl_numbers))

    if not acl_numbers:

        print(
            "\nWARNING: No inbound VTY access-class found."
        )

        return None, "No inbound VTY access-class found"

    if len(acl_numbers) > 1:

        print(
            "\nWARNING: Multiple inbound VTY ACLs found:"
        )

        for acl in acl_numbers:
            print(f"  ACL {acl}")

        print(
            "\nDevice will be skipped."
        )

        return None, "Multiple inbound VTY ACLs found"

    acl_number = acl_numbers[0]

    print(
        f"\nFound VTY inbound ACL: {acl_number}"
    )

    return acl_number, ""


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

        return "standard", ""

    elif "Extended IP access list" in output:

        print(
            f"\nACL {acl_number} is an EXTENDED ACL."
        )

        return "extended", "Extended ACL"

    else:

        print(
            f"\nWARNING: Could not determine ACL type."
        )

        return None, "Unable to determine ACL type"


# ============================================================
# CHECK IF ACE ALREADY EXISTS
# ============================================================

def ace_exists(connection, acl_number):

    output = connection.send_command(
        f"show access-lists {acl_number}"
    )

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

        return True, ""

    print(
        "\nERROR: permit 1.1.1.1 was NOT found."
    )

    return False, "ACE not found after configuration"


# ============================================================
# PROCESS DEVICE
# ============================================================

def process_device(device, username, password):

    hostname = device["hostname"]
    ip = device["ip"]

    result = {
        "hostname": hostname,
        "ip": ip,
        "ping": "",
        "ssh": "",
        "vty_acl": "",
        "acl_type": "",
        "ace_exists": "",
        "action": "",
        "verification": "",
        "result": "",
        "error": "",
    }

    print()
    print("=" * 70)
    print(f"DEVICE: {hostname}")
    print(f"IP:     {ip}")
    print("=" * 70)

    # --------------------------------------------------------
    # PING
    # --------------------------------------------------------

    ping_success, ping_error = ping_device(ip)

    if not ping_success:

        result["ping"] = "FAIL"
        result["result"] = "SKIPPED"
        result["error"] = ping_error

        print(
            f"\nSkipping {hostname}."
        )

        return result

    result["ping"] = "OK"

    # --------------------------------------------------------
    # SSH
    # --------------------------------------------------------

    cisco_device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
    }

    connection = None

    try:

        print("\nConnecting via SSH...")

        connection = ConnectHandler(
            **cisco_device
        )

        result["ssh"] = "OK"

        print(
            f"Successfully connected to {hostname}"
        )

        # ----------------------------------------------------
        # FIND VTY ACL
        # ----------------------------------------------------

        acl_number, acl_error = find_vty_acl(
            connection
        )

        if acl_number is None:

            result["result"] = "SKIPPED"
            result["error"] = acl_error

            return result

        result["vty_acl"] = acl_number

        # ----------------------------------------------------
        # DETERMINE ACL TYPE
        # ----------------------------------------------------

        acl_type, acl_type_error = determine_acl_type(
            connection,
            acl_number
        )

        if acl_type is None:

            result["result"] = "SKIPPED"
            result["error"] = acl_type_error

            return result

        result["acl_type"] = acl_type

        # ----------------------------------------------------
        # ONLY MODIFY STANDARD ACL
        # ----------------------------------------------------

        if acl_type != "standard":

            print()
            print(
                "SAFETY STOP:"
            )

            print(
                f"ACL {acl_number} is not a standard ACL."
            )

            print(
                "This device will NOT be modified."
            )

            result["action"] = "SKIPPED"
            result["result"] = "SKIPPED"
            result["error"] = "Extended ACL"

            return result

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
        # CHECK EXISTING ACE
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

            result["ace_exists"] = "YES"
            result["action"] = "NONE"
            result["verification"] = "NOT REQUIRED"
            result["result"] = "ALREADY CONFIGURED"

            return result

        result["ace_exists"] = "NO"

        # ----------------------------------------------------
        # PREVIEW
        # ----------------------------------------------------

        print()
        print("=" * 60)
        print("CHANGE PREVIEW")
        print("=" * 60)

        print(
            f"\nDevice:   {hostname}"
        )

        print(
            f"IP:       {ip}"
        )

        print(
            f"VTY ACL:  {acl_number}"
        )

        print(
            f"ACL Type: {acl_type}"
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
            f"ip access-list resequence "
            f"{acl_number} 10 10"
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

            result["action"] = "CANCELLED"
            result["result"] = "CANCELLED"

            return result

        # ----------------------------------------------------
        # APPLY CONFIGURATION
        # ----------------------------------------------------

        configure_acl(
            connection,
            acl_number
        )

        result["action"] = "APPLIED"

        # ----------------------------------------------------
        # VERIFY
        # ----------------------------------------------------

        verification_success, verification_error = verify_acl(
            connection,
            acl_number
        )

        if verification_success:

            result["verification"] = "PASS"
            result["result"] = "SUCCESS"

        else:

            result["verification"] = "FAIL"
            result["result"] = "FAILED"
            result["error"] = verification_error

        return result

    except NetmikoAuthenticationException:

        result["ssh"] = "FAIL"
        result["result"] = "FAILED"
        result["error"] = "Authentication failed"

        print(
            f"\nERROR: Authentication failed "
            f"for {hostname}"
        )

        return result

    except NetmikoTimeoutException:

        result["ssh"] = "FAIL"
        result["result"] = "FAILED"
        result["error"] = "SSH timeout"

        print(
            f"\nERROR: Connection timeout "
            f"for {hostname}"
        )

        return result

    except Exception as error:

        result["result"] = "FAILED"
        result["error"] = str(error)

        print(
            f"\nERROR on {hostname}: {error}"
        )

        return result

    finally:

        if connection:

            connection.disconnect()

            print(
                f"\nDisconnected from {hostname}"
            )


# ============================================================
# WRITE CSV REPORT
# ============================================================

def write_report(results):

    fieldnames = [
        "hostname",
        "ip",
        "ping",
        "ssh",
        "vty_acl",
        "acl_type",
        "ace_exists",
        "action",
        "verification",
        "result",
        "error",
    ]

    with open(
        REPORT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        writer.writeheader()

        writer.writerows(results)

    print()
    print(
        f"Report created: {REPORT_FILE}"
    )


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

    results = []

    for device in devices:

        result = process_device(
            device,
            username,
            password
        )

        results.append(result)

    # --------------------------------------------------------
    # WRITE REPORT
    # --------------------------------------------------------

    write_report(results)

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    total = len(results)

    ping_ok = sum(
        1 for r in results
        if r["ping"] == "OK"
    )

    ping_failed = sum(
        1 for r in results
        if r["ping"] == "FAIL"
    )

    ssh_ok = sum(
        1 for r in results
        if r["ssh"] == "OK"
    )

    ssh_failed = sum(
        1 for r in results
        if r["ssh"] == "FAIL"
    )

    changes = sum(
        1 for r in results
        if r["action"] == "APPLIED"
    )

    already_configured = sum(
        1 for r in results
        if r["result"] == "ALREADY CONFIGURED"
    )

    skipped = sum(
        1 for r in results
        if r["result"] == "SKIPPED"
    )

    failed = sum(
        1 for r in results
        if r["result"] == "FAILED"
    )

    print()
    print("=" * 70)
    print("AUTOMATION SUMMARY")
    print("=" * 70)

    print(
        f"Total Devices:        {total}"
    )

    print(
        f"Ping Successful:      {ping_ok}"
    )

    print(
        f"Ping Failed:          {ping_failed}"
    )

    print(
        f"SSH Successful:       {ssh_ok}"
    )

    print(
        f"SSH Failed:           {ssh_failed}"
    )

    print(
        f"ACL Changes Applied:  {changes}"
    )

    print(
        f"Already Configured:   {already_configured}"
    )

    print(
        f"Skipped:              {skipped}"
    )

    print(
        f"Failed:               {failed}"
    )

    print()
    print(
        f"Report: {REPORT_FILE}"
    )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()