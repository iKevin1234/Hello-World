import csv
import getpass
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)


# ============================================================
# SETTINGS
# ============================================================

MAX_WORKERS = 5

TARGET_IP = "1.1.1.1"

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H%M%S")

DISCOVERY_REPORT = (
    REPORT_DIR / f"discovery_{TIMESTAMP}.csv"
)

CHANGE_REPORT = (
    REPORT_DIR / f"change_{TIMESTAMP}.csv"
)


# ============================================================
# LOAD DEVICES
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
# PING
# ============================================================

def ping_device(ip):

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

            return True, ""

        return False, "Ping timeout"

    except Exception as error:

        return False, str(error)


# ============================================================
# FIND VTY ACL
# ============================================================

def find_vty_acl(connection):

    vty_config = connection.send_command(
        "show running-config | section ^line vty"
    )

    acl_numbers = re.findall(
        r"^\s*access-class\s+(\d+)\s+in\s*$",
        vty_config,
        re.MULTILINE
    )

    acl_numbers = list(
        dict.fromkeys(acl_numbers)
    )

    if not acl_numbers:

        return None, "No inbound VTY access-class found"

    if len(acl_numbers) > 1:

        return None, (
            "Multiple inbound VTY ACLs found: "
            + ", ".join(acl_numbers)
        )

    return acl_numbers[0], ""


# ============================================================
# DETERMINE ACL TYPE
# ============================================================

def determine_acl_type(connection, acl_number):

    output = connection.send_command(
        f"show access-lists {acl_number}"
    )

    if "Standard IP access list" in output:

        return "standard", ""

    if "Extended IP access list" in output:

        return "extended", "Extended ACL"

    return None, "Unable to determine ACL type"


# ============================================================
# CHECK EXISTING ACE
# ============================================================

def ace_exists(connection, acl_number):

    output = connection.send_command(
        f"show access-lists {acl_number}"
    )

    return bool(
        re.search(
            rf"\bpermit\s+{re.escape(TARGET_IP)}\b",
            output
        )
    )


# ============================================================
# DISCOVER ONE DEVICE
# ============================================================

def discover_device(device, username, password):

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
        "ready": "NO",
        "result": "",
        "error": "",
    }

    print(
        f"[DISCOVERY] {hostname} ({ip})"
    )

    # --------------------------------------------------------
    # PING
    # --------------------------------------------------------

    ping_ok, ping_error = ping_device(ip)

    if not ping_ok:

        result["ping"] = "FAIL"
        result["result"] = "SKIPPED"
        result["error"] = ping_error

        print(
            f"[DISCOVERY] {hostname} -> PING FAILED"
        )

        return result

    result["ping"] = "OK"

    # --------------------------------------------------------
    # SSH
    # --------------------------------------------------------

    connection = None

    cisco_device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
    }

    try:

        connection = ConnectHandler(
            **cisco_device
        )

        result["ssh"] = "OK"

        # ----------------------------------------------------
        # VTY ACL
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
        # ACL TYPE
        # ----------------------------------------------------

        acl_type, acl_error = determine_acl_type(
            connection,
            acl_number
        )

        if acl_type is None:

            result["result"] = "SKIPPED"
            result["error"] = acl_error

            return result

        result["acl_type"] = acl_type

        # ----------------------------------------------------
        # EXTENDED ACL SAFETY STOP
        # ----------------------------------------------------

        if acl_type != "standard":

            result["result"] = "SKIPPED"
            result["error"] = "Extended ACL"

            return result

        # ----------------------------------------------------
        # EXISTING ACE
        # ----------------------------------------------------

        exists = ace_exists(
            connection,
            acl_number
        )

        result["ace_exists"] = (
            "YES" if exists else "NO"
        )

        if exists:

            result["ready"] = "NO"
            result["result"] = "ALREADY CONFIGURED"

        else:

            result["ready"] = "YES"
            result["result"] = "READY"

        return result

    except NetmikoAuthenticationException:

        result["ssh"] = "FAIL"
        result["result"] = "FAILED"
        result["error"] = "Authentication failed"

        return result

    except NetmikoTimeoutException:

        result["ssh"] = "FAIL"
        result["result"] = "FAILED"
        result["error"] = "SSH timeout"

        return result

    except Exception as error:

        result["result"] = "FAILED"
        result["error"] = str(error)

        return result

    finally:

        if connection:

            connection.disconnect()


# ============================================================
# WRITE DISCOVERY REPORT
# ============================================================

def write_discovery_report(results):

    fieldnames = [
        "hostname",
        "ip",
        "ping",
        "ssh",
        "vty_acl",
        "acl_type",
        "ace_exists",
        "ready",
        "result",
        "error",
    ]

    with open(
        DISCOVERY_REPORT,
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


# ============================================================
# CONFIGURE ONE DEVICE
# ============================================================

def configure_device(result, username, password):

    hostname = result["hostname"]
    ip = result["ip"]
    acl_number = result["vty_acl"]

    output_result = result.copy()

    output_result["action"] = ""
    output_result["verification"] = ""
    output_result["change_result"] = ""
    output_result["change_error"] = ""

    # Only configure devices marked READY
    if result["ready"] != "YES":

        output_result["change_result"] = (
            result["result"]
        )

        return output_result

    connection = None

    cisco_device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
    }

    try:

        print(
            f"[CHANGE] {hostname} -> configuring ACL {acl_number}"
        )

        connection = ConnectHandler(
            **cisco_device
        )

        # ----------------------------------------------------
        # CONFIGURATION
        # ----------------------------------------------------

        commands = [
            f"ip access-list standard {acl_number}",
            f"permit {TARGET_IP} log",
            "exit",
            f"ip access-list resequence {acl_number} 10 10",
        ]

        connection.send_config_set(
            commands
        )

        output_result["action"] = (
            f"permit {TARGET_IP} log"
        )

        # ----------------------------------------------------
        # VERIFICATION
        # ----------------------------------------------------

        acl_output = connection.send_command(
            f"show access-lists {acl_number}"
        )

        if re.search(
            rf"\bpermit\s+{re.escape(TARGET_IP)}\b",
            acl_output
        ):

            output_result["verification"] = "PASS"
            output_result["change_result"] = "SUCCESS"

            print(
                f"[CHANGE] {hostname} -> SUCCESS"
            )

        else:

            output_result["verification"] = "FAIL"
            output_result["change_result"] = "FAILED"
            output_result["change_error"] = (
                "ACE not found after configuration"
            )

            print(
                f"[CHANGE] {hostname} -> VERIFICATION FAILED"
            )

        return output_result

    except NetmikoAuthenticationException:

        output_result["change_result"] = "FAILED"
        output_result["change_error"] = (
            "Authentication failed"
        )

        return output_result

    except NetmikoTimeoutException:

        output_result["change_result"] = "FAILED"
        output_result["change_error"] = (
            "SSH timeout"
        )

        return output_result

    except Exception as error:

        output_result["change_result"] = "FAILED"
        output_result["change_error"] = str(error)

        return output_result

    finally:

        if connection:

            connection.disconnect()


# ============================================================
# WRITE CHANGE REPORT
# ============================================================

def write_change_report(results):

    fieldnames = [
        "hostname",
        "ip",
        "ping",
        "ssh",
        "vty_acl",
        "acl_type",
        "ace_exists",
        "ready",
        "result",
        "error",
        "action",
        "verification",
        "change_result",
        "change_error",
    ]

    with open(
        CHANGE_REPORT,
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


# ============================================================
# DISCOVERY SUMMARY
# ============================================================

def print_discovery_summary(results):

    total = len(results)

    ping_ok = sum(
        r["ping"] == "OK"
        for r in results
    )

    ssh_ok = sum(
        r["ssh"] == "OK"
        for r in results
    )

    ready = sum(
        r["ready"] == "YES"
        for r in results
    )

    already = sum(
        r["result"] == "ALREADY CONFIGURED"
        for r in results
    )

    skipped = sum(
        r["result"] == "SKIPPED"
        for r in results
    )

    failed = sum(
        r["result"] == "FAILED"
        for r in results
    )

    print()
    print("=" * 70)
    print("DISCOVERY COMPLETE")
    print("=" * 70)

    print(
        f"Total Devices:        {total}"
    )

    print(
        f"Ping Successful:      {ping_ok}"
    )

    print(
        f"SSH Successful:       {ssh_ok}"
    )

    print(
        f"Ready for Change:     {ready}"
    )

    print(
        f"Already Configured:   {already}"
    )

    print(
        f"Skipped:              {skipped}"
    )

    print(
        f"Failed:               {failed}"
    )

    print()
    print(
        f"Discovery Report:"
    )

    print(
        f"{DISCOVERY_REPORT}"
    )

    return ready


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
        f"Loaded {len(devices)} devices."
    )

    # ========================================================
    # PHASE 1 - DISCOVERY
    # ========================================================

    print()
    print("=" * 70)
    print("PHASE 1 - DISCOVERY")
    print("=" * 70)

    discovery_results = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                discover_device,
                device,
                username,
                password
            ): device
            for device in devices
        }

        for future in as_completed(futures):

            result = future.result()

            discovery_results.append(
                result
            )

    # Keep report sorted by hostname
    discovery_results.sort(
        key=lambda x: x["hostname"]
    )

    write_discovery_report(
        discovery_results
    )

    ready_count = print_discovery_summary(
        discovery_results
    )

    # ========================================================
    # APPROVAL
    # ========================================================

    if ready_count == 0:

        print()
        print(
            "No devices are ready for configuration."
        )

        return

    print()
    print("=" * 70)
    print("CONFIGURATION APPROVAL")
    print("=" * 70)

    print(
        f"\n{ready_count} devices are ready "
        f"for configuration."
    )

    print(
        f"\nTarget ACE:"
    )

    print(
        f"permit {TARGET_IP} log"
    )

    print()
    print(
        "Discovery report:"
    )

    print(
        DISCOVERY_REPORT
    )

    confirmation = input(
        "\nType APPLY to begin configuration: "
    )

    if confirmation != "APPLY":

        print(
            "\nConfiguration cancelled."
        )

        return

    # ========================================================
    # PHASE 2 - CONFIGURATION
    # ========================================================

    print()
    print("=" * 70)
    print("PHASE 2 - CONFIGURATION")
    print("=" * 70)

    change_results = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                configure_device,
                result,
                username,
                password
            ): result
            for result in discovery_results
        }

        for future in as_completed(futures):

            result = future.result()

            change_results.append(
                result
            )

    change_results.sort(
        key=lambda x: x["hostname"]
    )

    write_change_report(
        change_results
    )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    successful = sum(
        r.get("change_result") == "SUCCESS"
        for r in change_results
    )

    failed = sum(
        r.get("change_result") == "FAILED"
        for r in change_results
    )

    already = sum(
        r.get("change_result") == "ALREADY CONFIGURED"
        for r in change_results
    )

    skipped = sum(
        r.get("change_result") == "SKIPPED"
        for r in change_results
    )

    print()
    print("=" * 70)
    print("FINAL AUTOMATION SUMMARY")
    print("=" * 70)

    print(
        f"Successful Changes:   {successful}"
    )

    print(
        f"Already Configured:   {already}"
    )

    print(
        f"Skipped:              {skipped}"
    )

    print(
        f"Failed:               {failed}"
    )

    print()
    print(
        f"Final Report:"
    )

    print(
        CHANGE_REPORT
    )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()