import csv
import getpass
import re
import socket
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

SSH_PORT = 22

SSH_PORT_TIMEOUT = 5

NETMIKO_CONN_TIMEOUT = 10
NETMIKO_AUTH_TIMEOUT = 10
NETMIKO_BANNER_TIMEOUT = 10


# ============================================================
# REPORT DIRECTORY
# ============================================================

REPORT_DIR = Path("reports")

REPORT_DIR.mkdir(exist_ok=True)

TIMESTAMP = datetime.now().strftime(
    "%Y-%m-%d_%H%M%S"
)

DISCOVERY_REPORT = (
    REPORT_DIR / f"discovery_{TIMESTAMP}.csv"
)

CHANGE_REPORT = (
    REPORT_DIR / f"change_{TIMESTAMP}.csv"
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
                "hostname": row["hostname"].strip(),
                "ip": row["ip"].strip(),
            })

    return devices


# ============================================================
# TEST TCP PORT 22
# ============================================================

def test_ssh_port(ip):

    try:

        sock = socket.create_connection(
            (ip, SSH_PORT),
            timeout=SSH_PORT_TIMEOUT
        )

        sock.close()

        return "OPEN", ""

    except ConnectionRefusedError:

        return (
            "REFUSED",
            f"TCP port {SSH_PORT} refused the connection"
        )

    except TimeoutError:

        return (
            "TIMEOUT",
            f"TCP port {SSH_PORT} connection timed out"
        )

    except OSError as error:

        error_text = str(error).lower()

        if "refused" in error_text:

            return (
                "REFUSED",
                str(error)
            )

        if "timed out" in error_text:

            return (
                "TIMEOUT",
                str(error)
            )

        return (
            "FAILED",
            str(error)
        )


# ============================================================
# GET ACTUAL DEVICE HOSTNAME
# ============================================================

def get_device_hostname(connection):

    output = connection.send_command(
        "show running-config | include ^hostname"
    )

    match = re.search(
        r"^hostname\s+(\S+)",
        output,
        re.MULTILINE | re.IGNORECASE
    )

    if match:

        return match.group(1).strip()

    return None


# ============================================================
# GET DEVICE MODEL
# ============================================================

def get_device_model(connection):

    output = connection.send_command(
        "show version"
    )

    # Common IOS/IOS-XE format:
    # cisco C9300-48P (X86) processor
    match = re.search(
        r"^cisco\s+(\S+)\s+\(",
        output,
        re.MULTILINE | re.IGNORECASE
    )

    if match:

        return match.group(1).strip()

    # Some platforms expose a Model Number field.
    match = re.search(
        r"^Model Number\s*[:\s]+(\S+)",
        output,
        re.MULTILINE | re.IGNORECASE
    )

    if match:

        return match.group(1).strip()

    # Older IOS output may use Processor board ID / hardware
    # descriptions without a clean model field. Do not guess.
    return "UNKNOWN"


# ============================================================
# VERIFY CSV HOSTNAME AGAINST DEVICE HOSTNAME
# ============================================================

def verify_hostname(
    expected_hostname,
    actual_hostname
):

    if not actual_hostname:

        return False

    return (
        expected_hostname.strip().lower()
        ==
        actual_hostname.strip().lower()
    )


# ============================================================
# GET DEVICE INTERFACE/IP INFORMATION
# ============================================================

def get_interface_ip_output(connection):

    return connection.send_command(
        "show ip interface brief"
    )


# ============================================================
# VERIFY CSV IP EXISTS ON DEVICE
# ============================================================

def verify_ip(
    expected_ip,
    interface_output
):

    # Look for the expected IP as a complete field.
    #
    # This prevents:
    #
    # 192.168.15.12
    #
    # from accidentally matching:
    #
    # 192.168.15.120

    pattern = (
        rf"(?<!\d)"
        rf"{re.escape(expected_ip)}"
        rf"(?!\d)"
    )

    return bool(
        re.search(
            pattern,
            interface_output
        )
    )


# ============================================================
# FIND VTY ACCESS-CLASS
# ============================================================

def find_vty_acl(connection):

    vty_config = connection.send_command(
        "show running-config | section ^line vty"
    )

    acl_numbers = re.findall(
        r"^\s*access-class\s+(\d+)\s+in(?:\s+vrf-also)?\s*$",
        vty_config,
        re.MULTILINE | re.IGNORECASE
    )

    acl_numbers = list(
        dict.fromkeys(acl_numbers)
    )

    if not acl_numbers:

        return None, (
            "No inbound VTY access-class found"
        )

    if len(acl_numbers) > 1:

        return None, (
            "Multiple inbound VTY ACLs found: "
            + ", ".join(acl_numbers)
        )

    return acl_numbers[0], ""


# ============================================================
# DETERMINE ACL TYPE
# ============================================================

def determine_acl_type(
    connection,
    acl_number
):

    output = connection.send_command(
        f"show access-lists {acl_number}"
    )

    if "Standard IP access list" in output:

        return "standard", ""

    if "Extended IP access list" in output:

        return "extended", "Extended ACL"

    return None, (
        "Unable to determine ACL type"
    )


# ============================================================
# GET ACL OUTPUT
# ============================================================

def get_acl_output(
    connection,
    acl_number
):

    return connection.send_command(
        f"show access-lists {acl_number}"
    )


# ============================================================
# DISCOVER ONE DEVICE
# ============================================================

def discover_device(
    device,
    username,
    password
):

    hostname = device["hostname"]
    ip = device["ip"]

    result = {
        "hostname": hostname,
        "ip": ip,

        "actual_hostname": "",
        "hostname_match": "",
        "model": "",

        "ip_found_on_device": "",

        "ssh_port": "",
        "ssh": "",

        "vty_acl": "",
        "acl_type": "",
        "ace_exists": "",

        "ready": "NO",
        "result": "",
        "error": "",

        "acl_output": "",
    }

    print(
        f"[DISCOVERY] {hostname} ({ip})"
    )


    # ========================================================
    # TEST TCP/22
    # ========================================================

    port_status, port_error = test_ssh_port(ip)

    result["ssh_port"] = port_status


    if port_status == "REFUSED":

        result["ssh"] = "NOT_ATTEMPTED"
        result["result"] = "SKIPPED"
        result["error"] = port_error

        print(
            f"[DISCOVERY] {hostname} -> "
            f"SSH REFUSED"
        )

        return result


    if port_status == "TIMEOUT":

        result["ssh"] = "NOT_ATTEMPTED"
        result["result"] = "SKIPPED"
        result["error"] = port_error

        print(
            f"[DISCOVERY] {hostname} -> "
            f"SSH PORT TIMEOUT"
        )

        return result


    if port_status == "FAILED":

        result["ssh"] = "NOT_ATTEMPTED"
        result["result"] = "SKIPPED"
        result["error"] = port_error

        print(
            f"[DISCOVERY] {hostname} -> "
            f"SSH PORT TEST FAILED"
        )

        return result


    print(
        f"[DISCOVERY] {hostname} -> "
        f"TCP/22 OPEN"
    )


    # ========================================================
    # NETMIKO SSH CONNECTION
    # ========================================================

    connection = None

    cisco_device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
        "port": SSH_PORT,

        "conn_timeout": NETMIKO_CONN_TIMEOUT,
        "auth_timeout": NETMIKO_AUTH_TIMEOUT,
        "banner_timeout": NETMIKO_BANNER_TIMEOUT,
    }


    try:

        connection = ConnectHandler(
            **cisco_device
        )

        result["ssh"] = "OK"

        print(
            f"[DISCOVERY] {hostname} -> "
            f"SSH/AUTH SUCCESS"
        )

        # ----------------------------------------------------
        # GET DEVICE MODEL
        # ----------------------------------------------------
        result["model"] = get_device_model(
            connection
        )

        print(
            f"[DISCOVERY] {hostname} -> "
            f"MODEL: {result['model']}"
        )


    except NetmikoAuthenticationException:

        result["ssh"] = "AUTH_FAILED"
        result["result"] = "FAILED"

        result["error"] = (
            "TACACS/SSH authentication failed"
        )

        print(
            f"[DISCOVERY] {hostname} -> "
            f"AUTHENTICATION FAILED"
        )

        return result


    except NetmikoTimeoutException as error:

        result["ssh"] = "SSH_TIMEOUT"
        result["result"] = "FAILED"
        result["error"] = str(error)

        print(
            f"[DISCOVERY] {hostname} -> "
            f"SSH NEGOTIATION TIMEOUT"
        )

        return result


    except Exception as error:

        error_text = str(error)
        error_lower = error_text.lower()

        if "refused" in error_lower:

            result["ssh"] = "SSH_REFUSED"
            result["result"] = "SKIPPED"
            result["error"] = error_text

            print(
                f"[DISCOVERY] {hostname} -> "
                f"SSH REFUSED"
            )

        elif "timed out" in error_lower:

            result["ssh"] = "SSH_TIMEOUT"
            result["result"] = "FAILED"
            result["error"] = error_text

            print(
                f"[DISCOVERY] {hostname} -> "
                f"SSH NEGOTIATION TIMEOUT"
            )

        else:

            result["ssh"] = "SSH_FAILED"
            result["result"] = "FAILED"
            result["error"] = error_text

            print(
                f"[DISCOVERY] {hostname} -> "
                f"SSH FAILED"
            )

        return result


    # ========================================================
    # DEVICE IDENTITY VERIFICATION
    # ========================================================

    try:

        # ----------------------------------------------------
        # GET ACTUAL HOSTNAME
        # ----------------------------------------------------

        actual_hostname = get_device_hostname(
            connection
        )

        result["actual_hostname"] = (
            actual_hostname or ""
        )

        print(
            f"[DISCOVERY] {hostname} -> "
            f"DEVICE HOSTNAME: "
            f"{actual_hostname}"
        )


        # ----------------------------------------------------
        # COMPARE HOSTNAMES
        # ----------------------------------------------------

        hostname_match = verify_hostname(
            hostname,
            actual_hostname
        )

        result["hostname_match"] = (
            "YES" if hostname_match else "NO"
        )


        if not hostname_match:

            result["result"] = "SKIPPED"

            result["error"] = (
                f"Hostname mismatch. "
                f"CSV={hostname}, "
                f"DEVICE={actual_hostname}"
            )

            print(
                f"[DISCOVERY] {hostname} -> "
                f"HOSTNAME MISMATCH - SKIPPED"
            )

            return result


        print(
            f"[DISCOVERY] {hostname} -> "
            f"HOSTNAME MATCH"
        )


        # ----------------------------------------------------
        # GET DEVICE IP INFORMATION
        # ----------------------------------------------------

        interface_output = (
            get_interface_ip_output(
                connection
            )
        )


        # ----------------------------------------------------
        # VERIFY CSV IP
        # ----------------------------------------------------

        ip_match = verify_ip(
            ip,
            interface_output
        )

        result["ip_found_on_device"] = (
            "YES" if ip_match else "NO"
        )


        if not ip_match:

            result["result"] = "SKIPPED"

            result["error"] = (
                f"CSV IP {ip} was not found "
                f"in show ip interface brief"
            )

            print(
                f"[DISCOVERY] {hostname} -> "
                f"IP {ip} NOT FOUND ON DEVICE - SKIPPED"
            )

            return result


        print(
            f"[DISCOVERY] {hostname} -> "
            f"IP {ip} VERIFIED"
        )


        # ====================================================
        # FIND VTY ACL
        # ====================================================

        acl_number, acl_error = find_vty_acl(
            connection
        )


        if acl_number is None:

            result["result"] = "SKIPPED"
            result["error"] = acl_error

            print(
                f"[DISCOVERY] {hostname} -> "
                f"VTY ACL NOT FOUND"
            )

            return result


        result["vty_acl"] = acl_number

        print(
            f"[DISCOVERY] {hostname} -> "
            f"VTY ACL {acl_number}"
        )


        # ====================================================
        # DETERMINE ACL TYPE
        # ====================================================

        acl_type, acl_error = determine_acl_type(
            connection,
            acl_number
        )


        if acl_type is None:

            result["result"] = "SKIPPED"
            result["error"] = acl_error

            print(
                f"[DISCOVERY] {hostname} -> "
                f"ACL TYPE UNKNOWN"
            )

            return result


        result["acl_type"] = acl_type


        # ====================================================
        # ONLY STANDARD ACLs
        # ====================================================

        if acl_type != "standard":

            result["result"] = "SKIPPED"
            result["error"] = "Extended ACL"

            print(
                f"[DISCOVERY] {hostname} -> "
                f"EXTENDED ACL - SKIPPED"
            )

            return result


        # ====================================================
        # GET CURRENT ACL
        # ========================================================

        acl_output = get_acl_output(
            connection,
            acl_number
        )

        result["acl_output"] = acl_output


        # ====================================================
        # CHECK TARGET ACE
        # ========================================================

        exists = bool(
            re.search(
                rf"\bpermit\s+{re.escape(TARGET_IP)}\b",
                acl_output
            )
        )

        result["ace_exists"] = (
            "YES" if exists else "NO"
        )


        # ====================================================
        # ALREADY CONFIGURED
        # ========================================================

        if exists:

            result["ready"] = "NO"

            result["result"] = (
                "ALREADY CONFIGURED"
            )

            print(
                f"[DISCOVERY] {hostname} -> "
                f"ALREADY CONFIGURED"
            )


        # ====================================================
        # READY
        # ========================================================

        else:

            result["ready"] = "YES"
            result["result"] = "READY"

            print(
                f"[DISCOVERY] {hostname} -> "
                f"READY FOR CONFIGURATION"
            )


        return result


    except Exception as error:

        result["result"] = "FAILED"
        result["error"] = str(error)

        print(
            f"[DISCOVERY] {hostname} -> "
            f"DISCOVERY FAILED"
        )

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
        "actual_hostname",
        "hostname_match",
        "model",
        "ip_found_on_device",
        "ssh_port",
        "ssh",
        "vty_acl",
        "acl_type",
        "ace_exists",
        "ready",
        "result",
        "error",
        "acl_output",
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
# DISPLAY COMPACT CHANGE PREVIEW
# ============================================================

def display_change_preview(results):

    ready_devices = [
        r for r in results
        if r["ready"] == "YES"
    ]

    print()
    print("=" * 90)
    print("PROPOSED CONFIGURATION CHANGES")
    print("=" * 90)

    print()

    print(
        f"{'#':<5}"
        f"{'HOSTNAME':<25}"
        f"{'IP ADDRESS':<18}"
        f"{'ACL':<8}"
        f"{'ACTION'}"
    )

    print("-" * 90)

    for number, result in enumerate(
        ready_devices,
        start=1
    ):

        print(
            f"{number:<5}"
            f"{result['hostname']:<25}"
            f"{result['ip']:<18}"
            f"{result['vty_acl']:<8}"
            f"ADD: permit {TARGET_IP} log"
        )

    print("-" * 90)

    print()

    print(
        f"{len(ready_devices)} DEVICES WILL BE MODIFIED"
    )

    print()

    print(
        "Target ACE:"
    )

    print(
        f"permit {TARGET_IP} log"
    )

    print()

    print(
        "Hostname and IP identity checks passed "
        "for all devices above."
    )

    print()

    print(
        "Detailed discovery information has been "
        "saved to the discovery CSV."
    )

    print()

    print(
        "Discovery report:"
    )

    print(
        DISCOVERY_REPORT
    )


# ============================================================
# CONFIGURE ONE DEVICE
# ============================================================

def configure_device(
    result,
    username,
    password
):

    hostname = result["hostname"]
    ip = result["ip"]
    acl_number = result["vty_acl"]

    output_result = result.copy()

    output_result["action"] = ""
    output_result["verification"] = ""
    output_result["change_result"] = ""
    output_result["change_error"] = ""


    # ========================================================
    # ONLY CONFIGURE READY DEVICES
    # ========================================================

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
        "port": SSH_PORT,

        "conn_timeout": NETMIKO_CONN_TIMEOUT,
        "auth_timeout": NETMIKO_AUTH_TIMEOUT,
        "banner_timeout": NETMIKO_BANNER_TIMEOUT,
    }


    try:

        print(
            f"[CHANGE] {hostname} -> "
            f"connecting"
        )

        connection = ConnectHandler(
            **cisco_device
        )


        # ====================================================
        # SECOND IDENTITY CHECK
        # ====================================================

        actual_hostname = get_device_hostname(
            connection
        )


        if not verify_hostname(
            hostname,
            actual_hostname
        ):

            output_result["change_result"] = (
                "SKIPPED"
            )

            output_result["change_error"] = (
                f"Hostname changed since discovery. "
                f"CSV={hostname}, "
                f"DEVICE={actual_hostname}"
            )

            print(
                f"[CHANGE] {hostname} -> "
                f"HOSTNAME MISMATCH - SKIPPED"
            )

            return output_result


        # ====================================================
        # SECOND IP CHECK
        # ====================================================

        interface_output = (
            get_interface_ip_output(
                connection
            )
        )


        if not verify_ip(
            ip,
            interface_output
        ):

            output_result["change_result"] = (
                "SKIPPED"
            )

            output_result["change_error"] = (
                f"CSV IP {ip} is no longer "
                f"present on device"
            )

            print(
                f"[CHANGE] {hostname} -> "
                f"IP VERIFICATION FAILED - SKIPPED"
            )

            return output_result


        # ====================================================
        # SECOND ACL CHECK
        # ====================================================

        current_acl = get_acl_output(
            connection,
            acl_number
        )


        if re.search(
            rf"\bpermit\s+{re.escape(TARGET_IP)}\b",
            current_acl
        ):

            output_result["change_result"] = (
                "ALREADY CONFIGURED"
            )

            output_result["change_error"] = (
                "Target ACE appeared after discovery"
            )

            print(
                f"[CHANGE] {hostname} -> "
                f"ALREADY CONFIGURED"
            )

            return output_result


        # ====================================================
        # CONFIGURE ACL
        # ========================================================

        print(
            f"[CHANGE] {hostname} -> "
            f"configuring ACL {acl_number}"
        )


        commands = [

            f"ip access-list standard {acl_number}",

            f"permit {TARGET_IP} log",

            "exit",

            f"ip access-list resequence "
            f"{acl_number} 10 10",
        ]


        connection.send_config_set(
            commands
        )


        output_result["action"] = (
            f"permit {TARGET_IP} log"
        )


        # ====================================================
        # VERIFY CONFIGURATION
        # ====================================================

        acl_output = get_acl_output(
            connection,
            acl_number
        )


        if re.search(
            rf"\bpermit\s+{re.escape(TARGET_IP)}\b",
            acl_output
        ):

            output_result["verification"] = "PASS"

            output_result["change_result"] = (
                "SUCCESS"
            )

            print(
                f"[CHANGE] {hostname} -> "
                f"SUCCESS"
            )


        else:

            output_result["verification"] = "FAIL"

            output_result["change_result"] = (
                "FAILED"
            )

            output_result["change_error"] = (
                "ACE not found after configuration"
            )

            print(
                f"[CHANGE] {hostname} -> "
                f"VERIFICATION FAILED"
            )


        return output_result


    except NetmikoAuthenticationException:

        output_result["change_result"] = (
            "FAILED"
        )

        output_result["change_error"] = (
            "TACACS/SSH authentication failed"
        )

        return output_result


    except NetmikoTimeoutException:

        output_result["change_result"] = (
            "FAILED"
        )

        output_result["change_error"] = (
            "SSH connection timeout"
        )

        return output_result


    except Exception as error:

        output_result["change_result"] = (
            "FAILED"
        )

        output_result["change_error"] = (
            str(error)
        )

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
        "actual_hostname",
        "hostname_match",
        "model",
        "ip_found_on_device",
        "ssh_port",
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

    ssh_port_open = sum(
        r["ssh_port"] == "OPEN"
        for r in results
    )

    ssh_refused = sum(
        r["ssh_port"] == "REFUSED"
        for r in results
    )

    ssh_timeout = sum(
        r["ssh_port"] == "TIMEOUT"
        for r in results
    )

    ssh_ok = sum(
        r["ssh"] == "OK"
        for r in results
    )

    auth_failed = sum(
        r["ssh"] == "AUTH_FAILED"
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
        f"TCP/22 Open:          {ssh_port_open}"
    )

    print(
        f"SSH Refused:          {ssh_refused}"
    )

    print(
        f"SSH Port Timeouts:    {ssh_timeout}"
    )

    print(
        f"SSH Successful:       {ssh_ok}"
    )

    print(
        f"Authentication Fail:  {auth_failed}"
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
        "Discovery Report:"
    )

    print(
        DISCOVERY_REPORT
    )

    return ready


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)

    print("Cisco IOS VTY ACL Automation")

    print("=" * 70)


    # ========================================================
    # TACACS CREDENTIALS
    # ========================================================

    username = input(
        "TACACS Username: "
    )

    password = getpass.getpass(
        "TACACS Password: "
    )


    # ========================================================
    # LOAD CSV
    # ========================================================

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


        for future in as_completed(
            futures
        ):

            result = future.result()

            discovery_results.append(
                result
            )


    # ========================================================
    # SORT RESULTS
    # ========================================================

    discovery_results.sort(
        key=lambda x: x["hostname"]
    )


    # ========================================================
    # WRITE DISCOVERY REPORT
    # ========================================================

    write_discovery_report(
        discovery_results
    )


    # ========================================================
    # DISPLAY SUMMARY
    # ========================================================

    ready_count = print_discovery_summary(
        discovery_results
    )


    # ========================================================
    # NOTHING READY
    # ========================================================

    if ready_count == 0:

        print()

        print(
            "No devices are ready for configuration."
        )

        return


    # ========================================================
    # DISPLAY CHANGE PLAN
    # ========================================================

    display_change_preview(
        discovery_results
    )


    # ========================================================
    # CONFIGURATION APPROVAL
    # ========================================================

    print()

    print("=" * 70)

    print("CONFIGURATION APPROVAL")

    print("=" * 70)

    print()

    print(
        "The above devices passed the identity checks "
        "and are scheduled for the ACL change."
    )

    print()

    print(
        "Target command:"
    )

    print(
        f"permit {TARGET_IP} log"
    )

    print()

    confirmation = input(
        "Type APPLY to begin configuration: "
    )


    # ========================================================
    # CANCEL
    # ========================================================

    if confirmation != "APPLY":

        print()

        print(
            "Configuration cancelled."
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


        for future in as_completed(
            futures
        ):

            result = future.result()

            change_results.append(
                result
            )


    # ========================================================
    # SORT FINAL RESULTS
    # ========================================================

    change_results.sort(
        key=lambda x: x["hostname"]
    )


    # ========================================================
    # WRITE FINAL REPORT
    # ========================================================

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
        "Final Report:"
    )

    print(
        CHANGE_REPORT
    )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()