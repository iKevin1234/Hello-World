# Cisco Access VLAN Report

Reads a switch inventory over SSH and creates an Excel report of configured access ports per VLAN, including up/down counts and switch stack information.

## Dependencies

- Python 3.10 or newer
- `netmiko` — SSH connections to Cisco switches
- `openpyxl` — reads the Excel inventory and writes the report

## Run with a Python virtual environment

From your project folder in PowerShell:

```powershell
# Create a venv once (skip if you already have one).
python -m venv .venv

# Activate it each time you open a new PowerShell session.
.\.venv\Scripts\Activate.ps1

# Install dependencies once in that venv.
python -m pip install netmiko openpyxl

# Run the script.
python .\access_vlan_report.py
```

For your current setup, where the script is inside `.venv\Scripts`, run these commands from that folder. Activation is unnecessary because you explicitly use the venv's Python:

```powershell
.\python.exe -m pip install netmiko openpyxl
.\python.exe .\access_vlan_report.py
```

## Inventory and credentials

Save **devices.xlsx** beside `access_vlan_report.py`. Put headers in row 1 of the first worksheet:

| IP Address | Hostname | Device Type |
|---|---|---|
| 192.168.15.2 | Switch-01 | cisco_ios |
| 192.168.15.3 | Nexus-01 | cisco_nxos |

`Hostname` and `Device Type` are optional. The script reads the hostname from the switch prompt and defaults to `cisco_ios` for IOS/IOS XE. Use `cisco_nxos` for Nexus.

Enter your TACACS and local fallback credentials when prompted. Passwords are hidden and not saved. Local credentials are retried only after authentication rejection; the switch's AAA policy determines whether they are accepted. Add `--enable` if a separate enable secret is required.

## Output

The report is saved as `vlan_reports\<timestamp>\access_vlan_report.xlsx` under the folder you run the command from:

- **VLAN Summary:** configured access-port totals and up/down counts per VLAN, including a row for switches with zero access ports.
- **Device Status:** collection results, errors, credential set used, stack membership, and total access-port counts.

The script uses read-only show commands and does not change switch configuration. Up means connected, not verified traffic flow. Close the output workbook while collection is running so progress saves can succeed.
