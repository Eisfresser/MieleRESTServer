#!/usr/bin/env python3
#
# Copyright (c) 2025 Alexander Kappner.
#
# This file is part of MieleRESTServer
# (see github).
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
"""
Interactive setup script for MieleRESTServer.

Guides the user through steps 0-3 of the README:
  0) Reset guidance
  1) Provision WiFi on the Miele device
  2) Provision cryptographic keys
  3) Generate the server configuration file

Cross-platform: works on macOS, Linux, and Windows.

Usage:
    python setup.py
"""

import ipaddress
import json
import sys
import textwrap

try:
    import requests
    import requests.packages.urllib3
except ImportError:
    sys.exit(
        "Missing dependency: requests\n"
        "Install it with:  pip install -r requirements.txt"
    )

try:
    import yaml
except ImportError:
    sys.exit(
        "Missing dependency: PyYAML\n"
        "Install it with:  pip install -r requirements.txt"
    )

try:
    import MieleCrypto
except ImportError:
    sys.exit(
        "Cannot import MieleCrypto. "
        "Please run this script from the MieleRESTServer repository root."
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def prompt(message, default=None):
    """Prompt the user for input, with an optional default value."""
    if default is not None:
        message = f"{message} [{default}]"
    value = input(f"{message}: ").strip()
    if not value and default is not None:
        return default
    return value


def prompt_ip(message):
    """Prompt for a valid IPv4/IPv6 address."""
    while True:
        raw = prompt(message)
        try:
            ipaddress.ip_address(raw)
            return raw
        except ValueError:
            print(f"  '{raw}' is not a valid IP address. Please try again.")


def prompt_yes_no(message, default_yes=True):
    """Prompt for a yes/no answer."""
    hint = "Y/n" if default_yes else "y/N"
    answer = input(f"{message} [{hint}]: ").strip().lower()
    if not answer:
        return default_yes
    return answer in ("y", "yes")


def banner(text):
    """Print a section banner."""
    width = 60
    print()
    print("=" * width)
    print(f"  {text}")
    print("=" * width)
    print()


# ---------------------------------------------------------------------------
# Step 0 – Reset guidance
# ---------------------------------------------------------------------------

def step0_reset_guidance():
    banner("Step 0: Device Reset")
    print(textwrap.dedent("""\
        If your Miele device has previously been provisioned (steps 1-2),
        it must be reset before it will accept a new configuration.

        To reset: use the local control panel on your Miele device.

        If the device is brand-new or has never been provisioned, you can
        skip this step.
    """))
    prompt_yes_no("Have you reset the device (or is it new)?")


# ---------------------------------------------------------------------------
# Step 1 – Provision WiFi
# ---------------------------------------------------------------------------

WIFI_TIMEOUT = (3, 3)  # (connect, read) in seconds


def provision_wifi(device_ip, ssid, password, security="WPA2"):
    """Send WiFi credentials to the Miele device.

    Tries HTTP first, then HTTPS, matching provision-wifi.sh behaviour.
    Returns True if at least one attempt succeeds.
    """
    payload = json.dumps({"SSID": ssid, "Sec": security, "Key": password})
    headers = {"Content-Type": "application/json"}
    success = False

    for scheme in ("http", "https"):
        url = f"{scheme}://{device_ip}/WLAN"
        print(f"  Trying {scheme.upper()} PUT {url} ...")
        try:
            resp = requests.put(
                url,
                data=payload,
                headers=headers,
                timeout=WIFI_TIMEOUT,
                verify=False,
            )
            print(f"    Response: {resp.status_code} {resp.text.strip()}")
            if resp.status_code < 400:
                success = True
        except requests.RequestException as exc:
            print(f"    Failed: {exc}")

    return success


def step1_provision_wifi():
    banner("Step 1: Provision WiFi")
    print(textwrap.dedent("""\
        Connect your computer to the Miele device's own access point
        (SSID starting with "Miele@home").

        The Miele appliance IS the access point, so its IP is typically
        your default gateway. To find it:
          - macOS/Linux:  ip route | grep default   (or: route -n get default)
          - Windows:      ipconfig  (look for "Default Gateway")
          - It is usually something like 192.168.0.1 or 192.168.1.1

        Alternatively, if the Miele AP does not run DHCP, you can run your
        own DHCP server (e.g. dnsmasq) and check which IP it assigns.
    """))

    device_ip = prompt_ip("Miele appliance IP (typically your default gateway)")
    ssid = prompt("Target WiFi SSID (the network you want the appliance to join)")
    password = prompt("Target WiFi password")
    security = prompt("WiFi security type", default="WPA2")

    # Suppress InsecureRequestWarning for self-signed certs
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )

    ok = provision_wifi(device_ip, ssid, password, security)
    if ok:
        print("\n  WiFi provisioning sent successfully.")
        print("  The device should now disconnect its AP and join the target WiFi.")
    else:
        print("\n  WARNING: Both HTTP and HTTPS attempts failed.")
        print("  Check the device IP and ensure you are connected to the Miele AP.")

    return ok


# ---------------------------------------------------------------------------
# Step 2 – Provision cryptographic keys
# ---------------------------------------------------------------------------

KEY_TIMEOUT = (3, 3)


def generate_keys():
    """Generate a random MieleProvisioningInfo and return it."""
    return MieleCrypto.MieleProvisioningInfo.generate_random()


def provision_keys(device_ip, keys_json):
    """Upload cryptographic keys to the Miele device.

    Tries HTTP first, then HTTPS with the pairing auth header,
    matching provision-key.sh behaviour.
    Returns True if at least one attempt succeeds.
    """
    success = False

    # HTTP attempt
    print(f"  Trying HTTP PUT http://{device_ip}/Security/Commissioning ...")
    try:
        resp = requests.put(
            f"http://{device_ip}/Security/Commissioning",
            data=keys_json,
            headers={"Content-Type": "application/json"},
            timeout=KEY_TIMEOUT,
        )
        print(f"    Response: {resp.status_code} {resp.text.strip()}")
        if resp.status_code < 400:
            success = True
    except requests.RequestException as exc:
        print(f"    Failed: {exc}")

    # HTTPS attempt (with pairing header, no cert verification)
    print(f"  Trying HTTPS PUT https://{device_ip}/Security/Commissioning ...")
    try:
        resp = requests.put(
            f"https://{device_ip}/Security/Commissioning",
            data=keys_json,
            headers={
                "Content-Type": "application/json",
                "Authorization": "MielePairing:Pairing",
            },
            timeout=KEY_TIMEOUT,
            verify=False,
        )
        print(f"    Response: {resp.status_code} {resp.text.strip()}")
        if resp.status_code < 400:
            success = True
    except requests.RequestException as exc:
        print(f"    Failed: {exc}")

    return success


def step2_provision_keys():
    banner("Step 2: Provision Cryptographic Keys")
    print(textwrap.dedent("""\
        Now connect your computer to the SAME WiFi network that you
        told the Miele appliance to join in step 1.

        The Miele appliance has a NEW IP on this network (different from
        step 1!), assigned by your home router. To find it:
          - Check your router's admin page for DHCP leases
          - Use a network scanner:  nmap -sn 192.168.1.0/24
          - Look for a device named "Miele" or a new/unknown host
    """))

    device_ip = prompt_ip("IP address of the Miele appliance on your home WiFi")

    info = generate_keys()
    keys_json = info.to_pairing_json()

    print(f"\n  Generated keys:")
    print(f"    GroupID:  {info.groupid}")
    print(f"    GroupKey: {info.groupkey.hex().upper()}")
    print(f"\n  Save these — you will need them for the server configuration.\n")

    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )

    ok = provision_keys(device_ip, keys_json)
    if ok:
        print("\n  Key provisioning sent successfully.")
        print("  The device will now require encrypted/signed communication.")
    else:
        print("\n  WARNING: Both HTTP and HTTPS attempts failed.")
        print("  Check the device IP and network connectivity.")

    return {
        "ip": device_ip,
        "groupId": info.groupid,
        "groupKey": info.groupkey.hex().upper(),
        "ok": ok,
    }


# ---------------------------------------------------------------------------
# Step 3 – Create server configuration
# ---------------------------------------------------------------------------

def build_device_entry(name, host, group_id, group_key, route="auto"):
    """Build a single device entry for the config."""
    return (name, {
        "host": host,
        "groupId": group_id,
        "groupKey": group_key,
        "route": route,
    })


def write_config(path, devices):
    """Write the server configuration YAML file.

    devices: list of (name, dict) tuples.
    """
    config = {"endpoints": dict(devices)}

    with open(path, "w") as fh:
        fh.write("#default location: /etc/MieleRESTServer.config\n")
        yaml.dump(config, fh, default_flow_style=False, sort_keys=False)

    print(f"\n  Configuration written to: {path}")


def prompt_device_entry(defaults=None):
    """Interactively prompt for one device's configuration."""
    defaults = defaults or {}
    name = prompt("Device name (e.g. washer, dryer)")
    host = defaults.get("ip") or prompt_ip("IP address of the Miele appliance")
    group_id = defaults.get("groupId") or prompt("GroupID")
    group_key = defaults.get("groupKey") or prompt("GroupKey")
    route = prompt("Device route (12-digit serial, or 'auto')", default="auto")
    return build_device_entry(name, host, group_id, group_key, route)


def step3_create_config(provisioned_devices=None):
    banner("Step 3: Create Server Configuration")
    provisioned_devices = provisioned_devices or []

    devices = []

    # Pre-fill from provisioned devices
    for dev in provisioned_devices:
        print(f"  Using provisioned device at {dev['ip']}:")
        name = prompt("  Device name (e.g. washer, dryer)")
        route = prompt("  Device route (12-digit serial, or 'auto')", default="auto")
        devices.append(build_device_entry(
            name, dev["ip"], dev["groupId"], dev["groupKey"], route,
        ))

    # Prompt for additional devices
    while True:
        if devices:
            if not prompt_yes_no("Add another device?", default_yes=False):
                break
        elif not provisioned_devices:
            print("  Enter device details manually.\n")

        if not devices and not provisioned_devices:
            devices.append(prompt_device_entry())
        elif not devices:
            # We had provisioned devices but somehow ended up empty — shouldn't happen
            break
        else:
            devices.append(prompt_device_entry())

    if not devices:
        print("  No devices configured. Skipping config file creation.")
        return

    config_path = prompt(
        "Output config file path",
        default="./MieleRESTServer.config",
    )
    write_config(config_path, devices)
    print(
        "\n  To use this config, copy it to /etc/MieleRESTServer.config"
        "\n  or the location expected by your server setup."
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(textwrap.dedent("""\

        ╔══════════════════════════════════════════════════════════╗
        ║         MieleRESTServer — Interactive Setup             ║
        ╠══════════════════════════════════════════════════════════╣
        ║  This script walks you through steps 0-3 of the README ║
        ║  to set up your Miele device and server configuration.  ║
        ║                                                         ║
        ║  You can skip any step if you have already completed it.║
        ╚══════════════════════════════════════════════════════════╝
    """))

    provisioned_devices = []

    # Step 0
    if prompt_yes_no("Run Step 0 (reset guidance)?"):
        step0_reset_guidance()

    # Step 1
    run_step1 = prompt_yes_no("Run Step 1 (provision WiFi)?")
    if run_step1:
        step1_provision_wifi()

    # Step 2 – may provision multiple devices
    run_step2 = prompt_yes_no("Run Step 2 (provision cryptographic keys)?")
    if run_step2:
        while True:
            result = step2_provision_keys()
            provisioned_devices.append(result)
            if not prompt_yes_no("Provision another device?", default_yes=False):
                break

    # Step 3
    if prompt_yes_no("Run Step 3 (create server config)?"):
        step3_create_config(provisioned_devices)

    banner("Setup Complete")
    print("  Next steps:")
    print("    - Install the server (step 4): sudo ./install.sh")
    print("    - Test: http://{YOUR_SERVER_IP}:5001/generate-summary/")
    print()


if __name__ == "__main__":
    main()
