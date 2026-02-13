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

Cross-platform: works on macOS, probably on Linux, possibly on Windows.

Usage:
    python miele_device_setup.py
"""

from __future__ import annotations

import ipaddress
import json
import platform
import socket
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

try:
    import requests
    import requests.packages.urllib3  # type: ignore[import-untyped]
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

# Optional: zeroconf for mDNS-based Miele device discovery
try:
    from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    HAS_ZEROCONF = True
except ImportError:
    HAS_ZEROCONF = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def prompt(message: str, default: str | None = None) -> str:
    """Prompt the user for input, with an optional default value."""
    if default is not None:
        message = f"{message} [{default}]"
    value = input(f"{message}: ").strip()
    if not value and default is not None:
        return default
    return value


def prompt_ip(message: str, default: str | None = None) -> str:
    """Prompt for a valid IPv4/IPv6 address, with optional default."""
    while True:
        raw = prompt(message, default=default)
        try:
            ipaddress.ip_address(raw)
            return raw
        except ValueError:
            print(f"  '{raw}' is not a valid IP address. Please try again.")


def prompt_yes_no(message: str, default_yes: bool = True) -> bool:
    """Prompt for a yes/no answer."""
    hint = "Y/n" if default_yes else "y/N"
    answer = input(f"{message} [{hint}]: ").strip().lower()
    if not answer:
        return default_yes
    return answer in ("y", "yes")


def banner(text: str) -> None:
    """Print a section banner."""
    width = 60
    print()
    print("=" * width)
    print(f"  {text}")
    print("=" * width)
    print()


# ---------------------------------------------------------------------------
# Network discovery
# ---------------------------------------------------------------------------

SCAN_TIMEOUT = 0.5  # seconds per host


def detect_default_gateway() -> str | None:
    """Try to detect the default gateway address. Returns IP string or None."""
    try:
        system = platform.system()
        if system == "Windows":
            output = subprocess.check_output(
                ["ipconfig"], text=True, stderr=subprocess.DEVNULL,
            )
            for line in output.splitlines():
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        gw = parts[-1].strip()
                        if gw:
                            ipaddress.ip_address(gw)
                            return gw
        elif system == "Darwin":
            output = subprocess.check_output(
                ["route", "-n", "get", "default"],
                text=True, stderr=subprocess.DEVNULL,
            )
            for line in output.splitlines():
                if "gateway:" in line:
                    gw = line.split("gateway:")[-1].strip()
                    ipaddress.ip_address(gw)
                    return gw
        else:  # Linux
            output = subprocess.check_output(
                ["ip", "route", "show", "default"],
                text=True, stderr=subprocess.DEVNULL,
            )
            # "default via 192.168.0.1 dev wlan0 ..."
            parts = output.split()
            if "via" in parts:
                gw = parts[parts.index("via") + 1]
                ipaddress.ip_address(gw)
                return gw
    except Exception:
        pass
    return None


def get_local_ip() -> str | None:
    """Get the local IP address of this machine on the current network.
    
    This UDP socket trick seems to be the most reliable cross-platform method in pure Python. 
    The alternatives all have problems:
      - socket.gethostbyname(socket.gethostname()) — Often returns 127.0.0.1 on Linux (depends on /etc/hosts config). Unreliable.
      - socket.getaddrinfo() — Same issue; it resolves the hostname, which may not map to the LAN interface.
      - netifaces / psutil — Work well but are external dependencies. netifaces is also unmaintained.
      - Parsing ifconfig/ip addr — Not portable across OSes, brittle.
    """
  
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        # Connect to a non-routable address — doesn't send any packets,
        # but the OS picks the right source interface.
        s.connect(("10.254.254.254", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _probe_host(ip: str) -> str | None:
    """Try to open a TCP connection on port 80 or 443. Returns ip or None."""
    for port in (80, 443):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SCAN_TIMEOUT)
            s.connect((ip, port))
            s.close()
            return ip
        except (socket.timeout, OSError):
            pass
    return None


def discover_miele_mdns(timeout: float = 5.0) -> list[str]:
    """Discover Miele devices via mDNS (_mieleathome._tcp.local).

    Returns a list of IP strings.  Requires the ``zeroconf`` package.
    """
    if not HAS_ZEROCONF:
        return []

    class _Listener(ServiceListener):
        def __init__(self) -> None:
            self.found = []

        def add_service(self, zc: Any, stype: str, name: str) -> None:
            info = zc.get_service_info(stype, name)
            if info:
                for addr in info.parsed_addresses():
                    if addr not in self.found:
                        self.found.append(addr)

        def remove_service(self, zc: Any, stype: str, name: str) -> None:
            pass

        def update_service(self, zc: Any, stype: str, name: str) -> None:
            pass

    zc = Zeroconf()
    listener = _Listener()
    ServiceBrowser(zc, "_mieleathome._tcp.local.", listener)

    import time
    time.sleep(timeout)
    zc.close()
    return listener.found


def probe_wifi_password(device_ip: str) -> str | None:
    """Try to reach the Miele device's /WLAN endpoint to verify connectivity.

    Tests both HTTP and HTTPS to determine which protocol the device speaks.
    Returns the working scheme ('http' or 'https') or None.
    """
    for scheme in ("http", "https"):
        try:
            resp = requests.get(
                f"{scheme}://{device_ip}/WLAN",
                timeout=(2, 2),
                verify=False,
            )
            if resp.status_code < 500:
                return scheme
        except requests.RequestException:
            pass
    return None


def detect_miele_ap_password() -> tuple[str | None, str]:
    """Detect the correct WiFi password for the Miele access point.

    Returns (password, explanation) tuple, or (None, explanation) on failure.

    Two SSID/password patterns exist:
      - SSID "Miele@home" (no suffix) -> password is "secured-by-tls"
      - SSID "Miele@home-{suffix}" -> password is the device serial number
    """
    # We can detect which case we're in by checking the current SSID
    ssid = _get_current_ssid()
    if ssid is None:
        return None, "Could not detect current SSID."
    if ssid == "Miele@home":
        return "secured-by-tls", (
            f'Connected to "{ssid}" — password is "secured-by-tls".'
        )
    if ssid.startswith("Miele@home-"):
        suffix = ssid[len("Miele@home-"):]
        return None, (
            f'Connected to "{ssid}" — the password is the device '
            f"serial number (from the physical sticker on the appliance). "
            f"The SSID suffix is \"{suffix}\"."
        )
    return None, f'Current SSID "{ssid}" does not look like a Miele AP.'


def _get_current_ssid() -> str | None:
    """Return the SSID of the currently connected WiFi network, or None."""
    try:
        system = platform.system()
        if system == "Darwin":
            # macOS 14.4+ uses the 'networksetup' approach; try airport first
            try:
                out = subprocess.check_output(
                    ["/System/Library/PrivateFrameworks/Apple80211.framework/"
                     "Versions/Current/Resources/airport", "-I"],
                    text=True, stderr=subprocess.DEVNULL,
                )
                for line in out.splitlines():
                    if " SSID:" in line:
                        return line.split("SSID:")[-1].strip()
            except Exception:
                pass
            # Fallback: networksetup
            out = subprocess.check_output(
                ["networksetup", "-getairportnetwork", "en0"],
                text=True, stderr=subprocess.DEVNULL,
            )
            if "Current Wi-Fi Network:" in out:
                return out.split("Current Wi-Fi Network:")[-1].strip()
        elif system == "Linux":
            out = subprocess.check_output(
                ["iwgetid", "-r"],
                text=True, stderr=subprocess.DEVNULL,
            )
            return out.strip() or None
        elif system == "Windows":
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                text=True, stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    return line.split(":")[-1].strip()
    except Exception:
        pass
    return None


def scan_subnet(exclude: list[str] | None = None) -> list[str]:
    """Scan the local /24 for hosts with open HTTP/HTTPS ports.

    Returns a sorted list of IP strings.
    """
    local_ip = get_local_ip()
    if not local_ip or local_ip.startswith("127."):
        return []

    excluded: set[str] = set(exclude or [])
    excluded.add(local_ip)

    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    hosts = [str(h) for h in network.hosts() if str(h) not in excluded]

    print(f"  Scanning {network} ({len(hosts)} hosts) ...")

    found = []
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_probe_host, h): h for h in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    found.sort(key=lambda ip: ipaddress.IPv4Address(ip))
    return found


# ---------------------------------------------------------------------------
# Step 0 – Reset guidance
# ---------------------------------------------------------------------------

def step0_reset_guidance() -> None:
    banner("Step 0: Device Reset")
    print(textwrap.dedent("""\
        If your Miele device has previously been provisioned (steps 1-2),
        it must be reset before it will accept a new configuration.

        To reset: use the local control panel on your Miele device.

        If the device is brand-new or has never been provisioned, you can
        skip this step.

        IMPORTANT TIMING:
        After a reset, the device takes ~90 seconds to boot its WiFi
        module. It then opens its access point for only ~30 minutes.
        Complete steps 1 and 2 within this window.
    """))
    prompt_yes_no("Have you reset the device (or is it new)?")


# ---------------------------------------------------------------------------
# Step 1 – Provision WiFi
# ---------------------------------------------------------------------------

WIFI_TIMEOUT = (3, 3)  # (connect, read) in seconds


def provision_wifi(device_ip: str, ssid: str, password: str, security: str = "WPA2") -> bool:
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


def step1_provision_wifi() -> bool:
    banner("Step 1: Provision WiFi")
    print(textwrap.dedent("""\
        Connect your computer to the Miele device's own access point
        (SSID starting with "Miele@home").

        WiFi password for the Miele AP:
          - SSID "Miele@home" (no suffix) -> password: secured-by-tls
          - SSID "Miele@home-XXX"         -> password: device serial number
                                             (from the sticker on the appliance)

        REMINDER: The AP is only available for ~30 minutes after a reset.

        If the Miele device runs its own DHCP server, its IP is your
        default gateway. If you are running your own DHCP server
        (e.g. dnsmasq), the Miele's IP is whatever was assigned to it.

        The script will try to detect the device automatically.
    """))

    # Try to detect which Miele AP SSID we're connected to and tell the user
    # the correct password.
    pw, explanation = detect_miele_ap_password()
    if explanation:
        print(f"  {explanation}")
        if pw:
            print(f"  -> AP password: {pw}\n")
        else:
            print()

    device_ip = None

    # Strategy 1: the Miele runs DHCP → it is the gateway.
    gw = detect_default_gateway()
    if gw:
        print(f"  Detected default gateway: {gw}")
        device_ip = prompt_ip("Miele appliance IP", default=gw)
    else:
        # Strategy 2: user runs their own DHCP server (dnsmasq) →
        # the Miele is the only other host on this point-to-point link.
        print("  No default gateway detected (you may be running your own DHCP).")
        print("  Scanning for the Miele device on the local subnet ...\n")
        candidates = scan_subnet(exclude=[gw] if gw else [])
        if len(candidates) == 1:
            print(f"  Found one device: {candidates[0]}")
            device_ip = prompt_ip("Miele appliance IP", default=candidates[0])
        elif candidates:
            print(f"  Found {len(candidates)} device(s):")
            for i, ip in enumerate(candidates, 1):
                print(f"    {i}) {ip}")
            print()
            device_ip = prompt_ip("Miele appliance IP (pick from above or enter manually)")
        else:
            print("  No devices found on the local subnet.")
            device_ip = prompt_ip("Miele appliance IP")
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
        print()
        print("  TIP: Assign a static IP or DHCP reservation on your router for")
        print("  the Miele device now. This prevents IP changes from breaking the")
        print("  server configuration later.")
    else:
        print("\n  WARNING: Both HTTP and HTTPS attempts failed.")
        print("  Check the device IP and ensure you are connected to the Miele AP.")

    return ok


# ---------------------------------------------------------------------------
# Step 2 – Provision cryptographic keys
# ---------------------------------------------------------------------------

KEY_TIMEOUT = (3, 3)


def generate_keys() -> Any:
    """Generate a random MieleProvisioningInfo and return it."""
    return MieleCrypto.MieleProvisioningInfo.generate_random()


KEY_RETRIES = 2


def provision_keys(device_ip: str, keys_json: str) -> bool:
    """Upload cryptographic keys to the Miele device.

    Tries HTTP first, then HTTPS with the pairing auth header,
    matching provision-key.sh behaviour.  Each protocol is attempted
    up to KEY_RETRIES times (devices can be flaky).
    Returns True if at least one attempt succeeds.
    """
    import time

    success = False

    # HTTP attempts
    for attempt in range(1, KEY_RETRIES + 1):
        print(f"  Trying HTTP PUT http://{device_ip}/Security/Commissioning "
              f"(attempt {attempt}/{KEY_RETRIES}) ...")
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
                break
        except requests.RequestException as exc:
            print(f"    Failed: {exc}")
        if attempt < KEY_RETRIES:
            time.sleep(1)

    # HTTPS attempts (with pairing header, no cert verification)
    for attempt in range(1, KEY_RETRIES + 1):
        print(f"  Trying HTTPS PUT https://{device_ip}/Security/Commissioning "
              f"(attempt {attempt}/{KEY_RETRIES}) ...")
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
                break
        except requests.RequestException as exc:
            print(f"    Failed: {exc}")
        if attempt < KEY_RETRIES:
            time.sleep(1)

    return success


def step2_provision_keys() -> dict[str, Any]:
    banner("Step 2: Provision Cryptographic Keys")
    print(textwrap.dedent("""\
        Now connect your computer to the SAME WiFi network that you
        told the Miele appliance to join in step 1.

        The Miele appliance has a NEW IP on this network (different from
        step 1!), assigned by your home router.
    """))

    # Trigger any local firewall prompt early.  macOS firewalls (Little
    # Snitch, LuLu, etc.) may ask the user to allow Python on first
    # network access — doing this now avoids racing against scan timeouts.
    print("  (Probing network — approve any firewall prompt that appears)\n")
    _probe_host(detect_default_gateway() or "192.168.1.1")

    prompt_yes_no("Are you connected to your home WiFi network?")

    device_ip = None

    # Strategy 1: mDNS discovery (most precise — only finds Miele devices)
    if HAS_ZEROCONF:
        print("  Searching for Miele devices via mDNS (_mieleathome._tcp.local) ...")
        mdns_results = discover_miele_mdns(timeout=5.0)
        if mdns_results:
            print(f"  Found {len(mdns_results)} Miele device(s) via mDNS:")
            for i, ip in enumerate(mdns_results, 1):
                print(f"    {i}) {ip}")
            print()
            if len(mdns_results) == 1:
                device_ip = prompt_ip("Miele appliance IP", default=mdns_results[0])
            else:
                device_ip = prompt_ip(
                    "Miele appliance IP (pick from above or enter manually)"
                )
        else:
            print("  No Miele devices found via mDNS.")
    else:
        print("  TIP: Install 'zeroconf' (pip install zeroconf) for precise")
        print("  Miele device discovery via mDNS instead of a subnet scan.\n")

    # Strategy 2: fall back to subnet scan
    if device_ip is None:
        gw = detect_default_gateway()
        exclude = [gw] if gw else []
        candidates = scan_subnet(exclude=exclude)

        if len(candidates) == 1:
            print(f"  Found one device: {candidates[0]}")
            device_ip = prompt_ip("Miele appliance IP", default=candidates[0])
        elif candidates:
            print(f"  Found {len(candidates)} device(s) with open HTTP/HTTPS ports:")
            for i, ip in enumerate(candidates, 1):
                print(f"    {i}) {ip}")
            print()
            device_ip = prompt_ip(
                "Miele appliance IP (pick from above or enter manually)"
            )
        else:
            print("  No devices found on the local subnet.")
            print("  Enter the Miele appliance IP manually.")
            device_ip = prompt_ip("Miele appliance IP")

    info = generate_keys()
    keys_json = info.to_pairing_json()

    print("\n  Generated keys:")
    print(f"    GroupID:  {info.groupid}")
    print(f"    GroupKey: {info.groupkey.hex().upper()}")
    print("\n  Save these — you will need them for the server configuration.\n")

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

def build_device_entry(name: str, host: str, group_id: str, group_key: str, route: str = "auto") -> tuple[str, dict[str, str]]:
    """Build a single device entry for the config."""
    return (name, {
        "host": host,
        "groupId": group_id,
        "groupKey": group_key,
        "route": route,
    })


def write_config(path: str, devices: list[tuple[str, dict[str, str]]]) -> None:
    """Write the server configuration YAML file.

    devices: list of (name, dict) tuples.
    """
    config = {"endpoints": dict(devices)}

    with open(path, "w") as fh:
        fh.write("#default location: /etc/MieleRESTServer.config\n")
        yaml.dump(config, fh, default_flow_style=False, sort_keys=False)

    print(f"\n  Configuration written to: {path}")


def prompt_device_entry(defaults: dict[str, str] | None = None) -> tuple[str, dict[str, str]]:
    """Interactively prompt for one device's configuration."""
    defaults = defaults or {}
    name = prompt("Device name (e.g. washer, dryer)")
    host = defaults.get("ip") or prompt_ip("IP address of the Miele appliance")
    group_id = defaults.get("groupId") or prompt("GroupID")
    group_key = defaults.get("groupKey") or prompt("GroupKey")
    route = prompt("Device route (12-digit serial, or 'auto')", default="auto")
    return build_device_entry(name, host, group_id, group_key, route)


def step3_create_config(provisioned_devices: list[dict[str, Any]] | None = None) -> None:
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

def main() -> None:
    print(textwrap.dedent("""\

        ╔══════════════════════════════════════════════════════════╗
        ║         MieleRESTServer — Interactive Device Setup       ║
        ╠══════════════════════════════════════════════════════════╣
        ║  This script walks you through steps 0-3 of the README   ║
        ║  to set up your Miele device and server configuration.   ║
        ║                                                          ║
        ║  You can skip any step if you have already completed it. ║
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

    banner("Miele device setup complete")

if __name__ == "__main__":
    main()
