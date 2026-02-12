"""Tests for miele_device_setup.py"""

import ipaddress
import json
import os
import socket
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, call, mock_open, patch

# Ensure repo root is on sys.path so we can import the module under test.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Provide a mock MieleCrypto so the import succeeds even when the real
# module's native dependencies (cryptography/numpy) are unavailable.
if "MieleCrypto" not in sys.modules:
    _mock_mc = types.ModuleType("MieleCrypto")
    _mock_info = MagicMock()
    _mock_info.groupid = "AABBCCDD00112233"
    _mock_info.groupkey = MagicMock()
    _mock_info.groupkey.hex.return_value = "00" * 64
    _mock_info.to_pairing_json.return_value = '{"groupId":"AABBCCDD00112233"}'
    _mock_cls = MagicMock()
    _mock_cls.generate_random.return_value = _mock_info
    _mock_mc.MieleProvisioningInfo = _mock_cls
    sys.modules["MieleCrypto"] = _mock_mc

import miele_device_setup as setup


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestPrompt(unittest.TestCase):
    @patch("builtins.input", return_value="hello")
    def test_returns_user_input(self, _):
        self.assertEqual(setup.prompt("msg"), "hello")

    @patch("builtins.input", return_value="")
    def test_returns_default_on_empty_input(self, _):
        self.assertEqual(setup.prompt("msg", default="fallback"), "fallback")

    @patch("builtins.input", return_value="override")
    def test_user_overrides_default(self, _):
        self.assertEqual(setup.prompt("msg", default="fallback"), "override")

    @patch("builtins.input", return_value="  spaced  ")
    def test_strips_whitespace(self, _):
        self.assertEqual(setup.prompt("msg"), "spaced")


class TestPromptIp(unittest.TestCase):
    @patch("builtins.input", return_value="192.168.1.1")
    def test_valid_ip(self, _):
        self.assertEqual(setup.prompt_ip("IP"), "192.168.1.1")

    @patch("builtins.input", return_value="")
    def test_default_ip(self, _):
        self.assertEqual(setup.prompt_ip("IP", default="10.0.0.1"), "10.0.0.1")

    @patch("builtins.input", side_effect=["not-an-ip", "192.168.0.5"])
    def test_retries_on_invalid(self, _):
        self.assertEqual(setup.prompt_ip("IP"), "192.168.0.5")

    @patch("builtins.input", return_value="::1")
    def test_ipv6(self, _):
        self.assertEqual(setup.prompt_ip("IP"), "::1")


class TestPromptYesNo(unittest.TestCase):
    @patch("builtins.input", return_value="")
    def test_default_yes(self, _):
        self.assertTrue(setup.prompt_yes_no("q?", default_yes=True))

    @patch("builtins.input", return_value="")
    def test_default_no(self, _):
        self.assertFalse(setup.prompt_yes_no("q?", default_yes=False))

    @patch("builtins.input", return_value="y")
    def test_yes(self, _):
        self.assertTrue(setup.prompt_yes_no("q?"))

    @patch("builtins.input", return_value="yes")
    def test_yes_full(self, _):
        self.assertTrue(setup.prompt_yes_no("q?"))

    @patch("builtins.input", return_value="n")
    def test_no(self, _):
        self.assertFalse(setup.prompt_yes_no("q?"))

    @patch("builtins.input", return_value="NO")
    def test_no_case_insensitive(self, _):
        self.assertFalse(setup.prompt_yes_no("q?"))


class TestBanner(unittest.TestCase):
    @patch("builtins.print")
    def test_banner_prints_equals_lines(self, mock_print):
        setup.banner("Test")
        # Should print: blank, ===, text, ===, blank
        calls = [c.args[0] if c.args else "" for c in mock_print.call_args_list]
        self.assertTrue(any("=" * 60 in str(c) for c in calls))
        self.assertTrue(any("Test" in str(c) for c in calls))


# ---------------------------------------------------------------------------
# Network discovery
# ---------------------------------------------------------------------------

class TestDetectDefaultGateway(unittest.TestCase):
    @patch("platform.system", return_value="Linux")
    @patch("subprocess.check_output",
           return_value="default via 192.168.1.1 dev wlan0 proto dhcp\n")
    def test_linux(self, *_):
        self.assertEqual(setup.detect_default_gateway(), "192.168.1.1")

    @patch("platform.system", return_value="Darwin")
    @patch("subprocess.check_output",
           return_value="   route to: default\n   gateway: 10.0.0.1\n")
    def test_macos(self, *_):
        self.assertEqual(setup.detect_default_gateway(), "10.0.0.1")

    @patch("platform.system", return_value="Windows")
    @patch("subprocess.check_output",
           return_value="   Default Gateway . . . : 172.16.0.1\n")
    def test_windows(self, *_):
        self.assertEqual(setup.detect_default_gateway(), "172.16.0.1")

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.check_output", side_effect=FileNotFoundError)
    def test_returns_none_on_error(self, *_):
        self.assertIsNone(setup.detect_default_gateway())

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.check_output", return_value="")
    def test_returns_none_on_empty_output(self, *_):
        self.assertIsNone(setup.detect_default_gateway())


class TestGetLocalIp(unittest.TestCase):
    @patch("socket.socket")
    def test_returns_ip(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.50", 0)
        mock_sock_cls.return_value = mock_sock
        self.assertEqual(setup.get_local_ip(), "192.168.1.50")

    @patch("socket.socket", side_effect=OSError)
    def test_returns_none_on_error(self, _):
        self.assertIsNone(setup.get_local_ip())


class TestProbeHost(unittest.TestCase):
    @patch("socket.socket")
    def test_returns_ip_on_port80(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None  # success
        mock_sock_cls.return_value = mock_sock
        self.assertEqual(setup._probe_host("1.2.3.4"), "1.2.3.4")

    @patch("socket.socket")
    def test_returns_none_when_both_fail(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout
        mock_sock_cls.return_value = mock_sock
        self.assertIsNone(setup._probe_host("1.2.3.4"))

    @patch("socket.socket")
    def test_returns_ip_on_port443_fallback(self, mock_sock_cls):
        mock_sock = MagicMock()
        # Port 80 fails, port 443 succeeds
        mock_sock.connect.side_effect = [socket.timeout, None]
        mock_sock_cls.return_value = mock_sock
        self.assertEqual(setup._probe_host("1.2.3.4"), "1.2.3.4")


class TestScanSubnet(unittest.TestCase):
    @patch("miele_device_setup.get_local_ip", return_value="127.0.0.1")
    def test_returns_empty_for_loopback(self, _):
        self.assertEqual(setup.scan_subnet(), [])

    @patch("miele_device_setup.get_local_ip", return_value=None)
    def test_returns_empty_when_no_local_ip(self, _):
        self.assertEqual(setup.scan_subnet(), [])

    @patch("miele_device_setup._probe_host")
    @patch("miele_device_setup.get_local_ip", return_value="192.168.1.50")
    def test_excludes_local_ip_and_specified(self, _, mock_probe):
        # Only "respond" for a single host
        def probe(ip):
            return ip if ip == "192.168.1.100" else None
        mock_probe.side_effect = probe

        found = setup.scan_subnet(exclude=["192.168.1.1"])
        self.assertIn("192.168.1.100", found)
        self.assertNotIn("192.168.1.50", found)
        self.assertNotIn("192.168.1.1", found)

    @patch("miele_device_setup._probe_host", return_value=None)
    @patch("miele_device_setup.get_local_ip", return_value="192.168.1.50")
    def test_returns_empty_when_no_hosts_respond(self, *_):
        self.assertEqual(setup.scan_subnet(), [])


# ---------------------------------------------------------------------------
# mDNS discovery
# ---------------------------------------------------------------------------

class TestDiscoverMieleMdns(unittest.TestCase):
    @patch.object(setup, "HAS_ZEROCONF", False)
    def test_returns_empty_without_zeroconf(self):
        self.assertEqual(setup.discover_miele_mdns(timeout=0.01), [])

    @patch.object(setup, "HAS_ZEROCONF", True)
    @patch.object(setup, "Zeroconf", create=True)
    @patch.object(setup, "ServiceBrowser", create=True)
    @patch("time.sleep")
    def test_returns_found_devices(self, mock_sleep, mock_browser_cls,
                                   mock_zc_cls):
        mock_zc = MagicMock()
        mock_zc_cls.return_value = mock_zc

        # Simulate the listener getting called with a service
        def fake_browser(zc, stype, listener):
            # Simulate add_service being called
            mock_info = MagicMock()
            mock_info.parsed_addresses.return_value = ["192.168.1.77"]
            zc.get_service_info.return_value = mock_info
            listener.add_service(zc, stype, "washer._mieleathome._tcp.local.")
            return MagicMock()

        mock_browser_cls.side_effect = fake_browser

        result = setup.discover_miele_mdns(timeout=0.01)
        self.assertEqual(result, ["192.168.1.77"])
        mock_zc.close.assert_called_once()

    @patch.object(setup, "HAS_ZEROCONF", True)
    @patch.object(setup, "Zeroconf", create=True)
    @patch.object(setup, "ServiceBrowser", create=True)
    @patch("time.sleep")
    def test_no_duplicates(self, mock_sleep, mock_browser_cls, mock_zc_cls):
        mock_zc = MagicMock()
        mock_zc_cls.return_value = mock_zc

        def fake_browser(zc, stype, listener):
            mock_info = MagicMock()
            mock_info.parsed_addresses.return_value = ["192.168.1.77"]
            zc.get_service_info.return_value = mock_info
            listener.add_service(zc, stype, "dev1._mieleathome._tcp.local.")
            listener.add_service(zc, stype, "dev1._mieleathome._tcp.local.")
            return MagicMock()

        mock_browser_cls.side_effect = fake_browser

        result = setup.discover_miele_mdns(timeout=0.01)
        self.assertEqual(result, ["192.168.1.77"])


# ---------------------------------------------------------------------------
# WiFi AP password detection
# ---------------------------------------------------------------------------

class TestGetCurrentSsid(unittest.TestCase):
    @patch("platform.system", return_value="Linux")
    @patch("subprocess.check_output", return_value="Miele@home\n")
    def test_linux_iwgetid(self, *_):
        self.assertEqual(setup._get_current_ssid(), "Miele@home")

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.check_output", return_value="\n")
    def test_linux_empty(self, *_):
        self.assertIsNone(setup._get_current_ssid())

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.check_output", side_effect=FileNotFoundError)
    def test_returns_none_on_error(self, *_):
        self.assertIsNone(setup._get_current_ssid())

    @patch("platform.system", return_value="Windows")
    @patch("subprocess.check_output", return_value=(
        "    Name : Wi-Fi\n"
        "    SSID : Miele@home-TAA1234\n"
        "    BSSID : aa:bb:cc:dd:ee:ff\n"
    ))
    def test_windows(self, *_):
        self.assertEqual(setup._get_current_ssid(), "Miele@home-TAA1234")

    @patch("platform.system", return_value="Darwin")
    @patch("subprocess.check_output")
    def test_macos_airport(self, mock_check, _):
        mock_check.return_value = "         SSID: MyNetwork\n"
        self.assertEqual(setup._get_current_ssid(), "MyNetwork")


class TestDetectMieleApPassword(unittest.TestCase):
    @patch("miele_device_setup._get_current_ssid", return_value="Miele@home")
    def test_plain_ssid(self, _):
        pw, explanation = setup.detect_miele_ap_password()
        self.assertEqual(pw, "secured-by-tls")
        self.assertIn("secured-by-tls", explanation)

    @patch("miele_device_setup._get_current_ssid",
           return_value="Miele@home-TAA1234")
    def test_suffixed_ssid(self, _):
        pw, explanation = setup.detect_miele_ap_password()
        self.assertIsNone(pw)
        self.assertIn("serial number", explanation)
        self.assertIn("TAA1234", explanation)

    @patch("miele_device_setup._get_current_ssid", return_value="MyHomeWifi")
    def test_unrelated_ssid(self, _):
        pw, explanation = setup.detect_miele_ap_password()
        self.assertIsNone(pw)
        self.assertIn("does not look like a Miele AP", explanation)

    @patch("miele_device_setup._get_current_ssid", return_value=None)
    def test_no_ssid(self, _):
        pw, explanation = setup.detect_miele_ap_password()
        self.assertIsNone(pw)
        self.assertIn("Could not detect", explanation)


# ---------------------------------------------------------------------------
# WiFi provisioning
# ---------------------------------------------------------------------------

class TestProvisionWifi(unittest.TestCase):
    @patch("requests.put")
    def test_http_success(self, mock_put):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "OK"
        mock_put.return_value = mock_resp

        result = setup.provision_wifi("192.168.1.1", "MyWifi", "pass123")
        self.assertTrue(result)
        # Should have been called for both http and https
        self.assertEqual(mock_put.call_count, 2)

    @patch("requests.put")
    def test_both_fail(self, mock_put):
        mock_put.side_effect = setup.requests.RequestException("timeout")
        result = setup.provision_wifi("192.168.1.1", "MyWifi", "pass123")
        self.assertFalse(result)

    @patch("requests.put")
    def test_http_fails_https_succeeds(self, mock_put):
        mock_fail = MagicMock()
        mock_fail.status_code = 500
        mock_fail.text = "error"
        mock_ok = MagicMock()
        mock_ok.status_code = 200
        mock_ok.text = "OK"
        mock_put.side_effect = [mock_fail, mock_ok]

        result = setup.provision_wifi("192.168.1.1", "MyWifi", "pass123")
        self.assertTrue(result)

    @patch("requests.put")
    def test_payload_format(self, mock_put):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "OK"
        mock_put.return_value = mock_resp

        setup.provision_wifi("10.0.0.1", "NetName", "secret", security="WPA2")

        first_call = mock_put.call_args_list[0]
        body = json.loads(first_call.kwargs["data"])
        self.assertEqual(body["SSID"], "NetName")
        self.assertEqual(body["Key"], "secret")
        self.assertEqual(body["Sec"], "WPA2")

    @patch("requests.put")
    def test_https_disables_cert_verify(self, mock_put):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "OK"
        mock_put.return_value = mock_resp

        setup.provision_wifi("10.0.0.1", "Net", "pw")

        # Second call is HTTPS — verify=False
        https_call = mock_put.call_args_list[1]
        self.assertFalse(https_call.kwargs["verify"])


# ---------------------------------------------------------------------------
# Key provisioning (with retries)
# ---------------------------------------------------------------------------

class TestProvisionKeys(unittest.TestCase):
    @patch("time.sleep")
    @patch("requests.put")
    def test_http_succeeds_first_try(self, mock_put, mock_sleep):
        ok_resp = MagicMock(status_code=200, text="OK")
        mock_put.return_value = ok_resp

        result = setup.provision_keys("192.168.1.1", '{"groupId":"abc"}')
        self.assertTrue(result)

    @patch("time.sleep")
    @patch("requests.put")
    def test_retries_on_failure(self, mock_put, mock_sleep):
        fail_exc = setup.requests.RequestException("conn refused")
        ok_resp = MagicMock(status_code=200, text="OK")
        # HTTP: fail, fail (2 retries); HTTPS: succeed first try
        mock_put.side_effect = [fail_exc, fail_exc, ok_resp]

        result = setup.provision_keys("192.168.1.1", '{"groupId":"abc"}')
        self.assertTrue(result)
        # Should have slept between HTTP retries
        mock_sleep.assert_called()

    @patch("time.sleep")
    @patch("requests.put")
    def test_all_retries_fail(self, mock_put, mock_sleep):
        mock_put.side_effect = setup.requests.RequestException("timeout")

        result = setup.provision_keys("192.168.1.1", '{"groupId":"abc"}')
        self.assertFalse(result)
        # 2 HTTP attempts + 2 HTTPS attempts = 4 total
        self.assertEqual(mock_put.call_count, 4)

    @patch("time.sleep")
    @patch("requests.put")
    def test_http_400_retries_then_https_succeeds(self, mock_put, mock_sleep):
        err_resp = MagicMock(status_code=400, text="Bad Request")
        ok_resp = MagicMock(status_code=200, text="OK")
        # HTTP: 400 twice (retries); HTTPS: 200
        mock_put.side_effect = [err_resp, err_resp, ok_resp]

        result = setup.provision_keys("192.168.1.1", '{"k":"v"}')
        self.assertTrue(result)

    @patch("time.sleep")
    @patch("requests.put")
    def test_https_uses_pairing_header(self, mock_put, mock_sleep):
        fail_resp = MagicMock(status_code=500, text="err")
        ok_resp = MagicMock(status_code=200, text="OK")
        # HTTP fails both retries; HTTPS succeeds
        mock_put.side_effect = [fail_resp, fail_resp, ok_resp]

        setup.provision_keys("10.0.0.1", '{}')

        # The third call is the first HTTPS attempt
        https_call = mock_put.call_args_list[2]
        self.assertEqual(
            https_call.kwargs["headers"]["Authorization"],
            "MielePairing:Pairing",
        )
        self.assertFalse(https_call.kwargs["verify"])

    @patch("time.sleep")
    @patch("requests.put")
    def test_http_success_breaks_early(self, mock_put, mock_sleep):
        ok_resp = MagicMock(status_code=200, text="OK")
        mock_put.return_value = ok_resp

        setup.provision_keys("10.0.0.1", '{}')

        # HTTP succeeds on first try (1 call) + HTTPS succeeds on first try
        # (1 call) = 2 total (not 4)
        self.assertEqual(mock_put.call_count, 2)


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

class TestBuildDeviceEntry(unittest.TestCase):
    def test_structure(self):
        name, config = setup.build_device_entry(
            "washer", "192.168.1.10", "AABB", "CCDD", "auto"
        )
        self.assertEqual(name, "washer")
        self.assertEqual(config["host"], "192.168.1.10")
        self.assertEqual(config["groupId"], "AABB")
        self.assertEqual(config["groupKey"], "CCDD")
        self.assertEqual(config["route"], "auto")

    def test_default_route(self):
        _, config = setup.build_device_entry(
            "dryer", "10.0.0.1", "GID", "GKEY"
        )
        self.assertEqual(config["route"], "auto")


class TestWriteConfig(unittest.TestCase):
    def test_writes_valid_yaml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                         delete=False) as f:
            path = f.name

        try:
            devices = [
                ("washer", {
                    "host": "192.168.1.10",
                    "groupId": "AABB",
                    "groupKey": "CCDD",
                    "route": "auto",
                }),
                ("dryer", {
                    "host": "192.168.1.11",
                    "groupId": "EEFF",
                    "groupKey": "1122",
                    "route": "000012345678",
                }),
            ]
            setup.write_config(path, devices)

            import yaml
            with open(path) as fh:
                content = fh.read()
                # Starts with the default-location comment
                self.assertIn("#default location:", content)

            with open(path) as fh:
                # Skip the comment line for YAML parsing
                lines = fh.readlines()
                yaml_text = "".join(
                    l for l in lines if not l.startswith("#")
                )
                data = yaml.safe_load(yaml_text)

            self.assertIn("endpoints", data)
            self.assertEqual(data["endpoints"]["washer"]["host"], "192.168.1.10")
            self.assertEqual(data["endpoints"]["dryer"]["route"], "000012345678")
        finally:
            os.unlink(path)

    def test_multiple_devices(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                         delete=False) as f:
            path = f.name

        try:
            devices = [
                setup.build_device_entry("a", "1.1.1.1", "g1", "k1"),
                setup.build_device_entry("b", "2.2.2.2", "g2", "k2"),
                setup.build_device_entry("c", "3.3.3.3", "g3", "k3"),
            ]
            setup.write_config(path, devices)

            import yaml
            with open(path) as fh:
                lines = fh.readlines()
                yaml_text = "".join(
                    l for l in lines if not l.startswith("#")
                )
                data = yaml.safe_load(yaml_text)

            self.assertEqual(len(data["endpoints"]), 3)
            self.assertIn("a", data["endpoints"])
            self.assertIn("b", data["endpoints"])
            self.assertIn("c", data["endpoints"])
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Probe WiFi password (HTTP/HTTPS endpoint check)
# ---------------------------------------------------------------------------

class TestProbeWifiPassword(unittest.TestCase):
    @patch("requests.get")
    def test_http_works(self, mock_get):
        mock_resp = MagicMock(status_code=200)
        mock_get.return_value = mock_resp
        self.assertEqual(setup.probe_wifi_password("10.0.0.1"), "http")

    @patch("requests.get")
    def test_https_fallback(self, mock_get):
        # HTTP fails, HTTPS works
        mock_ok = MagicMock(status_code=200)
        mock_get.side_effect = [
            setup.requests.RequestException("refused"),
            mock_ok,
        ]
        self.assertEqual(setup.probe_wifi_password("10.0.0.1"), "https")

    @patch("requests.get")
    def test_both_fail(self, mock_get):
        mock_get.side_effect = setup.requests.RequestException("timeout")
        self.assertIsNone(setup.probe_wifi_password("10.0.0.1"))

    @patch("requests.get")
    def test_500_is_rejected(self, mock_get):
        mock_resp = MagicMock(status_code=500)
        mock_get.return_value = mock_resp
        self.assertIsNone(setup.probe_wifi_password("10.0.0.1"))


if __name__ == "__main__":
    unittest.main()
