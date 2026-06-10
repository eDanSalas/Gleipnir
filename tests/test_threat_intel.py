
from __future__ import annotations

import subprocess
import unittest
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from src.detector import BLACKLISTED_EXTERNAL_IP, BlacklistedExternalIPEvent
from src.threat_intel import (
    STATUS_ERROR,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_SKIPPED,
    ThreatIntelCache,
    ThreatIntelResult,
    check_abuseipdb,
    check_virustotal,
    check_whois,
    enrich_blacklisted_ip_event,
    enrich_external_ip,
)


@dataclass(frozen=True)
class DummyConfig:
    log_dir: Path
    abuseipdb_api_key: str | None = "abuse-key"
    virustotal_api_key: str | None = "vt-key"
    threat_intel_timeout_seconds: float = 2.5
    threat_intel_cache_ttl_seconds: int = 86_400


class FakeResponse:
    def __init__(self, status_code: int, payload=None) -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


class ThreatIntelTests(unittest.TestCase):
    def test_check_abuseipdb_uses_api_key_and_caches_result(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))
            cache = ThreatIntelCache(Path(temp_dir) / "cache.json")
            request_get = Mock(
                return_value=FakeResponse(
                    200,
                    {"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 12}},
                )
            )

            first = check_abuseipdb(
                "8.8.8.8",
                config=config,
                cache=cache,
                request_get=request_get,
            )
            second = check_abuseipdb(
                "8.8.8.8",
                config=config,
                cache=cache,
                request_get=request_get,
            )

        self.assertEqual(first.status, STATUS_OK)
        self.assertFalse(first.cached)
        self.assertEqual(second.status, STATUS_OK)
        self.assertTrue(second.cached)
        request_get.assert_called_once()
        _, kwargs = request_get.call_args
        self.assertEqual(kwargs["headers"]["Key"], "abuse-key")
        self.assertEqual(kwargs["timeout"], 2.5)

    def test_check_virustotal_uses_api_key(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))
            request_get = Mock(
                return_value=FakeResponse(
                    200,
                    {"data": {"id": "1.1.1.1", "type": "ip_address"}},
                )
            )

            result = check_virustotal(
                "1.1.1.1",
                config=config,
                request_get=request_get,
            )

        self.assertEqual(result.status, STATUS_OK)
        _, kwargs = request_get.call_args
        self.assertEqual(kwargs["headers"]["x-apikey"], "vt-key")
        self.assertIn("1.1.1.1", request_get.call_args.args[0])

    def test_missing_api_key_skips_without_network_call(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir), abuseipdb_api_key=None)
            request_get = Mock()

            result = check_abuseipdb(
                "8.8.8.8",
                config=config,
                request_get=request_get,
            )

        self.assertEqual(result.status, STATUS_SKIPPED)
        self.assertIn("ABUSEIPDB_API_KEY", result.error)
        request_get.assert_not_called()

    def test_api_rate_limit_is_reported_without_exception(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))
            request_get = Mock(return_value=FakeResponse(429, {}))

            result = check_abuseipdb(
                "8.8.4.4",
                config=config,
                request_get=request_get,
            )

        self.assertEqual(result.status, STATUS_RATE_LIMITED)
        self.assertTrue(result.rate_limited)

    def test_api_error_is_reported_without_exception(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))
            request_get = Mock(return_value=FakeResponse(500, {}))

            result = check_virustotal(
                "8.8.4.4",
                config=config,
                request_get=request_get,
            )

        self.assertEqual(result.status, STATUS_ERROR)
        self.assertIn("HTTP 500", result.error)

    def test_network_error_is_reported_without_exception(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))
            request_get = Mock(side_effect=OSError("network down"))

            result = check_abuseipdb(
                "9.9.9.9",
                config=config,
                request_get=request_get,
            )

        self.assertEqual(result.status, STATUS_ERROR)
        self.assertIn("network down", result.error)

    def test_timeout_is_reported_without_exception(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))
            request_get = Mock(side_effect=TimeoutError("request timed out"))

            result = check_abuseipdb(
                "9.9.9.9",
                config=config,
                request_get=request_get,
            )

        self.assertEqual(result.status, STATUS_ERROR)
        self.assertIn("timed out", result.error)

    def test_incomplete_api_response_is_reported(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))
            request_get = Mock(return_value=FakeResponse(200, {}))

            result = check_virustotal(
                "8.8.4.4",
                config=config,
                request_get=request_get,
            )

        self.assertEqual(result.status, STATUS_ERROR)
        self.assertIn("Incomplete", result.error)

    def test_check_whois_uses_runner_and_caches_result(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))
            cache = ThreatIntelCache(Path(temp_dir) / "cache.json")
            runner = Mock(
                return_value=subprocess.CompletedProcess(
                    args=["whois", "8.8.8.8"],
                    returncode=0,
                    stdout="OrgName: Example Provider\n",
                    stderr="",
                )
            )

            first = check_whois(
                "8.8.8.8",
                config=config,
                cache=cache,
                whois_runner=runner,
            )
            second = check_whois(
                "8.8.8.8",
                config=config,
                cache=cache,
                whois_runner=runner,
            )

        self.assertEqual(first.status, STATUS_OK)
        self.assertIn("OrgName", first.data["raw"])
        self.assertTrue(second.cached)
        runner.assert_called_once()
        _, kwargs = runner.call_args
        self.assertEqual(kwargs["timeout"], 2.5)
        self.assertFalse(kwargs["check"])

    def test_check_whois_extracts_provider_asn_and_abuse_contact(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))
            runner = Mock(
                return_value=subprocess.CompletedProcess(
                    args=["whois", "8.8.8.8"],
                    returncode=0,
                    stdout=(
                        "OrgName: Example Hosting\n"
                        "NetName: EXAMPLE-NET\n"
                        "OriginAS: AS64500\n"
                        "OrgAbuseEmail: abuse@example.net\n"
                        "Comment: noc@example.net\n"
                    ),
                    stderr="",
                )
            )

            result = check_whois(
                "8.8.8.8",
                config=config,
                whois_runner=runner,
            )

        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["organization"], "Example Hosting")
        self.assertEqual(result.data["provider"], "EXAMPLE-NET")
        self.assertEqual(result.data["asn"], "AS64500")
        self.assertEqual(result.data["abuse_contact"], "abuse@example.net")
        self.assertIn("abuse@example.net", result.data["emails"])

    def test_check_whois_incomplete_response_is_reported(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))
            runner = Mock(
                return_value=subprocess.CompletedProcess(
                    args=["whois", "8.8.8.8"],
                    returncode=0,
                    stdout="",
                    stderr="",
                )
            )

            result = check_whois(
                "8.8.8.8",
                config=config,
                whois_runner=runner,
            )

        self.assertEqual(result.status, STATUS_ERROR)
        self.assertIn("Incomplete Whois response", result.error)

    def test_check_whois_rate_limit_is_reported(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))
            runner = Mock(
                return_value=subprocess.CompletedProcess(
                    args=["whois", "8.8.8.8"],
                    returncode=0,
                    stdout="Rate limit exceeded. Try again later.",
                    stderr="",
                )
            )

            result = check_whois(
                "8.8.8.8",
                config=config,
                whois_runner=runner,
            )

        self.assertEqual(result.status, STATUS_RATE_LIMITED)
        self.assertTrue(result.rate_limited)

    def test_private_ip_is_skipped(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))
            request_get = Mock()

            result = check_virustotal(
                "192.168.1.10",
                config=config,
                request_get=request_get,
            )

        self.assertEqual(result.status, STATUS_SKIPPED)
        self.assertIn("not external", result.error)
        request_get.assert_not_called()

    def test_enrich_external_ip_keeps_working_when_one_source_fails(self) -> None:
        ok_result = ThreatIntelResult(
            service="abuseipdb",
            ip="8.8.8.8",
            status=STATUS_OK,
        )
        vt_result = ThreatIntelResult(
            service="virustotal",
            ip="8.8.8.8",
            status=STATUS_OK,
        )
        whois_result = ThreatIntelResult(
            service="whois",
            ip="8.8.8.8",
            status=STATUS_OK,
        )

        with patch("src.threat_intel.check_abuseipdb", return_value=ok_result):
            with patch("src.threat_intel.check_virustotal", side_effect=RuntimeError("boom")):
                with patch("src.threat_intel.check_whois", return_value=whois_result):
                    results = enrich_external_ip("8.8.8.8", config=Mock(), cache=Mock())

        self.assertEqual(results["abuseipdb"], ok_result)
        self.assertEqual(results["virustotal"].status, STATUS_ERROR)
        self.assertIn("boom", results["virustotal"].error)
        self.assertEqual(results["whois"], whois_result)

    def test_enrich_blacklisted_ip_event_attaches_results(self) -> None:
        event = BlacklistedExternalIPEvent(
            event_type=BLACKLISTED_EXTERNAL_IP,
            timestamp=1710000000.25,
            ip_origen="192.168.1.10",
            ip_destino="8.8.8.8",
            protocolo="TCP",
            motivo="Malware C2",
            severidad="ALTA",
            alert_sent=True,
        )
        result = ThreatIntelResult(
            service="abuseipdb",
            ip="8.8.8.8",
            status=STATUS_OK,
        )

        with patch("src.threat_intel.enrich_external_ip", return_value={"abuseipdb": result}):
            enriched = enrich_blacklisted_ip_event(event, config=Mock(), cache=Mock())

        self.assertEqual(enriched.event_type, BLACKLISTED_EXTERNAL_IP)
        self.assertEqual(enriched.threat_intel_results["abuseipdb"], result)
        self.assertEqual(event.threat_intel_results, {})


if __name__ == "__main__":
    unittest.main()
