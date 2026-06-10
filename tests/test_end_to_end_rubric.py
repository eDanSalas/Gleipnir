"""End-to-end rubric verification for the simulated IDS flow."""

from __future__ import annotations

import io
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from src.config import Config
from src.detector import AUTHORIZED_DEVICE, BLACKLISTED_EXTERNAL_IP, UNAUTHORIZED_DEVICE
from src.runtime.engine import IDSEngine
from src.sniffer import parse_packet
from src.storage import DNS_EVENT, HTTP_EVENT, SQLiteEventStore, THREAT_INTEL_RESULT
from src.threat_intel import STATUS_OK, ThreatIntelResult


AUTHORIZED_IP = "192.168.1.10"
AUTHORIZED_MAC = "aa:bb:cc:dd:ee:ff"
DANGEROUS_IP = "203.0.113.50"
ADMIN_EMAIL = "admin@example.org"


def test_simulated_end_to_end_flow_covers_rubric_modules() -> None:
    """Verify the four main rubric modules without real traffic, SMTP, or internet."""
    with TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        _write_whitelist(root)
        _write_blacklist(root)
        config = _config(root)
        alert_sender = Mock()

        abuse_result = ThreatIntelResult(
            service="abuseipdb",
            ip=DANGEROUS_IP,
            status=STATUS_OK,
            data={
                "data": {
                    "abuseConfidenceScore": 95,
                    "totalReports": 12,
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Example Threat Hosting",
                }
            },
        )
        virustotal_result = ThreatIntelResult(
            service="virustotal",
            ip=DANGEROUS_IP,
            status=STATUS_OK,
            data={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 4,
                            "suspicious": 1,
                        }
                    }
                }
            },
        )
        whois_result = ThreatIntelResult(
            service="whois",
            ip=DANGEROUS_IP,
            status=STATUS_OK,
            data={
                "organization": "Example Hosting",
                "provider": "EXAMPLE-NET",
                "asn": "AS64500",
                "abuse_contact": "abuse@example.net",
                "emails": ["abuse@example.net", "noc@example.net"],
            },
        )

        with (
            patch(
                "src.detector._is_external_ip",
                side_effect=lambda ip: ip == DANGEROUS_IP,
            ),
            patch("src.threat_intel.check_abuseipdb", return_value=abuse_result) as abuse_mock,
            patch(
                "src.threat_intel.check_virustotal",
                return_value=virustotal_result,
            ) as virustotal_mock,
            patch("src.threat_intel.check_whois", return_value=whois_result) as whois_mock,
        ):
            engine = IDSEngine.from_config(
                config=config,
                alert_sender=alert_sender,
                console_stream=io.StringIO(),
            )

            authorized_result = engine.process_packet_event(
                _packet(
                    ip_origen=AUTHORIZED_IP,
                    mac_origen=AUTHORIZED_MAC,
                    ip_destino="192.168.1.1",
                )
            )
            unauthorized_result = engine.process_packet_event(
                _packet(
                    ip_origen="192.168.1.20",
                    mac_origen="00:11:22:33:44:55",
                    ip_destino="192.168.1.1",
                )
            )
            dns_result = engine.process_packet_event(
                parse_packet(_dns_packet()),
                dns_http_source=_dns_packet(),
            )
            http_result = engine.process_packet_event(
                parse_packet(_http_packet()),
                dns_http_source=_http_packet(),
            )
            blacklisted_result = engine.process_packet_event(
                _packet(
                    ip_origen=AUTHORIZED_IP,
                    mac_origen=AUTHORIZED_MAC,
                    ip_destino=DANGEROUS_IP,
                )
            )
            engine.shutdown()

        assert authorized_result.detection_event.event_type == AUTHORIZED_DEVICE
        assert unauthorized_result.detection_event.event_type == UNAUTHORIZED_DEVICE
        assert unauthorized_result.detection_event.alert_sent is True

        assert len(dns_result.dns_http_events) == 1
        dns_event = dns_result.dns_http_events[0]
        assert dns_event.dominio_consultado == "ejemplo.com"
        assert dns_event.tipo_consulta == "A"

        assert len(http_result.dns_http_events) == 1
        http_event = http_result.dns_http_events[0]
        assert http_event.host == "ejemplo.com"
        assert http_event.metodo == "GET"
        assert http_event.ruta == "/"

        assert blacklisted_result.blacklist_event is not None
        assert blacklisted_result.blacklist_event.event_type == BLACKLISTED_EXTERNAL_IP
        assert blacklisted_result.blacklist_event.ip_destino == DANGEROUS_IP
        assert blacklisted_result.blacklist_event.motivo == "Botnet"
        assert blacklisted_result.blacklist_event.alert_sent is True
        assert blacklisted_result.threat_intel_results["abuseipdb"] == abuse_result
        assert blacklisted_result.threat_intel_results["virustotal"] == virustotal_result
        assert blacklisted_result.threat_intel_results["whois"] == whois_result

        abuse_mock.assert_called_once()
        virustotal_mock.assert_called_once()
        whois_mock.assert_called_once()
        assert abuse_mock.call_args.args[0] == DANGEROUS_IP
        assert virustotal_mock.call_args.args[0] == DANGEROUS_IP
        assert whois_mock.call_args.args[0] == DANGEROUS_IP

        assert alert_sender.call_count == 3
        subjects = [call.args[0] for call in alert_sender.call_args_list]
        bodies = [call.args[1] for call in alert_sender.call_args_list]
        recipients = [call.args[2] for call in alert_sender.call_args_list]

        assert all(recipient == ADMIN_EMAIL for recipient in recipients)
        assert any(UNAUTHORIZED_DEVICE in subject for subject in subjects)
        assert any("ALERTA DE EMERGENCIA" in subject for subject in subjects)
        assert any("Reporte Forense" in subject for subject in subjects)

        unauthorized_body = next(body for subject, body in zip(subjects, bodies) if UNAUTHORIZED_DEVICE in subject)
        emergency_body = next(body for subject, body in zip(subjects, bodies) if "ALERTA DE EMERGENCIA" in subject)
        forensic_body = next(body for subject, body in zip(subjects, bodies) if "Reporte Forense" in subject)

        assert "192.168.1.20" in unauthorized_body
        assert DANGEROUS_IP in emergency_body
        assert "Botnet" in emergency_body
        assert DANGEROUS_IP in forensic_body
        assert "Botnet" in forensic_body
        assert "abuseipdb" in forensic_body
        assert "whois" in forensic_body
        assert "virustotal" in forensic_body
        assert "abuse@example.net" in forensic_body

        store = SQLiteEventStore(config.ids_db_path)
        report_data = store.build_report_data()
        dns_events = store.fetch_events(DNS_EVENT)
        http_events = store.fetch_events(HTTP_EVENT)
        threat_events = store.fetch_events(THREAT_INTEL_RESULT)
        store.close()

        assert len(report_data.authorized_devices) >= 1
        assert len(report_data.unauthorized_devices) == 1
        assert len(report_data.dns_events) == 1
        assert len(report_data.http_events) == 1
        assert len(report_data.blacklisted_external_ips) == 1
        assert len(report_data.threat_intel_results) == 3
        assert dns_events[0].domain == "ejemplo.com"
        assert http_events[0].domain == "ejemplo.com"
        assert {event.raw["service"] for event in threat_events} == {
            "abuseipdb",
            "virustotal",
            "whois",
        }


def _config(root: Path) -> Config:
    return Config(
        smtp_host="smtp.example.org",
        smtp_port=587,
        smtp_user="alerts@example.org",
        smtp_password="dummy-smtp-password",
        admin_email=ADMIN_EMAIL,
        whitelist_file=root / "whitelist.csv",
        blacklist_file=root / "blacklist.txt",
        log_dir=root / "logs",
        report_dir=root / "reports",
        ids_db_path=root / "gleipnir_events.db",
        abuseipdb_api_key="dummy-abuse-key",
        virustotal_api_key="dummy-vt-key",
        alert_cooldown_seconds=0,
        alert_max_per_minute=10,
    )


def _write_whitelist(root: Path) -> None:
    (root / "whitelist.csv").write_text(
        "ip,mac,description\n"
        f"{AUTHORIZED_IP},{AUTHORIZED_MAC},Laptop autorizada\n",
        encoding="utf-8",
    )


def _write_blacklist(root: Path) -> None:
    (root / "blacklist.txt").write_text(
        f"{DANGEROUS_IP},Botnet\n",
        encoding="utf-8",
    )


def _packet(
    *,
    ip_origen: str,
    mac_origen: str,
    ip_destino: str,
    protocolo: str = "TCP",
):
    return parse_packet(
        {
            "timestamp": 1710000000.25,
            "mac_origen": mac_origen,
            "mac_destino": "66:55:44:33:22:11",
            "ip_origen": ip_origen,
            "ip_destino": ip_destino,
            "protocolo": protocolo,
        }
    )


def _dns_packet() -> dict[str, object]:
    return {
        "timestamp": 1710000001.0,
        "mac_origen": AUTHORIZED_MAC,
        "mac_destino": "66:55:44:33:22:11",
        "ip_origen": AUTHORIZED_IP,
        "ip_destino": "192.168.1.53",
        "protocolo": "UDP",
        "dns_domain": "ejemplo.com.",
        "dns_query_type": "A",
    }


def _http_packet() -> dict[str, object]:
    return {
        "timestamp": 1710000002.0,
        "mac_origen": AUTHORIZED_MAC,
        "mac_destino": "66:55:44:33:22:11",
        "ip_origen": AUTHORIZED_IP,
        "ip_destino": "192.168.1.80",
        "protocolo": "TCP",
        "http_host": "ejemplo.com",
        "http_method": "GET",
        "http_path": "/",
    }
