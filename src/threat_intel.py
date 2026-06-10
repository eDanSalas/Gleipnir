
from __future__ import annotations

import ipaddress
import json
import logging
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from src.logger import get_logger

if TYPE_CHECKING:
    from src.config import Config
else:
    Config = Any


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
CACHE_FILE_NAME = "threat_intel_cache.json"
DEFAULT_ABUSEIPDB_MAX_AGE_DAYS = 90
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

STATUS_OK = "ok"
STATUS_SKIPPED = "skipped"
STATUS_ERROR = "error"
STATUS_RATE_LIMITED = "rate_limited"

_LOGGER = get_logger("threat_intel")
_LOGGER.addHandler(logging.NullHandler())

RequestGet = Callable[..., Any]
WhoisRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class ThreatIntelResult:

    service: str
    ip: str
    status: str
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    cached: bool = False
    rate_limited: bool = False


class ThreatIntelCache:

    # FUN-130
    def __init__(
        self,
        cache_path: str | Path,
        *,
        ttl_seconds: int = 86_400,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.cache_path = Path(cache_path)
        self.ttl_seconds = ttl_seconds
        self._clock = clock

    # FUN-131
    def get(self, service: str, ip: str) -> ThreatIntelResult | None:
        cache_data = self._load()
        entry = cache_data.get(self._key(service, ip))
        if not isinstance(entry, dict):
            return None

        created_at = float(entry.get("created_at", 0))
        if self.ttl_seconds > 0 and self._clock() - created_at > self.ttl_seconds:
            return None

        result_data = entry.get("result")
        if not isinstance(result_data, dict):
            return None

        return ThreatIntelResult(**{**result_data, "cached": True})

    # FUN-132
    def set(self, result: ThreatIntelResult) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_data = self._load()
        storable_result = asdict(result)
        storable_result["cached"] = False
        cache_data[self._key(result.service, result.ip)] = {
            "created_at": self._clock(),
            "result": storable_result,
        }

        temp_path = self.cache_path.with_suffix(f"{self.cache_path.suffix}.tmp")
        temp_path.write_text(
            json.dumps(cache_data, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        temp_path.replace(self.cache_path)

    def _load(self) -> dict[str, Any]:
        if not self.cache_path.exists():
            return {}

        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

        return data if isinstance(data, dict) else {}

    @staticmethod
    def _key(service: str, ip: str) -> str:
        return f"{service}:{ip}"


# FUN-133
def check_abuseipdb(
    ip: str,
    *,
    config: Config | None = None,
    cache: ThreatIntelCache | None = None,
    request_get: RequestGet | None = None,
) -> ThreatIntelResult:
    normalized_ip = _normalize_ip(ip)
    service = "abuseipdb"
    if not _is_external_ip(normalized_ip):
        return _skipped(service, normalized_ip, "IP address is not external")

    cached = _cache_get(service, normalized_ip, config, cache)
    if cached is not None:
        return cached

    runtime_config = _runtime_config(config)
    # EXP-015
    if not runtime_config.abuseipdb_api_key:
        return _skipped(service, normalized_ip, "ABUSEIPDB_API_KEY is not configured")

    getter = request_get or _load_requests_get()
    timeout = runtime_config.threat_intel_timeout_seconds

    try:
        response = getter(
            ABUSEIPDB_URL,
            headers={
                "Accept": "application/json",
                "Key": runtime_config.abuseipdb_api_key,
            },
            params={
                "ipAddress": normalized_ip,
                "maxAgeInDays": DEFAULT_ABUSEIPDB_MAX_AGE_DAYS,
            },
            timeout=timeout,
        )
    except Exception as exc:
        return _network_error(service, normalized_ip, exc)

    result = _result_from_http_response(service, normalized_ip, response)
    _cache_set(result, config, cache)
    return result


# FUN-134
def check_virustotal(
    ip: str,
    *,
    config: Config | None = None,
    cache: ThreatIntelCache | None = None,
    request_get: RequestGet | None = None,
) -> ThreatIntelResult:
    normalized_ip = _normalize_ip(ip)
    service = "virustotal"
    if not _is_external_ip(normalized_ip):
        return _skipped(service, normalized_ip, "IP address is not external")

    cached = _cache_get(service, normalized_ip, config, cache)
    if cached is not None:
        return cached

    runtime_config = _runtime_config(config)
    if not runtime_config.virustotal_api_key:
        return _skipped(service, normalized_ip, "VIRUSTOTAL_API_KEY is not configured")

    getter = request_get or _load_requests_get()
    timeout = runtime_config.threat_intel_timeout_seconds

    try:
        response = getter(
            VIRUSTOTAL_IP_URL.format(ip=normalized_ip),
            headers={
                "Accept": "application/json",
                "x-apikey": runtime_config.virustotal_api_key,
            },
            timeout=timeout,
        )
    except Exception as exc:
        return _network_error(service, normalized_ip, exc)

    result = _result_from_http_response(service, normalized_ip, response)
    _cache_set(result, config, cache)
    return result


# FUN-135
def check_whois(
    ip: str,
    *,
    config: Config | None = None,
    cache: ThreatIntelCache | None = None,
    whois_runner: WhoisRunner | None = None,
) -> ThreatIntelResult:
    normalized_ip = _normalize_ip(ip)
    service = "whois"
    if not _is_external_ip(normalized_ip):
        return _skipped(service, normalized_ip, "IP address is not external")

    cached = _cache_get(service, normalized_ip, config, cache)
    if cached is not None:
        return cached

    runtime_config = _runtime_config(config)
    runner = whois_runner or subprocess.run
    timeout = runtime_config.threat_intel_timeout_seconds

    try:
        completed = runner(
            ["whois", normalized_ip],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return _network_error(service, normalized_ip, exc, "whois command is not available")
    except subprocess.TimeoutExpired as exc:
        return _network_error(service, normalized_ip, exc, "whois query timed out")
    except Exception as exc:
        return _network_error(service, normalized_ip, exc)

    output = (completed.stdout or "").strip()
    error_output = (completed.stderr or "").strip()
    combined_text = f"{output}\n{error_output}".lower()
    if _looks_rate_limited(combined_text):
        result = ThreatIntelResult(
            service=service,
            ip=normalized_ip,
            status=STATUS_RATE_LIMITED,
            data={},
            error="Whois rate limit encountered",
            rate_limited=True,
        )
        _cache_set(result, config, cache)
        return result

    if completed.returncode != 0:
        result = ThreatIntelResult(
            service=service,
            ip=normalized_ip,
            status=STATUS_ERROR,
            data={"stderr": _truncate(error_output)},
            error=f"Whois command exited with code {completed.returncode}",
        )
        _cache_set(result, config, cache)
        return result

    if not output:
        result = ThreatIntelResult(
            service=service,
            ip=normalized_ip,
            status=STATUS_ERROR,
            data={},
            error="Incomplete Whois response",
        )
        _cache_set(result, config, cache)
        return result

    result = ThreatIntelResult(
        service=service,
        ip=normalized_ip,
        status=STATUS_OK,
        data=_parse_whois_output(output),
    )
    _cache_set(result, config, cache)
    return result


# FUN-136
def enrich_external_ip(
    ip: str,
    *,
    config: Config | None = None,
    cache: ThreatIntelCache | None = None,
) -> dict[str, ThreatIntelResult]:
    normalized_ip = _normalize_ip(ip)
    results: dict[str, ThreatIntelResult] = {}

    for service, checker in (
        ("abuseipdb", check_abuseipdb),
        ("virustotal", check_virustotal),
        ("whois", check_whois),
    ):
        try:
            results[service] = checker(normalized_ip, config=config, cache=cache)
        except Exception as exc:
            _LOGGER.exception(
                "Threat intelligence source failed: service=%s ip=%s",
                service,
                normalized_ip,
            )
            results[service] = ThreatIntelResult(
                service=service,
                ip=normalized_ip,
                status=STATUS_ERROR,
                error=f"Unexpected enrichment error: {exc}",
            )

    return results


# FUN-137
def enrich_blacklisted_ip_event(
    event: Any,
    *,
    config: Config | None = None,
    cache: ThreatIntelCache | None = None,
) -> Any:
    results = enrich_external_ip(event.ip_destino, config=config, cache=cache)
    return replace(event, threat_intel_results=results)


def _result_from_http_response(
    service: str,
    ip: str,
    response: Any,
) -> ThreatIntelResult:
    status_code = int(getattr(response, "status_code", 0))
    if status_code == 429:
        return ThreatIntelResult(
            service=service,
            ip=ip,
            status=STATUS_RATE_LIMITED,
            data={},
            error="API rate limit encountered",
            rate_limited=True,
        )

    if status_code >= 400:
        return ThreatIntelResult(
            service=service,
            ip=ip,
            status=STATUS_ERROR,
            data={},
            error=f"API returned HTTP {status_code}",
        )

    try:
        payload = response.json()
    except Exception as exc:
        return ThreatIntelResult(
            service=service,
            ip=ip,
            status=STATUS_ERROR,
            data={},
            error=f"Invalid JSON response: {exc}",
        )

    if not isinstance(payload, dict) or not payload:
        return ThreatIntelResult(
            service=service,
            ip=ip,
            status=STATUS_ERROR,
            data={},
            error="Incomplete API response",
        )

    return ThreatIntelResult(
        service=service,
        ip=ip,
        status=STATUS_OK,
        data=payload,
    )


def _runtime_config(config: Config | None) -> Config:
    if config is not None:
        return config

    from src.config import load_config

    return load_config()


def _cache_from_config(config: Config | None, cache: ThreatIntelCache | None) -> ThreatIntelCache:
    if cache is not None:
        return cache

    runtime_config = _runtime_config(config)
    return ThreatIntelCache(
        runtime_config.log_dir / CACHE_FILE_NAME,
        ttl_seconds=runtime_config.threat_intel_cache_ttl_seconds,
    )


def _cache_get(
    service: str,
    ip: str,
    config: Config | None,
    cache: ThreatIntelCache | None,
) -> ThreatIntelResult | None:
    result = _cache_from_config(config, cache).get(service, ip)
    if result is not None:
        _LOGGER.info("Threat intelligence cache hit: service=%s ip=%s", service, ip)

    return result


def _cache_set(
    result: ThreatIntelResult,
    config: Config | None,
    cache: ThreatIntelCache | None,
) -> None:
    try:
        _cache_from_config(config, cache).set(result)
    except OSError as exc:
        _LOGGER.warning(
            "Threat intelligence cache write failed: service=%s ip=%s error=%s",
            result.service,
            result.ip,
            exc,
        )


def _skipped(service: str, ip: str, reason: str) -> ThreatIntelResult:
    _LOGGER.info(
        "Threat intelligence skipped: service=%s ip=%s reason=%s",
        service,
        ip,
        reason,
    )
    return ThreatIntelResult(
        service=service,
        ip=ip,
        status=STATUS_SKIPPED,
        error=reason,
    )


def _network_error(
    service: str,
    ip: str,
    exc: Exception,
    message: str | None = None,
) -> ThreatIntelResult:
    error = message or f"Network/API error: {exc}"
    _LOGGER.warning(
        "Threat intelligence source unavailable: service=%s ip=%s error=%s",
        service,
        ip,
        error,
    )
    return ThreatIntelResult(
        service=service,
        ip=ip,
        status=STATUS_ERROR,
        data={},
        error=error,
    )


def _normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def _is_external_ip(value: str) -> bool:
    return ipaddress.ip_address(value).is_global


def _load_requests_get() -> RequestGet:
    try:
        import requests
    except ImportError as exc:
        raise RuntimeError("requests is required for API threat intelligence checks") from exc

    return requests.get


def _looks_rate_limited(text: str) -> bool:
    return any(
        phrase in text
        for phrase in (
            "rate limit",
            "rate-limit",
            "too many requests",
            "exceeded",
            "try again later",
        )
    )


def _parse_whois_output(output: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {"raw": _truncate(output)}
    emails = sorted(set(EMAIL_PATTERN.findall(output)))
    if emails:
        parsed["emails"] = emails[:10]

    for raw_line in output.splitlines():
        if ":" not in raw_line:
            continue

        raw_key, raw_value = raw_line.split(":", maxsplit=1)
        key = _normalize_whois_key(raw_key)
        value = raw_value.strip()
        if not value:
            continue

        if key in {"orgname", "organization", "owner", "responsible"}:
            parsed.setdefault("organization", value)
        elif key in {"netname", "descr", "description", "custname"}:
            parsed.setdefault("provider", value)
        elif key in {"originas", "origin", "autnum", "asn"}:
            parsed.setdefault("asn", value)

        if "abuse" in key and ("email" in key or "mailbox" in key or "contact" in key):
            parsed.setdefault("abuse_contact", value)

    if "abuse_contact" not in parsed:
        abuse_email = next((email for email in emails if "abuse" in email.lower()), None)
        if abuse_email:
            parsed["abuse_contact"] = abuse_email

    return parsed


def _normalize_whois_key(value: str) -> str:
    return (
        value.strip()
        .lower()
        .replace("-", "")
        .replace("_", "")
        .replace(" ", "")
    )


def _truncate(value: str, limit: int = 5_000) -> str:
    if len(value) <= limit:
        return value

    return value[:limit] + "\n[truncated]"
