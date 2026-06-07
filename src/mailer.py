"""SMTP alert delivery for Gleipnir IDS."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Any


DEFAULT_SMTP_TIMEOUT = 10


class MailerError(RuntimeError):
    """Raised when an alert email cannot be prepared or sent."""


def send_alert(subject: str, message: str, recipient: str) -> None:
    """Send an alert email using SMTP/TLS configuration from config.py."""
    config = _load_runtime_config()
    _send_alert_with_config(config, subject, message, recipient)


def _send_alert_with_config(
    config: Any,
    subject: str,
    message: str,
    recipient: str,
) -> None:
    _validate_email_input(subject, message, recipient)

    email = EmailMessage()
    email["Subject"] = subject.strip()
    email["From"] = config.smtp_user
    email["To"] = recipient.strip()
    email.set_content(message)

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP(
            config.smtp_host,
            config.smtp_port,
            timeout=DEFAULT_SMTP_TIMEOUT,
        ) as smtp:
            smtp.starttls(context=context)
            smtp.login(config.smtp_user, config.smtp_password)
            smtp.send_message(email)
    except (OSError, smtplib.SMTPException) as exc:
        raise MailerError("Failed to send alert email through configured SMTP") from exc


def _validate_email_input(subject: str, message: str, recipient: str) -> None:
    if not subject or not subject.strip():
        raise MailerError("Alert subject is required")

    if not message or not message.strip():
        raise MailerError("Alert message is required")

    if not recipient or not recipient.strip():
        raise MailerError("Alert recipient is required")


def _load_runtime_config() -> Any:
    from src.config import load_config

    return load_config()
