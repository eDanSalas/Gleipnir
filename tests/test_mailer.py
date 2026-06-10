
from __future__ import annotations

import unittest
from dataclasses import dataclass
from email.message import EmailMessage
from unittest.mock import Mock, patch

from src.mailer import MailerError, send_alert


@dataclass(frozen=True)
class DummyConfig:
    smtp_host: str = "smtp.example.org"
    smtp_port: int = 587
    smtp_user: str = "alerts@example.org"
    smtp_password: str = "smtp-secret"
    admin_email: str = "admin@example.org"


class MailerTests(unittest.TestCase):
    @patch("src.mailer.smtplib.SMTP")
    @patch("src.mailer._load_runtime_config")
    def test_send_alert_uses_tls_login_and_send_message(
        self,
        load_runtime_config: Mock,
        smtp_class: Mock,
    ) -> None:
        config = DummyConfig()
        load_runtime_config.return_value = config
        smtp = smtp_class.return_value.__enter__.return_value

        send_alert("Alerta IDS", "Equipo no autorizado detectado", config.admin_email)

        smtp_class.assert_called_once_with(
            config.smtp_host,
            config.smtp_port,
            timeout=10,
        )
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with(config.smtp_user, config.smtp_password)
        smtp.send_message.assert_called_once()

        sent_message = smtp.send_message.call_args.args[0]
        self.assertIsInstance(sent_message, EmailMessage)
        self.assertEqual(sent_message["Subject"], "Alerta IDS")
        self.assertEqual(sent_message["From"], config.smtp_user)
        self.assertEqual(sent_message["To"], config.admin_email)
        self.assertIn("Equipo no autorizado detectado", sent_message.get_content())

    @patch("src.mailer.smtplib.SMTP")
    @patch("src.mailer._load_runtime_config")
    def test_send_alert_never_places_password_in_email(
        self,
        load_runtime_config: Mock,
        smtp_class: Mock,
    ) -> None:
        config = DummyConfig()
        load_runtime_config.return_value = config
        smtp = smtp_class.return_value.__enter__.return_value

        send_alert("Alerta IDS", "Mensaje defensivo", config.admin_email)

        sent_message = smtp.send_message.call_args.args[0]
        self.assertNotIn(config.smtp_password, sent_message.as_string())

    @patch("src.mailer._load_runtime_config")
    def test_send_alert_rejects_empty_subject(self, load_runtime_config: Mock) -> None:
        load_runtime_config.return_value = DummyConfig()

        with self.assertRaisesRegex(MailerError, "subject"):
            send_alert("", "Mensaje", "admin@example.org")

    @patch("src.mailer._load_runtime_config")
    def test_send_alert_rejects_empty_message(self, load_runtime_config: Mock) -> None:
        load_runtime_config.return_value = DummyConfig()

        with self.assertRaisesRegex(MailerError, "message"):
            send_alert("Alerta", " ", "admin@example.org")

    @patch("src.mailer._load_runtime_config")
    def test_send_alert_rejects_empty_recipient(self, load_runtime_config: Mock) -> None:
        load_runtime_config.return_value = DummyConfig()

        with self.assertRaisesRegex(MailerError, "recipient"):
            send_alert("Alerta", "Mensaje", "")

    @patch("src.mailer.smtplib.SMTP")
    @patch("src.mailer._load_runtime_config")
    def test_send_alert_wraps_smtp_errors_without_password(
        self,
        load_runtime_config: Mock,
        smtp_class: Mock,
    ) -> None:
        config = DummyConfig()
        load_runtime_config.return_value = config
        smtp = smtp_class.return_value.__enter__.return_value
        smtp.login.side_effect = OSError("connection failed")

        with self.assertRaises(MailerError) as error:
            send_alert("Alerta", "Mensaje", config.admin_email)

        self.assertNotIn(config.smtp_password, str(error.exception))


if __name__ == "__main__":
    unittest.main()
