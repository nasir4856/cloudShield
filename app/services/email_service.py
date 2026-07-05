import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import current_app


logger = logging.getLogger(__name__)


def send_email(subject: str, body: str) -> None:
    user = current_app.config["EMAIL_USER"]
    password = current_app.config["EMAIL_PASSWORD"]
    recipient = current_app.config["EMAIL_RECIPIENT"]

    if not user or not password or not recipient:
        logger.warning("Email notification skipped because SMTP settings are incomplete.")
        return

    msg = MIMEMultipart()
    msg["From"] = user
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(
            current_app.config["EMAIL_HOST"],
            current_app.config["EMAIL_PORT"],
            timeout=30,
        ) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(user, recipient, msg.as_string())
        logger.info("Email sent successfully.")
    except smtplib.SMTPAuthenticationError:
        logger.exception("Failed to authenticate with SMTP server.")
    except smtplib.SMTPConnectError:
        logger.exception("Failed to connect to SMTP server.")
    except smtplib.SMTPException:
        logger.exception("SMTP error occurred.")
    except Exception:
        logger.exception("Unexpected error while sending email.")

