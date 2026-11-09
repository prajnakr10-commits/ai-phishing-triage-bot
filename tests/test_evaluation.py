
"""Evaluate phishing triage against synthetic labeled emails."""

import unittest
from triage.analyzer import analyze_email


def make_email(subject, body):
    message = (
        "From: sender@example.org\n"
        "To: analyst@example.org\n"
        f"Subject: {subject}\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        f"{body}\n"
    )
    return message.encode("utf-8")


class PhishingEvaluationTests(unittest.TestCase):

    def test_benign_newsletter(self):
        report = analyze_email(make_email(
            "Monthly newsletter",
            "Here are the latest company announcements."
        ))
        self.assertEqual(report["classification"], "Low")

    def test_benign_meeting(self):
        report = analyze_email(make_email(
            "Meeting reminder",
            "Our project meeting is scheduled for tomorrow."
        ))
        self.assertEqual(report["classification"], "Low")

    def test_benign_project_update(self):
        report = analyze_email(make_email(
            "Project status",
            "The quarterly report is ready for review."
        ))
        self.assertEqual(report["classification"], "Low")

    def test_phishing_credential_request(self):
        report = analyze_email(make_email(
            "URGENT verify your account immediately",
            "Enter your password at http://192.0.2.44/login"
        ))
        self.assertEqual(report["classification"], "Medium")
        self.assertEqual(report["score"], 50)

    def test_phishing_authentication_failures(self):
        message = (
            "From: security@example.org\n"
            "To: analyst@example.org\n"
            "Subject: Account alert\n"
            "Authentication-Results: mx.example.org; "
            "spf=fail; dkim=fail; dmarc=fail\n"
            "\n"
            "Your account requires attention."
        ).encode("utf-8")

        report = analyze_email(message)
        self.assertEqual(report["classification"], "Medium")

    def test_phishing_executable_attachment(self):
        from email.message import EmailMessage

        msg = EmailMessage()
        msg["From"] = "sender@example.org"
        msg["To"] = "analyst@example.org"
        msg["Subject"] = "Invoice"
        msg.set_content("Please review the attached file.")
        msg.add_attachment(
            b"synthetic test content",
            maintype="application",
            subtype="octet-stream",
            filename="invoice.exe"
        )

        report = analyze_email(msg.as_bytes())
        self.assertTrue(any(
            i["reason"] == "Potentially executable attachment"
            for i in report["indicators"]
        ))


if __name__ == "__main__":
    unittest.main()
