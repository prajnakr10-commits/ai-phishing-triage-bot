
"""Synthetic phishing triage evaluation with known labels."""

from triage.analyzer import analyze_email

CASES = [
    ("Legitimate newsletter", "benign",
     "Monthly newsletter", "Company announcements and events."),

    ("Legitimate meeting", "benign",
     "Meeting reminder", "Team meeting scheduled for tomorrow."),

    ("Legitimate project update", "benign",
     "Project progress", "The quarterly report is ready."),

    ("Credential phishing", "phishing",
     "URGENT verify your account immediately",
     "Enter your password at http://192.0.2.44/login"),

    ("Account verification phishing", "phishing",
     "Act now verify your account",
     "Sign in at http://192.0.2.55/verify"),

    ("Subtle phishing", "phishing",
     "Document shared with you",
     "Please review https://example.org/document"),
]


def create_email(subject, body):
    return (
        "From: sender@example.org\n"
        "To: analyst@example.org\n"
        f"Subject: {subject}\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        f"{body}\n"
    ).encode("utf-8")


tp = tn = fp = fn = 0

print("\nSOC PHISHING TRIAGE EVALUATION")
print("=" * 55)

for name, actual, subject, body in CASES:
    report = analyze_email(create_email(subject, body))

    predicted = (
        "phishing"
        if report["classification"] in ("Medium", "High")
        else "benign"
    )

    if actual == "phishing" and predicted == "phishing":
        tp += 1
    elif actual == "benign" and predicted == "benign":
        tn += 1
    elif actual == "benign" and predicted == "phishing":
        fp += 1
    else:
        fn += 1

    print(
        f"{name}: Actual={actual}, "
        f"Predicted={predicted}, "
        f"Risk={report['score']}/100"
    )

total = tp + tn + fp + fn

accuracy = (tp + tn) / total if total else 0
precision = tp / (tp + fp) if (tp + fp) else 0
recall = tp / (tp + fn) if (tp + fn) else 0

print("\nCONFUSION MATRIX")
print(f"TP: {tp}")
print(f"TN: {tn}")
print(f"FP: {fp}")
print(f"FN: {fn}")

print("\nMETRICS")
print(f"Accuracy: {accuracy:.2%}")
print(f"Precision: {precision:.2%}")
print(f"Recall: {recall:.2%}")

print("\nNote: Synthetic educational dataset only.")
print("Results do not represent real-world detection accuracy.")
