# Phishing Triage Bot — Detection Evaluation

## Evaluation Method

The phishing detection engine was tested using six synthetic labeled email scenarios.

For this evaluation, Medium and High priority were treated as flagged for analyst review, while Low priority was treated as not flagged.

## Results

| Metric | Result |
|---|---:|
| Total emails | 6 |
| True positives | 2 |
| True negatives | 3 |
| False positives | 0 |
| False negatives | 1 |
| Accuracy | 83.33% |
| Precision | 100% |
| Recall | 66.67% |

## Key Findings

- Two of three synthetic phishing cases were flagged for analyst review.
- All three synthetic legitimate emails remained unflagged.
- One subtle phishing scenario was missed because it did not trigger strong heuristic indicators.
- Nine automated tests passed.

## Limitations

This evaluation uses a small, synthetic educational dataset. Results cannot be generalized to real phishing campaigns or production environments.

The bot uses heuristic rules for prioritization, VirusTotal for optional reputation enrichment, and a local Llama 3.2 1B model for explanations.

AI-generated explanations require human verification.

## Future Improvements

- Add domain impersonation and lookalike detection.
- Improve HTML link-text versus destination analysis.
- Test against a larger independently labeled dataset.
- Measure false positives and false negatives across diverse phishing techniques.
- Improve detection of subtle credential-phishing attempts.