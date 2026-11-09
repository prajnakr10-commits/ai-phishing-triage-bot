from pathlib import Path
import unittest
from triage.analyzer import analyze_email

ROOT = Path(__file__).resolve().parents[1]

class AnalyzerTests(unittest.TestCase):
    def test_suspicious_sample(self):
        report = analyze_email((ROOT / 'samples/suspicious.eml').read_bytes())
        self.assertEqual(report['classification'], 'High')
        self.assertTrue(report['urls'])
        self.assertEqual(report['authentication']['dmarc'], 'fail')

    def test_benign_sample(self):
        report = analyze_email((ROOT / 'samples/benign.eml').read_bytes())
        self.assertEqual(report['classification'], 'Low')
        self.assertEqual(report['authentication']['spf'], 'pass')

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            analyze_email(b'A' * 10_000_001)

if __name__ == '__main__':
    unittest.main()
