import unittest
from afterlife import analyze, timestamp

NOW = timestamp('2026-11-02T00:00:00Z')

def row(verdict='malicious', source='a', date='2026-11-01T00:00:00Z', **extra):
    return dict(type='domain', value='Example.COM.', source=source, verdict=verdict, observed_at=date, **extra)

class EvidenceTests(unittest.TestCase):
    def check_status(self, rows, expected):
        self.assertEqual(analyze(list(enumerate(rows, 1)), NOW, 30)[0]['status'], expected)
    def test_conflict(self):
        self.check_status([row(), row('benign', 'b')], 'CONFLICT_REVIEW')
    def test_superseded(self):
        self.check_status([row(date='2026-10-31T00:00:00Z'), row('revoked')], 'REVOKED_REVIEW')
    def test_stale(self):
        self.check_status([row(date='2026-09-01T00:00:00Z')], 'STALE_REVIEW')
    def test_expiry_boundary(self):
        self.check_status([row(valid_until='2026-11-02T00:00:00Z')], 'STALE_REVIEW')
    def test_tied_conflict(self):
        self.check_status([row(), row('benign')], 'CONFLICT_REVIEW')
    def test_future_rejected(self):
        with self.assertRaises(ValueError):
            analyze([(1, row(date='2027-01-01T00:00:00Z'))], NOW, 30)
    def test_naive_time_rejected(self):
        with self.assertRaises(ValueError):
            timestamp('2026-11-02')
    def test_normalization(self):
        self.assertEqual(analyze([(1, row())], NOW, 30)[0]['value'], 'example.com')

if __name__ == '__main__':
    unittest.main()
