import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from verify_compliance import extract_pr_tickets

PATTERN = r"[A-Z]+-\d+"


class ExtractPrTicketsTests(unittest.TestCase):
    """Ticket hunting must be deterministic and identical for both agents."""

    def test_extracts_from_title_and_body_order_preserving_deduped(self):
        title = "BOL-2243: consolidated work"
        body = "Includes BOL-2236, BOL-2237 and again BOL-2243."
        self.assertEqual(
            extract_pr_tickets(title, body, PATTERN),
            ["BOL-2243", "BOL-2236", "BOL-2237"],
        )

    def test_no_tickets_returns_empty(self):
        self.assertEqual(extract_pr_tickets("no ticket here", "nor here", PATTERN), [])

    def test_title_only(self):
        self.assertEqual(extract_pr_tickets("PROJ-9: fix", "", PATTERN), ["PROJ-9"])


if __name__ == "__main__":
    unittest.main()
