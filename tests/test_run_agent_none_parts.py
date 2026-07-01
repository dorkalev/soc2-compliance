import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import verify_compliance

_HAS_GENAI = importlib.util.find_spec("google.genai") is not None


@unittest.skipUnless(_HAS_GENAI, "google-genai not installed (runs in CI)")
class RunAgentNonePartsTests(unittest.TestCase):
    """Regression: Gemini can return a candidate whose content.parts is None
    (finish_reason MAX_TOKENS / SAFETY). run_agent must not crash with
    "'NoneType' object is not iterable" — it should return a graceful summary."""

    @patch("google.genai.Client")
    def test_none_parts_returns_graceful_summary(self, mock_client_cls):
        candidate = MagicMock()
        candidate.content.parts = None  # truncated / filtered response
        candidate.finish_reason = "MAX_TOKENS"
        response = MagicMock()
        response.candidates = [candidate]

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = response
        mock_client_cls.return_value = mock_client

        with patch.object(verify_compliance, "GEMINI_API_KEY", "test-key"), \
             patch.object(verify_compliance, "GEMINI_API_KEY_FALLBACK", ""):
            # Must not raise; comment is only touched after this early return.
            result = verify_compliance.run_agent(MagicMock())

        self.assertEqual(result["tickets_found"], [])
        self.assertIn("no content parts", result["summary"])
        self.assertIn("MAX_TOKENS", result["summary"])


if __name__ == "__main__":
    unittest.main()
