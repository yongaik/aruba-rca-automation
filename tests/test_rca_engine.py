# tests/test_rca_engine.py
import json
import unittest
from pathlib import Path
from analysis.rca_engine import RCAEngine

MOCK_DIR = Path(__file__).parent / "mock_data"


class TestRCAEngine(unittest.TestCase):

    def test_rca_with_mock_data(self):
        uxi = json.loads((MOCK_DIR / "uxi_sample.json").read_text())
        central = json.loads((MOCK_DIR / "central_sample.json").read_text())
        clearpass = json.loads((MOCK_DIR / "clearpass_sample.json").read_text())

        engine = RCAEngine()
        result = engine.analyse(uxi, central, clearpass, "test_mock")

        self.assertIn("overall_severity", result)
        self.assertIn("root_cause", result)
        self.assertIn("recommended_steps", result)
        self.assertIsInstance(result["recommended_steps"], list)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    unittest.main()
