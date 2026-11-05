"""Identity parsing across SEL models, from anonymized SEL-Audit ID captures."""

from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel import client as sel_client
from sel_triage.integrations.devices.sel.adapters import adapter_for


FIXTURES = Path(__file__).parent / "fixtures" / "sel" / "identity"

# observed model -> expected adapter family ("generic" = no dedicated adapter yet)
EXPECTED = {
    "SEL-351": "sel351",
    "SEL-351A": "sel351",
    "SEL-351S": "sel351",
    "SEL-651R2": "sel651",
    "SEL-651RA": "sel651",
    "SEL-700G": "sel700g",
    "SEL-735": "sel735",
    "SEL-751": "sel751",
    "SEL-751A": "sel751",
    "SEL-851": "sel851",
}


class TestIdentityAcrossModels(unittest.TestCase):
    def test_every_model_fixture_is_present_and_anonymized(self):
        names = {path.name for path in FIXTURES.glob("id-*.txt")}
        self.assertEqual(names, {"id-{0}.txt".format(m.lower()) for m in EXPECTED})
        for path in FIXTURES.glob("id-*.txt"):
            text = path.read_text()
            self.assertTrue(text.startswith("ANONYMIZED CAPTURE:"))
            self.assertIn('"DEVID=LAB-RELAY-01"', text)
            self.assertNotIn("203.0.113.", text)

    def test_identity_model_and_family(self):
        for model, family in EXPECTED.items():
            with self.subTest(model=model):
                text = (FIXTURES / "id-{0}.txt".format(model.lower())).read_text()
                identity = sel_client._normalize_identity(text)
                self.assertEqual(identity.observed_model, model)
                self.assertEqual(identity.device_id, "LAB-RELAY-01")
                self.assertTrue(identity.firmware_id.startswith(model.replace("R2", "R")))
                self.assertEqual(sel_client._family_for(model), family)
                if family == "generic":
                    with self.assertRaises(ValueError):
                        adapter_for(model)
                else:
                    self.assertEqual(adapter_for(model).adapter.family, family)


if __name__ == "__main__":
    unittest.main()
