"""The packaged SEL command reference (extracted from instruction manuals)."""

import unittest

from sel_triage.integrations.devices.sel.reference import load_reference, reference_model, revision_number


class TestSelReference(unittest.TestCase):
    def test_every_fleet_model_has_a_reference(self):
        models = {doc["model"] for doc in load_reference()}
        for observed in ("SEL-351-5", "SEL-351A", "SEL-351S-7", "SEL-651R-2", "SEL-651RA", "SEL-700G",
                         "SEL-700GT", "SEL-735", "SEL-751", "SEL-751A", "SEL-851"):
            with self.subTest(observed=observed):
                self.assertIn(reference_model(observed), models)
        self.assertIsNone(reference_model("SEL-487E"))
        self.assertIsNone(reference_model(None))

    def test_rows_are_well_formed(self):
        for doc in load_reference():
            with self.subTest(model=doc["model"], manual=doc.get("manual_date")):
                self.assertTrue(doc["commands"])
                for row in doc["commands"]:
                    self.assertTrue(row["command"])
                    self.assertIn(row["kind"], {"read", "write", "session", "other"})

    def test_write_commands_are_marked_write(self):
        for doc in load_reference():
            kinds = {row["command"].split()[0].upper(): row["kind"] for row in doc["commands"]}
            for command in ("SET", "PAS", "OPE", "CLO"):
                if command in kinds:
                    with self.subTest(model=doc["model"], command=command):
                        self.assertEqual(kinds[command], "write")

    def test_revision_number(self):
        self.assertEqual(revision_number("R402"), 402)
        self.assertIsNone(revision_number("V2"))


if __name__ == "__main__":
    unittest.main()


class TestCommandPolicyAgainstManuals(unittest.TestCase):
    """Every fixed command sel-triage can send is a read (or session) command in the manuals."""

    FAMILY_MODELS = {
        "sel700g": ["SEL-700G"], "sel751": ["SEL-751", "SEL-751A"], "sel851": ["SEL-851"],
        "sel351": ["SEL-351", "SEL-351A", "SEL-351S"], "sel735": ["SEL-735"],
        "sel651": ["SEL-651R-2", "SEL-651RA", "SEL-651R"],
    }

    @staticmethod
    def _forms(row_command):
        # "MET or MET F" -> ["MET"], ["MET", "F"]; a form with a placeholder ("BRE n", where n
        # is W or R on a 351S) is a different command form, so only exact forms are compared.
        for alternative in row_command.replace(",", " or ").split(" or "):
            tokens = ["FILE" if t.upper() == "FIL" else t.upper() for t in alternative.split()]
            if tokens:
                yield tokens

    def test_policy_wire_texts_are_read_commands_in_every_manual(self):
        from sel_triage.integrations.devices.sel.commands import COMMANDS_BY_FAMILY

        newest = {}
        for doc in load_reference():
            newest.setdefault(doc["model"], doc)
        checked = 0
        for family, models in self.FAMILY_MODELS.items():
            for model in models:
                rows = newest[model]["commands"]
                for capability, command in COMMANDS_BY_FAMILY[family].items():
                    wire = command.wire_text.upper().split()
                    kinds = {row["kind"] for row in rows for form in self._forms(row["command"]) if form == wire}
                    if not kinds:
                        continue  # not in that manual's summary (e.g. HELP on a 351)
                    checked += 1
                    with self.subTest(model=model, capability=capability, wire=command.wire_text):
                        self.assertTrue(kinds <= {"read", "session"}, kinds)
        self.assertGreater(checked, 40)
