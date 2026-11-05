import ast
import inspect
import json
import tempfile
import unittest
import weakref
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from sel_triage.core.errors import TriageError
from sel_triage.core.inventory import DeviceTarget
from sel_triage.integrations.devices.sel.commands import COMMANDS_BY_FAMILY
from sel_triage.integrations.devices.sel import workflows
from sel_triage.tools import sel_snapshot
from sel_triage.tools import sel_visualize
from sel_triage.tools.sel_snapshot import run_snapshot


FIXTURES = Path(__file__).parent / "fixtures" / "sel"


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


NOW = datetime(2026, 7, 21, 23, 30, tzinfo=timezone.utc)
TARGET_700 = DeviceTarget(
    name="Lab Relay 700",
    kind="sel",
    host="192.0.2.10",
    port=23,
    model_hint="SEL-700GT",
    credential_ref="relay-700",
    timeout_seconds=5,
)
TARGET_651 = DeviceTarget(
    name="Lab Relay 651",
    kind="sel",
    host="192.0.2.11",
    port=23,
    model_hint="SEL-651R2",
    credential_ref="relay-651",
    timeout_seconds=5,
)


class FakeIdentity:
    def __init__(self, observed_model, raw_text, device_id="LAB-RELAY"):
        self.observed_model = observed_model
        self.raw_text = raw_text
        self.device_id = device_id


class FakeSecrets:
    def __init__(self, values):
        self.values = values
        self.calls = []

    def get(self, credential_ref):
        self.calls.append(credential_ref)
        value = self.values[credential_ref]
        if isinstance(value, Exception):
            raise value
        return value


class FakeClient:
    def __init__(self, model, responses, fail=None, fail_logout=False):
        self.model = model
        self.family = {
            "SEL-700GT": "sel700g",
            "SEL-651R2": "sel651",
            "SEL-735": "sel735",
        }[model]
        self.capabilities = tuple(COMMANDS_BY_FAMILY[self.family])
        self.responses = responses
        self.fail = fail or {}
        self.fail_logout = fail_logout
        self.calls = []
        self.logout_calls = 0
        identity_fixture = {
            "SEL-700GT": "700gt-id.txt",
            "SEL-651R2": "651r2-id.txt",
            "SEL-735": "identity/id-sel-735.txt",
        }[model]
        self.identity = FakeIdentity(model, fixture(identity_fixture))

    def login(self, password):
        self.calls.append(("login", password))
        failure = self.fail.get("login")
        if failure:
            raise failure
        return self.identity

    def run(self, capability):
        self.calls.append(("run", capability))
        failure = self.fail.get(capability)
        if failure:
            raise failure
        return self.responses[capability]

    def logout(self):
        self.logout_calls += 1
        if self.fail_logout:
            raise OSError("logout failed")


def client_factory_for(clients):
    by_name = dict(clients)

    def factory(target):
        return by_name[target.name]

    return factory


def responses_700(secret="not-present"):
    return {
        "status": fixture("700gt-status.txt") + "\n" + secret,
        "meter": fixture("700gt-meter.txt"),
        "breaker": fixture("700gt-breaker.txt"),
        "target": fixture("700gt-target.txt"),
        "history": fixture("700gt-history.txt"),
    }


def responses_651():
    return {
        "status": fixture("651r2-status.txt"),
        "meter": fixture("651r2-meter.txt"),
        "history": fixture("651r2-history.txt"),
    }


def imports_visualizer(source):
    tree = ast.parse(source)
    return any(
        (
            isinstance(node, ast.Import)
            and any(
                name.name == "sel_visualize" or name.name.endswith(".sel_visualize")
                for name in node.names
            )
        )
        or (
            isinstance(node, ast.ImportFrom)
            and (
                node.module == "sel_visualize"
                or (node.module or "").endswith(".sel_visualize")
                or any(name.name == "sel_visualize" for name in node.names)
            )
        )
        for node in ast.walk(tree)
    )


class TestSelSnapshot(unittest.TestCase):
    def test_secret_is_released_after_login_while_later_sources_are_redacted(self):
        secret_text = "snapshot-secret-fingerprint-sentinel"

        class EphemeralSecret(str):
            __slots__ = ("__weakref__",)

        class EphemeralSecrets:
            def get(self, credential_ref):
                return EphemeralSecret(secret_text)

        client = FakeClient(
            "SEL-700GT", responses_700(secret=secret_text)
        )
        original_run = client.run

        def login(password):
            client.secret_reference = weakref.ref(password)
            client.calls.append(("login", "[REDACTED]"))
            return client.identity

        def run(capability):
            if client.secret_reference() is not None:
                raise AssertionError("snapshot workflow retained the login secret")
            return original_run(capability)

        client.login = login
        client.run = run
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_snapshot(
                [TARGET_700],
                EphemeralSecrets(),
                root,
                client_factory_for({TARGET_700.name: client}),
                NOW,
                {},
            )
            target = result["targets"][0]
            status_path = root / next(
                reference["path"]
                for reference in target["evidence"]
                if reference["path"].endswith("status.txt")
            )
            stored_status = status_path.read_text(encoding="utf-8")

        self.assertTrue(result["ok"], result["errors"])
        self.assertNotIn(secret_text, stored_status)
        self.assertIn("[REDACTED]", stored_status)

    def test_valid_unsupported_model_is_categorized_after_identity(self):
        class UnsupportedIdentity:
            observed_model = "SEL-487E"
            device_id = "LAB-RELAY-UNKNOWN"
            raw_text = (
                'ID\r\n"FID=SEL-487E-R100-V0-Z001001-D20260101","A1B2"\r\n'
                '"DEVID=LAB-RELAY-UNKNOWN","C3D4"\r\n=>'
            )

        class UnsupportedClient:
            family = "generic"
            capabilities = tuple(COMMANDS_BY_FAMILY["generic"])

            def __init__(self):
                self.calls = []

            def login(self, password):
                self.calls.append(("login", password))
                return UnsupportedIdentity()

            def run(self, capability):
                raise AssertionError("unsupported model must not be probed")

            def logout(self):
                self.calls.append(("logout",))

        client = UnsupportedClient()
        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [TARGET_700],
                FakeSecrets({"relay-700": "pw"}),
                Path(directory),
                client_factory_for({TARGET_700.name: client}),
                NOW,
                {},
            )

        target = result["targets"][0]
        self.assertEqual(target["errors"][0]["category"], "unsupported_model")
        self.assertEqual(target["identity"]["observed_model"], "SEL-487E")
        self.assertFalse(target["ok"])

    def test_sel_snapshot_contract_has_truthful_status_and_provenance(self):
        complete_client = FakeClient("SEL-700GT", responses_700())
        partial_client = FakeClient("SEL-651R2", responses_651())

        with tempfile.TemporaryDirectory() as directory:
            complete = run_snapshot(
                [TARGET_700],
                FakeSecrets({"relay-700": "pw"}),
                Path(directory),
                client_factory_for({TARGET_700.name: complete_client}),
                NOW,
                {},
            )
            partial = run_snapshot(
                [TARGET_651],
                FakeSecrets({"relay-651": "pw"}),
                Path(directory),
                client_factory_for({TARGET_651.name: partial_client}),
                NOW,
                {},
            )

        self.assertIn("schema_version", complete)
        self.assertEqual(complete["schema_version"], "0.2")
        self.assertEqual(complete["tool"], "sel-snapshot")
        self.assertTrue(complete["ok"])
        self.assertFalse(complete["partial"])
        self.assertTrue(complete["targets"][0]["ok"])
        self.assertEqual(complete["provenance"]["access_level"], 1)
        self.assertTrue(complete["provenance"]["read_only"])

        self.assertFalse(partial["ok"])
        self.assertTrue(partial["partial"])
        self.assertFalse(partial["targets"][0]["ok"])
        self.assertTrue(partial["targets"][0]["partial"])
        self.assertTrue(partial["errors"])

    def test_authentication_failure_cannot_claim_ok_or_partial(self):
        client = FakeClient(
            "SEL-700GT",
            responses_700(),
            fail={
                "login": TriageError(
                    "bad credential",
                    category="authentication_failed",
                    reachable=True,
                )
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [TARGET_700],
                FakeSecrets({"relay-700": "pw"}),
                Path(directory),
                client_factory_for({TARGET_700.name: client}),
                NOW,
                {},
            )

        self.assertFalse(result["ok"])
        self.assertFalse(result["partial"])
        self.assertFalse(result["targets"][0]["ok"])
        self.assertFalse(result["targets"][0]["partial"])

    def test_password_substring_does_not_redact_structural_evidence_paths(self):
        secret = "relay"
        client = FakeClient("SEL-700GT", responses_700(secret=secret))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_snapshot(
                [TARGET_700],
                FakeSecrets({"relay-700": secret}),
                root,
                client_factory_for({TARGET_700.name: client}),
                NOW,
                {},
            )
            target = result["targets"][0]
            paths = [reference["path"] for reference in target["evidence"]]

            self.assertEqual(target["name"], "Lab Relay 700")
            self.assertTrue(any("relay" in path for path in paths))
            self.assertNotIn("[REDACTED]", target["manifest"])
            self.assertTrue(all((root / path).is_file() for path in paths))
            status_path = root / next(path for path in paths if path.endswith("status.txt"))
            self.assertIn("[REDACTED]", status_path.read_text(encoding="utf-8"))

    def test_same_timestamp_snapshots_use_distinct_manifests_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = run_snapshot(
                [TARGET_700],
                FakeSecrets({"relay-700": "pw"}),
                root,
                client_factory_for(
                    {TARGET_700.name: FakeClient("SEL-700GT", responses_700())}
                ),
                NOW,
                {},
            )
            first_manifest = root / first["targets"][0]["manifest"]
            incumbent = first_manifest.read_bytes()

            second = run_snapshot(
                [TARGET_700],
                FakeSecrets({"relay-700": "pw"}),
                root,
                client_factory_for(
                    {TARGET_700.name: FakeClient("SEL-700GT", responses_700())}
                ),
                NOW,
                {},
            )
            second_manifest = root / second["targets"][0]["manifest"]

            self.assertNotEqual(first_manifest, second_manifest)
            self.assertEqual(first_manifest.read_bytes(), incumbent)
            self.assertTrue(second_manifest.is_file())

    def test_targets_in_one_snapshot_share_one_collision_resistant_run_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [TARGET_700, TARGET_651],
                FakeSecrets({"relay-700": "pw", "relay-651": "pw"}),
                Path(directory),
                client_factory_for(
                    {
                        TARGET_700.name: FakeClient("SEL-700GT", responses_700()),
                        TARGET_651.name: FakeClient("SEL-651R2", responses_651()),
                    }
                ),
                NOW,
                {},
            )

        run_directories = {
            Path(target["manifest"]).parent.parent
            for target in result["targets"]
        }
        self.assertEqual(len(run_directories), 1)

    def test_fixed_capability_order_and_stable_envelope_shape(self):
        client = FakeClient("SEL-700GT", responses_700())
        secrets = FakeSecrets({"relay-700": "pw-700"})

        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [TARGET_700],
                secrets,
                Path(directory),
                client_factory_for({TARGET_700.name: client}),
                NOW,
                {},
            )

        self.assertEqual(
            client.calls,
            [
                ("login", "pw-700"),
                ("run", "status"),
                ("run", "meter"),
                ("run", "breaker"),
                ("run", "target"),
                ("run", "history"),
            ],
        )
        self.assertEqual(
            set(result),
            {
                "schema_version",
                "tool",
                "ran_at",
                "ok",
                "partial",
                "targets",
                "errors",
                "provenance",
            },
        )
        self.assertEqual(result["tool"], "sel-snapshot")
        self.assertEqual(result["ran_at"], "2026-07-21T23:30:00Z")
        target = result["targets"][0]
        self.assertEqual(
            set(target),
            {
                "name",
                "ok",
                "partial",
                "reachable",
                "transport_security",
                "model_hint",
                "identity",
                "snapshot",
                "completed_capabilities",
                "unavailable_capabilities",
                "diagnostics",
                "warnings",
                "errors",
                "evidence",
                "manifest",
                "provenance",
            },
        )
        self.assertTrue(target["reachable"])
        self.assertEqual(target["transport_security"], "plaintext")
        self.assertEqual(
            list(target["snapshot"]),
            ["status", "meter", "breaker", "target", "history"],
        )
        self.assertEqual(target["completed_capabilities"], list(target["snapshot"]))
        self.assertEqual(target["unavailable_capabilities"], [])
        self.assertEqual(client.logout_calls, 1)
        self.assertEqual(secrets.calls, ["relay-700"])

    def test_capability_order_is_intersected_with_adapter_and_client_policy(self):
        client = FakeClient("SEL-651R2", responses_651())
        secrets = FakeSecrets({"relay-651": "pw-651"})

        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [TARGET_651],
                secrets,
                Path(directory),
                client_factory_for({TARGET_651.name: client}),
                NOW,
                {},
            )

        self.assertEqual(
            [call for call in client.calls if call[0] == "run"],
            [("run", "status"), ("run", "meter"), ("run", "history")],
        )
        target = result["targets"][0]
        self.assertEqual(target["unavailable_capabilities"], ["breaker", "target"])
        self.assertEqual(
            [error["category"] for error in target["errors"]],
            ["command_unavailable", "command_unavailable"],
        )
        self.assertIn("partial_snapshot", [d["code"] for d in target["diagnostics"]])

    def test_client_declaration_cannot_widen_its_executable_family_policy(self):
        client = FakeClient("SEL-700GT", responses_700())
        client.family = "generic"  # policy allows only ID and HELP
        client.capabilities = ("identity", "status", "meter", "breaker", "target", "history")

        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [TARGET_700],
                FakeSecrets({"relay-700": "pw"}),
                Path(directory),
                client_factory_for({TARGET_700.name: client}),
                NOW,
                {},
            )

        self.assertEqual(
            [call for call in client.calls if call[0] == "run"], []
        )
        self.assertEqual(
            result["targets"][0]["unavailable_capabilities"],
            ["status", "meter", "breaker", "target", "history"],
        )

    def test_command_unavailable_during_collection_is_partial_and_not_fatal(self):
        failure = TriageError(
            "command unavailable", category="command_unavailable", reachable=None
        )
        client = FakeClient(
            "SEL-700GT", responses_700(), fail={"breaker": failure}
        )

        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [TARGET_700],
                FakeSecrets({"relay-700": "pw"}),
                Path(directory),
                client_factory_for({TARGET_700.name: client}),
                NOW,
                {},
            )

        self.assertEqual(
            [call for call in client.calls if call[0] == "run"],
            [
                ("run", "status"),
                ("run", "meter"),
                ("run", "breaker"),
                ("run", "target"),
                ("run", "history"),
            ],
        )
        target = result["targets"][0]
        self.assertNotIn("breaker", target["snapshot"])
        self.assertIn("breaker", target["unavailable_capabilities"])
        self.assertEqual(client.logout_calls, 1)

    def test_session_fatal_failure_logs_out_and_next_target_continues(self):
        first = FakeClient(
            "SEL-700GT",
            responses_700(),
            fail={
                "meter": TriageError(
                    "prompt timeout", category="prompt_timeout", reachable=True
                )
            },
        )
        second = FakeClient("SEL-651R2", responses_651())
        secrets = FakeSecrets({"relay-700": "first", "relay-651": "second"})

        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [TARGET_700, TARGET_651],
                secrets,
                Path(directory),
                client_factory_for(
                    {TARGET_700.name: first, TARGET_651.name: second}
                ),
                NOW,
                {},
            )

        self.assertEqual(first.logout_calls, 1)
        self.assertEqual(second.logout_calls, 1)
        self.assertEqual(secrets.calls, ["relay-700", "relay-651"])
        self.assertEqual(
            [call for call in first.calls if call[0] == "run"],
            [("run", "status"), ("run", "meter")],
        )
        self.assertEqual(
            [call for call in second.calls if call[0] == "run"],
            [("run", "status"), ("run", "meter"), ("run", "history")],
        )
        self.assertEqual(len(result["targets"]), 2)

    def test_one_secret_lookup_and_logout_when_login_fails(self):
        client = FakeClient(
            "SEL-700GT",
            responses_700(),
            fail={
                "login": TriageError(
                    "bad credential",
                    category="authentication_failed",
                    reachable=True,
                )
            },
        )
        secrets = FakeSecrets({"relay-700": "pw"})

        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [TARGET_700],
                secrets,
                Path(directory),
                client_factory_for({TARGET_700.name: client}),
                NOW,
                {},
            )

        self.assertEqual(secrets.calls, ["relay-700"])
        self.assertEqual(client.logout_calls, 1)
        self.assertEqual(result["targets"][0]["reachable"], True)
        self.assertIn(
            "authentication_failed",
            [d["code"] for d in result["targets"][0]["diagnostics"]],
        )

    def test_735_snapshot_normalizes_output_without_breaker_or_false_warnings(self):
        target = DeviceTarget(
            name="Lab Meter 735", kind="sel", host="192.0.2.12", port=23,
            model_hint="SEL-735", credential_ref="meter-735", timeout_seconds=5,
        )
        responses = {c: fixture("735-{0}.txt".format(c)) for c in ("status", "meter", "history", "target")}
        client = FakeClient("SEL-735", responses)
        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [target], FakeSecrets({"meter-735": "pw"}), Path(directory),
                client_factory_for({target.name: client}), NOW, {},
            )
            written = sorted(Path(ref["path"]).name for ref in result["targets"][0]["evidence"])
        target_result = result["targets"][0]
        self.assertNotIn(("run", "breaker"), client.calls)
        self.assertEqual(target_result["unavailable_capabilities"], [])
        self.assertEqual(written, ["history.txt", "identity.txt", "meter.txt", "status.txt", "target.txt"])
        codes = {d["code"]: d for d in target_result["diagnostics"]}
        self.assertNotIn("missing_measurement", codes)
        self.assertNotIn("partial_snapshot", codes)
        self.assertNotIn("command_unavailable", codes)
        self.assertNotIn("capture_only_output", codes)
        self.assertEqual(target_result["snapshot"]["meter"]["frequency_hz"], 60.0)
        self.assertEqual(target_result["snapshot"]["status"]["self_test"], "WARN")

    def test_evidence_refs_are_hashed_relative_and_secret_is_redacted(self):
        sentinel = "snapshot-secret-sentinel"
        client = FakeClient("SEL-700GT", responses_700(secret=sentinel))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_snapshot(
                [TARGET_700],
                FakeSecrets({"relay-700": sentinel}),
                root,
                client_factory_for({TARGET_700.name: client}),
                NOW,
                {},
            )
            target = result["targets"][0]
            status_ref = next(
                ref for ref in target["evidence"] if ref["path"].endswith("status.txt")
            )
            status_text = (root / status_ref["path"]).read_text(encoding="utf-8")
            manifest = json.loads((root / target["manifest"]).read_text())

        self.assertNotIn(sentinel, status_text)
        self.assertNotIn(sentinel, json.dumps(result))
        self.assertIn("[REDACTED]", status_text)
        self.assertFalse(Path(status_ref["path"]).is_absolute())
        self.assertEqual(manifest["evidence"], target["evidence"])
        self.assertTrue(all(len(ref["sha256"]) == 64 for ref in target["evidence"]))

    def test_fast_snapshot_never_requests_event_or_visualization_capabilities(self):
        client = FakeClient("SEL-700GT", responses_700())

        for module in (workflows, sel_snapshot):
            with self.subTest(module=module.__name__):
                source = inspect.getsource(module)
                self.assertFalse(imports_visualizer(source))

        self.assertTrue(imports_visualizer("from .sel_visualize import run as visualize"))

        with mock.patch.object(
            sel_visualize, "run", side_effect=AssertionError("visualizer called")
        ) as visualizer:
            with tempfile.TemporaryDirectory() as directory:
                run_snapshot(
                    [TARGET_700],
                    FakeSecrets({"relay-700": "pw"}),
                    Path(directory),
                    client_factory_for({TARGET_700.name: client}),
                    NOW,
                    {},
                )
        visualizer.assert_not_called()

        capabilities = [value for action, value in client.calls if action == "run"]
        self.assertTrue({"eve", "cev", "ser", "visualize"}.isdisjoint(capabilities))

    def test_settings_are_read_only_when_requested(self):
        client = FakeClient("SEL-700GT", responses_700())
        with tempfile.TemporaryDirectory() as directory:
            run_snapshot(
                [TARGET_700],
                FakeSecrets({"relay-700": "pw"}),
                Path(directory),
                client_factory_for({TARGET_700.name: client}),
                NOW,
                {},
            )
        capabilities = [value for action, value in client.calls if action == "run"]
        self.assertTrue(
            set(workflows.SETTINGS_CAPABILITIES).isdisjoint(capabilities)
        )

    def test_700g_settings_follow_the_fast_snapshot_and_are_saved(self):
        responses = responses_700()
        for capability in workflows.SETTINGS_CAPABILITIES:
            responses[capability] = "SHO\n\nPHROT    := ABC\n=>"
        client = FakeClient("SEL-700GT", responses)
        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [TARGET_700],
                FakeSecrets({"relay-700": "pw"}),
                Path(directory),
                client_factory_for({TARGET_700.name: client}),
                NOW,
                {},
                include_settings=True,
            )
            written = {
                Path(ref["path"]).name for ref in result["targets"][0]["evidence"]
            }
        capabilities = [value for action, value in client.calls if action == "run"]
        self.assertEqual(
            capabilities,
            list(workflows.SNAPSHOT_CAPABILITIES)
            + list(workflows.SETTINGS_CAPABILITIES),
        )
        target = result["targets"][0]
        for capability in workflows.SETTINGS_CAPABILITIES:
            self.assertIn(
                "{0}.txt".format(capability.replace("_", "-")), written
            )
            self.assertIn(capability, target["completed_capabilities"])
        self.assertEqual(target["errors"], [])

    def test_settings_request_on_unsupported_family_is_a_warning(self):
        target = DeviceTarget(
            name="Lab Meter 735", kind="sel", host="192.0.2.12", port=23,
            model_hint="SEL-735", credential_ref="meter-735", timeout_seconds=5,
        )
        responses = {c: fixture("735-{0}.txt".format(c)) for c in ("status", "meter", "history", "target")}
        client = FakeClient("SEL-735", responses)
        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [target], FakeSecrets({"meter-735": "pw"}), Path(directory),
                client_factory_for({target.name: client}), NOW, {},
                include_settings=True,
            )
        target_result = result["targets"][0]
        self.assertTrue(target_result["ok"])
        self.assertEqual(
            target_result["unavailable_capabilities"],
            list(workflows.SETTINGS_CAPABILITIES),
        )
        self.assertEqual(
            {w["code"] for w in target_result["warnings"]}, {"settings_unavailable"}
        )

    def test_evidence_write_failure_preserves_completed_data_and_cites_cause(self):
        client = FakeClient("SEL-700GT", responses_700())

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch(
                "sel_triage.integrations.devices.sel.workflows."
                "EvidenceStore.write_text",
                side_effect=OSError("disk unavailable"),
            ):
                result = run_snapshot(
                    [TARGET_700],
                    FakeSecrets({"relay-700": "pw"}),
                    Path(directory),
                    client_factory_for({TARGET_700.name: client}),
                    NOW,
                    {},
                )

        target = result["targets"][0]
        self.assertEqual(target["completed_capabilities"], list(target["snapshot"]))
        partial = next(d for d in target["diagnostics"] if d["code"] == "partial_snapshot")
        self.assertEqual(
            partial["evidence"], {"error_categories": ["evidence_write_failed"]}
        )
        self.assertEqual(
            partial["description"],
            "Snapshot completed with one or more evidence or session errors.",
        )

    def test_logout_failure_preserves_completed_data_and_cites_cause(self):
        client = FakeClient("SEL-700GT", responses_700(), fail_logout=True)

        with tempfile.TemporaryDirectory() as directory:
            result = run_snapshot(
                [TARGET_700],
                FakeSecrets({"relay-700": "pw"}),
                Path(directory),
                client_factory_for({TARGET_700.name: client}),
                NOW,
                {},
            )

        target = result["targets"][0]
        self.assertEqual(target["completed_capabilities"], list(target["snapshot"]))
        partial = next(d for d in target["diagnostics"] if d["code"] == "partial_snapshot")
        self.assertEqual(partial["evidence"], {"error_categories": ["logout_failed"]})
        self.assertEqual(
            partial["description"],
            "Snapshot completed with one or more evidence or session errors.",
        )

    def test_evidence_directory_failure_uses_stage_neutral_description(self):
        client = FakeClient("SEL-700GT", responses_700())

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch(
                "sel_triage.integrations.devices.sel.workflows.EvidenceStore",
                side_effect=OSError("directory unavailable"),
            ):
                result = run_snapshot(
                    [TARGET_700],
                    FakeSecrets({"relay-700": "pw"}),
                    Path(directory),
                    client_factory_for({TARGET_700.name: client}),
                    NOW,
                    {},
                )

        target = result["targets"][0]
        self.assertEqual(target["completed_capabilities"], list(target["snapshot"]))
        partial = next(d for d in target["diagnostics"] if d["code"] == "partial_snapshot")
        self.assertEqual(
            partial["evidence"], {"error_categories": ["evidence_write_failed"]}
        )
        self.assertEqual(
            partial["description"],
            "Snapshot completed with one or more evidence or session errors.",
        )

    def test_manifest_failure_uses_stage_neutral_description(self):
        client = FakeClient("SEL-700GT", responses_700())

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch(
                "sel_triage.integrations.devices.sel.workflows."
                "EvidenceStore.write_manifest",
                side_effect=OSError("manifest unavailable"),
            ):
                result = run_snapshot(
                    [TARGET_700],
                    FakeSecrets({"relay-700": "pw"}),
                    Path(directory),
                    client_factory_for({TARGET_700.name: client}),
                    NOW,
                    {},
                )

        target = result["targets"][0]
        self.assertEqual(target["completed_capabilities"], list(target["snapshot"]))
        partial = next(d for d in target["diagnostics"] if d["code"] == "partial_snapshot")
        self.assertEqual(
            partial["evidence"], {"error_categories": ["evidence_write_failed"]}
        )
        self.assertEqual(
            partial["description"],
            "Snapshot completed with one or more evidence or session errors.",
        )


if __name__ == "__main__":
    unittest.main()
