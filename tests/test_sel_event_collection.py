import ast
import hashlib
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
from sel_triage.integrations.devices.sel.adapters.sel651 import Sel651Adapter
from sel_triage.integrations.devices.sel.commands import COMMANDS_BY_FAMILY
from sel_triage.integrations.devices.sel.workflows import (
    EventSelector,
    collect_events,
)
from sel_triage.tools import sel_collect_events
from sel_triage.tools import sel_visualize


NOW = datetime(2026, 7, 21, 23, 45, tzinfo=timezone.utc)
SER_OLDEST_TO_NEWEST = (
    b"SER\r\n # Date Time Element State\r\n"
    b" 5 07/21/2026 11:59:56.000 SV01 Asserted\r\n"
    b" 4 07/21/2026 11:59:57.000 SV01 Deasserted\r\n"
    b" 3 07/21/2026 11:59:58.000 SV02 Asserted\r\n"
    b" 2 07/21/2026 11:59:59.000 TRIP Asserted\r\n"
    b" 1 07/21/2026 12:00:00.000 TRIP Deasserted\r\n=>"
)
TARGET = DeviceTarget(
    name="Lab Relay 651",
    kind="sel",
    host="192.0.2.11",
    port=23,
    model_hint="SEL-651R2",
    credential_ref="relay-651",
    timeout_seconds=5,
)


class FakeIdentity:
    observed_model = "SEL-651R2"
    device_id = "LAB-RECLOSER-01"
    raw_text = (
        'ID\r\n"FID=SEL-651R-2-R411-V1-Z011003-D20211018","0953"\r\n'
        '"DEVID=LAB-RECLOSER-01","C3D4"\r\n=>'
    )


class FakeSecrets:
    def __init__(self):
        self.calls = []

    def get(self, credential_ref):
        self.calls.append(credential_ref)
        return "synthetic-password"


class FakeClient:
    family = "sel651"
    capabilities = tuple(COMMANDS_BY_FAMILY["sel651"])

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []
        self.logout_calls = 0

    def login(self, password):
        self.calls.append(("login", password))
        return FakeIdentity()

    def run_bytes(self, capability, argument=None):
        self.calls.append(("run_bytes", capability, argument))
        value = self.responses[(capability, argument)]
        if isinstance(value, BaseException):
            raise value
        return value

    def logout(self):
        self.logout_calls += 1


def factory_for(client):
    def factory(target):
        return client

    return factory


def event_target(result):
    return result["targets"][0]


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


class TestSelEventCollection(unittest.TestCase):
    def test_secret_is_released_immediately_after_login(self):
        class EphemeralSecret(str):
            __slots__ = ("__weakref__",)

        class EphemeralSecrets:
            def get(self, credential_ref):
                return EphemeralSecret("synthetic-password")

        client = FakeClient(
            {("eve", 1): b"EVE 1\r\n=>", ("ser", None): b"SER\r\n=>"}
        )
        original_run_bytes = client.run_bytes

        def login(password):
            client.secret_reference = weakref.ref(password)
            client.calls.append(("login", "[REDACTED]"))
            return FakeIdentity()

        def run_bytes(capability, argument=None):
            if client.secret_reference() is not None:
                raise AssertionError("event workflow retained the secret after login")
            return original_run_bytes(capability, argument)

        client.login = login
        client.run_bytes = run_bytes
        with tempfile.TemporaryDirectory() as directory:
            result = collect_events(
                TARGET,
                secret_provider=EphemeralSecrets(),
                client_factory=factory_for(client),
                evidence_root=Path(directory),
                now=NOW,
            )

        self.assertTrue(result["ok"], result["errors"])

    def test_collection_uses_common_versioned_sel_envelope(self):
        client = FakeClient(
            {("eve", 1): b"EVE 1\r\n=>", ("ser", None): b"SER\r\n=>"}
        )
        with tempfile.TemporaryDirectory() as directory:
            result = collect_events(
                TARGET,
                secret_provider=FakeSecrets(),
                client_factory=factory_for(client),
                evidence_root=Path(directory),
                now=NOW,
            )

        self.assertIn("schema_version", result)
        self.assertEqual(result["schema_version"], "0.2")
        self.assertEqual(result["tool"], "sel-collect-events")
        self.assertTrue(result["ok"])
        self.assertFalse(result["partial"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["provenance"]["access_level"], 1)
        self.assertEqual(len(result["targets"]), 1)
        self.assertTrue(result["targets"][0]["ok"])

    def test_second_event_failure_preserves_first_artifact_and_manifest(self):
        client = FakeClient(
            {
                ("eve", 1): b"EVE 1\r\n=>",
                ("eve", 2): TriageError(
                    "prompt timeout", category="transport_timeout", reachable=True
                ),
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            try:
                result = collect_events(
                    TARGET,
                    EventSelector.latest(count=2),
                    secret_provider=FakeSecrets(),
                    client_factory=factory_for(client),
                    evidence_root=root,
                    now=NOW,
                )
            except Exception as exc:
                self.fail("collection discarded its partial result: {0}".format(exc))
            target = result["targets"][0]
            manifest = json.loads((root / target["manifest"]).read_text())

        self.assertFalse(result["ok"])
        self.assertTrue(result["partial"])
        self.assertEqual(len(target["artifacts"]), 1)
        self.assertEqual(target["errors"][0]["category"], "transport_timeout")
        self.assertEqual(len(manifest["evidence"]), 1)

    def test_primary_event_failure_is_not_masked_by_logout_or_manifest_failures(self):
        client = FakeClient(
            {
                ("eve", 1): TriageError(
                    "primary timeout", category="transport_timeout", reachable=True
                )
            }
        )

        def fail_logout():
            client.logout_calls += 1
            raise OSError("logout failed")

        client.logout = fail_logout
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch(
                "sel_triage.integrations.devices.sel.workflows."
                "EvidenceStore.write_manifest",
                side_effect=OSError("manifest failed"),
            ):
                try:
                    result = collect_events(
                        TARGET,
                        secret_provider=FakeSecrets(),
                        client_factory=factory_for(client),
                        evidence_root=Path(directory),
                        now=NOW,
                    )
                except Exception as exc:
                    self.fail("cleanup masked the primary result: {0}".format(exc))

        categories = [error["category"] for error in result["targets"][0]["errors"]]
        self.assertEqual(
            categories,
            ["transport_timeout", "logout_failed", "evidence_write_failed"],
        )

    def test_event_count_over_hard_limit_fails_before_secret_or_network(self):
        def never_called(*args, **kwargs):
            self.fail("secret or network dependency was called")

        with self.assertRaisesRegex(ValueError, "hard maximum"):
            collect_events(
                TARGET,
                EventSelector.latest(count=11),
                hard_event_limit=10,
                secret_provider=mock.Mock(get=never_called),
                client_factory=never_called,
            )

    def test_caller_cannot_raise_absolute_event_ceiling(self):
        def never_called(*args, **kwargs):
            self.fail("secret or network dependency was called")

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "absolute maximum.*10"):
                collect_events(
                    TARGET,
                    EventSelector.latest(count=11),
                    hard_event_limit=999,
                    secret_provider=mock.Mock(get=never_called),
                    client_factory=never_called,
                    evidence_root=Path(directory),
                )

    def test_invalid_selector_and_ser_limit_fail_before_secret_or_network(self):
        def never_called(*args, **kwargs):
            self.fail("secret or network dependency was called")

        cases = (
            lambda: EventSelector.latest(count=True),
            lambda: EventSelector.number(0),
            lambda: collect_events(
                TARGET,
                EventSelector.latest(),
                ser_limit=0,
                secret_provider=mock.Mock(get=never_called),
                client_factory=never_called,
            ),
            lambda: EventSelector.latest(event_format="unknown"),
        )
        for invoke in cases:
            with self.subTest(invoke=invoke):
                with self.assertRaises(ValueError):
                    invoke()

    def test_default_retrieves_newest_event_and_bounded_ser(self):
        event = b"EVE 1\r\nEvent Number = 10260\r\n=>"
        client = FakeClient(
            {("eve", 1): event, ("ser", None): SER_OLDEST_TO_NEWEST}
        )
        secrets = FakeSecrets()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = collect_events(
                TARGET,
                ser_limit=3,
                hard_event_limit=10,
                secret_provider=secrets,
                client_factory=factory_for(client),
                evidence_root=root,
                now=NOW,
            )
            target_result = event_target(result)
            paths = [root / item["path"] for item in target_result["artifacts"]]
            stored_event = paths[0].read_bytes()
            stored_ser = paths[1].read_bytes()
            manifest = json.loads((root / target_result["manifest"]).read_text())

        self.assertEqual(
            client.calls,
            [
                ("login", "synthetic-password"),
                ("run_bytes", "eve", 1),
                ("run_bytes", "ser", None),
            ],
        )
        self.assertEqual(client.logout_calls, 1)
        self.assertEqual(secrets.calls, ["relay-651"])
        self.assertEqual([a["kind"] for a in target_result["artifacts"]], ["event", "ser"])
        self.assertEqual(target_result["selection"]["count"], 1)
        self.assertEqual(target_result["selection"]["mode"], "latest")
        self.assertEqual(target_result["ser"]["limit"], 3)
        self.assertEqual(target_result["ser"]["rows_returned"], 3)
        self.assertEqual(target_result["ser"]["rows_available"], 5)
        self.assertTrue(target_result["ser"]["truncated"])
        self.assertEqual(stored_event, event)
        self.assertNotIn(b" 5 ", stored_ser)
        self.assertNotIn(b" 4 ", stored_ser)
        self.assertLess(stored_ser.index(b" 3 "), stored_ser.index(b" 2 "))
        self.assertLess(stored_ser.index(b" 2 "), stored_ser.index(b" 1 "))
        self.assertTrue(paths[0].name.endswith(".eve"))
        self.assertTrue(paths[1].name.endswith(".ser"))
        self.assertEqual(
            target_result["artifacts"][0]["sha256"], hashlib.sha256(event).hexdigest()
        )
        self.assertEqual(len(manifest["evidence"]), 2)

    def test_ser_limit_one_keeps_only_the_trailing_newest_row(self):
        client = FakeClient(
            {
                ("eve", 1): b"EVE 1\r\n=>",
                ("ser", None): SER_OLDEST_TO_NEWEST,
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = collect_events(
                TARGET,
                ser_limit=1,
                secret_provider=FakeSecrets(),
                client_factory=factory_for(client),
                evidence_root=root,
                now=NOW,
            )
            target_result = event_target(result)
            stored_ser = (root / target_result["artifacts"][-1]["path"]).read_bytes()

        self.assertIn(b"SER\r\n # Date Time Element State\r\n", stored_ser)
        self.assertNotIn(b" 2 ", stored_ser)
        self.assertIn(b" 1 07/21/2026 12:00:00.000", stored_ser)
        self.assertTrue(stored_ser.endswith(b"=>"))
        self.assertEqual(target_result["ser"]["rows_returned"], 1)
        self.assertTrue(target_result["ser"]["truncated"])

    def test_ser_without_truncation_preserves_all_bytes(self):
        client = FakeClient(
            {
                ("eve", 1): b"EVE 1\r\n=>",
                ("ser", None): SER_OLDEST_TO_NEWEST,
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = collect_events(
                TARGET,
                ser_limit=5,
                secret_provider=FakeSecrets(),
                client_factory=factory_for(client),
                evidence_root=root,
                now=NOW,
            )
            target_result = event_target(result)
            stored_ser = (root / target_result["artifacts"][-1]["path"]).read_bytes()

        self.assertEqual(stored_ser, SER_OLDEST_TO_NEWEST)
        self.assertEqual(target_result["ser"]["rows_returned"], 5)
        self.assertEqual(target_result["ser"]["rows_available"], 5)
        self.assertFalse(target_result["ser"]["truncated"])

    def test_latest_count_uses_only_adapter_owned_relative_recipes(self):
        client = FakeClient(
            {
                ("eve", 1): b"EVE 1\r\n=>",
                ("eve", 2): b"EVE 2\r\n=>",
                ("ser", None): b"SER\r\n=>",
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            result = collect_events(
                TARGET,
                EventSelector.latest(count=2),
                ser_limit=1,
                secret_provider=FakeSecrets(),
                client_factory=factory_for(client),
                evidence_root=Path(directory),
                now=NOW,
            )

        self.assertEqual(
            [call for call in client.calls if call[0] == "run_bytes"],
            [
                ("run_bytes", "eve", 1),
                ("run_bytes", "eve", 2),
                ("run_bytes", "ser", None),
            ],
        )
        self.assertEqual(
            [a["kind"] for a in event_target(result)["artifacts"]],
            ["event", "event", "ser"],
        )

    def test_explicit_number_and_captured_cev_formats_are_supported(self):
        cases = (
            ("eve", "eve", b"EVE 2\r\n=>"),
            ("cev", "cev", b"CEV 2\r\n\x02binary\r\n=>"),
            ("cev_raw", "cev", b"CEV R 2\r\n\x02binary\r\n=>"),
        )
        for event_format, extension, payload in cases:
            with self.subTest(event_format=event_format):
                capability = event_format
                client = FakeClient(
                    {
                        (capability, 2): payload,
                        ("ser", None): b"SER\r\n=>",
                    }
                )
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    result = collect_events(
                        TARGET,
                        EventSelector.number(2, event_format=event_format),
                        ser_limit=1,
                        secret_provider=FakeSecrets(),
                        client_factory=factory_for(client),
                        evidence_root=root,
                        now=NOW,
                    )
                    target_result = event_target(result)
                    artifact = target_result["artifacts"][0]
                    stored = (root / artifact["path"]).read_bytes()

                self.assertEqual(stored, payload)
                self.assertTrue(artifact["path"].endswith(".{0}".format(extension)))
                self.assertEqual(artifact["format"], event_format)
                self.assertEqual(target_result["selection"]["event_number"], 2)

    def test_sel651_adapter_declares_capture_backed_event_recipes(self):
        adapter = Sel651Adapter()

        requests = adapter.event_requests(EventSelector.latest(count=2))

        self.assertIs(iter(requests), requests)
        requests = list(requests)

        self.assertEqual(
            [(request.capability, request.argument) for request in requests],
            [("eve", 1), ("eve", 2)],
        )
        self.assertEqual(
            set(COMMANDS_BY_FAMILY["sel651"]),
            {"identity", "status", "meter", "history", "eve", "cev", "cev_raw", "ser", "file_read", "file_show"},
        )
        for capability in ("eve", "cev", "cev_raw", "ser"):
            command = COMMANDS_BY_FAMILY["sel651"][capability]
            self.assertGreater(command.max_bytes, 0)
            self.assertGreater(command.max_seconds, 0)

    def test_collection_has_no_visualization_dependency_or_automatic_call(self):
        for module in (sel_collect_events, inspect.getmodule(collect_events)):
            source = inspect.getsource(module)
            self.assertFalse(imports_visualizer(source), module.__name__)

        self.assertTrue(imports_visualizer("from .sel_visualize import run as visualize"))

        with mock.patch.object(
            sel_visualize, "run", side_effect=AssertionError("visualizer called")
        ) as visualizer:
            client = FakeClient(
                {("eve", 1): b"EVE 1\r\n=>", ("ser", None): b"SER\r\n=>"}
            )
            with tempfile.TemporaryDirectory() as directory:
                collect_events(
                    TARGET,
                    secret_provider=FakeSecrets(),
                    client_factory=factory_for(client),
                    evidence_root=Path(directory),
                    now=NOW,
                )
        visualizer.assert_not_called()

    def test_agent_facing_tool_is_a_direct_workflow_alias(self):
        self.assertIs(sel_collect_events.run, collect_events)



class TestSel700GEventCollection(unittest.TestCase):
    def test_700g_ser_is_parsed_into_records_and_summary(self):
        from pathlib import Path as _Path

        ser = (
            _Path(__file__).parent / "fixtures" / "sel" / "700gt-ser.txt"
        ).read_text().split("\n", 1)[1].encode()

        class Identity700:
            observed_model = "SEL-700G"
            device_id = "SEL-700GT"

        class Client700(FakeClient):
            family = "sel700g"
            capabilities = tuple(COMMANDS_BY_FAMILY["sel700g"])

            def login(self, password):
                self.calls.append(("login", password))
                return Identity700()

        client = Client700({("eve", 1): b"EVE 1\r\nsynthetic\r\n=>", ("ser", None): ser})
        target = DeviceTarget(
            name="Lab Relay 700", kind="sel", host="192.0.2.10", port=23,
            model_hint="SEL-700GT", credential_ref="relay-700", timeout_seconds=5,
        )
        with tempfile.TemporaryDirectory() as directory:
            result = collect_events(
                target,
                ser_limit=500,
                secret_provider=FakeSecrets(),
                client_factory=factory_for(client),
                evidence_root=Path(directory),
                now=NOW,
            )
        target_result = event_target(result)
        self.assertTrue(result["ok"], target_result["errors"])
        self.assertEqual(len(target_result["ser"]["records"]), 16)
        self.assertEqual(
            target_result["ser"]["element_summary"]["3PWRX1P"]["deasserted"], 6
        )

    def test_651_ser_records_are_parsed(self):
        # the 651 family now parses SER (shared SER table parser, live 651R-2/651RA captures)
        client = FakeClient({("eve", 1): b"EVE 1\r\n=>", ("ser", None): SER_OLDEST_TO_NEWEST})
        with tempfile.TemporaryDirectory() as directory:
            result = collect_events(
                TARGET,
                secret_provider=FakeSecrets(),
                client_factory=factory_for(client),
                evidence_root=Path(directory),
                now=NOW,
            )
        ser = event_target(result)["ser"]
        self.assertEqual(len(ser["records"]), 5)
        self.assertEqual(ser["element_summary"]["TRIP"]["asserted"], 1)


class TestSel751EventCollection(unittest.TestCase):
    """The 751 has no capture-backed event report recipe: collection reads HIS and SER."""

    FIXTURES = Path(__file__).parent / "fixtures" / "sel"
    TARGET_751 = DeviceTarget(
        name="Lab Relay 751", kind="sel", host="192.0.2.12", port=23,
        model_hint="SEL-751", credential_ref="relay-751", timeout_seconds=5,
    )

    def client(self, responses, capabilities=None):
        class Identity751:
            observed_model = "SEL-751"
            device_id = "LAB-RELAY-751"

        class Client751(FakeClient):
            family = "sel751"

            def login(self, password):
                self.calls.append(("login", password))
                return Identity751()

        client = Client751(responses)
        client.capabilities = tuple(
            COMMANDS_BY_FAMILY["sel751"] if capabilities is None else capabilities
        )
        return client

    def fixture(self, name):
        return (self.FIXTURES / name).read_text().split("\n", 1)[1].encode()

    def collect(self, client, root, selector=None, ser_limit=500):
        return collect_events(
            self.TARGET_751,
            selector,
            ser_limit=ser_limit,
            secret_provider=FakeSecrets(),
            client_factory=factory_for(client),
            evidence_root=root,
            now=NOW,
        )

    def test_collects_his_and_parsed_ser_without_event_reports(self):
        history = self.fixture("751-history.txt")
        ser = self.fixture("ser/751-synthetic-ser.txt")
        client = self.client({("history", None): history, ("ser", None): ser})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.collect(client, root)
            target = event_target(result)
            artifacts = target["artifacts"]
            stored = [(root / a["path"]).read_bytes() for a in artifacts]
            manifest = json.loads((root / target["manifest"]).read_text())

        self.assertTrue(result["ok"], target["errors"])
        self.assertEqual(
            client.calls,
            [
                ("login", "synthetic-password"),
                ("run_bytes", "history", None),
                ("run_bytes", "ser", None),
            ],
        )
        self.assertEqual(client.logout_calls, 1)
        self.assertEqual([a["kind"] for a in artifacts], ["history", "ser"])
        self.assertEqual([a["format"] for a in artifacts], ["his", "ser"])
        self.assertEqual(artifacts[0]["recipe"], {"capability": "history", "argument": None})
        self.assertTrue(artifacts[0]["path"].endswith(".his"))
        self.assertTrue(artifacts[1]["path"].endswith(".ser"))
        self.assertEqual(stored, [history, ser])
        self.assertEqual(len(manifest["evidence"]), 2)
        self.assertEqual(
            [w["code"] for w in target["warnings"]], ["event_reports_unavailable"]
        )
        self.assertEqual(target["ser"]["rows_returned"], 12)
        self.assertEqual(len(target["ser"]["records"]), 12)
        self.assertEqual(target["ser"]["records"][-1]["number"], 1)
        self.assertEqual(target["ser"]["element_summary"]["52A"]["deasserted"], 1)
        self.assertEqual(target["ser"]["element_summary"]["Relay Powered Up"]["event"], 1)
        events = target["history"]["events"]
        self.assertGreater(len(events), 0)
        self.assertTrue(all("event_number" in e and "timestamp" in e for e in events))

    def test_explicit_event_selector_still_collects_his_and_ser(self):
        client = self.client(
            {
                ("history", None): self.fixture("751-history.txt"),
                ("ser", None): self.fixture("ser/751-ser.txt"),
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self.collect(
                client, Path(directory), EventSelector.number(3, event_format="cev")
            )
        target = event_target(result)
        self.assertTrue(result["ok"], target["errors"])
        self.assertNotIn(("run_bytes", "cev", 3), client.calls)
        self.assertNotIn(("run_bytes", "eve", 3), client.calls)
        self.assertIn("SEL-751", target["warnings"][0]["message"])

    def test_ser_limit_bounds_the_751_ser(self):
        client = self.client(
            {
                ("history", None): self.fixture("751-history.txt"),
                ("ser", None): self.fixture("ser/751-synthetic-ser.txt"),
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self.collect(client, Path(directory), ser_limit=2)
        ser = event_target(result)["ser"]
        self.assertEqual((ser["rows_returned"], ser["rows_available"], ser["truncated"]), (2, 12, True))
        self.assertEqual([r["number"] for r in ser["records"]], [2, 1])

    def test_missing_ser_command_is_reported_before_any_read(self):
        client = self.client({}, capabilities=("identity", "history"))
        with tempfile.TemporaryDirectory() as directory:
            result = self.collect(client, Path(directory))
        target = event_target(result)
        self.assertFalse(result["ok"])
        self.assertEqual(target["errors"][0]["category"], "command_unavailable")
        self.assertIn("ser", target["errors"][0]["message"])
        self.assertEqual(client.calls, [("login", "synthetic-password")])

    def test_ser_failure_keeps_the_his_artifact(self):
        client = self.client(
            {
                ("history", None): self.fixture("751-history.txt"),
                ("ser", None): TriageError(
                    "prompt timeout", category="transport_timeout", reachable=True
                ),
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self.collect(client, Path(directory))
        target = event_target(result)
        self.assertFalse(result["ok"])
        self.assertTrue(result["partial"])
        self.assertEqual([a["kind"] for a in target["artifacts"]], ["history"])
        self.assertEqual(target["errors"][0]["stage"], "ser_retrieval")

    def test_only_the_751_is_a_ser_only_event_family(self):
        from sel_triage.integrations.devices.sel.adapters.sel735 import Sel735Adapter
        from sel_triage.integrations.devices.sel.adapters.sel751 import Sel751Adapter

        self.assertTrue(Sel751Adapter().ser_only_events)
        self.assertEqual(list(Sel751Adapter().event_requests(EventSelector.latest())), [])
        self.assertFalse(Sel651Adapter().ser_only_events)
        self.assertFalse(Sel735Adapter().ser_only_events)
        with self.assertRaisesRegex(ValueError, "command_unavailable"):
            Sel735Adapter().event_requests(EventSelector.latest())


if __name__ == "__main__":
    unittest.main()
