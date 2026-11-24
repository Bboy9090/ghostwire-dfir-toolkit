import json
import os
import tempfile
import unittest

from schema.event_schema import ProvenanceInfo, SecurityEvent
from security.dfir_triage import (
    IncidentCase,
    acquire_file_evidence,
    add_analyst_note,
    add_event_to_case,
    export_case_bundle,
    render_incident_report_markdown,
    verify_case_bundle,
    verify_evidence_integrity,
)


class TestDFIRTriage(unittest.TestCase):
    def test_acquire_verify_and_tamper_evident_case_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample_path = os.path.join(tmp, "dropper.sh")
            with open(sample_path, "wb") as f:
                f.write(b"#!/bin/sh\necho benign-test\n")

            ev = acquire_file_evidence(sample_path, collector="analyst-1")
            self.assertEqual(ev.magic_type, "script_shebang")
            self.assertTrue(verify_evidence_integrity(ev))
            self.assertEqual(len(ev.custody_chain), 2)

            case = IncidentCase(
                case_id="CASE-2026-001",
                title="Test Script Investigation",
                asset_id="mac-01",
                created_at="2026-11-23T12:00:00+00:00",
                evidence=[ev],
            )
            add_event_to_case(
                case,
                SecurityEvent(
                    asset_id="mac-01",
                    event_category="file",
                    event_action="create",
                    severity="medium",
                    confidence=0.9,
                    provenance=ProvenanceInfo(source_component="dfir_test", is_synthetic=True),
                    payload={"path": sample_path},
                ),
            )
            add_analyst_note(case, author="analyst-1", content="Confirmed harmless test script.", decision="benign")

            bundle_path = os.path.join(tmp, "case_bundle.json")
            export_case_bundle(case, bundle_path)
            self.assertTrue(verify_case_bundle(bundle_path))

            # Tamper with bundle and ensure verification fails
            with open(bundle_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            raw["case"]["status"] = "closed"
            with open(bundle_path, "w", encoding="utf-8") as f:
                json.dump(raw, f)
            self.assertFalse(verify_case_bundle(bundle_path))

            report = render_incident_report_markdown(case)
            self.assertIn("CASE-2026-001", report)
            self.assertIn(ev.sha256, report)
            self.assertIn("Confirmed harmless test script.", report)


if __name__ == "__main__":
    unittest.main()
