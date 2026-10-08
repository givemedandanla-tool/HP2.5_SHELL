"""Fail-closed contract tests for the existing Scheme C trust boundary."""
import copy
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gate"))
from rotation import evaluate_rotation, owner_exact_review
from approval_manifest import evaluate, compute_manifest_sha256

HEAD = "a" * 40
DIGEST = "sha256:" + "b" * 64

class RotationTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.old = {
            "schema_version": "HP25_GOVERNANCE_STATE_V1",
            "mode": "EXPERIMENTAL_SPIKE",
            "current_generation": 9,
            "policy_version": "HP25-GOVERNANCE-SHELL-POLICY-V1",
            "allowed_authority_ids": ["HUMAN-OLD"],
            "approved_revision": None,
            "last_approval_id": None,
            "note": "Synthetic Scheme C spike state only; not production approval.",
        }
        self.new = copy.deepcopy(self.old)
        self.new["current_generation"] = 10
        self.new["allowed_authority_ids"] = ["HUMAN-SCHEME-C-G10-UNIQUE0001"]
        self.new["authority_envelopes"] = {
            "HUMAN-SCHEME-C-G10-UNIQUE0001": {
                "authority_id": "HUMAN-SCHEME-C-G10-UNIQUE0001",
                "parent_authority_id": "HUMAN-OWNER",
                "subject_id": "HP25-GPT-ROOT-INTEGRATOR",
                "work_id": "HP25-PROGRESSIVE-SYSTEM-CONSOLIDATION-001",
                "exact_subject": HEAD,
                "generation": 10,
                "valid_from": (self.now - timedelta(minutes=1)).isoformat(),
                "valid_until": (self.now + timedelta(hours=2)).isoformat(),
                "writer_subject": "WRITER-A",
                "independent_auditor_subject": "AUDITOR-B",
                "independent_audit_receipt_sha256": DIGEST,
            }
        }

    def check_denied(self):
        self.assertFalse(evaluate_rotation(self.old, self.new, self.now)["allowed"])

    def test_bounded_rotation_permitted_after_review(self):
        self.assertTrue(evaluate_rotation(self.old, self.new, self.now)["allowed"])

    def test_stale_generation_rejected(self):
        self.new["current_generation"] = 9
        self.check_denied()

    def test_skipped_generation_rejected(self):
        self.new["current_generation"] = 11
        self.check_denied()

    def test_authority_replay_rejected(self):
        self.new["allowed_authority_ids"] = ["HUMAN-OLD"]
        self.check_denied()

    def test_approval_state_mutation_rejected(self):
        self.new["approved_revision"] = HEAD
        self.check_denied()

    def test_policy_change_rejected(self):
        self.new["policy_version"] = "MALICIOUS"
        self.check_denied()

    def test_extra_state_field_rejected(self):
        self.new["bypass"] = True
        self.check_denied()

    def test_missing_authority_envelope_rejected(self):
        self.new["authority_envelopes"] = {}
        self.check_denied()

    def test_unbounded_authority_rejected(self):
        self.new["authority_envelopes"]["HUMAN-SCHEME-C-G10-UNIQUE0001"]["valid_until"] = (
            self.now + timedelta(days=2)).isoformat()
        self.check_denied()

    def test_expired_authority_rejected(self):
        self.new["authority_envelopes"]["HUMAN-SCHEME-C-G10-UNIQUE0001"]["valid_until"] = (
            self.now - timedelta(seconds=1)).isoformat()
        self.check_denied()

    def test_self_audit_rejected(self):
        self.new["authority_envelopes"]["HUMAN-SCHEME-C-G10-UNIQUE0001"]["independent_auditor_subject"] = "WRITER-A"
        self.check_denied()

    def test_bad_audit_receipt_rejected(self):
        self.new["authority_envelopes"]["HUMAN-SCHEME-C-G10-UNIQUE0001"]["independent_audit_receipt_sha256"] = "not-a-digest"
        self.check_denied()

    def test_missing_parent_rejected(self):
        self.new["authority_envelopes"]["HUMAN-SCHEME-C-G10-UNIQUE0001"]["parent_authority_id"] = "SELF"
        self.check_denied()

    def test_wrong_subject_sha_rejected(self):
        self.new["authority_envelopes"]["HUMAN-SCHEME-C-G10-UNIQUE0001"]["exact_subject"] = "not-a-commit"
        self.check_denied()


    def test_authority_from_two_generations_ago_rejected(self):
        # G9 -> G10 and G10 -> G11 pass; G10 ID may not recur in G12.
        g10 = copy.deepcopy(self.new)
        self.assertTrue(evaluate_rotation(self.old, g10, self.now)["allowed"])
        g11 = copy.deepcopy(g10)
        g11["current_generation"] = 11
        g11["allowed_authority_ids"] = ["HUMAN-SCHEME-C-G11-UNIQUE0002"]
        env = g11["authority_envelopes"].pop("HUMAN-SCHEME-C-G10-UNIQUE0001")
        env["authority_id"] = g11["allowed_authority_ids"][0]
        env["generation"] = 11
        g11["authority_envelopes"][env["authority_id"]] = env
        self.assertTrue(evaluate_rotation(g10, g11, self.now)["allowed"])
        g12 = copy.deepcopy(g11)
        g12["current_generation"] = 12
        g12["allowed_authority_ids"] = ["HUMAN-SCHEME-C-G10-UNIQUE0001"]
        env = g12["authority_envelopes"].pop("HUMAN-SCHEME-C-G11-UNIQUE0002")
        env["authority_id"] = g12["allowed_authority_ids"][0]
        env["generation"] = 12
        g12["authority_envelopes"][env["authority_id"]] = env
        decision = evaluate_rotation(g11, g12, self.now)
        self.assertFalse(decision["allowed"])
        self.assertIn("authority_id_generation_binding", decision["reasons"])

    def test_forged_generation_in_authority_id_rejected(self):
        wrong = "HUMAN-SCHEME-C-G11-UNIQUE0001"
        self.new["allowed_authority_ids"] = [wrong]
        env = self.new["authority_envelopes"].pop("HUMAN-SCHEME-C-G10-UNIQUE0001")
        env["authority_id"] = wrong
        self.new["authority_envelopes"][wrong] = env
        self.check_denied()

    def test_legacy_unbound_authority_id_rejected(self):
        wrong = "HUMAN-UNBOUND-UNIQUE0001"
        self.new["allowed_authority_ids"] = [wrong]
        env = self.new["authority_envelopes"].pop("HUMAN-SCHEME-C-G10-UNIQUE0001")
        env["authority_id"] = wrong
        self.new["authority_envelopes"][wrong] = env
        self.check_denied()

    def test_unauthorized_history_field_rejected(self):
        self.new["used_authority_ids"] = ["HUMAN-OLD"]
        self.check_denied()

    def test_history_immutable_if_present_rejected(self):
        self.old["used_authority_ids"] = ["HUMAN-OLD"]
        self.new["used_authority_ids"] = []
        self.check_denied()

    def test_formal_mode_change_not_permitted_during_rotation(self):
        self.new["mode"] = "FORMAL_SCHEME_C"
        self.check_denied()

class ExactOwnerReviewTests(unittest.TestCase):
    def setUp(self):
        self.reviews = [{
            "id": 100, "state": "APPROVED", "commit_id": HEAD,
            "user": {"login": "givemedandanla-tool"},
        }]

    def test_distinct_exact_head_owner_approval(self):
        self.assertTrue(owner_exact_review(self.reviews, "givemedandanla-tool", "trusted-bot", HEAD))

    def test_self_approval_disallowed(self):
        self.assertFalse(owner_exact_review(self.reviews, "givemedandanla-tool", "givemedandanla-tool", HEAD))

    def test_stale_sha_disallowed(self):
        self.assertFalse(owner_exact_review(self.reviews, "givemedandanla-tool", "trusted-bot", "c" * 40))

    def test_other_reviewer_disallowed(self):
        self.assertFalse(owner_exact_review(self.reviews, "not-owner", "trusted-bot", HEAD))

    def test_later_dismissal_disallowed(self):
        self.reviews.append({
            "id": 101, "state": "DISMISSED", "commit_id": HEAD,
            "user": {"login": "givemedandanla-tool"},
        })
        self.assertFalse(owner_exact_review(self.reviews, "givemedandanla-tool", "trusted-bot", HEAD))

class ApprovalEnvelopeTests(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.manifest = {
            "schema_version": "HP25_GOVERNANCE_APPROVAL_V1",
            "approval_id": "approval-1",
            "source_repository_id": "1405362726",
            "source_repository_full_name": "givemedandanla-tool/phase2.5-autonomous-engineering",
            "source_commit_sha": HEAD,
            "source_main_observed_sha": "c" * 40,
            "candidate_work_id": "HP25-PROGRESSIVE-SYSTEM-CONSOLIDATION-001",
            "candidate_generation": 10, "audit_generation": 10,
            "candidate_state": "READY_FOR_APPROVAL",
            "exact_ci_run_id": 100,
            "exact_ci_head_sha": HEAD,
            "exact_ci_conclusion": "success",
            "independent_audit_id": "audit-1",
            "independent_audit_result": "PASS",
            "independent_auditor_subject": "AUDITOR-B",
            "independent_audit_receipt_sha256": DIGEST,
            "writer_subject": "WRITER-A",
            "blocking_findings": 0,
            "approved_revision": HEAD,
            "policy_version": "HP25-GOVERNANCE-SHELL-POLICY-V1",
            "authority_id": "HUMAN-SCHEME-C-G10-UNIQUE0001",
            "created_at": now.isoformat(),
            "source_evidence_fingerprint": "sha256:" + "c" * 64,
        }
        self.state = {
            "mode": "FORMAL_SCHEME_C",
            "current_generation": 10,
            "policy_version": "HP25-GOVERNANCE-SHELL-POLICY-V1",
            "allowed_authority_ids": ["HUMAN-SCHEME-C-G10-UNIQUE0001"],
            "authority_envelopes": {
                "HUMAN-SCHEME-C-G10-UNIQUE0001": {
                    "authority_id": "HUMAN-SCHEME-C-G10-UNIQUE0001",
                    "parent_authority_id": "HUMAN-OWNER",
                    "work_id": self.manifest["candidate_work_id"],
                    "exact_subject": HEAD,
                    "generation": 10,
                    "writer_subject": "WRITER-A",
                    "independent_auditor_subject": "AUDITOR-B",
                    "independent_audit_receipt_sha256": DIGEST,
                    "valid_from": (now - timedelta(minutes=2)).isoformat(),
                    "valid_until": (now + timedelta(hours=2)).isoformat(),
                }
            },
        }
        self.sign()

    def sign(self):
        self.manifest["manifest_sha256"] = compute_manifest_sha256(self.manifest)

    def test_exact_valid_approval(self):
        self.assertTrue(evaluate(self.manifest, self.state)["allowed"])


    def test_experimental_mode_rejects_real_exact_approval(self):
        self.state["mode"] = "EXPERIMENTAL_SPIKE"
        decision = evaluate(self.manifest, self.state)
        self.assertFalse(decision["allowed"])
        self.assertIn("scheme_c_formal_mode_not_active", decision["reasons"])

    def test_mode_missing_rejected(self):
        self.state.pop("mode")
        self.assertFalse(evaluate(self.manifest, self.state)["allowed"])

    def test_unknown_mode_rejected(self):
        self.state["mode"] = "ALMOST_PRODUCTION"
        self.assertFalse(evaluate(self.manifest, self.state)["allowed"])

    def test_note_cannot_override_experimental_mode(self):
        self.state["mode"] = "EXPERIMENTAL_SPIKE"
        self.state["note"] = "Formally approved by text"
        self.assertFalse(evaluate(self.manifest, self.state)["allowed"])

    def test_missing_envelope_rejected(self):
        self.state["authority_envelopes"] = {}
        self.assertFalse(evaluate(self.manifest, self.state)["allowed"])

    def test_expired_envelope_rejected(self):
        self.state["authority_envelopes"]["HUMAN-SCHEME-C-G10-UNIQUE0001"]["valid_until"] = (
            datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.assertFalse(evaluate(self.manifest, self.state)["allowed"])

    def test_subject_mismatch_rejected(self):
        self.state["authority_envelopes"]["HUMAN-SCHEME-C-G10-UNIQUE0001"]["exact_subject"] = "d" * 40
        self.assertFalse(evaluate(self.manifest, self.state)["allowed"])

    def test_receipt_mismatch_rejected(self):
        self.state["authority_envelopes"]["HUMAN-SCHEME-C-G10-UNIQUE0001"]["independent_audit_receipt_sha256"] = (
            "sha256:" + "f" * 64)
        self.assertFalse(evaluate(self.manifest, self.state)["allowed"])

    def test_tampered_manifest_hash_rejected(self):
        self.manifest["manifest_sha256"] = "sha256:" + "0" * 64
        self.assertFalse(evaluate(self.manifest, self.state)["allowed"])

if __name__ == "__main__":
    unittest.main()
