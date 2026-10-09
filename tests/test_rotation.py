"""Fail-closed contract tests for the existing Scheme C trust boundary."""
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gate"))
from rotation import (evaluate_rotation, owner_exact_review,
                      evaluate_formal_adoption, evaluate_state_change,
                      FORMAL_ADOPTION_NOTE)
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

class TrustedBotWorkflowStaticTests(unittest.TestCase):
    def test_dispatch_is_protected_main_owner_only(self):
        from pathlib import Path
        workflow = (Path(__file__).resolve().parent.parent / ".github/workflows/governance-gate.yml").read_text("utf-8")
        self.assertIn("github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.actor == github.repository_owner", workflow)
        self.assertIn("pull-requests: write", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("pull-requests: write\n\njobs:", workflow)

    def test_bot_branch_data_never_executed_by_dispatch(self):
        from pathlib import Path
        workflow = (Path(__file__).resolve().parent.parent / ".github/workflows/governance-gate.yml").read_text("utf-8")
        bot_job = workflow.split("  create-bot-rotation-pr:", 1)[1]
        self.assertIn('[[ "$changed" == "governance/state.json" ]]', bot_job)
        self.assertNotIn("python candidate/", bot_job)
        self.assertNotIn("run: bash candidate/", bot_job)
        self.assertNotIn('gh pr view "$url" --repo', bot_job)
        self.assertIn('gh api "repos/$GITHUB_REPOSITORY/pulls/$pr_number"', bot_job)
        self.assertIn('if ! verify_bot_pr_identity "$pr_json"; then', bot_job)
        self.assertIn("41898282", bot_job)

    def test_required_gate_event_is_trusted_default_branch_only(self):
        from pathlib import Path
        workflow = (Path(__file__).resolve().parent.parent / ".github/workflows/governance-gate.yml").read_text("utf-8")
        # Owner-initiated PR reopen must trigger protected-base pull_request_target,
        # not the candidate merge-branch pull_request_review workflow.
        self.assertIn("  pull_request_target:\n    types: [opened, synchronize, reopened]\n    branches: [main]", workflow)
        self.assertNotIn("\n  pull_request_review:", workflow)
        self.assertIn("if: github.event_name == 'pull_request_target' && github.event.pull_request.base.ref == 'main'", workflow)
        self.assertNotIn("github.event_name != 'push'", workflow)
        self.assertIn("ref: ${{ github.event.pull_request.base.sha }}", workflow)
        self.assertIn("python trusted/gate/rotation.py", workflow)
        self.assertIn("python trusted/gate/validate.py", workflow)
        self.assertNotIn("python candidate/gate/", workflow)

class BotRestIdentityRegressionTests(unittest.TestCase):
    """Execute the real inline workflow verifier with synthetic REST responses."""

    @classmethod
    def setUpClass(cls):
        from pathlib import Path
        workflow = (Path(__file__).resolve().parent.parent / ".github/workflows/governance-gate.yml").read_text("utf-8")
        match = re.search(r"(?ms)^          verify_bot_pr_identity\(\) \{\n.*?^          \}\n", workflow)
        if not match:
            raise AssertionError("trusted inline verifier is missing")
        cls.validator = textwrap.dedent(match.group(0))
        cls.head = "a" * 40
        cls.branch = "rotation/hp25-scheme-c-g10-f001-e2e-001"
        cls.repo = "givemedandanla-tool/HP2.5_SHELL"

    def valid_payload(self):
        return {
            "user": {"login": "github-actions[bot]", "type": "Bot", "id": 41898282},
            "head": {"sha": self.head, "ref": self.branch, "repo": {"full_name": self.repo}},
            "base": {"ref": "main"},
            "draft": True,
        }

    def run_verifier(self, data):
        self.assertIsNotNone(shutil.which("bash"), "bash required for workflow test")
        self.assertIsNotNone(shutil.which("jq"), "jq required for workflow test")
        env = dict(os.environ)
        env.update({"PR_JSON": json.dumps(data), "EXPECTED_HEAD": self.head,
                    "ROTATION_BRANCH": self.branch, "GITHUB_REPOSITORY": self.repo})
        script = "set -euo pipefail\n" + self.validator + "\nverify_bot_pr_identity \"$PR_JSON\"\n"
        return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, check=False)

    def test_live_rest_bot_author_and_exact_draft_pr_accepted(self):
        result = self.run_verifier(self.valid_payload())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_spoofed_or_stale_rest_fields_denied(self):
        changes = (
            ("untrusted_login", ("user", "login"), "app/github-actions"),
            ("owner_impersonation", ("user", "login"), "givemedandanla-tool"),
            ("untrusted_type", ("user", "type"), "User"),
            ("wrong_bot_id", ("user", "id"), 41898283),
            ("stale_head", ("head", "sha"), "b" * 40),
            ("untrusted_branch", ("head", "ref"), "rotation/other"),
            ("untrusted_repository", ("head", "repo", "full_name"), "other/repo"),
            ("wrong_base", ("base", "ref"), "unprotected"),
            ("not_draft", ("draft",), False),
            ("missing_author", ("user", "login"), None),
        )
        for label, path, value in changes:
            with self.subTest(case=label):
                data = self.valid_payload()
                field = data
                for key in path[:-1]:
                    field = field[key]
                field[path[-1]] = value
                result = self.run_verifier(data)
                self.assertNotEqual(result.returncode, 0, label)


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

class FormalAdoptionTests(unittest.TestCase):
    """正式採用與一般輪替分開；所有有限 Authority guard 必須繼續生效。"""

    def setUp(self):
        fixture = RotationTests()
        fixture.setUp()
        self.now = fixture.now
        self.old = fixture.old
        self.new = fixture.new
        self.new["mode"] = "FORMAL_SCHEME_C"
        self.new["note"] = FORMAL_ADOPTION_NOTE

    def envelope(self):
        return next(iter(self.new["authority_envelopes"].values()))

    def assert_denied(self, reason):
        decision = evaluate_state_change(self.old, self.new, self.now)
        self.assertFalse(decision["allowed"])
        self.assertIn(reason, decision["reasons"])

    def test_single_forward_adoption_routes_and_preserves_input(self):
        before, after = copy.deepcopy(self.old), copy.deepcopy(self.new)
        self.assertTrue(evaluate_formal_adoption(self.old, self.new, self.now)["allowed"])
        self.assertTrue(evaluate_state_change(self.old, self.new, self.now)["allowed"])
        self.assertEqual(self.old, before)
        self.assertEqual(self.new, after)

    def test_direct_ordinary_rotation_still_denies_mode_and_note(self):
        decision = evaluate_rotation(self.old, self.new, self.now)
        self.assertFalse(decision["allowed"])
        self.assertIn("immutable_field_changed:mode", decision["reasons"])
        self.assertIn("immutable_field_changed:note", decision["reasons"])

    def test_fixed_note_required(self):
        for note in (None, "", "Formally approved by note", FORMAL_ADOPTION_NOTE + " "):
            with self.subTest(note=note):
                self.new["note"] = note
                self.assert_denied("formal_adoption_note")

    def test_note_cannot_select_formal_route(self):
        self.new["mode"] = "EXPERIMENTAL_SPIKE"
        self.assert_denied("immutable_field_changed:note")

    def test_unknown_or_missing_modes_denied(self):
        for mode in (None, "ALMOST_FORMAL", {}, True):
            with self.subTest(target=mode):
                self.new["mode"] = mode
                self.assert_denied("formal_adoption_requires_formal_target")
            with self.subTest(base=mode):
                self.old["mode"] = mode
                self.new["mode"] = "FORMAL_SCHEME_C"
                self.assert_denied("formal_adoption_requires_experimental_base")
                self.old["mode"] = "EXPERIMENTAL_SPIKE"
        self.new.pop("mode")
        self.assert_denied("formal_adoption_requires_formal_target")

    def test_unknown_unchanged_mode_not_an_ordinary_rotation(self):
        self.old["mode"] = self.new["mode"] = "ALMOST_FORMAL"
        self.assert_denied("unsupported_state_mode")

    def test_downgrade_and_repeat_adoption_denied(self):
        self.old["mode"] = "FORMAL_SCHEME_C"
        self.new["mode"] = "EXPERIMENTAL_SPIKE"
        self.assert_denied("formal_adoption_requires_experimental_base")
        self.new["mode"] = "FORMAL_SCHEME_C"
        decision = evaluate_formal_adoption(self.old, self.new, self.now)
        self.assertFalse(decision["allowed"])
        self.assertIn("formal_adoption_requires_experimental_base", decision["reasons"])

    def test_formal_mode_can_rotate_authority_without_new_adoption(self):
        self.old["mode"] = "FORMAL_SCHEME_C"
        self.old["note"] = FORMAL_ADOPTION_NOTE
        self.assertTrue(evaluate_state_change(self.old, self.new, self.now)["allowed"])

    def test_generation_must_increment_exactly_once(self):
        for generation in (9, 11, True):
            with self.subTest(generation=generation):
                self.new["current_generation"] = generation
                self.assert_denied("generation_not_incremented_exactly_once")

    def test_approval_policy_history_and_extra_fields_remain_immutable(self):
        for field, value, reason in (
            ("approved_revision", HEAD, "immutable_field_changed:approved_revision"),
            ("last_approval_id", "approval-1", "immutable_field_changed:last_approval_id"),
            ("policy_version", "UNREVIEWED", "immutable_field_changed:policy_version"),
            ("schema_version", "UNKNOWN", "immutable_field_changed:schema_version"),
            ("manifest", {}, "unexpected_state_keys"),
            ("bypass", True, "unexpected_state_keys"),
        ):
            with self.subTest(field=field):
                original = copy.deepcopy(self.new)
                self.new[field] = value
                self.assert_denied(reason)
                self.new = original
        self.old["used_authority_ids"] = ["HUMAN-OLD"]
        self.new["used_authority_ids"] = []
        self.assert_denied("immutable_field_changed:used_authority_ids")

    def test_existing_approval_is_preserved_not_reissued(self):
        self.old["approved_revision"] = self.new["approved_revision"] = HEAD
        self.old["last_approval_id"] = self.new["last_approval_id"] = "historical-approval"
        self.assertTrue(evaluate_state_change(self.old, self.new, self.now)["allowed"])

    def test_missing_or_extra_authority_envelope_denied(self):
        self.new["authority_envelopes"] = {}
        self.assert_denied("authority_envelope_set_mismatch")
        self.setUp()
        self.envelope()["approval"] = True
        self.assert_denied("authority_envelope_shape")

    def test_authority_identity_and_receipt_guards_reused(self):
        for field, value, reason in (
            ("parent_authority_id", "SELF", "authority_parent_or_id"),
            ("generation", 11, "authority_generation"),
            ("work_id", "OTHER", "authority_work"),
            ("exact_subject", "not-a-commit", "authority_exact_subject"),
            ("subject_id", "", "authority_subject"),
            ("independent_auditor_subject", "WRITER-A", "writer_equals_auditor"),
            ("independent_audit_receipt_sha256", "unverified", "audit_receipt_digest"),
        ):
            with self.subTest(field=field):
                original = copy.deepcopy(self.new)
                self.envelope()[field] = value
                self.assert_denied(reason)
                self.new = original

    def test_finite_authority_time_guards_reused(self):
        for end in (self.now, self.now - timedelta(seconds=1), self.now + timedelta(days=2)):
            with self.subTest(end=end):
                self.envelope()["valid_until"] = end.isoformat()
                self.assert_denied("authority_lifetime")
        self.envelope()["valid_until"] = "invalid-time"
        self.assert_denied("authority_time_invalid")

    def test_generation_bound_authority_id_guard_reused(self):
        for aid in ("HUMAN-OLD", "HUMAN-SCHEME-C-G9-UNIQUE0001", "HUMAN-UNBOUND-UNIQUE0001"):
            with self.subTest(authority=aid):
                original = copy.deepcopy(self.new)
                envelope = self.new["authority_envelopes"].pop(self.new["allowed_authority_ids"][0])
                envelope["authority_id"] = aid
                self.new["allowed_authority_ids"] = [aid]
                self.new["authority_envelopes"] = {aid: envelope}
                self.assert_denied("authority_id_generation_binding")
                self.new = original

    def test_non_object_state_denied(self):
        for before, after in ((None, self.new), (self.old, [])):
            with self.subTest(before=before, after=after):
                self.assertEqual(evaluate_state_change(before, after, self.now),
                                 {"allowed": False, "reasons": ["state_not_object"]})

class FormalAdoptionCliTests(unittest.TestCase):
    """實際 CLI 路徑必須驗證 authenticated review；資料 evaluator 不授權 merge。"""

    setUp = FormalAdoptionTests.setUp

    def run_cli(self, reviews, author="trusted-bot"):
        import io
        import tempfile
        from contextlib import redirect_stdout
        from pathlib import Path
        from unittest.mock import patch
        from rotation import main
        with tempfile.TemporaryDirectory() as directory:
            before = Path(directory) / "trusted.json"
            after = Path(directory) / "candidate.json"
            before.write_text(json.dumps(self.old), encoding="utf-8")
            after.write_text(json.dumps(self.new), encoding="utf-8")
            output = io.StringIO()
            environment = {
                "GITHUB_REPOSITORY": "governance-owner/public-shell",
                "GITHUB_TOKEN": "synthetic-test-token",
                "ROTATION_PR_NUMBER": "1", "ROTATION_HEAD_SHA": HEAD,
                "ROTATION_PR_AUTHOR": author,
            }
            with patch.dict(os.environ, environment), patch.object(sys, "argv", ["rotation.py", str(before), str(after)]), \
                    patch("rotation.fetch_reviews", return_value=reviews) as fetch, redirect_stdout(output):
                with self.assertRaises(SystemExit) as exit_result:
                    main()
            fetch.assert_called_once_with("governance-owner/public-shell", "1", "synthetic-test-token")
            return exit_result.exception.code, json.loads(output.getvalue())

    def review(self, **changes):
        review = {"id": 100, "state": "APPROVED", "commit_id": HEAD,
                  "user": {"login": "governance-owner"}}
        review.update(changes)
        return review

    def test_cli_forward_adoption_requires_distinct_exact_owner_review(self):
        code, decision = self.run_cli([self.review()])
        self.assertEqual(code, 0)
        self.assertTrue(decision["allowed"])

    def test_cli_missing_stale_other_or_dismissed_review_denied(self):
        cases = (
            [], [self.review(commit_id="b" * 40)],
            [self.review(user={"login": "other-reviewer"})],
            [self.review(), self.review(id=101, state="DISMISSED")],
        )
        for reviews in cases:
            with self.subTest(reviews=reviews):
                code, decision = self.run_cli(reviews)
                self.assertEqual(code, 1)
                self.assertIn("missing_distinct_owner_exact_head_approval", decision["reasons"])

    def test_cli_owner_self_approval_denied(self):
        code, decision = self.run_cli([self.review()], author="governance-owner")
        self.assertEqual(code, 1)
        self.assertIn("missing_distinct_owner_exact_head_approval", decision["reasons"])

    def test_cli_owner_review_cannot_override_invalid_transition(self):
        self.new["approved_revision"] = HEAD
        code, decision = self.run_cli([self.review()])
        self.assertEqual(code, 1)
        self.assertIn("immutable_field_changed:approved_revision", decision["reasons"])

if __name__ == "__main__":
    unittest.main()
