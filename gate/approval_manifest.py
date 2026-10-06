import hashlib
import json
import re
from copy import deepcopy

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

REQUIRED = {
    "schema_version",
    "approval_id",
    "source_repository_id",
    "source_repository_full_name",
    "source_commit_sha",
    "source_main_observed_sha",
    "candidate_work_id",
    "candidate_generation",
    "audit_generation",
    "candidate_state",
    "exact_ci_run_id",
    "exact_ci_head_sha",
    "exact_ci_conclusion",
    "independent_audit_id",
    "independent_audit_result",
    "independent_auditor_subject",
    "independent_audit_receipt_sha256",
    "writer_subject",
    "blocking_findings",
    "approved_revision",
    "policy_version",
    "authority_id",
    "created_at",
    "source_evidence_fingerprint",
    "manifest_sha256",
}

def canonical_payload(manifest):
    value = deepcopy(manifest)
    value.pop("manifest_sha256", None)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")

def compute_manifest_sha256(manifest):
    return "sha256:" + hashlib.sha256(canonical_payload(manifest)).hexdigest()

def evaluate(manifest, state):
    reasons = []
    if not isinstance(manifest, dict):
        return {"allowed": False, "reasons": ["manifest_not_object"]}

    missing = sorted(REQUIRED - set(manifest))
    extra = sorted(set(manifest) - REQUIRED)
    if missing:
        reasons.append("missing_fields:" + ",".join(missing))
    if extra:
        reasons.append("unknown_fields:" + ",".join(extra))
    if reasons:
        return {"allowed": False, "reasons": reasons}

    if manifest["schema_version"] != "HP25_GOVERNANCE_APPROVAL_V1":
        reasons.append("schema_version")
    if not str(manifest["source_repository_id"]).isdigit():
        reasons.append("source_repository_id")
    if not REPO.fullmatch(str(manifest["source_repository_full_name"])):
        reasons.append("source_repository_full_name")

    for key in (
        "source_commit_sha",
        "source_main_observed_sha",
        "exact_ci_head_sha",
        "approved_revision",
    ):
        if not SHA40.fullmatch(str(manifest[key])):
            reasons.append(key)

    for key in ("independent_audit_receipt_sha256", "source_evidence_fingerprint"):
        if not SHA256.fullmatch(str(manifest[key])):
            reasons.append(key)

    if manifest["candidate_state"] != "READY_FOR_APPROVAL":
        reasons.append("candidate_state")
    if manifest["exact_ci_conclusion"] != "success":
        reasons.append("exact_ci")
    if manifest["independent_audit_result"] != "PASS":
        reasons.append("independent_audit")
    if manifest["blocking_findings"] != 0:
        reasons.append("blocking_findings")

    if not (
        manifest["source_commit_sha"]
        == manifest["exact_ci_head_sha"]
        == manifest["approved_revision"]
    ):
        reasons.append("revision_mismatch")

    if manifest["independent_auditor_subject"] == manifest["writer_subject"]:
        reasons.append("writer_equals_auditor")

    current_generation = state.get("current_generation")
    if not (
        manifest["candidate_generation"]
        == manifest["audit_generation"]
        == current_generation
    ):
        reasons.append("stale_generation_or_audit")

    if manifest["policy_version"] != state.get("policy_version"):
        reasons.append("policy_version")

    allowed_authorities = state.get("allowed_authority_ids", [])
    if manifest["authority_id"] not in allowed_authorities:
        reasons.append("authority")

    if compute_manifest_sha256(manifest) != manifest["manifest_sha256"]:
        reasons.append("manifest_hash")

    return {"allowed": not reasons, "reasons": reasons}
