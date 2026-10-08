"""Trusted Scheme C state rotation gate (always executed from protected base).

A rotation changes governance/state.json only. A separate GitHub OWNER's exact-head
APPROVED review is mandatory, in addition to protected PR/status checks.
"""
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.request import Request, urlopen

SHA40 = re.compile(r"^[a-f0-9]{40}$")
HASH = re.compile(r"^sha256:[a-f0-9]{64}$")
ID = re.compile(r"^[A-Za-z0-9_.-]{1,160}$")
ENVELOPE_KEYS = {
    "authority_id", "parent_authority_id", "subject_id", "work_id",
    "exact_subject", "generation", "valid_from", "valid_until",
    "writer_subject", "independent_auditor_subject",
    "independent_audit_receipt_sha256",
}
STATE_CHANGES = {"current_generation", "allowed_authority_ids", "authority_envelopes"}

def utc_time(value):
    if not isinstance(value, str):
        raise ValueError("invalid_time_type")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone_required")
    return parsed.astimezone(timezone.utc)

def evaluate_rotation(before, after, now=None):
    reasons = []
    now = now or datetime.now(timezone.utc)
    if not isinstance(before, dict) or not isinstance(after, dict):
        return {"allowed": False, "reasons": ["state_not_object"]}
    allowed_new_keys = set(before) | {"authority_envelopes"}
    if set(after) != allowed_new_keys:
        reasons.append("unexpected_state_keys")
    for key in (set(before) | set(after)) - STATE_CHANGES:
        if before.get(key) != after.get(key):
            reasons.append("immutable_field_changed:" + key)
    previous = before.get("current_generation")
    current = after.get("current_generation")
    if (not isinstance(previous, int) or isinstance(previous, bool)
            or not isinstance(current, int) or isinstance(current, bool)
            or current != previous + 1):
        reasons.append("generation_not_incremented_exactly_once")
    old_ids = before.get("allowed_authority_ids")
    new_ids = after.get("allowed_authority_ids")
    if not isinstance(old_ids, list) or not isinstance(new_ids, list) or len(new_ids) != 1:
        reasons.append("authority_set_not_singleton")
        new_ids = []
        old_ids = old_ids if isinstance(old_ids, list) else []
    elif not isinstance(new_ids[0], str) or not ID.fullmatch(new_ids[0]):
        reasons.append("invalid_authority_id")
    elif new_ids[0] in old_ids:
        reasons.append("authority_reused_or_renewed")
    records = after.get("authority_envelopes")
    if not isinstance(records, dict) or set(records) != set(new_ids):
        reasons.append("authority_envelope_set_mismatch")
        records = {}
    for aid, env in records.items():
        if not isinstance(env, dict) or set(env) != ENVELOPE_KEYS:
            reasons.append("authority_envelope_shape")
            continue
        if env["authority_id"] != aid or env["parent_authority_id"] != "HUMAN-OWNER":
            reasons.append("authority_parent_or_id")
        if env["generation"] != current:
            reasons.append("authority_generation")
        if not isinstance(env["work_id"], str) or not env["work_id"].startswith("HP25-"):
            reasons.append("authority_work")
        if not SHA40.fullmatch(str(env["exact_subject"])):
            reasons.append("authority_exact_subject")
        if not all(isinstance(env[field], str) and env[field] for field in
                   ("subject_id", "writer_subject", "independent_auditor_subject")):
            reasons.append("authority_subject")
        if env["writer_subject"] == env["independent_auditor_subject"]:
            reasons.append("writer_equals_auditor")
        if not HASH.fullmatch(str(env["independent_audit_receipt_sha256"])):
            reasons.append("audit_receipt_digest")
        try:
            start, end = utc_time(env["valid_from"]), utc_time(env["valid_until"])
            if not (start <= now < end and end - start <= timedelta(hours=4)
                    and end - start > timedelta(0)):
                reasons.append("authority_lifetime")
        except (ValueError, TypeError, OverflowError):
            reasons.append("authority_time_invalid")
    return {"allowed": not reasons, "reasons": sorted(set(reasons))}

def owner_exact_review(reviews, owner, author, head):
    if not owner or not author or not SHA40.fullmatch(str(head)):
        return False
    if owner.casefold() == author.casefold():
        return False
    by_owner = [r for r in reviews if
                isinstance(r, dict) and isinstance(r.get("user"), dict)
                and r["user"].get("login", "").casefold() == owner.casefold()]
    if not by_owner:
        return False
    latest = max(by_owner, key=lambda r: int(r.get("id") or 0))
    return latest.get("state") == "APPROVED" and latest.get("commit_id") == head

def fetch_reviews(repo, pr_number, token):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo or ""):
        raise ValueError("repository_invalid")
    if not str(pr_number).isdigit() or not token:
        raise ValueError("missing_pr_or_token")
    all_reviews = []
    for page in range(1, 11):
        url = ("https://api.github.com/repos/" + repo + "/pulls/" +
               str(pr_number) + "/reviews?per_page=100&page=" + str(page))
        request = Request(url, headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        with urlopen(request, timeout=15) as response:
            reviews = json.load(response)
        if not isinstance(reviews, list):
            raise ValueError("review_api_not_list")
        all_reviews.extend(reviews)
        if len(reviews) < 100:
            return all_reviews
    raise ValueError("review_pagination_incomplete")

def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: rotation.py TRUSTED_STATE CANDIDATE_STATE")
    try:
        before = json.loads(Path(sys.argv[1]).read_text("utf-8"))
        after = json.loads(Path(sys.argv[2]).read_text("utf-8"))
        decision = evaluate_rotation(before, after)
        repo = os.environ["GITHUB_REPOSITORY"]
        owner = repo.split("/")[0]
        pr_number = os.environ["ROTATION_PR_NUMBER"]
        head = os.environ["ROTATION_HEAD_SHA"]
        author = os.environ["ROTATION_PR_AUTHOR"]
        reviews = fetch_reviews(repo, pr_number, os.environ["GITHUB_TOKEN"])
        if not owner_exact_review(reviews, owner, author, head):
            decision["reasons"].append("missing_distinct_owner_exact_head_approval")
        decision["allowed"] = not decision["reasons"]
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        decision = {"allowed": False, "reasons": ["rotation_validation_failed:" + type(exc).__name__]}
    print(json.dumps(decision, sort_keys=True))
    raise SystemExit(0 if decision["allowed"] else 1)

if __name__ == "__main__":
    main()
