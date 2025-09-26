#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scope IAM policies to analyze for overly broad access.

Default behavior:
- Customer-managed (Scope=Local)
- Only attached policies
- Excludes policies used solely as permissions boundaries
- Flags:
  * Full admin (Allow + Action "*" or "*:*" + Resource "*")
  * Service-wide admin on all resources (e.g., "s3:*" on "*")
- Reports where each managed policy is attached (users/groups/roles)
- Optional: include inline identity policies (users, roles, groups)

Outputs:
- JSON report (detailed)
- CSV report (summary)
"""

import argparse
import csv
import json
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union, Set

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

JsonDict = Dict[str, Any]


# ---------------------------
# Utility functions
# ---------------------------

def decode_policy_document(maybe_encoded: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Accept either a dict (already JSON) or a string that might be URL-encoded JSON.
    Return a Python dict representing the policy document.
    """
    if isinstance(maybe_encoded, dict):
        return maybe_encoded

    s = (maybe_encoded or "").strip()
    if not s:
        return {}

    # Try raw JSON first
    try:
        return json.loads(s)
    except Exception:
        pass

    # Fallback: URL-decoded JSON
    try:
        decoded = urllib.parse.unquote(s)
        return json.loads(decoded)
    except Exception as e:
        raise ValueError(f"Unable to parse policy document (length={len(s)}): {e}") from e


def ensure_list(x: Any) -> List[Any]:
    """Return x as a list ([] for None)."""
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def extract_service_prefix(action: str) -> Optional[str]:
    """
    If action is like 'service:*', return 'service' (case-insensitive).
    Otherwise return None.
    """
    if not isinstance(action, str):
        return None
    a = action.lower()
    if a == "*" or a == "*:*":
        return None
    if a.endswith(":*") and ":" in a:
        return a.split(":")[0]
    return None


def analyze_policy_document(doc: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Analyze a policy document and return:
      (full_admin: bool, service_wide_on_all_resources: List[str])
    """
    stmts = ensure_list(doc.get("Statement"))
    full_admin = False
    svc_wide: Set[str] = set()

    for st in stmts:
        if not isinstance(st, dict):
            continue
        if st.get("Effect") != "Allow":
            continue

        actions = [a for a in ensure_list(st.get("Action")) if isinstance(a, str)]
        resources = [r for r in ensure_list(st.get("Resource")) if isinstance(r, str)]

        action_wild = any(a == "*" or a == "*:*" for a in actions)
        resource_all = any(r == "*" for r in resources)

        if action_wild and resource_all:
            full_admin = True

        if resource_all:
            for a in actions:
                svc = extract_service_prefix(a)
                if svc:
                    svc_wide.add(svc)

    return full_admin, sorted(svc_wide)


def paginate(client, op_name: str, result_key: str, **kwargs):
    """Generic paginator: yields items from the specified result_key across pages."""
    paginator = client.get_paginator(op_name)
    for page in paginator.paginate(**kwargs):
        for item in page.get(result_key, []):
            yield item


def list_entities_for_policy(iam, policy_arn: str) -> Tuple[List[str], List[str], List[str]]:
    """
    Return (users[], groups[], roles[]) that have the managed policy attached.
    """
    users: List[str] = []
    groups: List[str] = []
    roles: List[str] = []

    paginator = iam.get_paginator("list_entities_for_policy")
    for page in paginator.paginate(PolicyArn=policy_arn):
        users.extend([u["UserName"] for u in page.get("PolicyUsers", [])])
        groups.extend([g["GroupName"] for g in page.get("PolicyGroups", [])])
        roles.extend([r["RoleName"] for r in page.get("PolicyRoles", [])])

    return users, groups, roles


def safe_get_policy_version(iam, arn: str, version_id: str) -> Dict[str, Any]:
    """Get the policy version document as a decoded dict."""
    resp = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
    doc_raw = resp["PolicyVersion"]["Document"]
    return decode_policy_document(doc_raw)


# ---------------------------
# Scanners
# ---------------------------

def scan_managed_policies(
    iam,
    include_aws_managed: bool,
    include_unattached: bool,
    include_boundaries: bool
) -> List[Dict[str, Any]]:
    """
    Scan managed policies based on filters; analyze and return structured results.
    """
    list_kwargs = {}
    # Scope: Local = customer-managed (default). Include All if asked.
    list_kwargs["Scope"] = "All" if include_aws_managed else "Local"  # list-policies filter

    # OnlyAttached: True unless include_unattached requested.
    list_kwargs["OnlyAttached"] = not include_unattached

    # Exclude permissions boundaries unless requested.
    if not include_boundaries:
        list_kwargs["PolicyUsageFilter"] = "PermissionsPolicy"

    results: List[Dict[str, Any]] = []

    for pol in paginate(iam, "list_policies", "Policies", **list_kwargs):
        arn = pol["Arn"]
        name = pol["PolicyName"]
        default_version_id = pol.get("DefaultVersionId")
        attachment_count = pol.get("AttachmentCount", 0)
        is_attachable = pol.get("IsAttachable", True)

        # Fetch default version document
        try:
            doc = safe_get_policy_version(iam, arn, default_version_id)
            analysis_error = None
        except (ClientError, BotoCoreError, ValueError) as e:
            doc = {}
            analysis_error = f"get_policy_version: {e}"

        full_admin, svc_wide = analyze_policy_document(doc) if doc else (False, [])

        # Where is it attached?
        try:
            users, groups, roles = list_entities_for_policy(iam, arn)
        except (ClientError, BotoCoreError) as e:
            users, groups, roles = [], [], []
            analysis_error = f"{analysis_error} | list_entities_for_policy: {e}" if analysis_error else f"list_entities_for_policy: {e}"

        results.append({
            "Type": "Managed",
            "PolicyArn": arn,
            "PolicyName": name,
            "DefaultVersionId": default_version_id,
            "AttachmentCount": attachment_count,
            "IsAttachable": is_attachable,
            "FullAdmin": full_admin,
            "ServiceWideOnAllResources": svc_wide,
            "AttachedUsers": users,
            "AttachedGroups": groups,
            "AttachedRoles": roles,
            "AnalysisError": analysis_error
        })

    return results


def scan_inline_policies(iam) -> List[Dict[str, Any]]:
    """
    Scan inline identity policies (users, roles, groups). Return only flagged results:
    FullAdmin or ServiceWideOnAllResources non-empty; include errors for visibility.
    """
    flagged: List[Dict[str, Any]] = []

    # Users
    for u in paginate(iam, "list_users", "Users"):
        uname = u["UserName"]
        for pn in paginate(iam, "list_user_policies", "PolicyNames", UserName=uname):
            try:
                up = iam.get_user_policy(UserName=uname, PolicyName=pn)
                doc = decode_policy_document(up["PolicyDocument"])
                full_admin, svc_wide = analyze_policy_document(doc)
                if full_admin or svc_wide:
                    flagged.append({
                        "Type": "Inline",
                        "IdentityType": "User",
                        "IdentityName": uname,
                        "PolicyName": pn,
                        "FullAdmin": full_admin,
                        "ServiceWideOnAllResources": svc_wide,
                        "AnalysisError": None
                    })
            except Exception as e:
                flagged.append({
                    "Type": "Inline",
                    "IdentityType": "User",
                    "IdentityName": uname,
                    "PolicyName": pn,
                    "FullAdmin": False,
                    "ServiceWideOnAllResources": [],
                    "AnalysisError": f"get_user_policy: {e}"
                })

    # Roles
    for r in paginate(iam, "list_roles", "Roles"):
        rname = r["RoleName"]
        for pn in paginate(iam, "list_role_policies", "PolicyNames", RoleName=rname):
            try:
                rp = iam.get_role_policy(RoleName=rname, PolicyName=pn)
                doc = decode_policy_document(rp["PolicyDocument"])
                full_admin, svc_wide = analyze_policy_document(doc)
                if full_admin or svc_wide:
                    flagged.append({
                        "Type": "Inline",
                        "IdentityType": "Role",
                        "IdentityName": rname,
                        "PolicyName": pn,
                        "FullAdmin": full_admin,
                        "ServiceWideOnAllResources": svc_wide,
                        "AnalysisError": None
                    })
            except Exception as e:
                flagged.append({
                    "Type": "Inline",
                    "IdentityType": "Role",
                    "IdentityName": rname,
                    "PolicyName": pn,
                    "FullAdmin": False,
                    "ServiceWideOnAllResources": [],
                    "AnalysisError": f"get_role_policy: {e}"
                })

    # Groups
    for g in paginate(iam, "list_groups", "Groups"):
        gname = g["GroupName"]
        for pn in paginate(iam, "list_group_policies", "PolicyNames", GroupName=gname):
            try:
                gp = iam.get_group_policy(GroupName=gname, PolicyName=pn)
                doc = decode_policy_document(gp["PolicyDocument"])
                full_admin, svc_wide = analyze_policy_document(doc)
                if full_admin or svc_wide:
                    flagged.append({
                        "Type": "Inline",
                        "IdentityType": "Group",
                        "IdentityName": gname,
                        "PolicyName": pn,
                        "FullAdmin": full_admin,
                        "ServiceWideOnAllResources": svc_wide,
                        "AnalysisError": None
                    })
            except Exception as e:
                flagged.append({
                    "Type": "Inline",
                    "IdentityType": "Group",
                    "IdentityName": gname,
                    "PolicyName": pn,
                    "FullAdmin": False,
                    "ServiceWideOnAllResources": [],
                    "AnalysisError": f"get_group_policy: {e}"
                })

    return flagged


# ---------------------------
# Output writers
# ---------------------------

def write_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)


def write_csv_managed(path: str, records: List[Dict[str, Any]]) -> None:
    headers = [
        "PolicyType",
        "PolicyArn",
        "PolicyName",
        "DefaultVersionId",
        "AttachmentCount",
        "FullAdmin",
        "ServiceWideOnAllResources",
        "AttachedUsers",
        "AttachedGroups",
        "AttachedRoles",
        "AnalysisError"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in records:
            w.writerow([
                r.get("Type", "Managed"),
                r.get("PolicyArn"),
                r.get("PolicyName"),
                r.get("DefaultVersionId"),
                r.get("AttachmentCount"),
                r.get("FullAdmin"),
                ";".join(r.get("ServiceWideOnAllResources", [])),
                ";".join(r.get("AttachedUsers", [])),
                ";".join(r.get("AttachedGroups", [])),
                ";".join(r.get("AttachedRoles", [])),
                r.get("AnalysisError") or ""
            ])


def write_csv_inline(path: str, records: List[Dict[str, Any]]) -> None:
    headers = [
        "PolicyType",
        "IdentityType",
        "IdentityName",
        "PolicyName",
        "FullAdmin",
        "ServiceWideOnAllResources",
        "AnalysisError"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in records:
            w.writerow([
                r.get("Type", "Inline"),
                r.get("IdentityType"),
                r.get("IdentityName"),
                r.get("PolicyName"),
                r.get("FullAdmin"),
                ";".join(r.get("ServiceWideOnAllResources", [])),
                r.get("AnalysisError") or ""
            ])


# ---------------------------
# Main / CLI
# ---------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scope IAM policies to analyze (overly broad / full admin)."
    )
    parser.add_argument("--profile", help="AWS profile name (optional)")
    parser.add_argument("--region", help="AWS region (IAM is global; optional)", default=None)

    parser.add_argument("--include-aws-managed", action="store_true",
                        help="Include AWS-managed policies in addition to customer-managed")
    parser.add_argument("--include-unattached", action="store_true",
                        help="Include unattached managed policies")
    parser.add_argument("--include-boundaries", action="store_true",
                        help="Include policies used as permissions boundaries")

    parser.add_argument("--include-inline", action="store_true",
                        help="Scan inline identity policies (users/roles/groups)")

    parser.add_argument("--out-json", default="iam_policy_scope.json",
                        help="Output JSON file")
    parser.add_argument("--out-csv", default="iam_policy_scope.csv",
                        help="Output CSV file for managed policies")
    parser.add_argument("--out-inline-csv", default="iam_inline_scope.csv",
                        help="Output CSV file for flagged inline policies (only if --include-inline)")

    args = parser.parse_args()

    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    session = boto3.Session(**session_kwargs)

    config = Config(retries={"max_attempts": 10, "mode": "standard"})
    iam = session.client("iam", region_name=args.region, config=config)

    started = time.time()

    # 1) Managed policies
    managed = scan_managed_policies(
        iam=iam,
        include_aws_managed=args.include_aws_managed,
        include_unattached=args.include_unattached,
        include_boundaries=args.include_boundaries
    )

    # 2) Optional inline policies
    inline_flagged: List[Dict[str, Any]] = []
    if args.include_inline:
        inline_flagged = scan_inline_policies(iam)

    # Combined JSON payload
    payload = {
        "ManagedPolicies": managed,
        "InlinePoliciesFlagged": inline_flagged,
        "Summary": {
            "ManagedPoliciesTotal": len(managed),
            "ManagedFullAdmin": sum(1 for r in managed if r.get("FullAdmin")),
            "ManagedServiceWideHits": sum(1 for r in managed if r.get("ServiceWideOnAllResources")),
            "InlineFlaggedTotal": len(inline_flagged),
            "GeneratedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    }

    # Write outputs
    write_json(args.out_json, payload)
    write_csv_managed(args.out_csv, managed)
    if args.include_inline:
        write_csv_inline(args.out_inline_csv, inline_flagged)

    elapsed = time.time() - started
    print(f"Done in {elapsed:.1f}s")
    print(f"- JSON: {args.out_json}")
    print(f"- CSV (managed): {args.out_csv}")
    if args.include_inline:
        print(f"- CSV (inline flagged): {args.out_inline_csv}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
