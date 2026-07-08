#!/usr/bin/env python3
"""
Member 2 module for the local/authorized Web Cache Deception (WCD) demo.

Implements "Algorithm 1" (Dynamic-content Extraction / DE-style detection)
from "Web Cache Deception Escalates!" (Mirheidari et al., USENIX Security 2022):

    Step 1 - Confirm the original URL is genuinely dynamic
              (two requests with different client state -> different bodies).
    Step 2 - "Liveness" check on each attack URL: with a random payload,
              the server must still return dynamic content (not a generic
              error page), otherwise the confusion technique doesn't apply.
    Step 3 - Cache-status analysis: send the SAME attack URL twice and check
              that the first is a cache MISS and the second is a cache HIT
              (fuzzy header matching), plus a byte-for-byte / hash-based
              body comparison between the two responses.

Depends on Member 3's module for payload generation and cache-header
heuristics:

    from member3_wcd_completed import generate_attack_urls, infer_cache_status

Usage:
    python detection_engine.py --url http://localhost:8080/profile
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

import requests

# --- Member 3's module ---------------------------------------------------
from member3_wcd_completed import (
    AttackPayload,
    check_false_positive,
    generate_attack_urls,
    infer_cache_status,
    require_lab_target,
)


# =============================================================================
# Data structures
# =============================================================================


@dataclass
class Finding:
    original_url: str
    attack_url: str
    mode: str
    first_cache_status: str
    second_cache_status: str
    first_http_status: int
    second_http_status: int
    bodies_identical: bool
    body_hash: str
    status: str  # "suspicious" | "not_suspicious"
    reason: str


# =============================================================================
# Helpers
# =============================================================================


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _get(session: requests.Session, url: str, timeout: int, client_state: Optional[str] = None) -> requests.Response:
    """
    Send a GET request. `client_state` is used in Step 1 to simulate a
    different logged-in user / session (e.g. a fresh cookie), so we can
    verify the page is truly dynamic and not a static asset.
    """
    headers = {"User-Agent": "Member2-WCD-DetectionEngine/1.0"}
    cookies = {}
    if client_state:
        cookies["session_id"] = client_state
    return session.get(
        url,
        headers=headers,
        cookies=cookies,
        timeout=timeout,
        allow_redirects=False,
    )


# =============================================================================
# Step 1: dynamic-content check on the ORIGINAL url
# =============================================================================


def step1_check_dynamic(original_url: str, timeout: int = 8) -> bool:
    """
    Request the original URL twice with two different simulated client states
    (fresh session/cookie each time) and compare bodies.

    If the bodies differ, the page is confirmed dynamic (e.g. a fresh CSRF
    token each time), which is a prerequisite for WCD to be interesting:
    caching a static page leaks nothing sensitive.
    """
    session = requests.Session()

    state_a = uuid.uuid4().hex
    state_b = uuid.uuid4().hex

    resp_a = _get(session, original_url, timeout=timeout, client_state=state_a)
    resp_b = _get(session, original_url, timeout=timeout, client_state=state_b)

    is_dynamic = _hash(resp_a.content) != _hash(resp_b.content)

    print(f"[Step 1] GET {original_url}")
    print(f"         client_state A -> {resp_a.status_code}, hash={_hash(resp_a.content)[:12]}")
    print(f"         client_state B -> {resp_b.status_code}, hash={_hash(resp_b.content)[:12]}")
    print(f"         Dynamic content confirmed: {is_dynamic}\n")

    return is_dynamic


# =============================================================================
# Step 2: liveness check on each attack URL
# =============================================================================


def step2_liveness_check(
    payload: AttackPayload, timeout: int = 8
) -> bool:
    """
    Confirm the origin still returns dynamic content for this path-confusion
    mode (HTTP 200, non-error body), rather than a generic 404 / error page.

    IMPORTANT: this must NOT probe payload.attack_url itself. That exact URL
    is the cache key Step 3 needs to test fresh (expecting a MISS on its
    first request). If we requested it here first, we'd silently poison the
    cache ourselves, and Step 3 would see HIT->HIT instead of MISS->HIT,
    hiding a real finding behind a false "not suspicious" verdict.

    Instead, we build a throwaway sibling URL using the same path-confusion
    mode and file extension but a fresh random filename, so it exercises the
    same routing behavior on a different cache key.
    """
    from member3_wcd_completed import generate_attack_url  # same mode, fresh filename

    extension = getattr(payload, "extension", None) or ".css"
    probe_payload = generate_attack_url(
        payload.original_url, mode=payload.mode, extension=extension
    )
    probe_url = probe_payload.attack_url

    session = requests.Session()
    resp = _get(session, probe_url, timeout=timeout, client_state=uuid.uuid4().hex)

    alive = resp.status_code == 200 and len(resp.content) > 0

    return alive


# =============================================================================
# Step 3: cache-status + body comparison on the attack URL
# =============================================================================


def step3_cache_analysis(payload: AttackPayload, timeout: int = 8) -> Finding:
    """
    Send the SAME attack URL twice:
      - 1st request  -> expect cache MISS (poisons the cache with the
                         victim's dynamic response, e.g. containing a CSRF
                         token)
      - 2nd request  -> expect cache HIT  (an unauthenticated attacker now
                         receives the exact same body from the cache)

    Uses Member 3's fuzzy `infer_cache_status()` so this works across
    different reverse-proxy cache header conventions.

    NOTE: this assumes payload.attack_url has never been requested before
    (fresh cache key). Step 2 is responsible for NOT touching this exact
    URL - see step2_liveness_check()'s docstring.
    """
    session = requests.Session()

    victim_state = uuid.uuid4().hex
    first = _get(session, payload.attack_url, timeout=timeout, client_state=victim_state)
    # small delay so we don't race the proxy while it's still writing to cache
    time.sleep(0.2)
    second = _get(session, payload.attack_url, timeout=timeout, client_state=victim_state)

    first_status = infer_cache_status(first.headers)
    second_status = infer_cache_status(second.headers)
    bodies_identical = _hash(first.content) == _hash(second.content)

    suspicious = (
        first_status == "MISS"
        and second_status == "HIT"
        and bodies_identical
    )

    if suspicious:
        reason = (
            "First request MISS, second request HIT, identical bodies: "
            "the cache stored a dynamic/per-user response under a "
            "static-looking URL."
        )
    elif first_status == "UNKNOWN" or second_status == "UNKNOWN":
        reason = "Cache headers were UNKNOWN/not visible; cannot confirm from headers alone."
    elif first_status == "AMBIGUOUS" or second_status == "AMBIGUOUS":
        reason = "Cache headers were ambiguous (mixed hit/miss signals); needs manual review."
    elif not bodies_identical:
        reason = "Cache status looked suspicious but response bodies differ between requests."
    else:
        reason = "No MISS->HIT transition observed; page does not appear to be cached under this path."

    return Finding(
        original_url=payload.original_url,
        attack_url=payload.attack_url,
        mode=payload.mode,
        first_cache_status=first_status,
        second_cache_status=second_status,
        first_http_status=first.status_code,
        second_http_status=second.status_code,
        bodies_identical=bodies_identical,
        body_hash=_hash(first.content),
        status="suspicious" if suspicious else "not_suspicious",
        reason=reason,
    )


# =============================================================================
# Orchestration: Algorithm 1 end to end
# =============================================================================


def run_detection_engine(
    original_url: str,
    extensions: List[str],
    count_per_mode: int = 1,
    timeout: int = 8,
    allow_external: bool = False,
) -> List[Finding]:
    require_lab_target(original_url, allow_external=allow_external)

    print("=" * 70)
    print("Member 2 - Web Cache Deception Detection Engine (Algorithm 1)")
    print("=" * 70 + "\n")

    # --- Step 1 ---
    if not step1_check_dynamic(original_url, timeout=timeout):
        print("[!] Original URL does not appear to be dynamic. "
              "WCD would not leak per-user data here; continuing anyway "
              "for demo completeness.\n")

    # --- Payloads from Member 3 ---
    payloads = generate_attack_urls(
        original_url,
        extensions=extensions,
        count_per_mode=count_per_mode,
        allow_external=allow_external,
    )
    print(f"[i] Received {len(payloads)} candidate attack URLs from Member 3.\n")

    findings: List[Finding] = []

    for payload in payloads:
        print(f"--- Testing mode: {payload.mode} ({payload.attack_url}) ---")

        # --- Step 2 ---
        if not step2_liveness_check(payload, timeout=timeout):
            print("[Step 2] Not alive / did not return dynamic content -> skipping.\n")
            continue
        print("[Step 2] Attack URL is alive and returns dynamic content.")

        # --- Step 3 ---
        finding = step3_cache_analysis(payload, timeout=timeout)
        print(f"[Step 3] first={finding.first_cache_status} "
              f"second={finding.second_cache_status} "
              f"bodies_identical={finding.bodies_identical} "
              f"-> {finding.status.upper()}")
        print(f"         {finding.reason}\n")

        if finding.status == "suspicious":
            findings.append(finding)

    return findings


def apply_false_positive_filter(findings: List[Finding], timeout: int = 8, allow_external: bool = False) -> List[Finding]:
    """
    Pass every suspicious finding's original_url through Member 3's
    Algorithm 2 false-positive filter (check_false_positive). Findings whose
    original URL turns out to be cacheable WITHOUT any attack payload are
    dropped as false positives.
    """
    if not findings:
        return []

    print("=" * 70)
    print("Applying Member 3's Algorithm 2 false-positive filter")
    print("=" * 70 + "\n")

    kept: List[Finding] = []
    checked_urls: Dict[str, bool] = {}

    for finding in findings:
        if finding.original_url not in checked_urls:
            fp_result = check_false_positive(
                finding.original_url, timeout=timeout, allow_external=allow_external
            )
            checked_urls[finding.original_url] = fp_result.is_false_positive
            print(f"[FP check] {finding.original_url} -> "
                  f"{'FALSE POSITIVE' if fp_result.is_false_positive else 'kept'}")
            print(f"           {fp_result.conclusion}\n")

        if not checked_urls[finding.original_url]:
            kept.append(finding)

    return kept


# =============================================================================
# CLI
# =============================================================================


def parse_extensions(value: str) -> List[str]:
    return [ext.strip() if ext.strip().startswith(".") else "." + ext.strip()
            for ext in value.split(",") if ext.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Member 2 WCD detection engine (Algorithm 1)")
    parser.add_argument("--url", required=True, help="Original dynamic URL, e.g. http://localhost:8080/profile")
    parser.add_argument("--extensions", default=".css", help="Comma-separated static-looking extensions. Default: .css")
    parser.add_argument("--count-per-mode", type=int, default=1, help="Attack URLs to generate per mode")
    parser.add_argument("--timeout", type=int, default=8, help="HTTP timeout in seconds")
    parser.add_argument("--skip-fp-filter", action="store_true", help="Skip Member 3's Algorithm 2 false-positive filter")
    parser.add_argument("--output-json", help="Optional path to save final findings as JSON")
    parser.add_argument("--allow-external", action="store_true", help="Allow non-local targets (only with authorization)")

    args = parser.parse_args()

    findings = run_detection_engine(
        args.url,
        extensions=parse_extensions(args.extensions),
        count_per_mode=args.count_per_mode,
        timeout=args.timeout,
        allow_external=args.allow_external,
    )

    print("=" * 70)
    print(f"Algorithm 1 result: {len(findings)} suspicious finding(s) before FP filtering")
    print("=" * 70 + "\n")

    if not args.skip_fp_filter:
        findings = apply_false_positive_filter(
            findings, timeout=args.timeout, allow_external=args.allow_external
        )

    print("=" * 70)
    print(f"FINAL RESULT: {len(findings)} confirmed WCD finding(s)")
    print("=" * 70)
    for f in findings:
        print(f"  - [{f.mode}] {f.attack_url}")

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as fh:
            json.dump([asdict(f) for f in findings], fh, indent=2)
        print(f"\nSaved findings to: {args.output_json}")

    if not findings:
        sys.exit(0)


if __name__ == "__main__":
    main()
