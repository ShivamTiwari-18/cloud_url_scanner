#!/usr/bin/env python3
"""
cloud_storage_scanner.py

Single-file CLI to check S3 and Azure Blob URLs for public read/listing and optional
(non-destructive by default) write-testing.

Usage examples:
  # scan a few URLs
  python cloud_storage_scanner.py s3://my-bucket https://my-bucket.s3.amazonaws.com/ https://account.blob.core.windows.net/container

  # scan URLs from a file (one per line)
  python cloud_storage_scanner.py --input urls.txt --output report.json

  # run write test (DANGEROUS if used without permission)
  python cloud_storage_scanner.py s3://my-bucket --write-test --confirm-write

Notes:
 - By default the script performs only read/list checks (safe).
 - The write test will upload a small random object and attempt to delete it after.
 - Only enable write tests when you own the bucket/container or have authorization.

Requirements:
  - Python 3.8+
  - pip install requests tabulate boto3 (boto3 only if you plan to use AWS SDK automation)
"""
from __future__ import annotations
import argparse
import sys
import re
import requests
import json
import csv
import uuid
import time
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from datetime import datetime
from tabulate import tabulate

# Optional: boto3 for AWS SDK flows (not required for basic checks)
try:
    import boto3  # type: ignore
    HAS_BOTO3 = True
except Exception:
    HAS_BOTO3 = False

# ---------------------------
# Configurable defaults
# ---------------------------
USER_AGENT = "CloudScanner/1.0 (+https://example.local)"
REQUEST_TIMEOUT = 12  # seconds
MAX_THREADS = 8

# ---------------------------
# Helper detection functions
# ---------------------------

S3_HOST_PATTERNS = [
    re.compile(r"^(.+)\.s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com$"),  # bucket.s3.amazonaws.com or bucket.s3.dualstack.us-east-1.amazonaws.com
    re.compile(r"^s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com$"),       # s3.amazonaws.com (path-style)
]
AZURE_BLOB_PATTERN = re.compile(r"^([a-z0-9]{3,24})\.blob\.core\.windows\.net$", re.I)


def normalize_input(input_item: str) -> str:
    """Convert s3://bucket or azure://account/container into https URLs where possible."""
    if input_item.startswith("s3://"):
        bucket = input_item[5:].strip("/")
        return f"https://{bucket}.s3.amazonaws.com/"
    if input_item.startswith("azure://"):
        # azure://account/container  -> https://account.blob.core.windows.net/container
        parts = input_item[8:].split("/", 1)
        account = parts[0]
        container = parts[1] if len(parts) > 1 else ""
        if container:
            return f"https://{account}.blob.core.windows.net/{container}"
        else:
            return f"https://{account}.blob.core.windows.net/"
    # if it's a plain domain or http(s)
    if input_item.startswith("http://") or input_item.startswith("https://"):
        return input_item
    # bare bucket or domain: try S3 style
    if "." not in input_item and "/" not in input_item:
        return f"https://{input_item}.s3.amazonaws.com/"
    # fallback add https
    return "https://" + input_item.lstrip("/")


def detect_provider(parsed: urlparse) -> str:
    """Return 's3', 'azure', or 'unknown'"""
    host = parsed.netloc.lower()
    for p in S3_HOST_PATTERNS:
        if p.match(host):
            return "s3"
    if AZURE_BLOB_PATTERN.match(host):
        return "azure"
    # also check path-style s3 like s3.amazonaws.com/bucket
    if host.startswith("s3.") or host == "s3.amazonaws.com":
        return "s3"
    return "unknown"


# ---------------------------
# Request helpers
# ---------------------------
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})


def safe_get(url: str, params: dict = None, allow_redirects: bool = True) -> requests.Response:
    return session.get(url, params=params, timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects)


def safe_head(url: str) -> requests.Response:
    return session.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)


# ---------------------------
# Checks implementations
# ---------------------------

def check_s3_bucket_listing(url: str) -> Dict[str, Any]:
    """
    Check S3-style bucket listing by requesting the bucket root.
    Many public S3 buckets return an XML listing (ListBucketResult) if listing is enabled.
    """
    res: Dict[str, Any] = {"provider": "s3", "url": url, "listable": False, "read_ok": False, "status": None, "notes": []}
    try:
        r = safe_get(url)
        res["status"] = r.status_code
        ct = r.headers.get("Content-Type", "")
        body = r.text[:4096] if r.text else ""
        # common S3 listing XML contains <ListBucketResult>
        if r.status_code == 200 and "<ListBucketResult" in body:
            res["listable"] = True
            res["read_ok"] = True
            res["notes"].append("Bucket listable (XML listing found).")
        elif r.status_code == 200 and "<Error>" in body and "AccessDenied" not in body:
            # sometimes Azure or other providers; leave generic
            res["notes"].append("200 OK returned; content-type: " + ct)
        elif r.status_code in (403, 401):
            res["notes"].append("Access denied / auth required (403/401).")
        elif r.status_code == 404:
            res["notes"].append("Not found (404). Could be path-style mismatch.")
        else:
            # check for index.html presence or object read: many buckets serve website index
            if r.status_code == 200 and ("<html" in body.lower() or "index of /" in body.lower()):
                res["read_ok"] = True
                res["notes"].append("HTML index/website displayed at bucket root.")
    except requests.RequestException as e:
        res["status"] = f"err:{e}"
        res["notes"].append("Request error: " + str(e))
    return res


def check_s3_object_read(url: str) -> Dict[str, Any]:
    """
    For S3 object-style URL (or bucket URL), attempt HEAD to see if object is readable or yields 200.
    """
    res: Dict[str, Any] = {"provider": "s3", "url": url, "object_read": False, "status": None, "notes": []}
    try:
        r = safe_head(url)
        res["status"] = r.status_code
        if r.status_code == 200:
            res["object_read"] = True
            res["notes"].append("HEAD returned 200: object accessible/readable.")
        elif r.status_code in (403, 401):
            res["notes"].append("Unauthorized / access denied.")
        elif r.status_code == 404:
            res["notes"].append("Not found (404).")
        else:
            res["notes"].append(f"HEAD returned status {r.status_code}.")
    except requests.RequestException as e:
        res["status"] = f"err:{e}"
        res["notes"].append("Request error: " + str(e))
    return res


def check_azure_container_list(url: str) -> Dict[str, Any]:
    """
    Azure Blob container listing: container URL + '?restype=container&comp=list' often returns XML for public containers.
    Example: https://account.blob.core.windows.net/container?restype=container&comp=list
    """
    res: Dict[str, Any] = {"provider": "azure", "url": url, "listable": False, "read_ok": False, "status": None, "notes": []}
    parsed = urlparse(url)
    base = parsed.scheme + "://" + parsed.netloc + parsed.path.rstrip("/") + "/"
    q_url = base + "?restype=container&comp=list"
    try:
        r = safe_get(q_url)
        res["status"] = r.status_code
        body = r.text[:4096] if r.text else ""
        if r.status_code == 200 and "<EnumerationResults" in body:
            res["listable"] = True
            res["read_ok"] = True
            res["notes"].append("Container listable (XML EnumerationResults found).")
        elif r.status_code in (401, 403):
            res["notes"].append("Access denied / auth required.")
        elif r.status_code == 404:
            res["notes"].append("Not found (404).")
        else:
            # attempt HEAD on container URL
            h = safe_head(base)
            if h.status_code == 200:
                res["read_ok"] = True
                res["notes"].append("Container URL responded with 200 on HEAD; may expose content.")
            else:
                res["notes"].append(f"Container HEAD returned {h.status_code}.")
    except requests.RequestException as e:
        res["status"] = f"err:{e}"
        res["notes"].append("Request error: " + str(e))
    return res


# ---------------------------
# Optional write test (explicit)
# ---------------------------

def write_test_s3(url: str, delete_after: bool = True) -> Dict[str, Any]:
    """
    Attempt to PUT a tiny object to an S3 bucket path. This is potentially destructive and
    should only be used if you have permission. The function will upload a small text file
    with a random name and optionally delete it afterwards.
    """
    res = {"provider": "s3", "url": url, "write_ok": False, "uploaded_object": None, "status": None, "notes": []}
    # Construct an object URL: if input is bucket root, write to bucket/randomname
    parsed = urlparse(url)
    base = parsed.scheme + "://" + parsed.netloc + parsed.path.rstrip("/") + "/"
    randname = "cs-test-" + uuid.uuid4().hex + ".txt"
    object_url = urljoin(base, randname)
    try:
        # use PUT with a tiny body
        r = session.put(object_url, data=b"cloud-scanner-write-test\n", timeout=REQUEST_TIMEOUT)
        res["status"] = r.status_code
        if r.status_code in (200, 201):
            res["write_ok"] = True
            res["uploaded_object"] = object_url
            res["notes"].append(f"Uploaded test object: {object_url}")
            if delete_after:
                try:
                    d = session.delete(object_url, timeout=REQUEST_TIMEOUT)
                    if d.status_code in (204, 200):
                        res["notes"].append("Deleted test object after upload.")
                    else:
                        res["notes"].append(f"Delete returned {d.status_code}; object may remain.")
                except Exception as e:
                    res["notes"].append("Delete error: " + str(e))
        elif r.status_code in (403, 401):
            res["notes"].append("Upload blocked (403/401).")
        else:
            res["notes"].append(f"PUT returned {r.status_code}.")
    except requests.RequestException as e:
        res["status"] = f"err:{e}"
        res["notes"].append("Request error: " + str(e))
    return res


def write_test_azure(url: str, delete_after: bool = True) -> Dict[str, Any]:
    """
    Attempt to PUT (upload) a small blob. Azure requires specific headers; simpler approach is to PUT to
    container/blob with query string ?restype=container for listing - but for write test we perform a PUT to blob path.
    """
    res = {"provider": "azure", "url": url, "write_ok": False, "uploaded_object": None, "status": None, "notes": []}
    parsed = urlparse(url)
    base = parsed.scheme + "://" + parsed.netloc + parsed.path.rstrip("/") + "/"
    randname = "cs-test-" + uuid.uuid4().hex + ".txt"
    blob_url = urljoin(base, randname)
    try:
        # For Azure blob upload via PUT, one must set x-ms-blob-type header
        headers = {"x-ms-blob-type": "BlockBlob"}
        r = session.put(blob_url, data=b"cloud-scanner-write-test\n", headers=headers, timeout=REQUEST_TIMEOUT)
        res["status"] = r.status_code
        if r.status_code in (201, 200):
            res["write_ok"] = True
            res["uploaded_object"] = blob_url
            res["notes"].append(f"Uploaded test blob: {blob_url}")
            if delete_after:
                try:
                    d = session.delete(blob_url, timeout=REQUEST_TIMEOUT)
                    if d.status_code in (202, 200):
                        res["notes"].append("Deleted test blob after upload.")
                    else:
                        res["notes"].append(f"Delete returned {d.status_code}; blob may remain.")
                except Exception as e:
                    res["notes"].append("Delete error: " + str(e))
        elif r.status_code in (401, 403):
            res["notes"].append("Upload blocked (401/403).")
        else:
            res["notes"].append(f"PUT returned {r.status_code}.")
    except requests.RequestException as e:
        res["status"] = f"err:{e}"
        res["notes"].append("Request error: " + str(e))
    return res


# ---------------------------
# Orchestration
# ---------------------------

def analyze_url(raw_input: str, write_test: bool = False, delete_after: bool = True) -> Dict[str, Any]:
    url = normalize_input(raw_input.strip())
    parsed = urlparse(url)
    provider = detect_provider(parsed)
    result: Dict[str, Any] = {
        "input": raw_input,
        "normalized_url": url,
        "provider": provider,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "findings": [],
    }

    if provider == "s3":
        # Try listing root
        listing = check_s3_bucket_listing(url)
        result["findings"].append(listing)
        # Try object HEAD (some inputs may be object URLs)
        obj_read = check_s3_object_read(url)
        result["findings"].append(obj_read)
        if write_test:
            wt = write_test_s3(url, delete_after=delete_after)
            result["findings"].append(wt)
    elif provider == "azure":
        listing = check_azure_container_list(url)
        result["findings"].append(listing)
        # Attempt HEAD on container or object
        try:
            h = safe_head(url)
            result["findings"].append({"provider": "azure", "url": url, "head_status": h.status_code})
        except Exception as e:
            result["findings"].append({"provider": "azure", "url": url, "error": str(e)})
        if write_test:
            wt = write_test_azure(url, delete_after=delete_after)
            result["findings"].append(wt)
    else:
        # Unknown: do generic checks
        try:
            g = safe_get(url)
            result["findings"].append({"provider": "unknown", "url": url, "status": g.status_code, "content_type": g.headers.get("Content-Type", ""), "snippet": g.text[:512]})
        except Exception as e:
            result["findings"].append({"provider": "unknown", "url": url, "error": str(e)})

    # risk scoring (simple heuristic)
    score = 0
    notes = []
    for f in result["findings"]:
        # listable or read_ok increases risk
        if f.get("listable") or f.get("read_ok") or f.get("object_read"):
            score += 50
        if f.get("write_ok"):
            score += 40
        # errors lower score
        if isinstance(f.get("status"), int) and f.get("status") in (401, 403, 404):
            score += 0
        # textual hints
        for n in f.get("notes", []):
            notes.append(n)
    # Cap score
    score = min(score, 100)
    if score >= 70:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"
    result["risk_score"] = score
    result["risk_level"] = level
    result["summary_notes"] = notes
    return result


def run_scan(inputs: List[str], threads: int = MAX_THREADS, write_test: bool = False, delete_after: bool = True) -> List[Dict[str, Any]]:
    results = []
    with ThreadPoolExecutor(max_workers=min(threads, len(inputs) or 1)) as ex:
        future_to_inp = {ex.submit(analyze_url, inp, write_test, delete_after): inp for inp in inputs}
        for fut in as_completed(future_to_inp):
            inp = future_to_inp[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"input": inp, "error": str(e)}
            results.append(res)
    return results


# ---------------------------
# Reporting helpers
# ---------------------------

def print_summary(results: List[Dict[str, Any]]):
    rows = []
    for r in results:
        rows.append([r.get("input"),
                     r.get("provider"),
                     r.get("risk_level"),
                     r.get("risk_score"),
                     "; ".join(r.get("summary_notes")[:3])])
    print(tabulate(rows, headers=["Input", "Provider", "Risk", "Score", "Short notes"], tablefmt="github"))


def save_reports(results: List[Dict[str, Any]], outpath: Optional[str]):
    if not outpath:
        return
    # JSON
    json_path = outpath if outpath.lower().endswith(".json") else outpath + ".json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.utcnow().isoformat() + "Z", "results": results}, f, indent=2)
    # CSV summary
    csv_path = outpath if outpath.lower().endswith(".csv") else outpath + ".csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(["input", "provider", "risk_level", "risk_score", "summary_notes"])
        for r in results:
            writer.writerow([r.get("input"), r.get("provider"), r.get("risk_level"), r.get("risk_score"), " | ".join(r.get("summary_notes", [])[:5])])
    print(f"Reports saved: {json_path}, {csv_path}")


# ---------------------------
# CLI
# ---------------------------

def main(argv=None):
    p = argparse.ArgumentParser(description="Cloud storage public-access scanner (S3 & Azure Blob).")
    p.add_argument("urls", nargs="*", help="URLs or s3://... or azure://... inputs to scan. If omitted, use --input.")
    p.add_argument("--input", "-i", help="File with one URL per line.")
    p.add_argument("--output", "-o", help="Output base path for reports (creates .json and .csv).")
    p.add_argument("--threads", "-t", type=int, default=MAX_THREADS, help=f"Number of concurrent workers (default {MAX_THREADS}).")
    p.add_argument("--write-test", action="store_true", help="(Optional & dangerous) Attempt to upload a tiny test object to detect write permissions.")
    p.add_argument("--delete-after", action="store_true", default=True, help="Delete uploaded test object after write test (default true).")
    p.add_argument("--confirm-write", action="store_true", help="Extra required confirmation flag to allow write test. Must be provided with --write-test.")
    p.add_argument("--aws-sdk", action="store_true", help="(Optional) Use AWS SDK checks if boto3 is installed (not required).")
    args = p.parse_args(argv)

    candidates: List[str] = list(args.urls or [])
    if args.input:
        try:
            with open(args.input, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s:
                        candidates.append(s)
        except Exception as e:
            print("Error reading --input file:", e, file=sys.stderr)
            sys.exit(2)

    if not candidates:
        p.print_help()
        sys.exit(1)

    if args.write_test and not args.confirm_write:
        print("ERROR: --write-test requires explicit --confirm-write flag to proceed. Aborting.", file=sys.stderr)
        sys.exit(3)

    if args.write_test:
        print("WARNING: Write test is enabled. Only proceed if you have permission to test these resources.")
        time.sleep(0.8)

    print(f"Starting scan of {len(candidates)} targets (threads={args.threads})...")
    results = run_scan(candidates, threads=args.threads, write_test=args.write_test, delete_after=args.delete_after)

    print("\nSummary:")
    print_summary(results)

    if args.output:
        save_reports(results, args.output)

    # Brief textual summary
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for r in results:
        lvl = r.get("risk_level", "UNKNOWN")
        counts[lvl] = counts.get(lvl, 0) + 1
    print("\nCounts by risk level:", counts)


if __name__ == "__main__":
    main()
# cloud_url_scanner
A cloud URL scanner is a web security tool or service, usually hosted in the cloud, that analyzes URLs (web addresses) to determine whether they are safe or malicious. It helps protect users, businesses, and systems from threats like phishing, malware, spam, and drive-by downloads.
