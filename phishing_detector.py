"""
URL Shield - Python phishing URL analyzer
The detection logic is kept in Python. The Flask app only displays the input form and result.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from difflib import SequenceMatcher
from ipaddress import ip_address
from urllib.parse import urlparse
import re

TRUSTED_DOMAINS = [
    "google.com", "gmail.com", "youtube.com", "amazon.com", "amazon.in",
    "facebook.com", "instagram.com", "whatsapp.com", "microsoft.com",
    "apple.com", "github.com", "linkedin.com", "paypal.com", "netflix.com",
    "flipkart.com", "sbi.co.in", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "onlinesbi.sbi", "jecrcuniversity.edu.in"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "bank", "password",
    "signin", "wallet", "otp", "limited", "confirm", "support", "unlock"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"
}

@dataclass
class CheckResult:
    name: str
    status: str
    score: int
    details: str


def normalize_url(raw_url: str) -> str:
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        raw_url = "https://" + raw_url
    return raw_url


def get_host(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower().strip(".")


def is_ip_host(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def base_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def simplify_lookalikes(text: str) -> str:
    table = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    })
    return text.translate(table)


def check_valid_url(url: str, host: str) -> CheckResult:
    if not url or not host or "." not in host:
        return CheckResult("URL Format", "Risk", 20, "The input does not look like a complete website address.")
    return CheckResult("URL Format", "Safe", 0, "The URL format looks valid.")


def check_protocol(url: str) -> CheckResult:
    scheme = urlparse(url).scheme.lower()
    if scheme == "https":
        return CheckResult("HTTPS", "Safe", 0, "The URL uses HTTPS.")
    return CheckResult("HTTPS", "Risk", 20, "The URL does not use HTTPS.")


def check_ip_address(host: str) -> CheckResult:
    if is_ip_host(host):
        return CheckResult("IP Address", "Risk", 25, "The host is an IP address instead of a normal domain name.")
    return CheckResult("IP Address", "Safe", 0, "No IP address was found in the host.")


def check_url_length(url: str) -> CheckResult:
    length = len(url)
    if length > 100:
        return CheckResult("URL Length", "Risk", 15, f"The URL is very long ({length} characters).")
    if length > 75:
        return CheckResult("URL Length", "Warning", 8, f"The URL is moderately long ({length} characters).")
    return CheckResult("URL Length", "Safe", 0, f"The URL length is normal ({length} characters).")


def check_at_symbol(url: str) -> CheckResult:
    if "@" in url:
        return CheckResult("@ Symbol", "Risk", 20, "The URL contains '@', which can hide the real destination.")
    return CheckResult("@ Symbol", "Safe", 0, "No '@' symbol was found.")


def check_subdomains(host: str) -> CheckResult:
    if is_ip_host(host):
        return CheckResult("Subdomains", "Safe", 0, "Subdomain check skipped for IP address.")
    parts = host.split(".") if host else []
    subdomain_count = max(0, len(parts) - 2)
    if subdomain_count > 3:
        return CheckResult("Subdomains", "Risk", 15, f"Too many subdomains were found ({subdomain_count}).")
    if subdomain_count >= 2:
        return CheckResult("Subdomains", "Warning", 8, f"Multiple subdomains were found ({subdomain_count}).")
    return CheckResult("Subdomains", "Safe", 0, f"Subdomain count is normal ({subdomain_count}).")


def check_hyphens(host: str) -> CheckResult:
    hyphens = host.count("-")
    if hyphens >= 3:
        return CheckResult("Hyphens", "Risk", 12, f"The domain contains many hyphens ({hyphens}).")
    if hyphens >= 1:
        return CheckResult("Hyphens", "Warning", 5, f"The domain contains hyphen(s) ({hyphens}).")
    return CheckResult("Hyphens", "Safe", 0, "No hyphen was found in the domain.")


def check_keywords(url: str) -> CheckResult:
    lowered = url.lower()
    found = [word for word in SUSPICIOUS_KEYWORDS if word in lowered]
    if len(found) >= 3:
        return CheckResult("Suspicious Keywords", "Risk", 30, "Multiple risky words were found: " + ", ".join(found))
    if found:
        return CheckResult("Suspicious Keywords", "Warning", 8, "Risky word(s) were found: " + ", ".join(found))
    return CheckResult("Suspicious Keywords", "Safe", 0, "No suspicious keyword was found.")


def check_shortener(host: str) -> CheckResult:
    domain = base_domain(host)
    if domain in URL_SHORTENERS:
        return CheckResult("URL Shortener", "Warning", 10, "The URL uses a known shortening service.")
    return CheckResult("URL Shortener", "Safe", 0, "No common URL shortener was detected.")


def check_typosquatting(host: str) -> CheckResult:
    domain = base_domain(host)
    if not domain or domain in TRUSTED_DOMAINS or is_ip_host(host):
        return CheckResult("Typosquatting", "Safe", 0, "No typosquatting pattern was detected.")

    simplified_domain = simplify_lookalikes(domain)
    best_match = ""
    best_score = 0.0
    exact_lookalike = False

    for trusted in TRUSTED_DOMAINS:
        ratio = max(
            SequenceMatcher(None, domain, trusted).ratio(),
            SequenceMatcher(None, simplified_domain, trusted).ratio(),
        )
        if simplified_domain == trusted and domain != trusted:
            exact_lookalike = True
            ratio = 1.0
        if ratio > best_score:
            best_score = ratio
            best_match = trusted

    if exact_lookalike:
        return CheckResult("Typosquatting", "Risk", 70, f"The domain looks like a fake version of {best_match}.")
    if best_score >= 0.86:
        return CheckResult("Typosquatting", "Risk", 35, f"The domain is very similar to {best_match}.")
    if best_score >= 0.80:
        return CheckResult("Typosquatting", "Warning", 20, f"The domain is somewhat similar to {best_match}.")
    return CheckResult("Typosquatting", "Safe", 0, "No strong similarity to trusted domains was found.")


def verdict_from_score(score: int) -> tuple[str, str]:
    if score <= 30:
        return "Looks safe", "This URL has low visible risk based on the current checks."
    if score <= 60:
        return "Be careful", "This URL has warning signs. Verify it before entering any information."
    return "Stay away", "This URL has strong phishing indicators. Avoid using it."


def analyze_url(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    host = get_host(url) if url else ""

    if not raw_url or not raw_url.strip():
        return {
            "input_url": raw_url,
            "normalized_url": "",
            "host": "",
            "score": 0,
            "verdict": "No URL entered",
            "message": "Please enter a URL and click Check URL.",
            "checks": [],
        }

    checks = [
        check_valid_url(url, host),
        check_protocol(url),
        check_ip_address(host),
        check_url_length(url),
        check_at_symbol(url),
        check_subdomains(host),
        check_hyphens(host),
        check_keywords(url),
        check_shortener(host),
        check_typosquatting(host),
    ]

    total_score = min(sum(item.score for item in checks), 100)
    verdict, message = verdict_from_score(total_score)

    return {
        "input_url": raw_url,
        "normalized_url": url,
        "host": host,
        "score": total_score,
        "verdict": verdict,
        "message": message,
        "checks": [asdict(item) for item in checks],
    }
