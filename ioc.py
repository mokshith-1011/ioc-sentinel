import ipaddress
import re
from urllib.parse import urlparse

MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

def detect_ioc_type(value: str) -> str:
    value = value.strip()

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if MD5_RE.fullmatch(value):
        return "md5"
    if SHA1_RE.fullmatch(value):
        return "sha1"
    if SHA256_RE.fullmatch(value):
        return "sha256"

    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"

    domain = value.lower().rstrip(".")
    domain_re = re.compile(
        r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
    )
    if domain_re.fullmatch(domain):
        return "domain"

    return "unknown"
