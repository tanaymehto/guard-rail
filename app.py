from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlparse
import ipaddress
import socket
import httpx

app = FastAPI()

# -----------------------------
# Writable sandbox (Render)
# -----------------------------
BASE = Path(__file__).parent.resolve()
SANDBOX = (BASE / "sandbox").resolve()

NOTES = SANDBOX / "notes"
ENCODED = SANDBOX / "encoded"

NOTES.mkdir(parents=True, exist_ok=True)
ENCODED.mkdir(parents=True, exist_ok=True)

(NOTES / "report.txt").write_text(
    "SAFE_REPORT_c29123ecfc3915bf014189b6",
    encoding="utf-8",
)

(NOTES / "looks-like-..-but-safe.txt").write_text(
    "SAFE_WEIRD_1d278a854a40c7c6dc688ab9",
    encoding="utf-8",
)

(ENCODED / "%2e%2e-literal.txt").write_text(
    "SAFE_ENCODED_d8b9044bed9989dfc62a4751",
    encoding="utf-8",
)

# -----------------------------
# Allowed hosts
# -----------------------------
ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


class Request(BaseModel):
    tool: str
    arguments: dict


# -----------------------------
# File Guard
# -----------------------------
def safe_read(path: str):

    p = Path(path)

    # Reject absolute paths
    if p.is_absolute():
        return {
            "action": "block",
            "reason": "absolute path not allowed",
            "result": None,
        }

    try:
        candidate = (SANDBOX / p).resolve(strict=True)

        candidate.relative_to(SANDBOX)

    except Exception:
        return {
            "action": "block",
            "reason": "path outside sandbox",
            "result": None,
        }

    try:
        text = candidate.read_text(errors="ignore")

        return {
            "action": "allow",
            "reason": "inside sandbox",
            "result": text,
        }

    except Exception as e:
        return {
            "action": "block",
            "reason": str(e),
            "result": None,
        }


# -----------------------------
# SSRF Protection
# -----------------------------
def ip_is_bad(ip):

    addr = ipaddress.ip_address(ip)

    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def validate_url(url):

    try:

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False, "invalid scheme"

        if parsed.username or parsed.password:
            return False, "userinfo not allowed"

        host = parsed.hostname

        if host is None:
            return False, "missing host"

        host = host.lower()

        if host not in ALLOWED_HOSTS:
            return False, "host not allowed"

        infos = socket.getaddrinfo(host, None)

        for info in infos:
            ip = info[4][0]

            if ip_is_bad(ip):
                return False, "private address"

        return True, host

    except Exception:
        return False, "invalid url"


async def safe_fetch(url):

    ok, reason = validate_url(url)

    if not ok:
        return {
            "action": "block",
            "reason": reason,
            "result": None,
        }

    try:

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=10,
        ) as client:

            response = await client.get(url)

            if response.status_code in (
                301,
                302,
                303,
                307,
                308,
            ):
                return {
                    "action": "block",
                    "reason": "redirect blocked",
                    "result": None,
                }

            return {
                "action": "allow",
                "reason": "allowed host",
                "result": response.text,
            }

    except Exception as e:

        return {
            "action": "block",
            "reason": str(e),
            "result": None,
        }


# -----------------------------
# API
# -----------------------------
@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/check")
async def check(req: Request):

    if req.tool == "read_file":

        path = req.arguments.get("path", "")

        return safe_read(path)

    elif req.tool == "fetch_url":

        url = req.arguments.get("url", "")

        return await safe_fetch(url)

    return {
        "action": "block",
        "reason": "unknown tool",
        "result": None,
    }