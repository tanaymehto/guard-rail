from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlparse
import httpx

app = FastAPI()

# -----------------------------
# Sandbox
# -----------------------------
BASE = Path(__file__).parent.resolve()
SANDBOX = (BASE / "sandbox").resolve()

(NOTES := SANDBOX / "notes").mkdir(parents=True, exist_ok=True)
(ENCODED := SANDBOX / "encoded").mkdir(parents=True, exist_ok=True)

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
    try:
        p = Path(path)

        if p.is_absolute():
            raise ValueError()

        target = (SANDBOX / p).resolve(strict=True)
        target.relative_to(SANDBOX)

        return {
            "action": "allow",
            "reason": "inside sandbox",
            "result": target.read_text(errors="ignore"),
        }

    except Exception:
        return {
            "action": "block",
            "reason": "path outside sandbox",
            "result": None,
        }


# -----------------------------
# URL Guard
# -----------------------------
def validate_url(url: str):
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

        return True, host

    except Exception:
        return False, "invalid url"


async def safe_fetch(url: str):

    ok, reason = validate_url(url)

    if not ok:
        return {
            "action": "block",
            "reason": reason,
            "result": None,
        }

    timeout = httpx.Timeout(5.0, connect=2.0)

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
        ) as client:

            r = await client.get(url)

            if r.status_code in (301, 302, 303, 307, 308):
                return {
                    "action": "block",
                    "reason": "redirect blocked",
                    "result": None,
                }

            return {
                "action": "allow",
                "reason": "allowed host",
                "result": {
                    "body": r.text[:50000]
                },
            }

    except httpx.TimeoutException:
        return {
            "action": "block",
            "reason": "timeout",
            "result": None,
        }

    except Exception as e:
        return {
            "action": "block",
            "reason": str(e),
            "result": None,
        }


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/check")
async def check(req: Request):

    if req.tool == "read_file":
        return safe_read(req.arguments.get("path", ""))

    if req.tool == "fetch_url":
        return await safe_fetch(req.arguments.get("url", ""))

    return {
        "action": "block",
        "reason": "unknown tool",
        "result": None,
    }