from __future__ import annotations

import hmac
import ipaddress
import os
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

DATABASE_URL = os.environ["DATABASE_URL"]
API_KEY = os.getenv("SCANNER_API_KEY", "")
TIMEOUT = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "8"))
MAX_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", "65536"))
app = FastAPI(title="DK PHP Exposure Scanner", version="0.1.0")

def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    if not API_KEY or not x_api_key or not hmac.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Ugyldig eller manglende API-nøgle")


def db_connect():
    return psycopg.connect(DATABASE_URL)


@app.on_event("startup")
def startup():
    with db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domains (
                id BIGSERIAL PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL DEFAULT 'manual',
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id BIGSERIAL PRIMARY KEY,
                domain_id BIGINT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                status_code INTEGER,
                final_url TEXT,
                server_header TEXT,
                powered_by TEXT,
                php_indicator BOOLEAN NOT NULL DEFAULT false,
                version_observed TEXT,
                confidence TEXT NOT NULL DEFAULT 'unknown',
                notes TEXT NOT NULL DEFAULT ''
            )
        """)


class DomainImport(BaseModel):
    domains: list[str] = Field(min_length=1, max_length=1000)
    source: str = Field(default="manual", max_length=100)


def normalize_domain(raw: str) -> str:
    value = raw.strip().lower().rstrip(".")
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("Importér kun domænenavne, ikke URL'er med sti eller login")
        value = parsed.hostname or ""
    if not value or len(value) > 253 or "/" in value or ":" in value or "@" in value:
        raise ValueError("Ugyldigt domæne")
    try:
        value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Ugyldigt domænenavn") from exc
    labels = value.split(".")
    if len(labels) < 2 or any(not x or len(x) > 63 or x.startswith("-") or x.endswith("-") for x in labels):
        raise ValueError("Ugyldigt domæne")
    if any(not all(c.isalnum() or c == "-" for c in label) for label in labels):
        raise ValueError("Ugyldigt domænenavn")
    return value.encode("idna").decode("ascii")


def resolve_public_ips(host: str) -> list[str]:
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError("DNS-opslag fejlede") from exc
    ips = sorted({item[4][0].split("%", 1)[0] for item in answers})
    if not ips:
        raise RuntimeError("Ingen DNS-adresser")
    for text in ips:
        ip = ipaddress.ip_address(text)
        if not ip.is_global:
            raise RuntimeError("Domænet peger på en ikke-offentlig IP; scanning afvist")
    return ips


async def probe(domain: str) -> dict:
    errors: list[str] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            # Resolve and reject non-public destinations before issuing a request.
            resolve_public_ips(domain)
            async with httpx.AsyncClient(
                timeout=TIMEOUT,
                follow_redirects=False,
                trust_env=False,
                headers={"User-Agent": "DK-PHP-Exposure-Scanner/0.1 (+non-invasive security inventory)"},
                verify=True,
            ) as client:
                async with client.stream("GET", url) as response:
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) >= MAX_BYTES:
                            break
                    server = response.headers.get("server", "")[:500]
                    powered = response.headers.get("x-powered-by", "")[:500]
                    text = body.decode("utf-8", errors="ignore")
                    combined = f"{server} {powered} {text[:MAX_BYTES]}"
                    # Only capture explicit PHP version strings; do not infer a version from CMS names.
                    import re
                    matches = re.findall(r"(?i)PHP\s*/?\s*(\d+\.\d+(?:\.\d+)?)", combined)
                    version = matches[0] if matches else None
                    indicator = bool(matches) or "php" in powered.lower() or "php" in server.lower()
                    return {
                        "status_code": response.status_code,
                        "final_url": url,
                        "server_header": server,
                        "powered_by": powered,
                        "php_indicator": indicator,
                        "version_observed": version,
                        "confidence": "version-disclosed" if version else ("possible-php" if indicator else "unknown"),
                        "notes": "HTTP-redirects følges ikke; offentlig signaturkontrol, ikke en sårbarhedsbekræftelse.",
                    }
        except Exception as exc:
            errors.append(f"{scheme}: {str(exc)[:180]}")
    return {
        "status_code": None, "final_url": None, "server_header": "", "powered_by": "",
        "php_indicator": False, "version_observed": None, "confidence": "unreachable",
        "notes": "; ".join(errors)[:1000],
    }


@app.get("/health")
def health():
    with db_connect() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "service": "dk-php-exposure-scanner", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/domains/import", dependencies=[Depends(require_api_key)])
def import_domains(payload: DomainImport):
    accepted, rejected = 0, []
    with db_connect() as conn:
        for raw in payload.domains:
            try:
                domain = normalize_domain(raw)
            except ValueError as exc:
                rejected.append({"input": raw[:255], "reason": str(exc)})
                continue
            conn.execute(
                "INSERT INTO domains(domain, source) VALUES (%s, %s) ON CONFLICT(domain) DO NOTHING",
                (domain, payload.source),
            )
            accepted += 1
    return {"processed": len(payload.domains), "accepted_or_existing": accepted, "rejected": rejected}


@app.get("/domains", dependencies=[Depends(require_api_key)])
def list_domains(limit: int = 100, offset: int = 0, q: str | None = None):
    if not 1 <= limit <= 1000 or offset < 0:
        raise HTTPException(400, "limit skal være 1-1000 og offset mindst 0")
    with db_connect() as conn:
        if q:
            rows = conn.execute(
                "SELECT id, domain, source, created_at FROM domains WHERE domain ILIKE %s ORDER BY domain LIMIT %s OFFSET %s",
                (f"%{q[:253]}%", limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, domain, source, created_at FROM domains ORDER BY domain LIMIT %s OFFSET %s",
                (limit, offset),
            ).fetchall()
    return [{"id": r[0], "domain": r[1], "source": r[2], "created_at": r[3].isoformat()} for r in rows]


@app.post("/domains/{domain_id}/scan", dependencies=[Depends(require_api_key)])
async def scan_domain(domain_id: int):
    with db_connect() as conn:
        row = conn.execute("SELECT id, domain FROM domains WHERE id=%s", (domain_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Domæne ikke fundet")
    result = await probe(row[1])
    with db_connect() as conn:
        saved = conn.execute("""
            INSERT INTO scans(domain_id,status_code,final_url,server_header,powered_by,php_indicator,version_observed,confidence,notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id, scanned_at
        """, (row[0], result["status_code"], result["final_url"], result["server_header"], result["powered_by"], result["php_indicator"], result["version_observed"], result["confidence"], result["notes"])).fetchone()
    return {"scan_id": saved[0], "domain": row[1], "scanned_at": saved[1].isoformat(), **result}


@app.get("/results", dependencies=[Depends(require_api_key)])
def results(limit: int = 100, offset: int = 0):
    if not 1 <= limit <= 1000 or offset < 0:
        raise HTTPException(400, "limit skal være 1-1000 og offset mindst 0")
    with db_connect() as conn:
        rows = conn.execute("""
            SELECT s.id,d.domain,s.scanned_at,s.status_code,s.server_header,s.powered_by,
                   s.php_indicator,s.version_observed,s.confidence,s.notes
            FROM scans s JOIN domains d ON d.id=s.domain_id
            ORDER BY s.scanned_at DESC LIMIT %s OFFSET %s
        """, (limit, offset)).fetchall()
    return [{"scan_id": r[0], "domain": r[1], "scanned_at": r[2].isoformat(), "status_code": r[3],
             "server_header": r[4], "powered_by": r[5], "php_indicator": r[6], "version_observed": r[7],
             "confidence": r[8], "notes": r[9]} for r in rows]


@app.get("/results.csv", dependencies=[Depends(require_api_key)])
def results_csv():
    from fastapi.responses import StreamingResponse
    import csv, io
    with db_connect() as conn:
        rows = conn.execute("""
            SELECT d.domain,s.scanned_at,s.status_code,s.server_header,s.powered_by,s.php_indicator,
                   s.version_observed,s.confidence,s.notes
            FROM scans s JOIN domains d ON d.id=s.domain_id ORDER BY s.scanned_at DESC
        """).fetchall()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["domain", "scanned_at", "status_code", "server_header", "x_powered_by", "php_indicator", "version_observed", "confidence", "notes"])
    writer.writerows(rows)
    return StreamingResponse(iter([buffer.getvalue()]), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=dk-php-scanner-results.csv"})
