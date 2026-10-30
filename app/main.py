from __future__ import annotations

import asyncio
import hmac
import hashlib
import ipaddress
import os
import secrets
import socket
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import dns.asyncresolver
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
        conn.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ")
        conn.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS verification_token_hash TEXT")
        conn.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS verification_expires_at TIMESTAMPTZ")
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
        # This endpoint accepts hostnames, not IP-literal scan targets.
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("IP-adresser accepteres ikke; angiv et domænenavn")
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


def _validate_public_ips(answers) -> list[str]:
    ips = sorted({item[4][0].split("%", 1)[0] for item in answers})
    if not ips:
        raise RuntimeError("Ingen DNS-adresser")
    for address in ips:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise RuntimeError("Domænet peger på en ikke-offentlig IP; scanning afvist")
    return ips


def resolve_public_ips(host: str) -> list[str]:
    """Synchronous resolver retained for direct validation and compatibility tests."""
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError("DNS-opslag fejlede") from exc
    return _validate_public_ips(answers)


async def resolve_public_ips_async(host: str) -> list[str]:
    """Resolve DNS without blocking the async request/event loop."""
    try:
        loop = asyncio.get_running_loop()
        answers = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError("DNS-opslag fejlede") from exc
    return _validate_public_ips(answers)


class _PinnedNetworkBackend:
    """Connect to one approved IP while httpcore retains the URL hostname for TLS."""

    def __init__(self, hostname: str, address: str):
        from httpcore._backends.auto import AutoBackend

        self.hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
        self.address = str(ipaddress.ip_address(address))
        self._backend = AutoBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        requested = host.decode("ascii").lower().rstrip(".") if isinstance(host, bytes) else str(host).lower().rstrip(".")
        if requested != self.hostname:
            import httpcore
            raise httpcore.ConnectError("Unexpected destination host")
        return await self._backend.connect_tcp(
            self.address, port, timeout=timeout,
            local_address=local_address, socket_options=socket_options,
        )

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        import httpcore
        raise httpcore.ConnectError("Unix sockets are not permitted")

    async def sleep(self, seconds):
        return await self._backend.sleep(seconds)


def _pinned_transport(domain: str, ip_text: str) -> httpx.AsyncHTTPTransport:
    """Build a transport whose TCP backend cannot resolve or connect elsewhere."""
    transport = httpx.AsyncHTTPTransport(verify=True, trust_env=False)
    # httpx 0.28/httpcore 1.x exposes this backend seam on its connection pool.
    # Keeping the URL hostname intact makes httpcore perform SNI and certificate
    # hostname verification against the submitted domain, not the pinned IP.
    transport._pool._network_backend = _PinnedNetworkBackend(domain, ip_text)
    return transport


async def _read_response_body_limited(response: httpx.Response, max_bytes: int) -> tuple[int, bool]:
    """Discard a response body while enforcing a decoded-byte processing limit.

    The body is never retained. HTTPX yields bounded chunks, and iteration stops
    as soon as the configured limit would be exceeded.
    """
    if max_bytes < 0:
        raise ValueError("MAX_RESPONSE_BYTES must not be negative")

    consumed = 0
    truncated = False
    async for chunk in response.aiter_bytes(chunk_size=8192):
        remaining = max_bytes - consumed
        if len(chunk) > remaining:
            consumed += remaining
            truncated = True
            break
        consumed += len(chunk)
    return consumed, truncated


async def probe(domain: str) -> dict:
    errors: list[str] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            # Resolve once, reject mixed/private answers, then pin TCP to an approved IP.
            # The original hostname remains the HTTP Host and TLS verification name.
            approved_ips = await resolve_public_ips_async(domain)
            transport = _pinned_transport(domain, approved_ips[0])
            async with httpx.AsyncClient(
                timeout=TIMEOUT,
                follow_redirects=False,
                trust_env=False,
                headers={"User-Agent": "DK-PHP-Exposure-Scanner/0.1 (+non-invasive security inventory)"},
                transport=transport,
            ) as client:
                async with client.stream("GET", f"{scheme}://{domain}/") as response:
                    server = response.headers.get("server", "")[:500]
                    powered = response.headers.get("x-powered-by", "")[:500]
                    # Only trust explicit version disclosure in X-Powered-By, never page content.
                    import re
                    matches = re.findall(r"(?i)PHP\s*/?\s*(\d+\.\d+(?:\.\d+)?)", powered)
                    version = matches[0] if matches else None
                    indicator = "php" in powered.lower() or "php" in server.lower()
                    if response.status_code == 403:
                        confidence = "blocked"
                        status_note = "Serveren afviste forespørgslen (HTTP 403); PHP-fravær kan ikke konkluderes."
                    elif response.status_code == 429:
                        confidence = "rate-limited"
                        status_note = "Serveren begrænsede forespørgslen (HTTP 429); PHP-fravær kan ikke konkluderes."
                    else:
                        confidence = "version-disclosed" if version else ("possible-php" if indicator else "unknown")
                        status_note = ""
                    _body_bytes, body_truncated = await _read_response_body_limited(response, MAX_BYTES)
                    if body_truncated:
                        status_note += (" " if status_note else "") + f"Response body blev afkortet ved {MAX_BYTES} bytes."
                    return {
                        "status_code": response.status_code,
                        "final_url": url,
                        "server_header": server,
                        "powered_by": powered,
                        "php_indicator": indicator,
                        "version_observed": version,
                        "confidence": confidence,
                        "notes": "HTTP-redirects følges ikke; offentlig signaturkontrol, ikke en sårbarhedsbekræftelse. " + status_note,
                    }
        except httpx.TimeoutException:
            errors.append(f"{scheme}: timeout")
        except httpx.ConnectError:
            errors.append(f"{scheme}: connection-failed")
        except httpx.TransportError:
            errors.append(f"{scheme}: transport-failed")
        except RuntimeError:
            # DNS failures and rejected non-public destinations are reported
            # without exposing resolver details or internal exception text.
            errors.append(f"{scheme}: dns-or-destination-rejected")
        except Exception:
            # Keep unexpected implementation details out of persisted scan results.
            errors.append(f"{scheme}: internal-error")
    return {
        "status_code": None, "final_url": None, "server_header": "", "powered_by": "",
        "php_indicator": False, "version_observed": None, "confidence": "unreachable",
        "notes": "Forespørgslen kunne ikke gennemføres: " + "; ".join(errors),
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


@app.post("/domains/{domain_id}/verification-challenge", dependencies=[Depends(require_api_key)])
def create_domain_verification_challenge(domain_id: int):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
    with db_connect() as conn:
        row = conn.execute("SELECT domain FROM domains WHERE id=%s", (domain_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Domæne ikke fundet")
        conn.execute(
            "UPDATE domains SET verified_at=NULL, verification_token_hash=%s, verification_expires_at=%s WHERE id=%s",
            (token_hash, expires_at, domain_id),
        )
    return {"domain": row[0], "record_name": f"_dk-php-scanner-verification.{row[0]}",
            "record_type": "TXT", "record_value": f"dk-php-scanner-verification={token}",
            "expires_at": expires_at.isoformat()}


@app.post("/domains/{domain_id}/verify", dependencies=[Depends(require_api_key)])
async def verify_domain_control(domain_id: int):
    with db_connect() as conn:
        row = conn.execute("SELECT domain, verification_token_hash, verification_expires_at FROM domains WHERE id=%s", (domain_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Domæne ikke fundet")
    domain, token_hash, expires_at = row
    now = datetime.now(timezone.utc)
    if not token_hash or not expires_at or expires_at <= now:
        raise HTTPException(400, "Verifikationschallenge mangler eller er udløbet")
    try:
        answers = await dns.asyncresolver.resolve(f"_dk-php-scanner-verification.{domain}", "TXT", lifetime=5)
        valid = False
        for answer in answers:
            value = b"".join(answer.strings).decode("utf-8", errors="strict")
            prefix = "dk-php-scanner-verification="
            if value.startswith(prefix):
                supplied_hash = hashlib.sha256(value[len(prefix):].encode("utf-8")).hexdigest()
                if hmac.compare_digest(supplied_hash, token_hash):
                    valid = True
                    break
    except Exception:
        valid = False
    if not valid:
        raise HTTPException(400, "DNS TXT-verifikation kunne ikke bekræftes")
    with db_connect() as conn:
        updated = conn.execute(
            "UPDATE domains SET verified_at=%s, verification_token_hash=NULL, verification_expires_at=NULL WHERE id=%s AND verification_token_hash=%s AND verification_expires_at>%s RETURNING domain",
            (now, domain_id, token_hash, now),
        ).fetchone()
    if not updated:
        raise HTTPException(409, "Challenge er udløbet eller allerede anvendt")
    return {"domain": updated[0], "verified": True, "verified_at": now.isoformat()}

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
        row = conn.execute("SELECT id, domain, verified_at FROM domains WHERE id=%s", (domain_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Domæne ikke fundet")
    if row[2] is None:
        raise HTTPException(403, "Domænet skal verificeres før scanning")
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


def _safe_csv_cell(value):
    """Neutralize spreadsheet formulas in untrusted textual CSV cells."""
    if not isinstance(value, str):
        return value
    if value.startswith(("\t", "\r", "\n")):
        return "'" + value
    stripped = value.lstrip(" ")
    if stripped.startswith(("=", "+", "-", "@")):
        prefix_length = len(value) - len(stripped)
        return value[:prefix_length] + "'" + stripped
    return value


@app.get("/results.csv", dependencies=[Depends(require_api_key)])
def results_csv():
    import csv
    import io
    from fastapi.responses import StreamingResponse

    columns = [
        "domain", "scanned_at", "status_code", "server_header", "x_powered_by",
        "php_indicator", "version_observed", "confidence", "notes",
    ]

    def generate_csv():
        # A named psycopg cursor keeps the result set on the PostgreSQL server;
        # fetchmany bounds application memory while the response is streamed.
        with db_connect() as conn:
            with conn.cursor(name="scanner_csv_export") as cursor:
                cursor.execute("""
                    SELECT d.domain,s.scanned_at,s.status_code,s.server_header,s.powered_by,s.php_indicator,
                           s.version_observed,s.confidence,s.notes
                    FROM scans s JOIN domains d ON d.id=s.domain_id ORDER BY s.scanned_at DESC
                """)
                buffer = io.StringIO()
                writer = csv.writer(buffer)
                writer.writerow(columns)
                yield buffer.getvalue()
                while rows := cursor.fetchmany(500):
                    buffer.seek(0)
                    buffer.truncate(0)
                    writer.writerows(tuple(_safe_csv_cell(value) for value in row) for row in rows)
                    yield buffer.getvalue()

    return StreamingResponse(
        generate_csv(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=dk-php-scanner-results.csv"},
    )
