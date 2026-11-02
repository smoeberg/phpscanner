from __future__ import annotations

import asyncio
import hmac
import hashlib
import ipaddress
import os
import secrets
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import dns.asyncresolver
import httpx
import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from typing import Literal

from app.observability import configure_logger

DATABASE_URL = os.environ["DATABASE_URL"]
API_KEY = os.getenv("SCANNER_API_KEY", "")
TIMEOUT = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "8"))
MAX_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", "65536"))
MAX_CONCURRENT_SCANS = 4
SCAN_COOLDOWN_SECONDS = 60
SCAN_SLOT_LEASE_SECONDS = 90
SCAN_EXECUTION_DEADLINE_SECONDS = 60
app = FastAPI(title="DK PHP Exposure Scanner", version="0.1.0")
logger = configure_logger("scanner.api")


@app.middleware("http")
async def log_http_requests(request, call_next):
    request_id = uuid.uuid4().hex
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "http_request_failed",
            extra={
                "event": "http_request", "request_id": request_id,
                "method": request.method, "path": request.url.path,
                "status_code": 500,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )
        raise
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "http_request_completed",
        extra={
            "event": "http_request", "request_id": request_id,
            "method": request.method, "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        },
    )
    return response

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
            CREATE TABLE IF NOT EXISTS scan_rate_limits (
                domain_id BIGINT PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
                last_scan_started_at TIMESTAMPTZ NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_slots (
                slot_id INTEGER PRIMARY KEY,
                lease_until TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
                lease_token TEXT
            )
        """)
        conn.execute("ALTER TABLE scan_slots ADD COLUMN IF NOT EXISTS lease_token TEXT")
        conn.execute(
            "INSERT INTO scan_slots(slot_id) SELECT generate_series(1, %s) ON CONFLICT DO NOTHING",
            (MAX_CONCURRENT_SCANS,),
        )
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


class AuthorizationGrant(BaseModel):
    basis_type: Literal["written_permission", "contract", "other"]
    description: str = Field(default="", max_length=2000)
    evidence_reference: str = Field(min_length=1, max_length=1000)
    granted_by: str = Field(min_length=1, max_length=200)
    valid_from: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    valid_until: datetime | None = None


class ScanTargetStatus(BaseModel):
    status: Literal["active", "disabled"]


class DomainImport(BaseModel):
    domains: list[str] = Field(min_length=1, max_length=1000)
    source: str = Field(default="manual", max_length=100)


class ProspectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    organization_number: str | None = Field(default=None, max_length=100)
    website_url: str | None = Field(default=None, max_length=500)
    notes: str = Field(default="", max_length=2000)


class ProspectDomainAssociation(BaseModel):
    domain_id: int = Field(gt=0)


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


def _pinned_request_target(domain: str, ip_text: str, scheme: str) -> tuple[str, dict[str, str], dict[str, str]]:
    """Legacy URL formatter retained for compatibility tests; probe does not use it."""
    ip = ipaddress.ip_address(ip_text)
    authority = f"[{ip}]" if ip.version == 6 else str(ip)
    return f"{scheme}://{authority}/", {"Host": domain}, {"sni_hostname": domain.encode("ascii")}


def _pinned_transport(domain: str, ip_text: str, *, verify=True) -> httpx.AsyncHTTPTransport:
    """Build a transport whose TCP backend cannot resolve or connect elsewhere.

    ``verify`` is injectable for isolated integration tests; production callers
    use the secure default (certificate and hostname verification enabled).
    """
    transport = httpx.AsyncHTTPTransport(verify=verify)
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


@app.get("/health/live")
def health_live():
    """Liveness only: this process can serve requests."""
    return {"status": "ok", "service": "dk-php-exposure-scanner"}


@app.get("/health/ready")
def health_ready():
    """Readiness: the API can reach its required PostgreSQL database."""
    try:
        with db_connect() as conn:
            conn.execute("SELECT 1")
    except psycopg.Error:
        logger.warning("readiness_check_failed", extra={"event": "readiness_check", "status_code": 503})
        raise HTTPException(status_code=503, detail="Database unavailable")
    return {"status": "ok", "service": "dk-php-exposure-scanner", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/health")
def health():
    """Backward-compatible readiness endpoint."""
    return health_ready()


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
        answers = await dns.asyncresolver.resolve(f"_dk-php-scanner-verification.{domain}.", "TXT", lifetime=5)
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
                "SELECT id, domain, source, created_at, verified_at FROM domains WHERE domain ILIKE %s ORDER BY domain LIMIT %s OFFSET %s",
                (f"%{q[:253]}%", limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, domain, source, created_at, verified_at FROM domains ORDER BY domain LIMIT %s OFFSET %s",
                (limit, offset),
            ).fetchall()
    return [{"id": r[0], "domain": r[1], "source": r[2], "created_at": r[3].isoformat(), "verified_at": r[4].isoformat() if r[4] else None, "verified": r[4] is not None} for r in rows]



@app.post("/prospects", status_code=201, dependencies=[Depends(require_api_key)])
def create_prospect(payload: ProspectCreate):
    name = payload.name.strip()
    if not name:
        raise HTTPException(400, "Prospectnavn skal indeholde tekst")
    organization_number = payload.organization_number.strip() if payload.organization_number else None
    website_url = payload.website_url.strip() if payload.website_url else None
    with db_connect() as conn:
        row = conn.execute(
            """
            INSERT INTO prospects(name, organization_number, website_url, notes)
            VALUES (%s, %s, %s, %s)
            RETURNING id, name, organization_number, website_url, notes, created_at, updated_at
            """,
            (name, organization_number or None, website_url or None, payload.notes),
        ).fetchone()
    return {
        "id": row[0], "name": row[1], "organization_number": row[2],
        "website_url": row[3], "notes": row[4],
        "created_at": row[5].isoformat(), "updated_at": row[6].isoformat(),
        "domains": [],
    }


@app.get("/prospects", dependencies=[Depends(require_api_key)])
def list_prospects(limit: int = 100, offset: int = 0, q: str | None = None):
    if not 1 <= limit <= 1000 or offset < 0:
        raise HTTPException(400, "limit skal være 1-1000 og offset mindst 0")
    with db_connect() as conn:
        if q:
            rows = conn.execute(
                """
                WITH selected_prospects AS (
                    SELECT p.*
                    FROM prospects AS p
                    WHERE p.name ILIKE %s
                       OR COALESCE(p.organization_number, '') ILIKE %s
                    ORDER BY p.name, p.id
                    LIMIT %s OFFSET %s
                )
                SELECT p.id, p.name, p.organization_number, p.website_url, p.notes,
                       p.created_at, p.updated_at, pd.id, d.id, d.domain,
                       pd.association_status, pd.created_at
                FROM selected_prospects AS p
                LEFT JOIN prospect_domains AS pd ON pd.prospect_id = p.id
                LEFT JOIN domains AS d ON d.id = pd.domain_id
                ORDER BY p.name, p.id, d.domain
                """,
                (f"%{q[:200]}%", f"%{q[:200]}%", limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                WITH selected_prospects AS (
                    SELECT p.*
                    FROM prospects AS p
                    ORDER BY p.name, p.id
                    LIMIT %s OFFSET %s
                )
                SELECT p.id, p.name, p.organization_number, p.website_url, p.notes,
                       p.created_at, p.updated_at, pd.id, d.id, d.domain,
                       pd.association_status, pd.created_at
                FROM selected_prospects AS p
                LEFT JOIN prospect_domains AS pd ON pd.prospect_id = p.id
                LEFT JOIN domains AS d ON d.id = pd.domain_id
                ORDER BY p.name, p.id, d.domain
                """,
                (limit, offset),
            ).fetchall()

    prospects = {}
    for row in rows:
        prospect = prospects.setdefault(row[0], {
            "id": row[0], "name": row[1], "organization_number": row[2],
            "website_url": row[3], "notes": row[4],
            "created_at": row[5].isoformat(), "updated_at": row[6].isoformat(),
            "domains": [],
        })
        if row[7] is not None:
            prospect["domains"].append({
                "association_id": row[7], "domain_id": row[8], "domain": row[9],
                "association_status": row[10], "associated_at": row[11].isoformat(),
            })
    return list(prospects.values())


@app.post("/prospects/{prospect_id}/domains", dependencies=[Depends(require_api_key)])
def associate_domain_with_prospect(
    prospect_id: int, payload: ProspectDomainAssociation
):
    with db_connect() as conn:
        if not conn.execute(
            "SELECT id FROM prospects WHERE id = %s", (prospect_id,)
        ).fetchone():
            raise HTTPException(404, "Prospect ikke fundet")
        domain = conn.execute(
            "SELECT id, domain FROM domains WHERE id = %s", (payload.domain_id,)
        ).fetchone()
        if not domain:
            raise HTTPException(404, "Domæne ikke fundet")
        association = conn.execute(
            """
            INSERT INTO prospect_domains(prospect_id, domain_id, association_status)
            VALUES (%s, %s, 'unverified')
            ON CONFLICT (prospect_id, domain_id) DO NOTHING
            RETURNING id, association_status, created_at
            """,
            (prospect_id, payload.domain_id),
        ).fetchone()
        if not association:
            association = conn.execute(
                """
                SELECT id, association_status, created_at
                FROM prospect_domains
                WHERE prospect_id = %s AND domain_id = %s
                """,
                (prospect_id, payload.domain_id),
            ).fetchone()
    return {
        "association_id": association[0], "prospect_id": prospect_id,
        "domain_id": domain[0], "domain": domain[1],
        "association_status": association[1],
        "associated_at": association[2].isoformat(),
    }


@app.post("/domains/{domain_id}/authorizations", dependencies=[Depends(require_api_key)])
def create_authorization(domain_id: int, payload: AuthorizationGrant):
    if not payload.evidence_reference.strip() or not payload.granted_by.strip():
        raise HTTPException(400, "evidence_reference og granted_by skal indeholde tekst")
    if payload.valid_from.tzinfo is None or payload.valid_from.utcoffset() is None:
        raise HTTPException(400, "valid_from skal indeholde tidszone")
    if payload.valid_until is not None:
        if payload.valid_until.tzinfo is None or payload.valid_until.utcoffset() is None:
            raise HTTPException(400, "valid_until skal indeholde tidszone")
        if payload.valid_until <= payload.valid_from:
            raise HTTPException(400, "valid_until skal ligge efter valid_from")

    with db_connect() as conn:
        domain = conn.execute(
            "SELECT id, domain FROM domains WHERE id = %s",
            (domain_id,),
        ).fetchone()
        if not domain:
            raise HTTPException(404, "Domæne ikke fundet")
        basis = conn.execute(
            """
            INSERT INTO authorization_bases
                (domain_id, basis_type, description, evidence_reference, granted_by, valid_from, valid_until)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id, created_at, revoked_at
            """,
            (domain_id, payload.basis_type, payload.description, payload.evidence_reference,
             payload.granted_by, payload.valid_from, payload.valid_until),
        ).fetchone()
        target = conn.execute(
            """
            INSERT INTO scan_targets(domain_id, authorization_basis_id, status)
            VALUES (%s, %s, 'active')
            RETURNING id, status, created_at
            """,
            (domain_id, basis[0]),
        ).fetchone()

    return {
        "authorization_id": basis[0],
        "domain_id": domain[0],
        "domain": domain[1],
        "basis_type": payload.basis_type,
        "description": payload.description,
        "evidence_reference": payload.evidence_reference,
        "granted_by": payload.granted_by,
        "valid_from": payload.valid_from.isoformat(),
        "valid_until": payload.valid_until.isoformat() if payload.valid_until else None,
        "created_at": basis[1].isoformat(),
        "revoked_at": basis[2].isoformat() if basis[2] else None,
        "scan_target_id": target[0],
        "target_status": target[1],
        "target_created_at": target[2].isoformat(),
    }


@app.get("/domains/{domain_id}/authorizations", dependencies=[Depends(require_api_key)])
def list_authorizations(domain_id: int):
    with db_connect() as conn:
        if not conn.execute("SELECT id FROM domains WHERE id = %s", (domain_id,)).fetchone():
            raise HTTPException(404, "Domæne ikke fundet")
        rows = conn.execute(
            """
            SELECT ab.id, ab.basis_type, ab.description, ab.evidence_reference,
                   ab.granted_by, ab.valid_from, ab.valid_until, ab.created_at,
                   ab.revoked_at, st.id, st.status,
                   (ab.revoked_at IS NULL AND ab.valid_from <= now()
                    AND (ab.valid_until IS NULL OR ab.valid_until > now())
                    AND st.status = 'active') AS currently_authorized
            FROM authorization_bases AS ab
            JOIN scan_targets AS st
              ON st.authorization_basis_id = ab.id AND st.domain_id = ab.domain_id
            WHERE ab.domain_id = %s
            ORDER BY ab.created_at DESC, ab.id DESC
            """,
            (domain_id,),
        ).fetchall()
    return [
        {
            "authorization_id": r[0], "basis_type": r[1], "description": r[2],
            "evidence_reference": r[3], "granted_by": r[4],
            "valid_from": r[5].isoformat(),
            "valid_until": r[6].isoformat() if r[6] else None,
            "created_at": r[7].isoformat(),
            "revoked_at": r[8].isoformat() if r[8] else None,
            "scan_target_id": r[9], "target_status": r[10],
            "currently_authorized": r[11],
        }
        for r in rows
    ]


@app.post("/authorizations/{authorization_id}/revoke", dependencies=[Depends(require_api_key)])
def revoke_authorization(authorization_id: int):
    with db_connect() as conn:
        row = conn.execute(
            """
            UPDATE authorization_bases
            SET revoked_at = COALESCE(revoked_at, now())
            WHERE id = %s
            RETURNING id, domain_id, revoked_at
            """,
            (authorization_id,),
        ).fetchone()
    if not row:
        raise HTTPException(404, "Autorisationsgrundlag ikke fundet")
    return {"authorization_id": row[0], "domain_id": row[1], "revoked_at": row[2].isoformat()}


@app.patch("/scan-targets/{target_id}", dependencies=[Depends(require_api_key)])
def set_scan_target_status(target_id: int, payload: ScanTargetStatus):
    with db_connect() as conn:
        row = conn.execute(
            """
            UPDATE scan_targets
            SET status = %s
            WHERE id = %s
            RETURNING id, domain_id, authorization_basis_id, status
            """,
            (payload.status, target_id),
        ).fetchone()
    if not row:
        raise HTTPException(404, "Scanmål ikke fundet")
    return {
        "scan_target_id": row[0], "domain_id": row[1],
        "authorization_id": row[2], "status": row[3],
    }


class ScanAuthorizationError(Exception):
    """Raised when a domain has no currently valid, enabled scan authorization."""


def reserve_scan_capacity(domain_id: int) -> tuple[int, str] | None:
    """Atomically validate authorization and reserve capacity for a scan.

    The authorization rows are share-locked in the same transaction as the
    capacity/cooldown reservation. A concurrent revoke/disable therefore
    serializes with scan initiation; authorization is evaluated at reservation
    time, not inferred from DNS control verification.
    """
    lease_token = secrets.token_urlsafe(32)
    with db_connect() as conn:
        authorized = conn.execute(
            """
            SELECT st.id
            FROM scan_targets AS st
            JOIN authorization_bases AS ab
              ON ab.id = st.authorization_basis_id
             AND ab.domain_id = st.domain_id
            WHERE st.domain_id = %s
              AND st.status = 'active'
              AND ab.revoked_at IS NULL
              AND ab.valid_from <= now()
              AND (ab.valid_until IS NULL OR ab.valid_until > now())
            FOR SHARE OF st, ab
            """,
            (domain_id,),
        ).fetchone()
        if not authorized:
            raise ScanAuthorizationError("No active authorization for this scan target")

        slot = conn.execute(
            """
            WITH candidate AS (
                SELECT slot_id FROM scan_slots
                WHERE lease_until <= now()
                ORDER BY slot_id
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE scan_slots AS s
            SET lease_until = now() + (%s * interval '1 second'),
                lease_token = %s
            FROM candidate
            WHERE s.slot_id = candidate.slot_id
            RETURNING s.slot_id
            """,
            (SCAN_SLOT_LEASE_SECONDS, lease_token),
        ).fetchone()
        if not slot:
            return None
        slot_id = slot[0]
        permitted = conn.execute(
            """
            INSERT INTO scan_rate_limits(domain_id, last_scan_started_at)
            VALUES (%s, now())
            ON CONFLICT (domain_id) DO UPDATE
            SET last_scan_started_at = now()
            WHERE scan_rate_limits.last_scan_started_at <= now() - (%s * interval '1 second')
            RETURNING domain_id
            """,
            (domain_id, SCAN_COOLDOWN_SECONDS),
        ).fetchone()
        if not permitted:
            conn.execute(
                "UPDATE scan_slots SET lease_until = '-infinity', lease_token = NULL WHERE slot_id = %s AND lease_token = %s",
                (slot_id, lease_token),
            )
            return None
        return slot_id, lease_token


def release_scan_capacity(slot_id: int, lease_token: str) -> None:
    """Release only the reservation still owned by this exact fencing token."""
    with db_connect() as conn:
        conn.execute(
            "UPDATE scan_slots SET lease_until = '-infinity', lease_token = NULL WHERE slot_id = %s AND lease_token = %s",
            (slot_id, lease_token),
        )


def enqueue_scan_job(domain_id: int) -> int:
    """Persist a scan request only when a current authorization covers the domain."""
    with db_connect() as conn:
        authorized = conn.execute(
            """
            SELECT st.id
            FROM scan_targets AS st
            JOIN authorization_bases AS ab
              ON ab.id = st.authorization_basis_id
             AND ab.domain_id = st.domain_id
            WHERE st.domain_id = %s
              AND st.status = 'active'
              AND ab.revoked_at IS NULL
              AND ab.valid_from <= now()
              AND (ab.valid_until IS NULL OR ab.valid_until > now())
            FOR SHARE OF st, ab
            """,
            (domain_id,),
        ).fetchone()
        if not authorized:
            raise ScanAuthorizationError("No active authorization for this scan target")
        row = conn.execute(
            """
            INSERT INTO scan_jobs(domain_id, status)
            VALUES (%s, 'queued')
            RETURNING id, created_at
            """,
            (domain_id,),
        ).fetchone()
    return row[0]


@app.post("/domains/{domain_id}/scan", status_code=202, dependencies=[Depends(require_api_key)])
def scan_domain(domain_id: int):
    with db_connect() as conn:
        row = conn.execute(
            "SELECT id, domain, verified_at FROM domains WHERE id=%s",
            (domain_id,),
        ).fetchone()
    if not row:
        raise HTTPException(404, "Domæne ikke fundet")
    if row[2] is None:
        raise HTTPException(403, "Domænet skal verificeres før scanning")
    try:
        job_id = enqueue_scan_job(domain_id)
    except ScanAuthorizationError:
        raise HTTPException(403, "Scanning kræver et gyldigt, aktivt autorisationsgrundlag")
    except Exception:
        raise HTTPException(503, "Scan-jobbet kunne ikke oprettes")
    return {
        "job_id": job_id,
        "domain_id": domain_id,
        "domain": row[1],
        "status": "queued",
        "status_url": f"/scan-jobs/{job_id}",
    }


@app.get("/scan-jobs/{job_id}", dependencies=[Depends(require_api_key)])
def get_scan_job(job_id: int):
    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT j.id, j.domain_id, d.domain, j.status, j.attempts,
                   j.created_at, j.started_at, j.finished_at, j.scan_id, j.last_error
            FROM scan_jobs AS j
            JOIN domains AS d ON d.id = j.domain_id
            WHERE j.id = %s
            """,
            (job_id,),
        ).fetchone()
    if not row:
        raise HTTPException(404, "Scan-job ikke fundet")
    return {
        "job_id": row[0], "domain_id": row[1], "domain": row[2],
        "status": row[3], "attempts": row[4],
        "created_at": row[5].isoformat(),
        "started_at": row[6].isoformat() if row[6] else None,
        "finished_at": row[7].isoformat() if row[7] else None,
        "scan_id": row[8], "error": row[9],
    }


@app.get("/scans/{scan_id}/observations", dependencies=[Depends(require_api_key)])
def get_scan_observations(scan_id: int):
    with db_connect() as conn:
        exists = conn.execute(
            "SELECT id FROM scans WHERE id = %s",
            (scan_id,),
        ).fetchone()
        if not exists:
            raise HTTPException(404, "Scan ikke fundet")
        rows = conn.execute(
            """
            SELECT id, observation_type, observed_value, source, observed_at, metadata
            FROM scan_observations
            WHERE scan_id = %s
            ORDER BY id
            """,
            (scan_id,),
        ).fetchall()
    return [
        {
            "observation_id": row[0],
            "observation_type": row[1],
            "value": row[2],
            "source": row[3],
            "observed_at": row[4].isoformat(),
            "metadata": row[5],
        }
        for row in rows
    ]


@app.get("/scans/{scan_id}/findings", dependencies=[Depends(require_api_key)])
def get_scan_findings(scan_id: int):
    with db_connect() as conn:
        exists = conn.execute(
            "SELECT id FROM scans WHERE id = %s",
            (scan_id,),
        ).fetchone()
        if not exists:
            raise HTTPException(404, "Scan ikke fundet")
        rows = conn.execute(
            """
            SELECT id, finding_type, assessment, confidence, version_observed,
                   rationale, evidence, created_at
            FROM scan_findings
            WHERE scan_id = %s
            ORDER BY id
            """,
            (scan_id,),
        ).fetchall()
    return [
        {
            "finding_id": row[0],
            "finding_type": row[1],
            "assessment": row[2],
            "confidence": row[3],
            "version_observed": row[4],
            "rationale": row[5],
            "evidence": row[6],
            "created_at": row[7].isoformat(),
        }
        for row in rows
    ]


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
        "php_indicator", "version_observed", "scan_confidence", "notes",
        "finding_type", "finding_assessment", "finding_confidence",
        "finding_version_observed", "finding_rationale", "finding_evidence",
        "prospect_associations",
    ]

    def generate_csv():
        # A named psycopg cursor keeps the result set on the PostgreSQL server;
        # fetchmany bounds application memory while the response is streamed.
        with db_connect() as conn:
            with conn.cursor(name="scanner_csv_export") as cursor:
                cursor.execute("""
                    SELECT d.domain,s.scanned_at,s.status_code,s.server_header,s.powered_by,s.php_indicator,
                           s.version_observed,s.confidence,s.notes,
                           f.finding_type,f.assessment,f.confidence,f.version_observed,f.rationale,
                           f.evidence::text,
                           COALESCE((
                               SELECT jsonb_agg(
                                   jsonb_build_object(
                                       'prospect_id', p.id,
                                       'prospect_name', p.name,
                                       'association_status', pd.association_status
                                   )
                                   ORDER BY p.name, p.id
                               )
                               FROM prospect_domains AS pd
                               JOIN prospects AS p ON p.id = pd.prospect_id
                               WHERE pd.domain_id = d.id
                           ), '[]'::jsonb)::text
                    FROM scans s
                    JOIN domains d ON d.id=s.domain_id
                    LEFT JOIN scan_findings f
                      ON f.scan_id=s.id AND f.finding_type='php_runtime_disclosure'
                    ORDER BY s.scanned_at DESC
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
