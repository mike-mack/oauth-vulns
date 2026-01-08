import sqlite3
import os
import secrets
import hashlib
import base64
import logging
import time
from datetime import datetime, timedelta
from typing import Optional, List
from urllib.parse import urlparse, urlencode, parse_qs
from contextlib import contextmanager

import uvicorn
from fastapi import FastAPI, Request, Form, Query, HTTPException, Header
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator

# Configure secure logging - NO sensitive data
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="OAuth Authorization Server (Hardened)",
    description="A secure OAuth 2.0 authorization server with PKCE",
    version="1.0.0"
)

# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    return response

# Database path - separate from vulnerable implementation
DB_PATH = os.path.join(os.path.dirname(__file__), "hardened_oauth.db")

# Constants
ACCESS_TOKEN_EXPIRY = 3600  # 1 hour
AUTH_CODE_EXPIRY = 600  # 10 minutes
MAX_SCOPE_LENGTH = 200
MAX_STATE_LENGTH = 500
ALLOWED_SCOPES = {"read", "write", "admin", "delete"}
RATE_LIMIT_WINDOW = 60  # 1 minute
RATE_LIMIT_MAX_REQUESTS = 10

# Rate limiting storage (in production, use Redis)
rate_limit_store = {}


# ========================
# Models
# ========================

class ClientRegistration(BaseModel):
    client_id: str
    client_secret: str
    redirect_uris: List[str]
    scopes: str
    
    @validator('client_id')
    def validate_client_id(cls, v):
        if not v or len(v) < 8 or len(v) > 64:
            raise ValueError("client_id must be 8-64 characters")
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError("client_id must be alphanumeric (with - or _)")
        return v
    
    @validator('client_secret')
    def validate_client_secret(cls, v):
        if not v or len(v) < 32:
            raise ValueError("client_secret must be at least 32 characters")
        return v
    
    @validator('redirect_uris')
    def validate_redirect_uris(cls, v):
        if not v or len(v) == 0:
            raise ValueError("At least one redirect_uri required")
        for uri in v:
            parsed = urlparse(uri)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid redirect_uri: {uri}")
            if parsed.scheme not in ['https', 'http']:
                raise ValueError(f"redirect_uri must use http or https: {uri}")
            # In production, require HTTPS only
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    scope: str


# ========================
# Database Setup
# ========================

@contextmanager
def db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def hash_secret(secret: str) -> str:
    """Hash a client secret using SHA-256"""
    return hashlib.sha256(secret.encode()).hexdigest()


def verify_secret(secret: str, hashed: str) -> bool:
    """Verify a secret against its hash"""
    return hash_secret(secret) == hashed


def init_authz_database():
    """Initialize authorization server tables with security"""
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Create clients table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS oauth_clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT UNIQUE NOT NULL,
                client_secret_hash TEXT NOT NULL,
                redirect_uris TEXT NOT NULL,
                scopes TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create authorization requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS authorization_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT UNIQUE NOT NULL,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT,
                state TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                code_challenge_method TEXT NOT NULL,
                csrf_token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        
        # Create authorization codes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS authorization_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT,
                code_challenge TEXT NOT NULL,
                user_id TEXT,
                used BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        
        # Create access tokens table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS access_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                client_id TEXT NOT NULL,
                scope TEXT,
                user_id TEXT,
                revoked BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        
        # Insert default client with hashed secret
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO oauth_clients (client_id, client_secret_hash, redirect_uris, scopes)
                VALUES (?, ?, ?, ?)
            """, (
                "oauth-client-1",
                hash_secret("oauth-client-secret-1"),
                "http://localhost:3000/callback,http://localhost:8080/callback",
                "read,write,delete"
            ))
            conn.commit()
            logger.info("Initialized default client (secrets are hashed)")
        except sqlite3.IntegrityError:
            pass


# Initialize database on startup
init_authz_database()


# ========================
# Security Helper Functions
# ========================

def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """Verify PKCE code_verifier against code_challenge"""
    if method == "S256":
        # SHA256 hash of verifier
        hashed = hashlib.sha256(code_verifier.encode()).digest()
        computed_challenge = base64.urlsafe_b64encode(hashed).decode().rstrip('=')
        return computed_challenge == code_challenge
    elif method == "plain":
        # Plain text (not recommended but supported)
        return code_verifier == code_challenge
    return False


def strict_redirect_uri_match(registered_uris: List[str], requested_uri: str) -> bool:
    """Strict redirect URI validation - exact match only"""
    return requested_uri in registered_uris


def validate_scope(requested_scope: str, allowed_scope: str) -> bool:
    """Validate that requested scopes are subset of allowed scopes"""
    if not requested_scope:
        return True
    
    requested = set(requested_scope.split(','))
    allowed = set(allowed_scope.split(','))
    
    # Check all requested scopes are in allowed set
    if not requested.issubset(allowed):
        return False
    
    # Check all scopes are in the global allowlist
    if not requested.issubset(ALLOWED_SCOPES):
        return False
    
    return True


def check_rate_limit(client_id: str) -> bool:
    """Simple rate limiting check"""
    now = time.time()
    key = f"rate_limit:{client_id}"
    
    if key not in rate_limit_store:
        rate_limit_store[key] = []
    
    # Remove old requests outside the window
    rate_limit_store[key] = [
        req_time for req_time in rate_limit_store[key]
        if now - req_time < RATE_LIMIT_WINDOW
    ]
    
    # Check if limit exceeded
    if len(rate_limit_store[key]) >= RATE_LIMIT_MAX_REQUESTS:
        return False
    
    # Add current request
    rate_limit_store[key].append(now)
    return True


def cleanup_expired_data():
    """Remove expired codes and tokens"""
    with db_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        
        cursor.execute("DELETE FROM authorization_requests WHERE expires_at < ?", (now,))
        cursor.execute("DELETE FROM authorization_codes WHERE expires_at < ?", (now,))
        cursor.execute("DELETE FROM access_tokens WHERE expires_at < ?", (now,))
        
        conn.commit()


# ========================
# API Endpoints
# ========================

@app.get("/")
async def index():
    """Root endpoint"""
    return JSONResponse(content={
        "service": "OAuth 2.0 Authorization Server (Hardened)",
        "version": "1.0.0",
        "endpoints": {
            "authorization": "/authorize",
            "token": "/token",
            "register": "/register",
            "revoke": "/revoke"
        },
        "security_features": [
            "PKCE required (RFC 7636)",
            "State parameter required",
            "Strict redirect URI validation",
            "Authorization code single-use",
            "Short-lived tokens and codes",
            "Rate limiting",
            "Secure secret hashing"
        ]
    })


@app.post("/register")
async def register_client(registration: ClientRegistration):
    """
    Register a new OAuth client with strict validation.
    
    Security:
    - Validates client_id format and length
    - Requires strong client_secret (32+ chars)
    - Validates redirect_uris format
    - Hashes client_secret before storage
    - Validates scopes against allowlist
    """
    # Validate scopes
    requested_scopes = set(registration.scopes.split(','))
    if not requested_scopes.issubset(ALLOWED_SCOPES):
        raise HTTPException(
            status_code=400,
            detail="Invalid scopes requested"
        )
    
    # Hash the client secret
    secret_hash = hash_secret(registration.client_secret)
    
    try:
        with db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO oauth_clients (client_id, client_secret_hash, redirect_uris, scopes)
                VALUES (?, ?, ?, ?)
            """, (
                registration.client_id,
                secret_hash,
                ','.join(registration.redirect_uris),
                registration.scopes
            ))
            conn.commit()
        
        logger.info(f"Client registered: {registration.client_id}")
        
        return JSONResponse(content={
            "message": "Client registered successfully",
            "client_id": registration.client_id
        })
    
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Client ID already exists")


@app.get("/authorize")
async def authorize(
    request: Request,
    client_id: str = Query(...),
    response_type: str = Query(...),
    redirect_uri: str = Query(...),
    scope: Optional[str] = Query(None),
    state: str = Query(...),  # Required!
    code_challenge: str = Query(...),  # Required (PKCE)!
    code_challenge_method: str = Query(...)  # Required (PKCE)!
):
    """
    Authorization endpoint - initiate OAuth flow with strict validation.
    
    Security:
    - Requires PKCE (code_challenge, code_challenge_method)
    - Requires state parameter
    - Strict redirect_uri validation (exact match)
    - Validates response_type
    - Validates scopes
    - Generates CSRF token for approval form
    """
    cleanup_expired_data()
    
    # Validate response_type
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only 'code' response_type supported")
    
    # Validate PKCE parameters
    if not code_challenge or not code_challenge_method:
        raise HTTPException(status_code=400, detail="PKCE required: code_challenge and code_challenge_method")
    
    if code_challenge_method not in ["S256", "plain"]:
        raise HTTPException(status_code=400, detail="code_challenge_method must be 'S256' or 'plain'")
    
    # Validate state parameter
    if not state or len(state) > MAX_STATE_LENGTH:
        raise HTTPException(status_code=400, detail="State parameter required and must be < 500 chars")
    
    # Validate scope length
    if scope and len(scope) > MAX_SCOPE_LENGTH:
        raise HTTPException(status_code=400, detail="Scope too long")
    
    # Get and validate client
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT redirect_uris, scopes FROM oauth_clients WHERE client_id = ?",
            (client_id,)
        )
        result = cursor.fetchone()
        
        if not result:
            raise HTTPException(status_code=400, detail="Invalid client_id")
        
        registered_uris = result["redirect_uris"].split(",")
        allowed_scopes = result["scopes"]
    
    # Strict redirect URI validation - exact match
    if not strict_redirect_uri_match(registered_uris, redirect_uri):
        logger.warning(f"Redirect URI mismatch for client {client_id}")
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    
    # Validate requested scopes
    if scope and not validate_scope(scope, allowed_scopes):
        raise HTTPException(status_code=400, detail="Invalid scope requested")
    
    # Generate request ID and CSRF token
    request_id = generate_secure_token()
    csrf_token = generate_secure_token()
    
    # Store authorization request
    expires_at = (datetime.utcnow() + timedelta(seconds=600)).isoformat()
    
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO authorization_requests 
            (request_id, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, csrf_token, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (request_id, client_id, redirect_uri, scope or "", state, code_challenge, code_challenge_method, csrf_token, expires_at))
        conn.commit()
    
    logger.info(f"Authorization request initiated for client: {client_id}")
    
    # Return authorization page with consent form
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authorization Request</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{
                font-family: Arial, sans-serif;
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .container {{
                background-color: white;
                border-radius: 8px;
                padding: 30px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            h1 {{
                color: #333;
                border-bottom: 2px solid #4CAF50;
                padding-bottom: 10px;
            }}
            .info {{
                background-color: #e3f2fd;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
            }}
            .info p {{
                margin: 8px 0;
            }}
            .warning {{
                background-color: #fff3e0;
                border-left: 4px solid #ff9800;
                padding: 15px;
                margin: 20px 0;
            }}
            .buttons {{
                margin-top: 30px;
                display: flex;
                gap: 10px;
            }}
            button {{
                padding: 12px 30px;
                font-size: 16px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                flex: 1;
            }}
            .approve {{
                background-color: #4CAF50;
                color: white;
            }}
            .approve:hover {{
                background-color: #45a049;
            }}
            .deny {{
                background-color: #f44336;
                color: white;
            }}
            .deny:hover {{
                background-color: #da190b;
            }}
            .security-badge {{
                display: inline-block;
                background-color: #4CAF50;
                color: white;
                padding: 4px 8px;
                border-radius: 3px;
                font-size: 12px;
                margin-left: 10px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Authorization Request <span class="security-badge">SECURED</span></h1>
            
            <div class="info">
                <p><strong>Client:</strong> {client_id}</p>
                <p><strong>Requested Scopes:</strong> {scope or 'default'}</p>
                <p><strong>Redirect URI:</strong> {redirect_uri}</p>
                <p><strong>Security:</strong> PKCE Enabled ✓</p>
            </div>
            
            <div class="warning">
                <strong>⚠️ Authorization Request</strong>
                <p>The application <strong>{client_id}</strong> is requesting access to your data.</p>
                <p>Only approve if you trust this application.</p>
            </div>
            
            <form method="POST" action="/approve">
                <input type="hidden" name="request_id" value="{request_id}">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                
                <div class="buttons">
                    <button type="submit" name="action" value="approve" class="approve">
                        ✓ Approve
                    </button>
                    <button type="submit" name="action" value="deny" class="deny">
                        ✗ Deny
                    </button>
                </div>
            </form>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)


@app.post("/approve")
async def approve_consent(
    request_id: str = Form(...),
    csrf_token: str = Form(...),
    action: str = Form(...)
):
    cleanup_expired_data()
    
    # Retrieve authorization request
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, csrf_token, expires_at
            FROM authorization_requests WHERE request_id = ?
        """, (request_id,))
        result = cursor.fetchone()
        
        if not result:
            raise HTTPException(status_code=400, detail="Invalid or expired authorization request")
        
        # Validate CSRF token
        if csrf_token != result["csrf_token"]:
            logger.warning(f"CSRF token mismatch for request {request_id}")
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
        
        # Check expiration
        if datetime.fromisoformat(result["expires_at"]) < datetime.utcnow():
            raise HTTPException(status_code=400, detail="Authorization request expired")
        
        client_id = result["client_id"]
        redirect_uri = result["redirect_uri"]
        scope = result["scope"]
        state = result["state"]
        code_challenge = result["code_challenge"]
        code_challenge_method = result["code_challenge_method"]
        
        # Delete the authorization request (single-use)
        cursor.execute("DELETE FROM authorization_requests WHERE request_id = ?", (request_id,))
        conn.commit()
    
    # Handle denial
    if action == "deny":
        logger.info(f"Authorization denied by user for client: {client_id}")
        error_params = urlencode({
            "error": "access_denied",
            "error_description": "User denied authorization",
            "state": state
        })
        return RedirectResponse(url=f"{redirect_uri}?{error_params}")
    
    # Generate authorization code
    auth_code = generate_secure_token()
    expires_at = (datetime.utcnow() + timedelta(seconds=AUTH_CODE_EXPIRY)).isoformat()
    user_id = "user123"  # In production, get from session
    
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO authorization_codes 
            (code, client_id, redirect_uri, scope, code_challenge, user_id, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (auth_code, client_id, redirect_uri, scope, code_challenge, user_id, expires_at))
        conn.commit()
    
    logger.info(f"Authorization code generated for client: {client_id}")
    
    # Redirect with code
    params = urlencode({
        "code": auth_code,
        "state": state
    })
    
    return RedirectResponse(url=f"{redirect_uri}?{params}")


@app.post("/token")
async def issue_token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    code_verifier: str = Form(...)  # Required (PKCE)!
):
    cleanup_expired_data()
    
    # Validate grant_type
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant_type")
    
    # Rate limiting
    if not check_rate_limit(client_id):
        logger.warning(f"Rate limit exceeded for client: {client_id}")
        raise HTTPException(status_code=429, detail="Too many requests")
    
    # Validate client credentials
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT client_secret_hash, redirect_uris, scopes FROM oauth_clients WHERE client_id = ?",
            (client_id,)
        )
        client_result = cursor.fetchone()
        
        if not client_result:
            raise HTTPException(status_code=401, detail="Invalid client credentials")
        
        # Verify client secret
        if not verify_secret(client_secret, client_result["client_secret_hash"]):
            logger.warning(f"Invalid client secret for client: {client_id}")
            raise HTTPException(status_code=401, detail="Invalid client credentials")
        
        # Retrieve authorization code
        cursor.execute("""
            SELECT code_challenge, redirect_uri, scope, user_id, used, expires_at
            FROM authorization_codes WHERE code = ? AND client_id = ?
        """, (code, client_id))
        code_result = cursor.fetchone()
        
        if not code_result:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        # Check if code already used
        if code_result["used"]:
            logger.warning(f"Authorization code reuse attempt by client: {client_id}")
            raise HTTPException(status_code=400, detail="Authorization code already used")
        
        # Check code expiration
        if datetime.fromisoformat(code_result["expires_at"]) < datetime.utcnow():
            raise HTTPException(status_code=400, detail="Authorization code expired")
        
        # Validate redirect_uri
        if code_result["redirect_uri"] != redirect_uri:
            raise HTTPException(status_code=400, detail="Redirect URI mismatch")
        
        # Verify PKCE
        if not code_verifier:
            raise HTTPException(status_code=400, detail="code_verifier required")
        
        if not verify_pkce(code_verifier, code_result["code_challenge"], "S256"):
            logger.warning(f"PKCE verification failed for client: {client_id}")
            raise HTTPException(status_code=400, detail="Invalid code_verifier")
        
        # Mark code as used
        cursor.execute("UPDATE authorization_codes SET used = 1 WHERE code = ?", (code,))
        
        # Generate access token
        access_token = generate_secure_token(48)
        expires_at = (datetime.utcnow() + timedelta(seconds=ACCESS_TOKEN_EXPIRY)).isoformat()
        
        cursor.execute("""
            INSERT INTO access_tokens (token, client_id, scope, user_id, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (access_token, client_id, code_result["scope"], code_result["user_id"], expires_at))
        
        conn.commit()
    
    logger.info(f"Access token issued for client: {client_id}")
    
    return JSONResponse(content={
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRY,
        "scope": code_result["scope"]
    })


@app.post("/revoke")
async def revoke_token(
    token: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...)
):
    """
    Token revocation endpoint.
    
    Security:
    - Client authentication required
    - Marks token as revoked (not deleted for audit trail)
    """
    # Validate client credentials
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT client_secret_hash FROM oauth_clients WHERE client_id = ?",
            (client_id,)
        )
        result = cursor.fetchone()
        
        if not result or not verify_secret(client_secret, result["client_secret_hash"]):
            raise HTTPException(status_code=401, detail="Invalid client credentials")
        
        # Revoke token
        cursor.execute("""
            UPDATE access_tokens SET revoked = 1 
            WHERE token = ? AND client_id = ?
        """, (token, client_id))
        conn.commit()
    
    logger.info(f"Token revoked for client: {client_id}")
    
    return JSONResponse(content={"message": "Token revoked successfully"})


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return JSONResponse(content={"status": "healthy", "timestamp": datetime.utcnow().isoformat()})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
