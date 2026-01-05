"""
Vulnerable OAuth Authorization Server
WARNING: This is intentionally vulnerable for educational purposes.
DO NOT use in production!

Vulnerabilities included:
- Ignores PKCE (code_challenge, code_verifier)
- Ignores state parameter
- Extremely weak redirect URI validation (allows subdomain/subdirectory manipulation)
- No client validation
- No scope validation
- Allows authorization code replay
- Tokens and codes never expire
- Leaks tokens and codes in errors and logs
- No CSRF protection
"""

import sqlite3
import os
import secrets
import logging
from typing import Optional
from urllib.parse import urlparse, urlencode
from contextlib import contextmanager

from fastapi import FastAPI, Request, Form, Query, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel

# Configure logging to leak sensitive data (vulnerable!)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="OAuth Authorization Server (Vulnerable)",
    description="A deliberately vulnerable OAuth authorization server for learning purposes",
    version="1.0.0"
)

# Database path - shared with resource server
DB_PATH = os.path.join(os.path.dirname(__file__), "hr_database.db")


# ========================
# Models
# ========================

class ClientRegistration(BaseModel):
    client_id: str
    client_secret: str
    redirect_uris: list[str]
    scopes: str  # Comma-separated scopes


class TokenRequest(BaseModel):
    grant_type: str
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    scope: str


# ========================
# Database Setup
# ========================

def get_db_connection():
    """Get a database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_connection():
    """Context manager for database connections"""
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()


def init_authz_database():
    """Initialize authorization server tables"""
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Create clients table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS oauth_clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT UNIQUE NOT NULL,
                client_secret TEXT NOT NULL,
                redirect_uris TEXT NOT NULL,
                scopes TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create authorization requests table (to track pending authorizations)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS authorization_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT UNIQUE NOT NULL,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT,
                state TEXT,
                code_challenge TEXT,
                code_challenge_method TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create authorization codes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS authorization_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT NOT NULL,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT,
                user_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Insert default client (vulnerable - no proper registration flow)
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO oauth_clients (client_id, client_secret, redirect_uris, scopes)
                VALUES (?, ?, ?, ?)
            """, (
                "oauth-client-1",
                "oauth-client-secret-1",
                "http://localhost:3000/callback,http://localhost:8080/callback",
                "read,write,delete"
            ))
        except sqlite3.IntegrityError:
            pass
        
        conn.commit()
        
        # Log the client creation (leaking sensitive info!)
        logger.info(f"Initialized client: oauth-client-1 with secret: oauth-client-secret-1")


# Initialize database on module load
init_authz_database()


# ========================
# Helper Functions (Vulnerable!)
# ========================

def validate_redirect_uri(client_id: str, redirect_uri: str) -> bool:
    """
    VULNERABLE: Extremely weak redirect URI validation.
    
    Issues:
    1. Only checks if the registered URI is contained in the requested URI
    2. Allows subdomain manipulation (attacker.legitimate.com)
    3. Allows subdirectory manipulation (legitimate.com/callback/../../attacker)
    4. No scheme validation
    5. No exact match required
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT redirect_uris FROM oauth_clients WHERE client_id = ?",
            (client_id,)
        )
        result = cursor.fetchone()
        
        if not result:
            # VULNERABLE: No client validation - accept any client_id!
            logger.warning(f"Unknown client_id: {client_id}, but allowing anyway!")
            return True
        
        registered_uris = result["redirect_uris"].split(",")
        
        # VULNERABLE: Only check if any registered URI's host is "contained" in the redirect_uri
        for registered_uri in registered_uris:
            parsed_registered = urlparse(registered_uri)
            parsed_requested = urlparse(redirect_uri)
            
            # Super weak validation - just check if the registered host appears anywhere
            if parsed_registered.netloc in redirect_uri:
                logger.info(f"Redirect URI validated (weakly): {redirect_uri}")
                return True
        
        # Even if validation "fails", log and allow it anyway (vulnerable!)
        logger.warning(f"Redirect URI validation failed for {redirect_uri}, but allowing anyway for 'compatibility'")
        return True  # Always return True - maximum vulnerability!


def validate_client(client_id: str, client_secret: Optional[str] = None) -> bool:
    """
    VULNERABLE: No real client validation.
    
    Issues:
    1. Accepts any client_id
    2. Secret validation is optional and logged
    3. Leaks client information in logs
    """
    logger.info(f"Validating client: {client_id} with secret: {client_secret}")
    
    # VULNERABLE: Always return True - no validation!
    return True


def validate_scope(requested_scope: str, client_id: str) -> str:
    """
    VULNERABLE: No scope validation.
    
    Issues:
    1. Accepts any scope without checking client's allowed scopes
    2. Returns whatever is requested
    """
    logger.info(f"Scope requested: {requested_scope} for client: {client_id}")
    
    # VULNERABLE: Return whatever is requested without validation
    return requested_scope if requested_scope else "read"


def generate_authorization_code() -> str:
    """Generate an authorization code"""
    code = secrets.token_urlsafe(32)
    logger.info(f"Generated authorization code: {code}")  # VULNERABLE: Logging sensitive data!
    return code


def generate_access_token() -> str:
    """Generate an access token"""
    token = secrets.token_urlsafe(32)
    logger.info(f"Generated access token: {token}")  # VULNERABLE: Logging sensitive data!
    return token


# ========================
# HTML Templates (Inline for simplicity)
# ========================

AUTHORIZE_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Request</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .warning {{ background-color: #ffebee; border: 1px solid #f44336; padding: 10px; margin-bottom: 20px; }}
        .info {{ background-color: #e3f2fd; border: 1px solid #2196f3; padding: 10px; margin-bottom: 20px; }}
        form {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; }}
        button {{ padding: 10px 20px; margin: 5px; cursor: pointer; }}
        .approve {{ background-color: #4caf50; color: white; border: none; }}
        .deny {{ background-color: #f44336; color: white; border: none; }}
        .scopes {{ margin: 10px 0; }}
        .scope-item {{ padding: 5px; background-color: #e0e0e0; margin: 2px; display: inline-block; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="warning">
        <strong>⚠️ WARNING:</strong> This is a VULNERABLE authorization server for educational purposes only!
    </div>
    
    <h1>Authorization Request</h1>
    
    <div class="info">
        <p><strong>Application:</strong> {client_id}</p>
        <p><strong>Redirect URI:</strong> {redirect_uri}</p>
        <p><strong>Requested Scopes:</strong></p>
        <div class="scopes">
            {scope_items}
        </div>
        <!-- VULNERABLE: Displaying state and other params that could be manipulated -->
        <p><small>State: {state}</small></p>
        <p><small>Request ID: {request_id}</small></p>
    </div>
    
    <form method="POST" action="/approve">
        <input type="hidden" name="request_id" value="{request_id}">
        <input type="hidden" name="client_id" value="{client_id}">
        <input type="hidden" name="redirect_uri" value="{redirect_uri}">
        <input type="hidden" name="scope" value="{scope}">
        <input type="hidden" name="state" value="{state}">
        
        <p>Do you want to authorize this application to access your data?</p>
        
        <button type="submit" name="action" value="approve" class="approve">Approve</button>
        <button type="submit" name="action" value="deny" class="deny">Deny</button>
    </form>
    
    <!-- VULNERABLE: Debug info exposed -->
    <div style="margin-top: 30px; padding: 10px; background-color: #fff3e0; border: 1px solid #ff9800;">
        <strong>Debug Info (should not be visible in production!):</strong>
        <pre>
Client ID: {client_id}
Redirect URI: {redirect_uri}
Scope: {scope}
State: {state}
Request ID: {request_id}
        </pre>
    </div>
</body>
</html>
"""

ERROR_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Error</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .error {{ background-color: #ffebee; border: 1px solid #f44336; padding: 20px; }}
    </style>
</head>
<body>
    <div class="error">
        <h1>Authorization Error</h1>
        <p><strong>Error:</strong> {error}</p>
        <p><strong>Description:</strong> {error_description}</p>
        <!-- VULNERABLE: Leaking sensitive information in error page -->
        <p><strong>Client ID:</strong> {client_id}</p>
        <p><strong>Redirect URI:</strong> {redirect_uri}</p>
        <p><strong>Requested Scope:</strong> {scope}</p>
    </div>
</body>
</html>
"""


# ========================
# API Endpoints
# ========================

@app.get("/")
async def root():
    """Public endpoint - server info"""
    return {
        "message": "OAuth Authorization Server (Vulnerable)",
        "endpoints": {
            "authorize": "GET /authorize",
            "approve": "POST /approve", 
            "token": "POST /token",
            "register": "POST /register"
        },
        "warning": "This server is intentionally vulnerable for educational purposes!",
        "vulnerabilities": [
            "Ignores PKCE",
            "Ignores state parameter",
            "Weak redirect URI validation",
            "No client validation",
            "No scope validation",
            "Authorization code replay allowed",
            "No token expiration",
            "Leaks sensitive data in logs and errors"
        ]
    }


@app.get("/authorize", response_class=HTMLResponse)
async def authorize(
    response_type: str = Query(..., description="Must be 'code' for authorization code flow"),
    client_id: str = Query(..., description="Client identifier"),
    redirect_uri: str = Query(..., description="Redirect URI"),
    scope: Optional[str] = Query(None, description="Requested scopes"),
    state: Optional[str] = Query(None, description="State parameter (ignored!)"),
    code_challenge: Optional[str] = Query(None, description="PKCE code challenge (ignored!)"),
    code_challenge_method: Optional[str] = Query(None, description="PKCE method (ignored!)")
):
    """
    Authorization endpoint - initiates the authorization code flow.
    
    VULNERABILITIES:
    - Ignores PKCE (code_challenge, code_challenge_method)
    - Ignores state parameter
    - Weak redirect URI validation
    - No client validation
    """
    # Log everything including sensitive data (vulnerable!)
    logger.info(f"Authorization request: client_id={client_id}, redirect_uri={redirect_uri}, scope={scope}, state={state}")
    logger.info(f"PKCE params (being ignored!): code_challenge={code_challenge}, code_challenge_method={code_challenge_method}")
    
    # Only support authorization code flow
    if response_type != "code":
        error_html = ERROR_PAGE_TEMPLATE.format(
            error="unsupported_response_type",
            error_description=f"Only 'code' response_type is supported, got: {response_type}",
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope or "none"
        )
        return HTMLResponse(content=error_html, status_code=400)
    
    # VULNERABLE: Weak redirect URI validation (always passes)
    validate_redirect_uri(client_id, redirect_uri)
    
    # VULNERABLE: No client validation
    validate_client(client_id)
    
    # VULNERABLE: No scope validation - accept anything
    validated_scope = validate_scope(scope or "read", client_id)
    
    # Generate request ID and store the authorization request
    request_id = secrets.token_urlsafe(16)
    
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO authorization_requests 
            (request_id, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (request_id, client_id, redirect_uri, validated_scope, state, code_challenge, code_challenge_method))
        conn.commit()
    
    # Log the request_id (leaking it!)
    logger.info(f"Created authorization request: {request_id}")
    
    # Generate scope items HTML
    scopes = validated_scope.split(",") if validated_scope else ["read"]
    scope_items = " ".join([f'<span class="scope-item">{s.strip()}</span>' for s in scopes])
    
    # Return the authorization page
    html_content = AUTHORIZE_PAGE_TEMPLATE.format(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=validated_scope,
        scope_items=scope_items,
        state=state or "",
        request_id=request_id
    )
    
    return HTMLResponse(content=html_content)


@app.post("/approve")
async def approve(
    request_id: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(None),
    state: str = Form(None),
    action: str = Form(...)
):
    """
    Approval endpoint - handles user's decision on authorization request.
    
    VULNERABILITIES:
    - No CSRF protection
    - State parameter ignored
    - Authorization codes never expire
    - Codes can be replayed
    """
    logger.info(f"Approval request: request_id={request_id}, action={action}, client_id={client_id}")
    
    if action == "deny":
        # User denied - redirect with error
        error_params = urlencode({
            "error": "access_denied",
            "error_description": "User denied the authorization request",
            "state": state or ""
        })
        redirect_url = f"{redirect_uri}?{error_params}"
        logger.info(f"User denied authorization, redirecting to: {redirect_url}")
        return RedirectResponse(url=redirect_url, status_code=302)
    
    # User approved - generate authorization code
    code = generate_authorization_code()
    
    # Store the authorization code (never expires - vulnerable!)
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # VULNERABLE: Don't delete old codes - allows replay!
        cursor.execute("""
            INSERT INTO authorization_codes (code, client_id, redirect_uri, scope, user_id)
            VALUES (?, ?, ?, ?, ?)
        """, (code, client_id, redirect_uri, scope, "user-123"))  # Hardcoded user for demo
        conn.commit()
    
    # Log the code (leaking it!)
    logger.info(f"Generated authorization code: {code} for client: {client_id}")
    
    # Build redirect URL with code
    # VULNERABLE: State is included but never validated
    params = {"code": code}
    if state:
        params["state"] = state
    
    redirect_url = f"{redirect_uri}?{urlencode(params)}"
    
    # Log the full redirect URL with code (leaking it!)
    logger.info(f"Redirecting to: {redirect_url}")
    
    return RedirectResponse(url=redirect_url, status_code=302)


@app.post("/token")
async def token(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None)  # PKCE - will be ignored!
):
    """
    Token endpoint - exchanges authorization code for access token.
    
    VULNERABILITIES:
    - PKCE verification skipped (code_verifier ignored)
    - No client authentication
    - Authorization codes can be reused (replay attack)
    - Tokens never expire
    - Leaks tokens in response and logs
    """
    # Log everything including secrets (vulnerable!)
    logger.info(f"Token request: grant_type={grant_type}, code={code}, client_id={client_id}, client_secret={client_secret}")
    logger.info(f"PKCE code_verifier (being ignored!): {code_verifier}")
    
    if grant_type != "authorization_code":
        # VULNERABLE: Leaking grant_type in error
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_grant_type",
                "error_description": f"Only 'authorization_code' grant type is supported, got: {grant_type}",
                "received_params": {
                    "grant_type": grant_type,
                    "code": code,
                    "client_id": client_id
                }
            }
        )
    
    if not code:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "Authorization code is required",
                "client_id": client_id
            }
        )
    
    # Look up the authorization code
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # VULNERABLE: Don't check if code was already used - allows replay!
        cursor.execute(
            "SELECT * FROM authorization_codes WHERE code = ?",
            (code,)
        )
        code_data = cursor.fetchone()
        
        if not code_data:
            # VULNERABLE: Leaking the attempted code in error
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_grant",
                    "error_description": f"Invalid authorization code: {code}",
                    "attempted_code": code,
                    "client_id": client_id
                }
            )
        
        # VULNERABLE: No validation of:
        # - client_id matching the code
        # - redirect_uri matching the original request
        # - PKCE code_verifier
        # - Code expiration
        
        # Generate access token
        access_token = generate_access_token()
        
        # Store the access token (for resource server to validate)
        cursor.execute("""
            INSERT INTO oauth_tokens (access_token, client_id, scopes)
            VALUES (?, ?, ?)
        """, (access_token, code_data["client_id"], code_data["scope"] or "read"))
        conn.commit()
        
        # VULNERABLE: Don't invalidate the code - can be replayed!
        # cursor.execute("DELETE FROM authorization_codes WHERE code = ?", (code,))
        
        # Log the token (leaking it!)
        logger.info(f"Issued access token: {access_token} for client: {code_data['client_id']}")
    
    # VULNERABLE: Include extra debug info in response
    return JSONResponse(content={
        "access_token": access_token,
        "token_type": "Bearer",
        "scope": code_data["scope"] or "read",
        # VULNERABLE: Including debug info that shouldn't be exposed
        "debug_info": {
            "code_used": code,
            "client_id": code_data["client_id"],
            "original_redirect_uri": code_data["redirect_uri"],
            "warning": "This debug info should not be included in production!"
        }
    })


@app.post("/register")
async def register_client(
    client_id: str = Form(...),
    client_secret: str = Form(...),
    redirect_uris: str = Form(..., description="Comma-separated redirect URIs"),
    scopes: str = Form("read", description="Comma-separated scopes")
):
    """
    Client registration endpoint.
    
    VULNERABILITIES:
    - No authentication required to register
    - No validation of redirect URIs
    - No validation of scopes
    - Accepts any client_id (could overwrite existing)
    - Logs secrets
    """
    # Log everything including secrets (vulnerable!)
    logger.info(f"Client registration: client_id={client_id}, client_secret={client_secret}, redirect_uris={redirect_uris}, scopes={scopes}")
    
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # VULNERABLE: Use INSERT OR REPLACE - can overwrite existing clients!
        cursor.execute("""
            INSERT OR REPLACE INTO oauth_clients (client_id, client_secret, redirect_uris, scopes)
            VALUES (?, ?, ?, ?)
        """, (client_id, client_secret, redirect_uris, scopes))
        conn.commit()
    
    # VULNERABLE: Return the secret in response
    return JSONResponse(content={
        "message": "Client registered successfully",
        "client_id": client_id,
        "client_secret": client_secret,  # Should never be returned!
        "redirect_uris": redirect_uris.split(","),
        "scopes": scopes.split(","),
        "warning": "This response includes sensitive data that should not be exposed!"
    })


# ========================
# Debug Endpoints (Extra Vulnerable!)
# ========================

@app.get("/debug/clients")
async def debug_clients():
    """
    Debug endpoint - lists all registered clients with secrets!
    EXTREMELY VULNERABLE!
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM oauth_clients")
        clients = cursor.fetchall()
        
        return {
            "warning": "This endpoint exposes all client secrets!",
            "clients": [
                {
                    "client_id": c["client_id"],
                    "client_secret": c["client_secret"],  # Should never expose!
                    "redirect_uris": c["redirect_uris"].split(","),
                    "scopes": c["scopes"].split(",")
                }
                for c in clients
            ]
        }


@app.get("/debug/codes")
async def debug_codes():
    """
    Debug endpoint - lists all authorization codes!
    EXTREMELY VULNERABLE!
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM authorization_codes")
        codes = cursor.fetchall()
        
        return {
            "warning": "This endpoint exposes all authorization codes!",
            "codes": [
                {
                    "code": c["code"],
                    "client_id": c["client_id"],
                    "redirect_uri": c["redirect_uri"],
                    "scope": c["scope"],
                    "created_at": c["created_at"]
                }
                for c in codes
            ]
        }


@app.get("/debug/tokens")
async def debug_tokens():
    """
    Debug endpoint - lists all access tokens!
    EXTREMELY VULNERABLE!
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM oauth_tokens")
        tokens = cursor.fetchall()
        
        return {
            "warning": "This endpoint exposes all access tokens!",
            "tokens": [
                {
                    "access_token": t["access_token"],
                    "client_id": t["client_id"],
                    "scopes": t["scopes"],
                    "created_at": t["created_at"]
                }
                for t in tokens
            ]
        }


# ========================
# Run Server
# ========================

if __name__ == "__main__":
    import uvicorn
    
    print("=" * 60)
    print("WARNING: This is a VULNERABLE OAuth Authorization Server!")
    print("For educational purposes only. DO NOT use in production!")
    print("=" * 60)
    print("\nPre-registered client:")
    print("  - Client ID: oauth-client-1")
    print("  - Client Secret: oauth-client-secret-1")
    print("  - Scopes: read, write, delete")
    print("  - Redirect URIs: http://localhost:3000/callback, http://localhost:8080/callback")
    print("\nVulnerabilities:")
    print("  - PKCE ignored")
    print("  - State parameter ignored")
    print("  - Weak redirect URI validation")
    print("  - No client validation")
    print("  - No scope validation")
    print("  - Authorization code replay allowed")
    print("  - No token expiration")
    print("  - Sensitive data leaked in logs and errors")
    print("\n" + "=" * 60)
    
    uvicorn.run(app, host="0.0.0.0", port=8001)
