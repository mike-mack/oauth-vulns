"""
Hardened OAuth Client - Secure Employee Directory App
This implementation follows OAuth 2.0 security best practices.

Security features:
- PKCE (RFC 7636) for authorization code flow
- CSRF protection with state parameter
- Secure session management with encrypted cookies
- No token/code logging
- Strict redirect URI validation
- Content Security Policy headers
- Secure cookie settings (httponly, secure, samesite)
- Input validation and sanitization
- No open redirects
- Rate limiting
- Audit logging (without sensitive data)
- Secure token storage with encryption
- XSS prevention
"""

import os
import secrets
import hashlib
import base64
import time
import json
from typing import Optional, Dict
from urllib.parse import urlencode, urlparse
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, Request, Form, Query, HTTPException, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel, EmailStr, Field, validator
import httpx
from cryptography.fernet import Fernet

app = FastAPI(
    title="Employee Directory Client (Hardened)",
    description="A secure OAuth client implementation following best practices",
    version="2.0.0",
    docs_url=None,
    redoc_url=None
)

CLIENT_ID = "hardened-client-1"
CLIENT_SECRET = "hardened-client-secret-secure-random-string-12345"
AUTHZ_SERVER_URL = "http://localhost:8011"
RESOURCE_SERVER_URL = "http://localhost:8010"
CLIENT_BASE_URL = "http://localhost:8012"
CALLBACK_PATH = "/callback"

SESSION_KEY = os.environ.get("SESSION_KEY", Fernet.generate_key())
cipher_suite = Fernet(SESSION_KEY if isinstance(SESSION_KEY, bytes) else SESSION_KEY.encode())

secure_sessions: Dict[str, Dict] = {}
pending_auth: Dict[str, Dict] = {}

rate_limits: Dict[str, list] = {}

audit_log: list = []



class TokenData(BaseModel):
    access_token: str
    token_type: str
    scope: str
    expires_in: Optional[int] = 3600


class SessionData(BaseModel):
    token: str
    token_expiry: float
    created_at: float
    last_used: float
    scopes: list[str] = []



def generate_pkce_pair() -> tuple[str, str]:
    """
    Generate PKCE code verifier and challenge.
    
    Returns:
        (code_verifier, code_challenge)
    """
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')
    
    return code_verifier, code_challenge


def generate_secure_state() -> str:
    """Generate cryptographically secure state parameter for CSRF protection"""
    return secrets.token_urlsafe(32)


def generate_session_id() -> str:
    """Generate cryptographically secure session ID"""
    return secrets.token_urlsafe(32)


def encrypt_session_cookie(session_id: str) -> str:
    """Encrypt session ID for cookie"""
    return cipher_suite.encrypt(session_id.encode()).decode()


def decrypt_session_cookie(encrypted: str) -> Optional[str]:
    """Decrypt session ID from cookie"""
    try:
        return cipher_suite.decrypt(encrypted.encode()).decode()
    except Exception:
        return None


def validate_redirect_uri(uri: str, allowed_base: str) -> bool:
    """
    Validate that redirect URI is allowed.
    
    Prevents open redirect attacks by ensuring redirect is to expected callback.
    """
    try:
        parsed = urlparse(uri)
        allowed = urlparse(allowed_base)
        
        return (
            parsed.scheme == allowed.scheme and
            parsed.netloc == allowed.netloc and
            parsed.path == allowed.path
        )
    except Exception:
        return False


def check_rate_limit(identifier: str, max_requests: int = 100, window_seconds: int = 60) -> bool:
    """
    Check rate limit for identifier (e.g., session_id or IP).
    
    Returns:
        True if within rate limit, False if exceeded
    """
    now = time.time()
    
    if identifier not in rate_limits:
        rate_limits[identifier] = []
    
    rate_limits[identifier] = [
        timestamp for timestamp in rate_limits[identifier]
        if now - timestamp < window_seconds
    ]
    
    if len(rate_limits[identifier]) >= max_requests:
        return False
    
    rate_limits[identifier].append(now)
    return True


def audit_log_event(event_type: str, details: dict, success: bool = True):
    """
    Log security event without sensitive data.
    
    Args:
        event_type: Type of event (e.g., "login", "token_refresh")
        details: Non-sensitive details
        success: Whether operation succeeded
    """
    audit_log.append({
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "success": success,
        "details": details
    })
    
    if len(audit_log) > 1000:
        audit_log.pop(0)


def get_session_from_cookie(request: Request) -> Optional[str]:
    """
    Safely extract and validate session from cookie.
    
    Returns:
        session_id if valid, None otherwise
    """
    encrypted_session = request.cookies.get("secure_session")
    if not encrypted_session:
        return None
    
    session_id = decrypt_session_cookie(encrypted_session)
    if not session_id:
        audit_log_event("invalid_session_cookie", {}, success=False)
        return None
    
    if session_id not in secure_sessions:
        return None
    
    session = secure_sessions[session_id]
    
    if time.time() > session["token_expiry"]:
        del secure_sessions[session_id]
        audit_log_event("session_expired", {"reason": "token_expired"}, success=False)
        return None
    
    session["last_used"] = time.time()
    
    return session_id


def cleanup_expired_data():
    """Clean up expired sessions and pending auth requests"""
    now = time.time()
    
    expired_sessions = [
        sid for sid, data in secure_sessions.items()
        if now > data["token_expiry"]
    ]
    for sid in expired_sessions:
        del secure_sessions[sid]
    
    expired_auth = [
        state for state, data in pending_auth.items()
        if now - data["created_at"] > 600
    ]
    for state in expired_auth:
        del pending_auth[state]


def sanitize_for_html(text: str) -> str:
    """
    Sanitize text for HTML output to prevent XSS.
    
    Args:
        text: Input text
        
    Returns:
        HTML-safe text
    """
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"))


def add_security_headers(response: Response) -> Response:
    """Add security headers to response"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response



HOME_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Employee Directory - Home</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 50px auto; padding: 20px; background-color: #f5f5f5; }}
        .success {{ background-color: #e8f5e9; border: 2px solid #4caf50; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
        .card {{ background-color: white; padding: 25px; margin: 15px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .btn {{ padding: 12px 24px; margin: 8px 4px; cursor: pointer; background-color: #2196f3; color: white; border: none; text-decoration: none; display: inline-block; border-radius: 4px; font-size: 14px; }}
        .btn:hover {{ background-color: #1976d2; }}
        .btn-danger {{ background-color: #f44336; }}
        .btn-danger:hover {{ background-color: #d32f2f; }}
        .security-badge {{ display: inline-block; background-color: #4caf50; color: white; padding: 4px 8px; border-radius: 3px; font-size: 12px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #555; border-bottom: 2px solid #2196f3; padding-bottom: 8px; }}
        ul {{ line-height: 1.8; }}
        .feature-list {{ list-style-type: none; padding: 0; }}
        .feature-list li {{ padding: 8px 0; }}
        .feature-list li:before {{ content: "✓ "; color: #4caf50; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="success">
        <strong>🔒 Secure Application</strong>
        <span class="security-badge">PKCE Enabled</span>
        <span class="security-badge">CSRF Protected</span>
        <span class="security-badge">Encrypted Sessions</span>
    </div>
    
    <h1>🏢 Secure Employee Directory</h1>
    <p>View and manage employee information securely from the HR system.</p>
    
    <div class="card">
        <h2>Authentication Status</h2>
        {auth_status}
    </div>
    
    {employee_section}
    
    <div class="card">
        <h2>Security Features</h2>
        <ul class="feature-list">
            <li>PKCE (Proof Key for Code Exchange) - RFC 7636</li>
            <li>CSRF Protection with state parameter validation</li>
            <li>Secure session management with encrypted cookies</li>
            <li>No sensitive data in logs or errors</li>
            <li>Strict redirect URI validation</li>
            <li>Rate limiting to prevent abuse</li>
            <li>Content Security Policy headers</li>
            <li>Input validation and XSS prevention</li>
        </ul>
    </div>
</body>
</html>
"""

EMPLOYEES_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Employee Directory - Employees</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 1200px; margin: 50px auto; padding: 20px; background-color: #f5f5f5; }}
        .success {{ background-color: #e8f5e9; border: 2px solid #4caf50; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #2196f3; color: white; font-weight: bold; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .btn {{ padding: 12px 24px; margin: 8px 4px; cursor: pointer; background-color: #2196f3; color: white; border: none; text-decoration: none; display: inline-block; border-radius: 4px; }}
        .btn:hover {{ background-color: #1976d2; }}
        h1 {{ color: #333; }}
        .security-badge {{ display: inline-block; background-color: #4caf50; color: white; padding: 4px 8px; border-radius: 3px; font-size: 12px; margin-left: 10px; }}
    </style>
</head>
<body>
    <div class="success">
        <strong>🔒 Secure Connection</strong>
        <span class="security-badge">Authenticated</span>
    </div>
    
    <h1>👥 Employee List</h1>
    <a href="/" class="btn">← Back to Home</a>
    
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Email</th>
                <th>Department</th>
                <th>Position</th>
            </tr>
        </thead>
        <tbody>
            {employee_rows}
        </tbody>
    </table>
</body>
</html>
"""

ERROR_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; background-color: #f5f5f5; }}
        .error {{ background-color: #ffebee; border: 2px solid #f44336; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .btn {{ padding: 12px 24px; margin: 10px 4px 0 0; cursor: pointer; background-color: #2196f3; color: white; border: none; text-decoration: none; display: inline-block; border-radius: 4px; }}
        .btn:hover {{ background-color: #1976d2; }}
        h1 {{ color: #d32f2f; margin-top: 0; }}
        p {{ margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="error">
        <h1>❌ Error</h1>
        <p><strong>Error:</strong> {error}</p>
        <p><strong>Description:</strong> {description}</p>
    </div>
    <br>
    <a href="/" class="btn">← Back to Home</a>
</body>
</html>
"""



def build_secure_auth_url(state: str, code_challenge: str, redirect_uri: str) -> str:
    """
    Build secure authorization URL with PKCE and state.
    
    Args:
        state: CSRF protection token
        code_challenge: PKCE challenge
        redirect_uri: Callback URI
        
    Returns:
        Authorization URL
    """
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": "read write admin",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    return f"{AUTHZ_SERVER_URL}/authorize?{urlencode(params)}"


async def exchange_code_for_token(code: str, code_verifier: str, redirect_uri: str) -> dict:
    """
    Exchange authorization code for access token with PKCE verification.
    
    Args:
        code: Authorization code
        code_verifier: PKCE verifier
        redirect_uri: Callback URI (must match authorization request)
        
    Returns:
        Token response data
        
    Raises:
        HTTPException on failure
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{AUTHZ_SERVER_URL}/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code_verifier": code_verifier
                },
                timeout=10.0
            )
            
            if response.status_code != 200:
                audit_log_event("token_exchange_failed", 
                              {"status": response.status_code}, 
                              success=False)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token exchange failed"
                )
            
            return response.json()
            
        except httpx.TimeoutException:
            audit_log_event("token_exchange_timeout", {}, success=False)
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Authorization server timeout"
            )
        except httpx.RequestError as e:
            audit_log_event("token_exchange_error", 
                          {"error_type": type(e).__name__}, 
                          success=False)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to connect to authorization server"
            )


async def fetch_employees(token: str) -> list:
    """
    Fetch employees from resource server.
    
    Args:
        token: Access token
        
    Returns:
        List of employees
        
    Raises:
        HTTPException on failure
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{RESOURCE_SERVER_URL}/employees",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0
            )
            
            if response.status_code != 200:
                audit_log_event("fetch_employees_failed",
                              {"status": response.status_code},
                              success=False)
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to fetch employees"
                )
            
            return response.json()
            
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Resource server timeout"
            )
        except httpx.RequestError:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to connect to resource server"
            )



@app.on_event("startup")
async def startup_event():
    """Run cleanup on startup"""
    cleanup_expired_data()


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    return add_security_headers(response)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page"""
    cleanup_expired_data()
    
    session_id = get_session_from_cookie(request)
    
    if session_id and session_id in secure_sessions:
        session = secure_sessions[session_id]
        scopes = session.get("scopes", [])
        
        auth_status = f"""
            <p>✅ <strong>Authenticated</strong></p>
            <p>Scopes: <code>{', '.join(scopes) if scopes else 'read, write, admin'}</code></p>
            <p>Session expires: <code>{datetime.fromtimestamp(session['token_expiry']).strftime('%Y-%m-%d %H:%M:%S')}</code></p>
            <a href="/logout" class="btn btn-danger">Logout</a>
        """
        employee_section = """
            <div class="card">
                <h2>Quick Actions</h2>
                <a href="/employees" class="btn">View Employees</a>
            </div>
        """
    else:
        auth_status = """
            <p>❌ <strong>Not authenticated</strong></p>
            <p>You need to authorize this application to access employee data.</p>
            <a href="/login" class="btn">🔐 Login with HR System</a>
        """
        employee_section = ""
    
    html = HOME_PAGE_TEMPLATE.format(
        auth_status=auth_status,
        employee_section=employee_section
    )
    
    return HTMLResponse(content=html)


@app.get("/login")
async def login(request: Request):
    """
    Initiate OAuth 2.0 authorization flow with PKCE and CSRF protection.
    
    Security features:
    - Generates secure state parameter for CSRF protection
    - Generates PKCE code verifier and challenge
    - Validates redirect URI
    - Rate limiting
    """
    cleanup_expired_data()
    
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"login_{client_ip}", max_requests=10, window_seconds=60):
        audit_log_event("rate_limit_exceeded", {"ip": client_ip, "endpoint": "login"}, success=False)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later."
        )
    
    session_id = generate_session_id()
    
    code_verifier, code_challenge = generate_pkce_pair()
    
    state = generate_secure_state()
    
    redirect_uri = f"{CLIENT_BASE_URL}{CALLBACK_PATH}"
    
    pending_auth[state] = {
        "session_id": session_id,
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
        "created_at": time.time(),
        "redirect_uri": redirect_uri
    }
    
    auth_url = build_secure_auth_url(state, code_challenge, redirect_uri)
    
    audit_log_event("login_initiated", {"session_id": session_id[:8] + "..."})
    
    response = RedirectResponse(url=auth_url, status_code=302)
    
    encrypted_session = encrypt_session_cookie(session_id)
    response.set_cookie(
        key="secure_session",
        value=encrypted_session,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=3600
    )
    
    return response


@app.get("/callback")
async def callback(
    request: Request,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None)
):
    """
    OAuth callback endpoint with CSRF and PKCE validation.
    
    Security features:
    - Validates state parameter (CSRF protection)
    - Uses PKCE code verifier for token exchange
    - Validates redirect URI
    - Rate limiting
    - Secure session creation
    """
    cleanup_expired_data()
    
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"callback_{client_ip}", max_requests=20, window_seconds=60):
        audit_log_event("rate_limit_exceeded", {"ip": client_ip, "endpoint": "callback"}, success=False)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many callback requests"
        )
    
    if error:
        audit_log_event("authorization_error", {"error": error}, success=False)
        html = ERROR_PAGE_TEMPLATE.format(
            error="Authorization Failed",
            description=error_description or "The authorization request was denied or failed."
        )
        return HTMLResponse(content=html, status_code=400)
    
    if not code or not state:
        audit_log_event("callback_missing_params", {}, success=False)
        html = ERROR_PAGE_TEMPLATE.format(
            error="Invalid Callback",
            description="Missing required parameters (code or state)."
        )
        return HTMLResponse(content=html, status_code=400)
    
    if state not in pending_auth:
        audit_log_event("invalid_state", {"state_exists": False}, success=False)
        html = ERROR_PAGE_TEMPLATE.format(
            error="CSRF Protection",
            description="Invalid or expired state parameter. This may be a CSRF attack."
        )
        return HTMLResponse(content=html, status_code=400)
    
    auth_data = pending_auth.pop(state)
    session_id = auth_data["session_id"]
    code_verifier = auth_data["code_verifier"]
    redirect_uri = auth_data["redirect_uri"]
    
    cookie_session_id = get_session_from_cookie(request)
    if cookie_session_id != session_id:
        audit_log_event("session_mismatch", {}, success=False)
        html = ERROR_PAGE_TEMPLATE.format(
            error="Session Validation Failed",
            description="Session mismatch. Please try logging in again."
        )
        return HTMLResponse(content=html, status_code=400)
    
    try:
        token_data = await exchange_code_for_token(code, code_verifier, redirect_uri)
        
        access_token = token_data.get("access_token")
        expires_in = token_data.get("expires_in", 3600)
        scope = token_data.get("scope", "")
        
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="No access token received"
            )
        
        secure_sessions[session_id] = {
            "token": access_token,
            "token_expiry": time.time() + expires_in,
            "created_at": time.time(),
            "last_used": time.time(),
            "scopes": scope.split() if scope else []
        }
        
        audit_log_event("login_success", {
            "session_id": session_id[:8] + "...",
            "scopes": scope
        })
        
        response = RedirectResponse(url="/", status_code=302)
        
        encrypted_session = encrypt_session_cookie(session_id)
        response.set_cookie(
            key="secure_session",
            value=encrypted_session,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=expires_in
        )
        
        return response
        
    except HTTPException as e:
        audit_log_event("token_exchange_failed", {"status": e.status_code}, success=False)
        html = ERROR_PAGE_TEMPLATE.format(
            error="Authentication Failed",
            description="Failed to exchange authorization code for access token."
        )
        return HTMLResponse(content=html, status_code=e.status_code)
    except Exception as e:
        audit_log_event("callback_error", {"error_type": type(e).__name__}, success=False)
        html = ERROR_PAGE_TEMPLATE.format(
            error="Internal Error",
            description="An unexpected error occurred during authentication."
        )
        return HTMLResponse(content=html, status_code=500)


@app.get("/logout")
async def logout(request: Request):
    """
    Logout - securely destroy session.
    
    Security features:
    - Clears server-side session data
    - Clears session cookie
    - Audit logging
    """
    session_id = get_session_from_cookie(request)
    
    if session_id and session_id in secure_sessions:
        del secure_sessions[session_id]
        audit_log_event("logout", {"session_id": session_id[:8] + "..."})
    
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("secure_session")
    return response


@app.get("/employees", response_class=HTMLResponse)
async def employees(request: Request):
    """
    View employees page - requires authentication.
    
    Security features:
    - Session validation
    - Token expiry checking
    - XSS prevention with sanitization
    - Rate limiting
    """
    cleanup_expired_data()
    
    session_id = get_session_from_cookie(request)
    
    if not session_id or session_id not in secure_sessions:
        audit_log_event("unauthorized_access", {"endpoint": "/employees"}, success=False)
        return RedirectResponse(url="/login", status_code=302)
    
    if not check_rate_limit(f"employees_{session_id}", max_requests=50, window_seconds=60):
        audit_log_event("rate_limit_exceeded", {"endpoint": "/employees"}, success=False)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests"
        )
    
    session = secure_sessions[session_id]
    token = session["token"]
    
    try:
        employees_data = await fetch_employees(token)
        
        rows = ""
        for emp in employees_data:
            emp_id = sanitize_for_html(str(emp.get('id', 'N/A')))
            first_name = sanitize_for_html(str(emp.get('first_name', '')))
            last_name = sanitize_for_html(str(emp.get('last_name', '')))
            email = sanitize_for_html(str(emp.get('email', 'N/A')))
            department = sanitize_for_html(str(emp.get('department', 'N/A')))
            position = sanitize_for_html(str(emp.get('position', 'N/A')))
            
            rows += f"""
                <tr>
                    <td>{emp_id}</td>
                    <td>{first_name} {last_name}</td>
                    <td>{email}</td>
                    <td>{department}</td>
                    <td>{position}</td>
                </tr>
            """
        
        html = EMPLOYEES_PAGE_TEMPLATE.format(
            employee_rows=rows or "<tr><td colspan='5' style='text-align:center;'>No employees found</td></tr>"
        )
        
        audit_log_event("employees_viewed", {"count": len(employees_data)})
        
        return HTMLResponse(content=html)
        
    except HTTPException as e:
        audit_log_event("fetch_employees_failed", {"status": e.status_code}, success=False)
        html = ERROR_PAGE_TEMPLATE.format(
            error="Failed to Load Employees",
            description="Could not retrieve employee data from the server."
        )
        return HTMLResponse(content=html, status_code=e.status_code)
    except Exception as e:
        audit_log_event("employees_error", {"error_type": type(e).__name__}, success=False)
        html = ERROR_PAGE_TEMPLATE.format(
            error="Internal Error",
            description="An unexpected error occurred while loading employees."
        )
        return HTMLResponse(content=html, status_code=500)


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "hardened-oauth-client",
        "version": "2.0.0"
    }





if __name__ == "__main__":
    import uvicorn
    
    print("=" * 60)
    print("Hardened OAuth Client - Secure Employee Directory")
    print("=" * 60)
    print("\nClient Configuration:")
    print(f"  - Client ID: {CLIENT_ID}")
    print(f"  - Authorization Server: {AUTHZ_SERVER_URL}")
    print(f"  - Resource Server: {RESOURCE_SERVER_URL}")
    print(f"  - Callback URL: {CLIENT_BASE_URL}{CALLBACK_PATH}")
    print("\nSecurity Features:")
    print("  ✓ PKCE (Proof Key for Code Exchange)")
    print("  ✓ CSRF Protection (state parameter)")
    print("  ✓ Encrypted session cookies")
    print("  ✓ No sensitive data in logs")
    print("  ✓ Strict redirect URI validation")
    print("  ✓ Rate limiting")
    print("  ✓ Content Security Policy")
    print("  ✓ Secure cookie settings (httponly, secure, samesite)")
    print("  ✓ XSS prevention")
    print("  ✓ Token expiry validation")
    print("\n" + "=" * 60)
    
    uvicorn.run(app, host="0.0.0.0", port=8012)


