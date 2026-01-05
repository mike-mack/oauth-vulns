"""
Vulnerable OAuth Client - Employee Directory App
WARNING: This is intentionally vulnerable for educational purposes.
DO NOT use in production!

Vulnerabilities included:
- No CSRF protection
- Open redirects
- Unsanitized user content upload
- Tokens and codes logged everywhere
- No state parameter validation
- No PKCE
- Stores tokens insecurely
- XSS vulnerabilities
"""

import os
import logging
import secrets
import httpx
from typing import Optional
from urllib.parse import urlencode, quote
from pathlib import Path

from fastapi import FastAPI, Request, Form, Query, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Configure logging to leak sensitive data (vulnerable!)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Employee Directory Client (Vulnerable)",
    description="A deliberately vulnerable OAuth client for learning purposes",
    version="1.0.0"
)

# Configuration
CLIENT_ID = "oauth-client-1"
CLIENT_SECRET = "oauth-client-secret-1"
AUTHZ_SERVER_URL = "http://localhost:8001"
RESOURCE_SERVER_URL = "http://localhost:8000"
CLIENT_BASE_URL = "http://localhost:8002"
CALLBACK_PATH = "/callback"

# User content directory - will store uploaded files without sanitization
USERCONTENT_DIR = os.path.join(os.path.dirname(__file__), "usercontent")
os.makedirs(USERCONTENT_DIR, exist_ok=True)

# In-memory token storage (vulnerable - no encryption, no session binding)
# In a real attack scenario, this could be exploited
token_storage = {}


# ========================
# Models
# ========================

class TokenData(BaseModel):
    access_token: str
    token_type: str
    scope: str


# ========================
# HTML Templates
# ========================

HOME_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Employee Directory - Home</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 50px auto; padding: 20px; }}
        .warning {{ background-color: #ffebee; border: 1px solid #f44336; padding: 10px; margin-bottom: 20px; }}
        .card {{ background-color: #f5f5f5; padding: 20px; margin: 10px 0; border-radius: 5px; }}
        button, .btn {{ padding: 10px 20px; margin: 5px; cursor: pointer; background-color: #2196f3; color: white; border: none; text-decoration: none; display: inline-block; }}
        .btn-danger {{ background-color: #f44336; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background-color: #2196f3; color: white; }}
        .debug {{ background-color: #fff3e0; border: 1px solid #ff9800; padding: 10px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="warning">
        <strong>⚠️ WARNING:</strong> This is a VULNERABLE OAuth client for educational purposes only!
    </div>
    
    <h1>🏢 Employee Directory</h1>
    <p>View and manage employee information from the HR system.</p>
    
    <div class="card">
        <h2>Authentication Status</h2>
        {auth_status}
    </div>
    
    {employee_section}
    
    <div class="card">
        <h2>Features</h2>
        <ul>
            <li><a href="/employees">View Employees</a> (requires authorization)</li>
            <li><a href="/upload">Upload Content</a> (no sanitization!)</li>
            <li><a href="/redirect?url=https://example.com">Test Redirect</a> (open redirect!)</li>
        </ul>
    </div>
    
    <div class="debug">
        <strong>Debug Info (should not be visible!):</strong>
        <pre>
Session ID: {session_id}
Token: {token}
Client ID: {client_id}
Auth Server: {auth_server}
        </pre>
    </div>
</body>
</html>
"""

EMPLOYEES_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Employee Directory - Employees</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 50px auto; padding: 20px; }}
        .warning {{ background-color: #ffebee; border: 1px solid #f44336; padding: 10px; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background-color: #2196f3; color: white; }}
        .btn {{ padding: 10px 20px; margin: 5px; cursor: pointer; background-color: #2196f3; color: white; border: none; text-decoration: none; }}
        .debug {{ background-color: #fff3e0; border: 1px solid #ff9800; padding: 10px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="warning">
        <strong>⚠️ WARNING:</strong> This is a VULNERABLE OAuth client!
    </div>
    
    <h1>👥 Employee List</h1>
    <a href="/" class="btn">← Back to Home</a>
    
    <table>
        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Email</th>
            <th>Department</th>
            <th>Position</th>
        </tr>
        {employee_rows}
    </table>
    
    <div class="debug">
        <strong>Debug - Token Used:</strong>
        <pre>{token}</pre>
    </div>
</body>
</html>
"""

UPLOAD_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Upload Content</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .warning {{ background-color: #ffebee; border: 1px solid #f44336; padding: 10px; margin-bottom: 20px; }}
        .card {{ background-color: #f5f5f5; padding: 20px; margin: 10px 0; border-radius: 5px; }}
        input, textarea {{ width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }}
        button {{ padding: 10px 20px; background-color: #2196f3; color: white; border: none; cursor: pointer; }}
        .btn {{ padding: 10px 20px; margin: 5px; background-color: #2196f3; color: white; border: none; text-decoration: none; display: inline-block; }}
    </style>
</head>
<body>
    <div class="warning">
        <strong>⚠️ WARNING:</strong> This upload has NO SANITIZATION! Files are served as-is.
    </div>
    
    <h1>📤 Upload Content</h1>
    <a href="/" class="btn">← Back to Home</a>
    
    <div class="card">
        <h2>Upload a File</h2>
        <form method="POST" action="/upload" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <br>
            <label>Custom filename (optional):</label>
            <input type="text" name="filename" placeholder="Leave empty to use original name">
            <br>
            <button type="submit">Upload</button>
        </form>
    </div>
    
    <div class="card">
        <h2>Create HTML Content</h2>
        <form method="POST" action="/upload/html">
            <label>Filename:</label>
            <input type="text" name="filename" placeholder="example.html" required>
            <br>
            <label>HTML Content (no sanitization!):</label>
            <textarea name="content" rows="10" placeholder="<html>...</html>"></textarea>
            <br>
            <button type="submit">Create</button>
        </form>
    </div>
    
    <div class="card">
        <h2>Uploaded Files</h2>
        <ul>
            {file_list}
        </ul>
    </div>
</body>
</html>
"""

LOGIN_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login Required</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .warning {{ background-color: #ffebee; border: 1px solid #f44336; padding: 10px; margin-bottom: 20px; }}
        .card {{ background-color: #f5f5f5; padding: 20px; margin: 10px 0; border-radius: 5px; text-align: center; }}
        .btn {{ padding: 15px 30px; background-color: #4caf50; color: white; border: none; text-decoration: none; font-size: 18px; display: inline-block; }}
    </style>
</head>
<body>
    <div class="warning">
        <strong>⚠️ WARNING:</strong> This OAuth flow has NO CSRF protection!
    </div>
    
    <h1>🔐 Authorization Required</h1>
    
    <div class="card">
        <p>To access employee data, you need to authorize this application.</p>
        <p>Click below to login via the HR OAuth system:</p>
        <br>
        <a href="{auth_url}" class="btn">Authorize with HR System</a>
        <br><br>
        <small>You will be redirected to: {auth_url}</small>
    </div>
    
    <!-- VULNERABLE: Showing the full auth URL with all params -->
    <div style="margin-top: 20px; padding: 10px; background-color: #fff3e0; border: 1px solid #ff9800;">
        <strong>Debug (OAuth URL):</strong>
        <pre style="word-wrap: break-word;">{auth_url}</pre>
    </div>
</body>
</html>
"""

ERROR_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .error {{ background-color: #ffebee; border: 1px solid #f44336; padding: 20px; }}
        .btn {{ padding: 10px 20px; background-color: #2196f3; color: white; border: none; text-decoration: none; }}
    </style>
</head>
<body>
    <div class="error">
        <h1>❌ Error</h1>
        <p><strong>Error:</strong> {error}</p>
        <p><strong>Description:</strong> {description}</p>
        <!-- VULNERABLE: Leaking sensitive info in error page -->
        <p><strong>Code:</strong> {code}</p>
        <p><strong>Token:</strong> {token}</p>
        <p><strong>Session:</strong> {session}</p>
    </div>
    <br>
    <a href="/" class="btn">← Back to Home</a>
</body>
</html>
"""


# ========================
# Helper Functions
# ========================

def get_session_id(request: Request) -> str:
    """Get or create a session ID (vulnerable - no secure session management)"""
    session_id = request.cookies.get("session_id")
    if not session_id:
        session_id = secrets.token_urlsafe(16)
        logger.info(f"Created new session: {session_id}")  # Logging session IDs!
    return session_id


def get_stored_token(session_id: str) -> Optional[str]:
    """Get stored token for session (vulnerable - in-memory, no encryption)"""
    token = token_storage.get(session_id)
    logger.debug(f"Retrieved token for session {session_id}: {token}")  # Logging tokens!
    return token


def store_token(session_id: str, token: str):
    """Store token for session (vulnerable - in-memory, no encryption)"""
    token_storage[session_id] = token
    logger.info(f"Stored token for session {session_id}: {token}")  # Logging tokens!


def build_auth_url(session_id: str, redirect_uri: Optional[str] = None) -> str:
    """
    Build the authorization URL.
    
    VULNERABILITIES:
    - No state parameter for CSRF protection
    - No PKCE
    - Redirect URI can be manipulated
    """
    callback_uri = redirect_uri or f"{CLIENT_BASE_URL}{CALLBACK_PATH}"
    
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": callback_uri,
        "scope": "read,write,delete",
        # VULNERABLE: No state parameter! CSRF attacks possible
        # VULNERABLE: No PKCE (code_challenge)!
    }
    
    auth_url = f"{AUTHZ_SERVER_URL}/authorize?{urlencode(params)}"
    logger.info(f"Built auth URL: {auth_url}")  # Logging full auth URL
    
    return auth_url


async def fetch_employees(token: str) -> list:
    """Fetch employees from resource server"""
    logger.info(f"Fetching employees with token: {token}")  # Logging token!
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{RESOURCE_SERVER_URL}/employees",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch employees: {response.text}, token: {token}")
            raise HTTPException(status_code=response.status_code, detail=response.text)
        
        return response.json()


async def exchange_code_for_token(code: str, redirect_uri: str) -> str:
    """
    Exchange authorization code for access token.
    
    VULNERABILITIES:
    - No PKCE verification
    - Code logged
    - Token logged
    """
    logger.info(f"Exchanging code for token: code={code}, redirect_uri={redirect_uri}")
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{AUTHZ_SERVER_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,  # Logging secret in debug!
            }
        )
        
        logger.debug(f"Token response: {response.text}")  # Logging full response with token!
        
        if response.status_code != 200:
            logger.error(f"Token exchange failed: {response.text}, code: {code}")
            raise HTTPException(status_code=response.status_code, detail=response.text)
        
        data = response.json()
        token = data.get("access_token")
        logger.info(f"Received access token: {token}")  # Logging token!
        
        return token


# ========================
# API Endpoints
# ========================

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page"""
    session_id = get_session_id(request)
    token = get_stored_token(session_id)
    
    if token:
        auth_status = f"""
            <p>✅ Authorized</p>
            <p>Token: <code>{token[:20]}...</code></p>
            <a href="/logout" class="btn btn-danger">Logout</a>
        """
        employee_section = """
            <div class="card">
                <h2>Quick Actions</h2>
                <a href="/employees" class="btn">View Employees</a>
            </div>
        """
    else:
        auth_url = build_auth_url(session_id)
        auth_status = f"""
            <p>❌ Not authorized</p>
            <a href="{auth_url}" class="btn">Login with HR System</a>
        """
        employee_section = ""
    
    html = HOME_PAGE_TEMPLATE.format(
        auth_status=auth_status,
        employee_section=employee_section,
        session_id=session_id,
        token=token or "None",
        client_id=CLIENT_ID,
        auth_server=AUTHZ_SERVER_URL
    )
    
    response = HTMLResponse(content=html)
    response.set_cookie("session_id", session_id, httponly=False, secure=False, samesite="none")  # Vulnerable cookie settings!
    return response


@app.get("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    redirect_uri: Optional[str] = Query(None, description="Custom redirect URI (vulnerable!)")
):
    """
    Login page - initiates OAuth flow.
    
    VULNERABILITIES:
    - Accepts custom redirect_uri from query param
    - No CSRF protection
    - No state parameter
    """
    session_id = get_session_id(request)
    
    # VULNERABLE: Allow custom redirect URI from query param!
    auth_url = build_auth_url(session_id, redirect_uri)
    
    logger.info(f"Login initiated for session {session_id}, redirect_uri: {redirect_uri}")
    
    html = LOGIN_PAGE_TEMPLATE.format(auth_url=auth_url)
    
    response = HTMLResponse(content=html)
    response.set_cookie("session_id", session_id, httponly=False, secure=False, samesite="none")
    return response


@app.get("/callback")
async def callback(
    request: Request,
    code: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
    state: Optional[str] = Query(None)  # Ignored! No CSRF protection
):
    """
    OAuth callback endpoint.
    
    VULNERABILITIES:
    - State parameter ignored (no CSRF validation)
    - Code logged in errors
    - No PKCE verification
    """
    session_id = get_session_id(request)
    
    # Log everything including the code (vulnerable!)
    logger.info(f"Callback received: code={code}, error={error}, state={state}, session={session_id}")
    
    if error:
        # VULNERABLE: Including sensitive info in error page
        html = ERROR_PAGE_TEMPLATE.format(
            error=error,
            description=error_description or "Unknown error",
            code=code or "N/A",
            token="N/A",
            session=session_id
        )
        return HTMLResponse(content=html, status_code=400)
    
    if not code:
        html = ERROR_PAGE_TEMPLATE.format(
            error="missing_code",
            description="No authorization code received",
            code="N/A",
            token="N/A",
            session=session_id
        )
        return HTMLResponse(content=html, status_code=400)
    
    # VULNERABLE: No state validation - CSRF attacks possible!
    # We should verify: state == stored_state_for_session
    # But we don't!
    
    try:
        # Exchange code for token
        redirect_uri = f"{CLIENT_BASE_URL}{CALLBACK_PATH}"
        token = await exchange_code_for_token(code, redirect_uri)
        
        # Store token (insecurely)
        store_token(session_id, token)
        
        logger.info(f"Successfully obtained token for session {session_id}: {token}")
        
        # Redirect to home
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie("session_id", session_id, httponly=False, secure=False, samesite="none")
        return response
        
    except Exception as e:
        logger.error(f"Token exchange failed: {str(e)}, code: {code}")
        html = ERROR_PAGE_TEMPLATE.format(
            error="token_exchange_failed",
            description=str(e),
            code=code,  # VULNERABLE: Showing code in error!
            token="N/A",
            session=session_id
        )
        return HTMLResponse(content=html, status_code=500)


@app.get("/logout")
async def logout(request: Request):
    """Logout - clear stored token"""
    session_id = get_session_id(request)
    
    if session_id in token_storage:
        old_token = token_storage.pop(session_id)
        logger.info(f"Logged out session {session_id}, cleared token: {old_token}")  # Logging old token!
    
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("session_id")
    return response


@app.get("/employees", response_class=HTMLResponse)
async def employees(request: Request):
    """View employees page"""
    session_id = get_session_id(request)
    token = get_stored_token(session_id)
    
    if not token:
        return RedirectResponse(url="/login", status_code=302)
    
    try:
        employees_data = await fetch_employees(token)
        
        rows = ""
        for emp in employees_data:
            # VULNERABLE: No XSS protection - data rendered directly
            rows += f"""
                <tr>
                    <td>{emp.get('id', 'N/A')}</td>
                    <td>{emp.get('first_name', '')} {emp.get('last_name', '')}</td>
                    <td>{emp.get('email', 'N/A')}</td>
                    <td>{emp.get('department', 'N/A')}</td>
                    <td>{emp.get('position', 'N/A')}</td>
                </tr>
            """
        
        html = EMPLOYEES_PAGE_TEMPLATE.format(
            employee_rows=rows or "<tr><td colspan='5'>No employees found</td></tr>",
            token=token  # VULNERABLE: Showing full token!
        )
        
        response = HTMLResponse(content=html)
        response.set_cookie("session_id", session_id, httponly=False, secure=False, samesite="none")
        return response
        
    except Exception as e:
        logger.error(f"Failed to fetch employees: {str(e)}, token: {token}")
        html = ERROR_PAGE_TEMPLATE.format(
            error="fetch_failed",
            description=str(e),
            code="N/A",
            token=token,  # VULNERABLE: Showing token in error!
            session=session_id
        )
        return HTMLResponse(content=html, status_code=500)


# ========================
# Open Redirect (Vulnerable!)
# ========================

@app.get("/redirect")
async def open_redirect(
    url: str = Query(..., description="URL to redirect to"),
    token: Optional[str] = Query(None, description="Optional token to append")
):
    """
    VULNERABLE: Open redirect endpoint.
    
    Allows redirecting to ANY URL, including:
    - Attacker-controlled domains
    - Can be used for phishing
    - Can leak tokens via query params
    """
    logger.info(f"Open redirect to: {url}, token: {token}")
    
    # VULNERABLE: No validation of target URL!
    redirect_url = url
    if token:
        # VULNERABLE: Appending token to redirect URL (token leakage!)
        redirect_url = f"{url}?token={token}"
    
    return RedirectResponse(url=redirect_url, status_code=302)


@app.get("/goto")
async def goto(
    next: str = Query(..., description="Next URL"),
    request: Request = None
):
    """Another open redirect endpoint"""
    session_id = get_session_id(request) if request else "unknown"
    token = get_stored_token(session_id) if request else None
    
    logger.info(f"Goto redirect: next={next}, session={session_id}, token={token}")
    
    # VULNERABLE: Completely open redirect
    return RedirectResponse(url=next, status_code=302)


# ========================
# User Content Upload (Vulnerable!)
# ========================

@app.get("/upload", response_class=HTMLResponse)
async def upload_page():
    """Upload page"""
    # List existing files
    files = []
    if os.path.exists(USERCONTENT_DIR):
        for filename in os.listdir(USERCONTENT_DIR):
            files.append(f'<li><a href="/usercontent/{filename}">{filename}</a></li>')
    
    file_list = "".join(files) if files else "<li>No files uploaded yet</li>"
    
    html = UPLOAD_PAGE_TEMPLATE.format(file_list=file_list)
    return HTMLResponse(content=html)


@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    filename: Optional[str] = Form(None)
):
    """
    VULNERABLE: File upload with NO sanitization.
    
    Issues:
    - No file type validation
    - No content sanitization
    - Path traversal possible
    - Malicious HTML/JS can be uploaded
    """
    # Use custom filename or original (VULNERABLE: no sanitization!)
    save_filename = filename if filename else file.filename
    
    # VULNERABLE: No path traversal protection!
    # An attacker could use filename like "../../../etc/passwd"
    file_path = os.path.join(USERCONTENT_DIR, save_filename)
    
    logger.info(f"Uploading file: {save_filename} to {file_path}")
    
    # Save file without any validation
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    
    return JSONResponse(content={
        "message": "File uploaded successfully",
        "filename": save_filename,
        "path": f"/usercontent/{save_filename}",
        "size": len(content),
        "warning": "No sanitization was performed!"
    })


@app.post("/upload/html")
async def upload_html(
    filename: str = Form(...),
    content: str = Form(...)
):
    """
    VULNERABLE: Create HTML file with NO sanitization.
    
    This allows storing arbitrary HTML/JS that will be served as-is,
    enabling XSS attacks, credential theft, etc.
    """
    # VULNERABLE: No sanitization of filename or content!
    file_path = os.path.join(USERCONTENT_DIR, filename)
    
    logger.info(f"Creating HTML file: {filename}")
    logger.debug(f"Content: {content[:100]}...")  # Logging content!
    
    with open(file_path, "w") as f:
        f.write(content)
    
    return JSONResponse(content={
        "message": "HTML file created successfully",
        "filename": filename,
        "path": f"/usercontent/{filename}",
        "warning": "Content was NOT sanitized! XSS is possible!"
    })


@app.get("/usercontent/{filepath:path}", response_class=HTMLResponse)
async def serve_user_content(filepath: str):
    """
    VULNERABLE: Serve user-uploaded content WITHOUT sanitization.
    
    Files are served with their original content-type based on extension,
    allowing malicious HTML/JS to execute in browser.
    """
    file_path = os.path.join(USERCONTENT_DIR, filepath)
    
    logger.info(f"Serving user content: {filepath}")
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"File not found: {filepath}")
    
    # VULNERABLE: Serve file as-is without sanitization
    with open(file_path, "r", errors="ignore") as f:
        content = f.read()
    
    # Determine content type (vulnerable - trusts file extension)
    if filepath.endswith(".html") or filepath.endswith(".htm"):
        return HTMLResponse(content=content)
    elif filepath.endswith(".js"):
        return HTMLResponse(content=content, media_type="application/javascript")
    elif filepath.endswith(".css"):
        return HTMLResponse(content=content, media_type="text/css")
    else:
        return HTMLResponse(content=content, media_type="text/plain")


# ========================
# Debug Endpoints (Extra Vulnerable!)
# ========================

@app.get("/debug/sessions")
async def debug_sessions():
    """
    VULNERABLE: Exposes all sessions and tokens!
    """
    return {
        "warning": "This endpoint exposes all sessions and tokens!",
        "sessions": {
            session_id: {
                "token": token,
                "token_preview": token[:20] + "..." if token else None
            }
            for session_id, token in token_storage.items()
        }
    }


@app.get("/debug/config")
async def debug_config():
    """
    VULNERABLE: Exposes all configuration including secrets!
    """
    return {
        "warning": "This endpoint exposes sensitive configuration!",
        "config": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,  # Should NEVER expose!
            "auth_server": AUTHZ_SERVER_URL,
            "resource_server": RESOURCE_SERVER_URL,
            "callback_url": f"{CLIENT_BASE_URL}{CALLBACK_PATH}"
        }
    }


@app.get("/debug/steal-token")
async def steal_token(request: Request, exfil_url: Optional[str] = Query(None)):
    """
    VULNERABLE: Demonstration of token theft.
    
    This shows how an attacker could steal a token by:
    1. Getting victim to visit this URL
    2. Token is extracted from session
    3. Token could be exfiltrated to attacker's server
    """
    session_id = get_session_id(request)
    token = get_stored_token(session_id)
    
    logger.warning(f"Token theft demonstration! Session: {session_id}, Token: {token}")
    
    if exfil_url and token:
        # In a real attack, this would send the token to an attacker's server
        logger.critical(f"SIMULATED EXFIL: Would send token {token} to {exfil_url}")
    
    return {
        "warning": "This demonstrates token theft!",
        "session_id": session_id,
        "stolen_token": token,
        "exfil_url": exfil_url
    }


# ========================
# Run Server
# ========================

if __name__ == "__main__":
    import uvicorn
    
    print("=" * 60)
    print("WARNING: This is a VULNERABLE OAuth Client!")
    print("For educational purposes only. DO NOT use in production!")
    print("=" * 60)
    print("\nClient Configuration:")
    print(f"  - Client ID: {CLIENT_ID}")
    print(f"  - Client Secret: {CLIENT_SECRET}")
    print(f"  - Authorization Server: {AUTHZ_SERVER_URL}")
    print(f"  - Resource Server: {RESOURCE_SERVER_URL}")
    print(f"  - Callback URL: {CLIENT_BASE_URL}{CALLBACK_PATH}")
    print("\nVulnerabilities:")
    print("  - No CSRF protection (no state parameter)")
    print("  - No PKCE")
    print("  - Open redirects at /redirect and /goto")
    print("  - Unsanitized file uploads at /upload")
    print("  - XSS via /usercontent/*")
    print("  - Tokens logged everywhere")
    print("  - Insecure cookie settings")
    print("  - Debug endpoints expose secrets")
    print("\n" + "=" * 60)
    
    uvicorn.run(app, host="0.0.0.0", port=8002)
