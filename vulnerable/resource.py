"""
Vulnerable OAuth Resource Server - HR Application
WARNING: This is intentionally vulnerable for educational purposes.
DO NOT use in production!

Vulnerabilities included:
- Accepts tokens from multiple sources (header, form, query param) - allows token leakage
- No token signature verification
- Tokens stored in plain text in database
- SQL injection vulnerabilities
- No rate limiting
- Verbose error messages expose internal details
"""

import sqlite3
import os
from typing import Optional, List
from enum import Enum
from contextlib import contextmanager

from fastapi import FastAPI, Depends, HTTPException, Query, Form, Header, Request
from pydantic import BaseModel

# Initialize FastAPI app
app = FastAPI(
    title="HR Resource Server (Vulnerable)",
    description="A deliberately vulnerable OAuth resource server for learning purposes",
    version="1.0.0"
)

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), "hr_database.db")


# ========================
# Enums and Models
# ========================

class Scope(str, Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    DELETE = "delete"


class Employee(BaseModel):
    id: Optional[int] = None
    first_name: str
    last_name: str
    email: str
    department: str
    position: str
    salary: Optional[float] = None  # Sensitive PII - requires admin scope
    ssn: Optional[str] = None  # Sensitive PII - requires admin scope
    date_of_birth: Optional[str] = None  # Sensitive PII - requires admin scope
    phone: Optional[str] = None


class EmployeeCreate(BaseModel):
    first_name: str
    last_name: str
    email: str
    department: str
    position: str
    salary: Optional[float] = None
    ssn: Optional[str] = None
    date_of_birth: Optional[str] = None
    phone: Optional[str] = None


class EmployeeUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    department: Optional[str] = None
    position: Optional[str] = None
    salary: Optional[float] = None
    ssn: Optional[str] = None
    date_of_birth: Optional[str] = None
    phone: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str
    scopes: List[str]


class TokenInfo(BaseModel):
    token: str
    client_id: str
    scopes: str
    expires_at: str


# ========================
# Database Setup
# ========================

def get_db_connection():
    """Get a database connection - vulnerable to connection issues"""
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


def init_database():
    """Initialize the database with tables and sample data"""
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Create tokens table - stores tokens in plain text (vulnerable!)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS oauth_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                access_token TEXT UNIQUE NOT NULL,
                client_id TEXT NOT NULL,
                scopes TEXT NOT NULL,
                expires_at TIMESTAMP DEFAULT (datetime('now', '+1 hour')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create employees table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                department TEXT NOT NULL,
                position TEXT NOT NULL,
                salary REAL,
                ssn TEXT,
                date_of_birth TEXT,
                phone TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Insert sample tokens with different scopes
        sample_tokens = [
            ("read_token_12345", "client_read", "read"),
            ("write_token_67890", "client_write", "read,write"),
            ("admin_token_secret", "client_admin", "read,write,admin"),
            ("delete_token_danger", "client_delete", "read,write,delete"),
            ("superuser_token_ultimate", "client_super", "read,write,admin,delete"),
        ]
        
        for token, client_id, scopes in sample_tokens:
            try:
                cursor.execute(
                    "INSERT OR IGNORE INTO oauth_tokens (access_token, client_id, scopes) VALUES (?, ?, ?)",
                    (token, client_id, scopes)
                )
            except sqlite3.IntegrityError:
                pass
        
        # Insert sample employees
        sample_employees = [
            ("John", "Doe", "john.doe@company.com", "Engineering", "Software Engineer", 95000.00, "123-45-6789", "1990-05-15", "555-0101"),
            ("Jane", "Smith", "jane.smith@company.com", "HR", "HR Manager", 85000.00, "234-56-7890", "1985-08-22", "555-0102"),
            ("Bob", "Johnson", "bob.johnson@company.com", "Sales", "Sales Representative", 65000.00, "345-67-8901", "1992-03-10", "555-0103"),
            ("Alice", "Williams", "alice.williams@company.com", "Engineering", "Senior Developer", 120000.00, "456-78-9012", "1988-11-30", "555-0104"),
            ("Charlie", "Brown", "charlie.brown@company.com", "Marketing", "Marketing Specialist", 55000.00, "567-89-0123", "1995-07-18", "555-0105"),
        ]
        
        for emp in sample_employees:
            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO employees 
                    (first_name, last_name, email, department, position, salary, ssn, date_of_birth, phone)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, emp)
            except sqlite3.IntegrityError:
                pass
        
        conn.commit()


# Initialize database on module load
init_database()


# ========================
# Token Validation (Vulnerable!)
# ========================

async def get_token_from_multiple_sources(
    request: Request,
    authorization: Optional[str] = Header(None),
    access_token: Optional[str] = Query(None, description="OAuth token (vulnerable - visible in logs!)"),
    token: Optional[str] = Form(None),
) -> str:
    """
    VULNERABLE: Accepts tokens from multiple sources.
    
    Security issues:
    1. Query params are logged in server logs and browser history
    2. Form body tokens can be intercepted
    3. No preference order means attackers can try multiple injection points
    """
    # Try to get token from Authorization header first
    if authorization:
        # Support both "Bearer <token>" and raw token (vulnerable!)
        if authorization.startswith("Bearer "):
            return authorization[7:]
        return authorization  # Accepts raw token without Bearer prefix!
    
    # Try query parameter (VULNERABLE - tokens in URL are logged!)
    if access_token:
        return access_token
    
    # Try form body
    if token:
        return token
    
    # Also check raw body for token (extra vulnerable!)
    try:
        body = await request.body()
        if body:
            body_str = body.decode()
            if "token=" in body_str:
                return body_str.split("token=")[1].split("&")[0]
    except Exception:
        pass
    
    raise HTTPException(
        status_code=401,
        detail="No access token provided. Token can be provided via: Authorization header, 'access_token' query param, or 'token' form field",
        headers={"WWW-Authenticate": "Bearer"}
    )


def validate_token(token: str) -> dict:
    """
    VULNERABLE: Token validation with multiple security issues.
    
    Issues:
    1. SQL injection vulnerability (token not sanitized)
    2. No signature verification
    3. Verbose error messages
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # VULNERABLE TO SQL INJECTION!
        # An attacker could use: ' OR '1'='1
        query = f"SELECT * FROM oauth_tokens WHERE access_token = '{token}'"
        
        try:
            cursor.execute(query)
            result = cursor.fetchone()
        except sqlite3.Error as e:
            # Verbose error message exposes database details
            raise HTTPException(
                status_code=500,
                detail=f"Database error while validating token: {str(e)}. Query was: {query}"
            )
        
        if not result:
            raise HTTPException(
                status_code=401,
                detail=f"Invalid token: '{token}' not found in database",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        return {
            "token": result["access_token"],
            "client_id": result["client_id"],
            "scopes": result["scopes"].split(","),
            "expires_at": result["expires_at"]
        }


def require_scope(required_scope: Scope):
    """Dependency factory to require specific scope"""
    async def scope_checker(
        token: str = Depends(get_token_from_multiple_sources)
    ) -> dict:
        token_data = validate_token(token)
        
        if required_scope.value not in token_data["scopes"]:
            raise HTTPException(
                status_code=403,
                detail=f"Token '{token}' does not have required scope: {required_scope.value}. Available scopes: {token_data['scopes']}"
            )
        
        return token_data
    
    return scope_checker


# ========================
# API Endpoints
# ========================

@app.get("/")
async def root():
    """Public endpoint - no authentication required"""
    return {
        "message": "HR Resource Server (Vulnerable OAuth Implementation)",
        "endpoints": {
            "employees": "/employees",
            "employee": "/employees/{id}",
            "employee_pii": "/employees/{id}/pii",
            "tokens": "/tokens (admin only)"
        },
        "warning": "This server is intentionally vulnerable for educational purposes!"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "database": DB_PATH}


# ========================
# Employee Endpoints
# ========================

@app.get("/employees", response_model=List[Employee])
async def list_employees(
    token_data: dict = Depends(require_scope(Scope.READ)),
    department: Optional[str] = Query(None, description="Filter by department"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    List all employees (basic info only).
    Requires: read scope
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # VULNERABLE TO SQL INJECTION via department parameter!
        if department:
            query = f"SELECT id, first_name, last_name, email, department, position, phone FROM employees WHERE department = '{department}' LIMIT {limit} OFFSET {offset}"
        else:
            query = f"SELECT id, first_name, last_name, email, department, position, phone FROM employees LIMIT {limit} OFFSET {offset}"
        
        cursor.execute(query)
        employees = cursor.fetchall()
        
        return [
            Employee(
                id=emp["id"],
                first_name=emp["first_name"],
                last_name=emp["last_name"],
                email=emp["email"],
                department=emp["department"],
                position=emp["position"],
                phone=emp["phone"]
            )
            for emp in employees
        ]


@app.get("/employees/{employee_id}", response_model=Employee)
async def get_employee(
    employee_id: int,
    token_data: dict = Depends(require_scope(Scope.READ))
):
    """
    Get employee by ID (basic info only).
    Requires: read scope
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Using parameterized query here (not vulnerable)
        cursor.execute(
            "SELECT id, first_name, last_name, email, department, position, phone FROM employees WHERE id = ?",
            (employee_id,)
        )
        emp = cursor.fetchone()
        
        if not emp:
            raise HTTPException(status_code=404, detail=f"Employee with ID {employee_id} not found")
        
        return Employee(
            id=emp["id"],
            first_name=emp["first_name"],
            last_name=emp["last_name"],
            email=emp["email"],
            department=emp["department"],
            position=emp["position"],
            phone=emp["phone"]
        )


@app.get("/employees/{employee_id}/pii", response_model=Employee)
async def get_employee_pii(
    employee_id: int,
    token_data: dict = Depends(require_scope(Scope.ADMIN))
):
    """
    Get employee with sensitive PII (salary, SSN, DOB).
    Requires: admin scope
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM employees WHERE id = ?", (employee_id,))
        emp = cursor.fetchone()
        
        if not emp:
            raise HTTPException(status_code=404, detail=f"Employee with ID {employee_id} not found")
        
        return Employee(
            id=emp["id"],
            first_name=emp["first_name"],
            last_name=emp["last_name"],
            email=emp["email"],
            department=emp["department"],
            position=emp["position"],
            salary=emp["salary"],
            ssn=emp["ssn"],
            date_of_birth=emp["date_of_birth"],
            phone=emp["phone"]
        )


@app.post("/employees", response_model=Employee, status_code=201)
async def create_employee(
    employee: EmployeeCreate,
    token_data: dict = Depends(require_scope(Scope.WRITE))
):
    """
    Create a new employee.
    Requires: write scope
    Note: Creating with PII (salary, SSN) requires admin scope
    """
    # Check if trying to set sensitive fields without admin scope
    if (employee.salary or employee.ssn or employee.date_of_birth) and "admin" not in token_data["scopes"]:
        raise HTTPException(
            status_code=403,
            detail="Setting sensitive PII (salary, SSN, DOB) requires admin scope"
        )
    
    with db_connection() as conn:
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO employees (first_name, last_name, email, department, position, salary, ssn, date_of_birth, phone)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                employee.first_name,
                employee.last_name,
                employee.email,
                employee.department,
                employee.position,
                employee.salary,
                employee.ssn,
                employee.date_of_birth,
                employee.phone
            ))
            conn.commit()
            
            employee_id = cursor.lastrowid
            
            return Employee(
                id=employee_id,
                first_name=employee.first_name,
                last_name=employee.last_name,
                email=employee.email,
                department=employee.department,
                position=employee.position,
                salary=employee.salary if "admin" in token_data["scopes"] else None,
                ssn=employee.ssn if "admin" in token_data["scopes"] else None,
                date_of_birth=employee.date_of_birth if "admin" in token_data["scopes"] else None,
                phone=employee.phone
            )
        except sqlite3.IntegrityError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Employee with email {employee.email} already exists. Error: {str(e)}"
            )


@app.put("/employees/{employee_id}", response_model=Employee)
async def update_employee(
    employee_id: int,
    employee: EmployeeUpdate,
    token_data: dict = Depends(require_scope(Scope.WRITE))
):
    """
    Update an employee.
    Requires: write scope
    Note: Updating PII (salary, SSN) requires admin scope
    """
    # Check if trying to update sensitive fields without admin scope
    if (employee.salary is not None or employee.ssn is not None or employee.date_of_birth is not None) and "admin" not in token_data["scopes"]:
        raise HTTPException(
            status_code=403,
            detail="Updating sensitive PII (salary, SSN, DOB) requires admin scope"
        )
    
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # First check if employee exists
        cursor.execute("SELECT * FROM employees WHERE id = ?", (employee_id,))
        existing = cursor.fetchone()
        
        if not existing:
            raise HTTPException(status_code=404, detail=f"Employee with ID {employee_id} not found")
        
        # Build update query dynamically (vulnerable pattern but using params)
        updates = []
        values = []
        
        update_fields = employee.model_dump(exclude_unset=True)
        for field, value in update_fields.items():
            if value is not None:
                updates.append(f"{field} = ?")
                values.append(value)
        
        if updates:
            values.append(employee_id)
            query = f"UPDATE employees SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
            cursor.execute(query, values)
            conn.commit()
        
        # Fetch updated employee
        cursor.execute("SELECT * FROM employees WHERE id = ?", (employee_id,))
        emp = cursor.fetchone()
        
        return Employee(
            id=emp["id"],
            first_name=emp["first_name"],
            last_name=emp["last_name"],
            email=emp["email"],
            department=emp["department"],
            position=emp["position"],
            salary=emp["salary"] if "admin" in token_data["scopes"] else None,
            ssn=emp["ssn"] if "admin" in token_data["scopes"] else None,
            date_of_birth=emp["date_of_birth"] if "admin" in token_data["scopes"] else None,
            phone=emp["phone"]
        )


@app.delete("/employees/{employee_id}")
async def delete_employee(
    employee_id: int,
    token_data: dict = Depends(require_scope(Scope.DELETE))
):
    """
    Delete an employee.
    Requires: delete scope
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Check if employee exists
        cursor.execute("SELECT id FROM employees WHERE id = ?", (employee_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail=f"Employee with ID {employee_id} not found")
        
        cursor.execute("DELETE FROM employees WHERE id = ?", (employee_id,))
        conn.commit()
        
        return {"message": f"Employee {employee_id} deleted successfully", "deleted_by": token_data["client_id"]}


# ========================
# Admin Endpoints
# ========================

@app.get("/employees/search/pii", response_model=List[Employee])
async def search_employees_by_pii(
    ssn: Optional[str] = Query(None),
    salary_min: Optional[float] = Query(None),
    salary_max: Optional[float] = Query(None),
    token_data: dict = Depends(require_scope(Scope.ADMIN))
):
    """
    Search employees by PII fields.
    Requires: admin scope
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # VULNERABLE TO SQL INJECTION via SSN!
        conditions = []
        if ssn:
            conditions.append(f"ssn LIKE '%{ssn}%'")
        if salary_min is not None:
            conditions.append(f"salary >= {salary_min}")
        if salary_max is not None:
            conditions.append(f"salary <= {salary_max}")
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT * FROM employees WHERE {where_clause}"
        
        cursor.execute(query)
        employees = cursor.fetchall()
        
        return [
            Employee(
                id=emp["id"],
                first_name=emp["first_name"],
                last_name=emp["last_name"],
                email=emp["email"],
                department=emp["department"],
                position=emp["position"],
                salary=emp["salary"],
                ssn=emp["ssn"],
                date_of_birth=emp["date_of_birth"],
                phone=emp["phone"]
            )
            for emp in employees
        ]


@app.get("/tokens", response_model=List[TokenInfo])
async def list_tokens(
    token_data: dict = Depends(require_scope(Scope.ADMIN))
):
    """
    List all tokens in the system (VERY VULNERABLE!).
    Requires: admin scope
    
    This exposes all tokens - a major security vulnerability!
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT access_token, client_id, scopes, expires_at FROM oauth_tokens")
        tokens = cursor.fetchall()
        
        return [
            TokenInfo(
                token=t["access_token"],
                client_id=t["client_id"],
                scopes=t["scopes"],
                expires_at=t["expires_at"]
            )
            for t in tokens
        ]


@app.post("/tokens", response_model=Token)
async def create_token(
    client_id: str = Form(...),
    scopes: str = Form(..., description="Comma-separated scopes"),
    token_data: dict = Depends(require_scope(Scope.ADMIN))
):
    """
    Create a new token (admin only).
    This is a simplified token creation for testing purposes.
    """
    import secrets
    new_token = secrets.token_urlsafe(32)
    
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO oauth_tokens (access_token, client_id, scopes) VALUES (?, ?, ?)",
            (new_token, client_id, scopes)
        )
        conn.commit()
    
    return Token(
        access_token=new_token,
        token_type="bearer",
        scopes=scopes.split(",")
    )


# ========================
# Debug Endpoints (Extra Vulnerable!)
# ========================

@app.get("/debug/token-info")
async def debug_token_info(
    token: str = Depends(get_token_from_multiple_sources)
):
    """
    Debug endpoint that exposes token information.
    VULNERABLE: Exposes internal token details!
    """
    token_data = validate_token(token)
    return {
        "token": token,  # Echoing the token back is dangerous!
        "token_data": token_data,
        "warning": "This endpoint should not exist in production!"
    }


@app.get("/debug/database")
async def debug_database(
    token_data: dict = Depends(require_scope(Scope.ADMIN))
):
    """
    Debug endpoint that exposes database structure.
    VULNERABLE: Exposes database schema!
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        schema = {}
        for table in tables:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            schema[table] = [
                {"name": col[1], "type": col[2], "nullable": not col[3], "primary_key": bool(col[5])}
                for col in columns
            ]
        
        return {
            "database_path": DB_PATH,
            "tables": tables,
            "schema": schema,
            "warning": "This endpoint exposes sensitive database information!"
        }


# ========================
# Run Server
# ========================

if __name__ == "__main__":
    import uvicorn
    
    print("=" * 60)
    print("WARNING: This is a VULNERABLE OAuth Resource Server!")
    print("For educational purposes only. DO NOT use in production!")
    print("=" * 60)
    print("\nSample tokens for testing:")
    print("  - read_token_12345 (read scope)")
    print("  - write_token_67890 (read, write scopes)")
    print("  - admin_token_secret (read, write, admin scopes)")
    print("  - delete_token_danger (read, write, delete scopes)")
    print("  - superuser_token_ultimate (all scopes)")
    print("\n" + "=" * 60)
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
