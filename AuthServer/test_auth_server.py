#!/usr/bin/env python3
"""
Test script for auth server certificate generation
Validates certificate structure and Windows compatibility
"""

import requests
import json
import base64
from OpenSSL import crypto
from datetime import datetime
import struct

# Configuration
AUTH_SERVER = "http://localhost:5000"
TEST_USER = {
    "user_id": "testuser001",
    "username": "ross.green@secretzero.com",
    "sid": "S-1-5-21-2065755198-886904826-1734203342-1104"
}

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)

def test_health():
    """Test 1: Health check"""
    print_header("TEST 1: Health Check")
    
    try:
        response = requests.get(f"{AUTH_SERVER}/health")
        response.raise_for_status()
        data = response.json()
        
        print(f"✓ Server Status: {data['status']}")
        print(f"  Registered Users: {data['registered_users']}")
        print(f"  Active Sessions: {data['active_sessions']}")
        print(f"  CA Subject: {data.get('ca_subject', 'N/A')}")
        return True
    except Exception as e:
        print(f"✗ Health check failed: {e}")
        return False

def test_ca_certificate():
    """Test 2: Download and validate CA certificate"""
    print_header("TEST 2: CA Certificate Validation")
    
    try:
        response = requests.get(f"{AUTH_SERVER}/api/ca/certificate")
        response.raise_for_status()
        ca_cert_pem = response.text
        
        # Parse certificate
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)
        
        # Validate CA properties
        print("✓ CA Certificate Downloaded")
        print(f"  Subject: {ca_cert.get_subject().CN}")
        print(f"  Issuer: {ca_cert.get_issuer().CN}")
        print(f"  Serial: {ca_cert.get_serial_number()}")
        
        # Check validity
        not_after = datetime.strptime(
            ca_cert.get_notAfter().decode('ascii'),
            '%Y%m%d%H%M%SZ'
        )
        print(f"  Valid Until: {not_after}")
        
        # Check if it's a CA
        for i in range(ca_cert.get_extension_count()):
            ext = ca_cert.get_extension(i)
            if ext.get_short_name() == b'basicConstraints':
                print(f"  Basic Constraints: {ext}")
                if b'CA:TRUE' in bytes(ext):
                    print("  ✓ Valid CA certificate")
                else:
                    print("  ✗ Not a CA certificate!")
                    return False
        
        return True
    except Exception as e:
        print(f"✗ CA certificate test failed: {e}")
        return False

def test_session_creation():
    """Test 3: Create authentication session"""
    print_header("TEST 3: Session Creation")
    
    try:
        payload = {"server_id": "TEST-SERVER"}
        response = requests.post(
            f"{AUTH_SERVER}/api/session/create",
            json=payload
        )
        response.raise_for_status()
        data = response.json()
        
        print(f"✓ Session Created")
        print(f"  Session ID: {data['session_id'][:20]}...")
        print(f"  Expires In: {data['expires_in']} seconds")
        
        # Parse QR data
        qr_data = json.loads(data['qr_data'])
        print(f"  Challenge: {qr_data['challenge'][:20]}...")
        
        return data['session_id']
    except Exception as e:
        print(f"✗ Session creation failed: {e}")
        return None

def test_authentication(session_id):
    """Test 4: Authenticate and generate certificate"""
    print_header("TEST 4: Authentication & Certificate Generation")
    
    try:
        payload = {
            "session_id": session_id,
            "user_id": TEST_USER["user_id"]
        }
        response = requests.post(
            f"{AUTH_SERVER}/api/authenticate",
            json=payload
        )
        response.raise_for_status()
        data = response.json()
        
        print(f"✓ Authentication Successful")
        print(f"  Certificate Serial: {data['certificate_serial']}")
        
        return True
    except Exception as e:
        print(f"✗ Authentication failed: {e}")
        return False

def test_certificate_retrieval(session_id):
    """Test 5: Retrieve and validate certificate"""
    print_header("TEST 5: Certificate Retrieval & Validation")
    
    try:
        response = requests.get(
            f"{AUTH_SERVER}/api/session/status/{session_id}"
        )
        response.raise_for_status()
        data = response.json()
        
        if data['status'] != 'authenticated':
            print(f"✗ Session not authenticated: {data['status']}")
            return False
        
        print("✓ Certificate Retrieved")
        
        # Validate certificate structure
        cert_pem = data['certificate']
        key_pem = data['private_key']
        pfx_b64 = data['pfx']
        
        # Parse certificate
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        
        print(f"\n📜 Certificate Details:")
        print(f"  Subject CN: {cert.get_subject().CN}")
        print(f"  Issuer CN: {cert.get_issuer().CN}")
        print(f"  Serial Number: {cert.get_serial_number()}")
        
        # Check validity period
        not_before = datetime.strptime(
            cert.get_notBefore().decode('ascii'),
            '%Y%m%d%H%M%SZ'
        )
        not_after = datetime.strptime(
            cert.get_notAfter().decode('ascii'),
            '%Y%m%d%H%M%SZ'
        )
        
        validity_minutes = (not_after - not_before).total_seconds() / 60
        print(f"  Valid From: {not_before}")
        print(f"  Valid Until: {not_after}")
        print(f"  Validity Period: {validity_minutes:.1f} minutes")
        
        if validity_minutes > 6:
            print(f"  ⚠ Warning: Certificate validity too long (should be ~5 min)")
        
        # Validate extensions
        print(f"\n🔐 Certificate Extensions:")
        
        has_smart_card_logon = False
        has_upn = False
        has_sid = False
        
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            ext_name = ext.get_short_name().decode('ascii')
            
            if ext_name == 'extendedKeyUsage':
                ext_value = str(ext)
                print(f"  ✓ Extended Key Usage: {ext_value}")
                if '1.3.6.1.4.1.311.20.2.2' in ext_value or 'Smart Card Logon' in ext_value:
                    has_smart_card_logon = True
                    print("    ✓ Smart Card Logon EKU present")
                else:
                    print("    ✗ Smart Card Logon EKU MISSING!")
            
            elif ext_name == 'subjectAltName':
                ext_value = str(ext)
                print(f"  ✓ Subject Alternative Name: {ext_value}")
                if TEST_USER['username'] in ext_value or 'otherName' in ext_value:
                    has_upn = True
                    print("    ✓ UPN present")
                else:
                    print("    ✗ UPN MISSING!")
            
            elif ext_name == '1.3.6.1.4.1.311.25.2':
                has_sid = True
                print(f"  ✓ SID Extension present")
                
                # Try to decode SID
                try:
                    sid_data = ext.get_data()
                    # Skip ASN.1 wrapper (first 2 bytes: 0x04 <length>)
                    if sid_data[0] == 0x04:
                        sid_bytes = sid_data[2:]
                        # Parse SID
                        revision = sid_bytes[0]
                        sub_auth_count = sid_bytes[1]
                        authority = struct.unpack('>Q', b'\x00\x00' + sid_bytes[2:8])[0]
                        
                        sub_authorities = []
                        offset = 8
                        for _ in range(sub_auth_count):
                            sub_auth = struct.unpack('<I', sid_bytes[offset:offset+4])[0]
                            sub_authorities.append(sub_auth)
                            offset += 4
                        
                        sid_string = f"S-{revision}-{authority}-" + "-".join(map(str, sub_authorities))
                        print(f"    Decoded SID: {sid_string}")
                        
                        if sid_string == TEST_USER['sid']:
                            print(f"    ✓ SID matches expected value")
                        else:
                            print(f"    ✗ SID mismatch!")
                            print(f"      Expected: {TEST_USER['sid']}")
                            print(f"      Got: {sid_string}")
                except Exception as e:
                    print(f"    ⚠ Could not decode SID: {e}")
            
            elif ext_name == 'keyUsage':
                print(f"  ✓ Key Usage: {ext}")
        
        # Summary
        print(f"\n📊 Windows Compatibility Check:")
        checks_passed = 0
        total_checks = 3
        
        if has_smart_card_logon:
            print("  ✓ Smart Card Logon EKU")
            checks_passed += 1
        else:
            print("  ✗ Smart Card Logon EKU MISSING (CRITICAL)")
        
        if has_upn:
            print("  ✓ UPN in Subject Alternative Name")
            checks_passed += 1
        else:
            print("  ✗ UPN MISSING (CRITICAL)")
        
        if has_sid:
            print("  ✓ SID Extension for Strong Mapping")
            checks_passed += 1
        else:
            print("  ✗ SID Extension MISSING (CRITICAL for Windows Server 2022+)")
        
        # Validate private key
        try:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)
            print(f"  ✓ Private key valid ({key.bits()} bits)")
            checks_passed += 0.5
            total_checks += 0.5
        except Exception as e:
            print(f"  ✗ Private key invalid: {e}")
        
        # Validate PFX
        try:
            pfx_bytes = base64.b64decode(pfx_b64)
            pfx = crypto.load_pkcs12(pfx_bytes, b'')
            print(f"  ✓ PFX/PKCS12 valid")
            checks_passed += 0.5
            total_checks += 0.5
        except Exception as e:
            print(f"  ✗ PFX invalid: {e}")
        
        print(f"\n{'='*60}")
        print(f"COMPATIBILITY SCORE: {checks_passed}/{total_checks}")
        
        if checks_passed == total_checks:
            print("✓ CERTIFICATE FULLY COMPATIBLE WITH WINDOWS")
            return True
        elif checks_passed >= total_checks - 1:
            print("⚠ CERTIFICATE MOSTLY COMPATIBLE (minor issues)")
            return True
        else:
            print("✗ CERTIFICATE HAS CRITICAL ISSUES")
            return False
        
    except Exception as e:
        print(f"✗ Certificate retrieval failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_crl():
    """Test 6: Certificate Revocation List"""
    print_header("TEST 6: Certificate Revocation List")
    
    try:
        response = requests.get(f"{AUTH_SERVER}/api/crl")
        response.raise_for_status()
        
        crl_pem = response.content
        crl = crypto.load_crl(crypto.FILETYPE_PEM, crl_pem)
        
        print("✓ CRL Retrieved")
        print(f"  Format: PEM")
        
        # Get revoked certificates
        revoked = crl.get_revoked()
        if revoked:
            print(f"  Revoked Certificates: {len(revoked)}")
        else:
            print(f"  Revoked Certificates: 0 (CRL empty)")
        
        return True
    except Exception as e:
        print(f"✗ CRL test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 10 + "AUTH SERVER CERTIFICATE TEST SUITE" + " " * 14 + "║")
    print("╚" + "═" * 58 + "╝")
    
    results = []
    
    # Test 1: Health
    results.append(("Health Check", test_health()))
    
    # Test 2: CA Certificate
    results.append(("CA Certificate", test_ca_certificate()))
    
    # Test 3: Session Creation
    session_id = test_session_creation()
    results.append(("Session Creation", session_id is not None))
    
    if session_id:
        # Test 4: Authentication
        auth_result = test_authentication(session_id)
        results.append(("Authentication", auth_result))
        
        if auth_result:
            # Test 5: Certificate Validation (most important)
            cert_result = test_certificate_retrieval(session_id)
            results.append(("Certificate Validation", cert_result))
    
    # Test 6: CRL
    results.append(("CRL Service", test_crl()))
    
    # Summary
    print_header("TEST SUMMARY")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:8} {test_name}")
    
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Server is ready for Windows integration.")
    elif passed >= total - 1:
        print("\n⚠ MOSTLY WORKING - Review failures above.")
    else:
        print("\n❌ CRITICAL FAILURES - Fix issues before proceeding.")
    
    print("="*60)
    
    return passed == total

if __name__ == "__main__":
    import sys
    success = main()
    sys.exit(0 if success else 1)