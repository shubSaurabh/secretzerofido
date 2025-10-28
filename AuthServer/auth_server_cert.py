"""
RDP QR Authentication Server with Certificate Generation
Handles authentication sessions, user registration, and ephemeral certificate issuance
Includes CRL (Certificate Revocation List) service
Uses cryptography library for full X.509 extension support
"""

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import secrets
import time
import threading
from datetime import datetime, timedelta, timezone
import base64
import json
import yaml
import logging
from pathlib import Path
import struct

# Cryptography library imports
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Load configuration
config_path = Path(__file__).parent / 'config.yaml'
if config_path.exists():
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
else:
    # Default configuration
    config = {
        'server': {'host': '0.0.0.0', 'port': 5000, 'debug': True},
        'security': {'session_timeout': 120, 'max_sessions': 1000},
        'certificates': {
            'validity_minutes': 5,
            'key_size': 2048,
            'ca_cert_path': './ca/ca_cert.pem',
            'ca_key_path': './ca/ca_key.pem',
            'crl_url': 'http://192.168.126.133:5000/api/crl'
        },
        'storage': {
            'revoked_certs_path': './data/revoked_certs.json',
            'issued_certs_path': './data/issued_certs.json'
        }
    }

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# In-memory storage (use database in production)
sessions = {}  # session_id -> AuthSession
users = {}     # user_id -> {username, sid}
revoked_certs = []  # List of revoked certificate serial numbers
issued_certs = []  # Track all issued certificates

SESSION_TIMEOUT = config['security']['session_timeout']
MAX_SESSIONS = config['security']['max_sessions']
CERT_VALIDITY_MINUTES = config['certificates']['validity_minutes']
CRL_URL = config['certificates']['crl_url']

# CA objects
ca_cert = None
ca_key = None


class AuthSession:
    """Represents an authentication session"""
    
    def __init__(self, session_id, challenge, server_id):
        self.session_id = session_id
        self.challenge = challenge
        self.server_id = server_id
        self.timestamp = datetime.now()
        self.status = 'pending'  # pending, authenticated, expired
        self.user_id = None
        self.certificate = None
        self.cert_serial = None


def sid_to_bytes(sid_string):
    """
    Convert Windows SID string to bytes for certificate extension
    SID format: S-1-5-21-2065755198-886904826-1734203342-1104
    """
    parts = sid_string.split('-')
    
    # Remove 'S' prefix
    if parts[0] == 'S':
        parts = parts[1:]
    
    # Parse components
    revision = int(parts[0])  # Usually 1
    authority = int(parts[1])  # Usually 5 for NT AUTHORITY
    sub_authorities = [int(x) for x in parts[2:]]
    
    # Pack into binary format
    # Format: revision(1 byte) + subauth_count(1 byte) + authority(6 bytes) + subauths(4 bytes each)
    sid_bytes = struct.pack('B', revision)  # Revision
    sid_bytes += struct.pack('B', len(sub_authorities))  # Sub-authority count
    
    # Authority (6 bytes, big-endian)
    sid_bytes += struct.pack('>Q', authority)[2:]  # Take last 6 bytes
    
    # Sub-authorities (little-endian 32-bit integers)
    for sub_auth in sub_authorities:
        sid_bytes += struct.pack('<I', sub_auth)
    
    return sid_bytes


def load_revoked_certs():
    """Load revoked certificates from disk"""
    global revoked_certs
    
    revoked_path = Path(config['storage']['revoked_certs_path'])
    
    if revoked_path.exists():
        try:
            with open(revoked_path, 'r') as f:
                revoked_certs = json.load(f)
            logger.info(f"Loaded {len(revoked_certs)} revoked certificates from {revoked_path}")
        except Exception as e:
            logger.error(f"Error loading revoked certificates: {e}")
            revoked_certs = []
    else:
        revoked_certs = []
        logger.info("No existing revoked certificates file found")


def save_revoked_certs():
    """Save revoked certificates to disk"""
    revoked_path = Path(config['storage']['revoked_certs_path'])
    
    # Create directory if it doesn't exist
    revoked_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(revoked_path, 'w') as f:
            json.dump(revoked_certs, f, indent=2)
        logger.debug(f"Saved {len(revoked_certs)} revoked certificates to {revoked_path}")
    except Exception as e:
        logger.error(f"Error saving revoked certificates: {e}")


def load_issued_certs():
    """Load issued certificates from disk"""
    global issued_certs
    
    issued_path = Path(config['storage']['issued_certs_path'])
    
    if issued_path.exists():
        try:
            with open(issued_path, 'r') as f:
                data = json.load(f)
                # Convert ISO format strings back to datetime objects
                for cert in data:
                    cert['issued_at'] = datetime.fromisoformat(cert['issued_at'])
                    cert['expires_at'] = datetime.fromisoformat(cert['expires_at'])
                issued_certs = data
            logger.info(f"Loaded {len(issued_certs)} issued certificates from {issued_path}")
        except Exception as e:
            logger.error(f"Error loading issued certificates: {e}")
            issued_certs = []
    else:
        issued_certs = []
        logger.info("No existing issued certificates file found")


def save_issued_certs():
    """Save issued certificates to disk"""
    issued_path = Path(config['storage']['issued_certs_path'])
    
    # Create directory if it doesn't exist
    issued_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        # Convert datetime objects to ISO format strings for JSON
        data = []
        for cert in issued_certs:
            cert_copy = cert.copy()
            cert_copy['issued_at'] = cert['issued_at'].isoformat()
            cert_copy['expires_at'] = cert['expires_at'].isoformat()
            data.append(cert_copy)
        
        with open(issued_path, 'w') as f:
            json.dump(data, f, indent=2)
        logger.debug(f"Saved {len(issued_certs)} issued certificates to {issued_path}")
    except Exception as e:
        logger.error(f"Error saving issued certificates: {e}")


def initialize_ca():
    """Initialize or create CA certificate and key"""
    global ca_cert, ca_key
    
    ca_cert_path = Path(config['certificates']['ca_cert_path'])
    ca_key_path = Path(config['certificates']['ca_key_path'])
    
    # Create ca directory if it doesn't exist
    ca_cert_path.parent.mkdir(parents=True, exist_ok=True)
    
    if ca_cert_path.exists() and ca_key_path.exists():
        # Load existing CA
        logger.info("Loading existing CA certificate and key...")
        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(ca_key_path, 'rb') as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        logger.info(f"CA loaded: {ca_cert.subject.rfc4514_string()}")
    else:
        # Create new CA
        logger.info("Creating new CA certificate...")
        
        # Generate CA key pair
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecretZero"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "QR Auth CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SecretZero QR Authentication CA"),
        ])
        
        ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            ca_key.public_key()
        ).serial_number(
            1000
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        ).sign(ca_key, hashes.SHA256(), default_backend())
        
        # Save CA certificate and key
        with open(ca_cert_path, 'wb') as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        with open(ca_key_path, 'wb') as f:
            f.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        logger.info(f"CA created and saved: {ca_cert.subject.rfc4514_string()}")
        logger.info(f"CA cert: {ca_cert_path}")
        logger.info(f"CA key: {ca_key_path}")


def generate_client_certificate(user_id, username, sid):
    """
    Generate ephemeral client certificate for Windows authentication
    
    CRITICAL: Must include Microsoft-specific extensions:
    - Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2)
    - UPN in Subject Alternative Name
    - SID extension for strong mapping (1.3.6.1.4.1.311.25.2)
    - CRL Distribution Points
    """
    
    # Generate key pair for client
    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=config['certificates']['key_size'],
        backend=default_backend()
    )
    
    # Generate unique serial number
    serial = int(time.time() * 1000)
    
    # Create subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecretZero"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    
    # Convert SID to bytes for the extension
    sid_bytes = sid_to_bytes(sid)
    
    # Wrap SID in ASN.1 OCTET STRING
    # Tag 0x04 = OCTET STRING
    sid_asn1 = bytes([0x04, len(sid_bytes)]) + sid_bytes
    
    # Microsoft Smart Card Logon OID
    smartcard_logon_oid = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")
    
    # Microsoft UPN OID for otherName in SAN
    upn_oid = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
    
    # Microsoft SID extension OID (szOID_NTDS_CA_SECURITY_EXT)
    sid_oid = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2")
    
    # Create Subject Alternative Name with UPN
    # The UPN value must be DER-encoded as a UTF8String
    # Tag 0x0C = UTF8String, followed by length and the UTF8-encoded string
    upn_value = username.encode('utf-8')
    upn_der = bytes([0x0C, len(upn_value)]) + upn_value
    
    san = x509.SubjectAlternativeName([
        x509.OtherName(upn_oid, upn_der)
    ])
    
    # Create CRL Distribution Points
    crl_dp = x509.CRLDistributionPoints([
        x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(CRL_URL)],
            relative_name=None,
            crl_issuer=None,
            reasons=None
        )
    ])
    
    # Build the certificate
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        client_key.public_key()
    ).serial_number(
        serial
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(minutes=CERT_VALIDITY_MINUTES)
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
            smartcard_logon_oid,  # Smart Card Logon
        ]),
        critical=False,
    ).add_extension(
        san,
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False,
    ).add_extension(
        crl_dp,
        critical=False,
    )
    
    # Add Microsoft SID extension (CRITICAL for strong mapping - CVE-2022-26931)
    # This MUST be included for Windows Server 2022+ after May 2022 updates
    cert_builder = cert_builder.add_extension(
        x509.UnrecognizedExtension(sid_oid, sid_asn1),
        critical=False,
    )
    
    # Sign the certificate with CA key
    client_cert = cert_builder.sign(ca_key, hashes.SHA256(), default_backend())
    
    # Track issued certificate
    cert_info = {
        'serial': serial,
        'username': username,
        'user_id': user_id,
        'issued_at': datetime.now(),
        'expires_at': datetime.now() + timedelta(minutes=CERT_VALIDITY_MINUTES),
        'revoked': False
    }
    issued_certs.append(cert_info)
    
    # Save to disk
    save_issued_certs()
    
    # Export as PEM
    cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    # Create PKCS#12 bundle for Windows import
    p12_data = pkcs12.serialize_key_and_certificates(
        name=username.encode('utf-8'),
        key=client_key,
        cert=client_cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.NoEncryption()
    )
    p12_b64 = base64.b64encode(p12_data).decode()
    
    logger.info(f"Generated certificate for {username} (serial: {serial})")
    logger.info(f"  Valid for: {CERT_VALIDITY_MINUTES} minutes")
    logger.info(f"  Expires at: {cert_info['expires_at'].isoformat()}")
    logger.info(f"  CRL URL: {CRL_URL}")
    
    return {
        'certificate': cert_pem,
        'private_key': key_pem,
        'pkcs12': p12_b64,
        'serial': serial,
        'expires_at': cert_info['expires_at'].isoformat(),
        'username': username,
        'sid': sid
    }


def cleanup_expired_sessions():
    """Background thread to clean up expired sessions and certificates"""
    while True:
        time.sleep(60)  # Check every minute
        
        current_time = datetime.now()
        expired_sessions = []
        needs_save = False
        
        # Find expired sessions
        for sid, session in sessions.items():
            if (current_time - session.timestamp).seconds > SESSION_TIMEOUT:
                expired_sessions.append(sid)
                
                # Revoke certificate if one was issued
                if session.cert_serial and session.cert_serial not in revoked_certs:
                    revoked_certs.append(session.cert_serial)
                    logger.info(f"Auto-revoked expired certificate: {session.cert_serial}")
                    needs_save = True
        
        # Remove expired sessions
        for sid in expired_sessions:
            del sessions[sid]
            logger.info(f"Cleaned up expired session: {sid}")
        
        # Auto-revoke expired certificates
        for cert_info in issued_certs:
            if not cert_info['revoked'] and current_time > cert_info['expires_at']:
                serial = cert_info['serial']
                if serial not in revoked_certs:
                    revoked_certs.append(serial)
                    cert_info['revoked'] = True
                    logger.info(f"Auto-revoked expired certificate: {serial}")
                    needs_save = True
        
        # Save to disk if any changes were made
        if needs_save:
            save_revoked_certs()
            save_issued_certs()


@app.route('/api/session/create', methods=['POST'])
def create_session():
    """
    Create authentication session for RDP server
    
    Request body:
    {
        "server_id": "rdp-server-01",
        "challenge": "random_challenge_string"
    }
    
    Response:
    {
        "session_id": "abc123...",
        "qr_data": "...",
        "expires_in": 120
    }
    """
    try:
        data = request.json
        server_id = data.get('server_id', 'unknown')
        challenge = data.get('challenge', secrets.token_urlsafe(32))
        
        # Clean up old sessions if at limit
        if len(sessions) >= MAX_SESSIONS:
            oldest_session = min(sessions.items(), key=lambda x: x[1].timestamp)
            del sessions[oldest_session[0]]
            logger.warning(f"Removed oldest session to maintain limit: {oldest_session[0]}")
        
        # Generate session ID
        session_id = secrets.token_urlsafe(16)
        
        # Create session
        session = AuthSession(session_id, challenge, server_id)
        sessions[session_id] = session
        
        # Generate QR code data
        qr_data = {
            'session_id': session_id,
            'challenge': challenge,
            'server_id': server_id,
            'timestamp': session.timestamp.isoformat()
        }
        
        logger.info(f"Created session {session_id} for server {server_id}")
        
        return jsonify({
            'session_id': session_id,
            'qr_data': json.dumps(qr_data),
            'expires_in': SESSION_TIMEOUT
        }), 201
        
    except Exception as e:
        logger.error(f"Session creation error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/session/<session_id>', methods=['GET'])
def get_session_status(session_id):
    """
    Check session status and retrieve certificate if authenticated
    
    Response:
    {
        "status": "pending|authenticated|expired",
        "certificate": {...}  // Only if authenticated
    }
    """
    try:
        session = sessions.get(session_id)
        
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        # Check if session expired
        if (datetime.now() - session.timestamp).seconds > SESSION_TIMEOUT:
            session.status = 'expired'
        
        response = {
            'status': session.status,
            'session_id': session_id,
            'server_id': session.server_id
        }
        
        if session.status == 'authenticated' and session.certificate:
            response['certificate'] = session.certificate
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Session status error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    """
    Authenticate user for a session and generate certificate
    
    Request body:
    {
        "session_id": "abc123...",
        "user_id": "user001"
    }
    
    Response:
    {
        "success": true,
        "message": "Authentication successful",
        "certificate_serial": 123456
    }
    """
    try:
        data = request.json
        session_id = data.get('session_id')
        user_id = data.get('user_id')
        
        # Validate required fields
        if not all([session_id, user_id]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Validate session exists
        session = sessions.get(session_id)
        if not session:
            logger.warning(f"Authentication attempt for invalid session: {session_id}")
            return jsonify({'error': 'Invalid session'}), 404
        
        if session.status != 'pending':
            logger.warning(f"Authentication attempt for non-pending session: {session_id}")
            return jsonify({'error': 'Session already processed'}), 400
        
        # Check session not expired
        if (datetime.now() - session.timestamp).seconds > SESSION_TIMEOUT:
            session.status = 'expired'
            logger.warning(f"Authentication attempt for expired session: {session_id}")
            return jsonify({'error': 'Session expired'}), 400
        
        # Validate user exists
        user = users.get(user_id)
        if not user:
            logger.warning(f"Authentication attempt for unregistered user: {user_id}")
            return jsonify({'error': 'User not registered'}), 404
        
        # Generate ephemeral certificate
        try:
            cert_data = generate_client_certificate(
                user_id,
                user['username'],
                user['sid']
            )
            
            # Mark session as authenticated
            session.status = 'authenticated'
            session.user_id = user_id
            session.certificate = cert_data
            session.cert_serial = cert_data['serial']
            
            logger.info(f"User {user_id} ({user['username']}) authenticated for session {session_id}")
            logger.info(f"Issued certificate serial: {cert_data['serial']}")
            
            return jsonify({
                'success': True,
                'message': 'Authentication successful',
                'certificate_serial': cert_data['serial']
            }), 200
            
        except Exception as e:
            logger.error(f"Certificate generation failed for user {user_id}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return jsonify({'error': 'Certificate generation failed'}), 500
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/user/register', methods=['POST'])
def register_user():
    """
    Register a new user
    
    Request body:
    {
        "user_id": "user001",
        "username": "ross.green@secretzero.com",
        "sid": "S-1-5-21-2065755198-886904826-1734203342-1104"
    }
    
    Response:
    {
        "success": true,
        "user_id": "user001",
        "username": "ross.green@secretzero.com"
    }
    """
    try:
        data = request.json
        user_id = data.get('user_id')
        username = data.get('username')
        sid = data.get('sid')
        
        # Validate required fields
        if not all([user_id, username, sid]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if user_id in users:
            logger.warning(f"Registration attempt for existing user: {user_id}")
            return jsonify({'error': 'User already exists'}), 400
        
        # Validate SID format
        if not sid.startswith('S-'):
            return jsonify({'error': 'Invalid SID format'}), 400
        
        # Store user
        users[user_id] = {
            'username': username,
            'sid': sid,
            'registered_at': datetime.now().isoformat()
        }
        
        logger.info(f"Registered user: {username} ({user_id}) with SID: {sid}")
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'username': username
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/users', methods=['GET'])
def list_users():
    """
    List all registered users (for debugging/administration)
    
    Response:
    {
        "users": [
            {
                "user_id": "user001",
                "username": "ross.green@secretzero.com",
                "sid": "S-1-5-21-...",
                "registered_at": "2025-10-25T10:00:00"
            }
        ]
    }
    """
    user_list = [
        {
            'user_id': uid,
            'username': user['username'],
            'sid': user['sid'],
            'registered_at': user['registered_at']
        }
        for uid, user in users.items()
    ]
    return jsonify({'users': user_list, 'count': len(user_list)}), 200


@app.route('/api/user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    """
    Delete a user (for administration)
    
    Response:
    {
        "success": true,
        "message": "User deleted"
    }
    """
    if user_id in users:
        username = users[user_id]['username']
        del users[user_id]
        logger.info(f"Deleted user: {username} ({user_id})")
        return jsonify({'success': True, 'message': 'User deleted'}), 200
    else:
        return jsonify({'error': 'User not found'}), 404


@app.route('/api/certificate/revoke/<int:serial>', methods=['POST'])
def revoke_certificate(serial):
    """
    Manually revoke a certificate
    
    Response:
    {
        "success": true,
        "message": "Certificate revoked"
    }
    """
    if serial not in revoked_certs:
        revoked_certs.append(serial)
        save_revoked_certs()  # Persist to disk
        logger.info(f"Manually revoked certificate: {serial}")
        return jsonify({'success': True, 'message': 'Certificate revoked'}), 200
    else:
        return jsonify({'message': 'Certificate already revoked'}), 200


@app.route('/api/crl', methods=['GET'])
def get_crl():
    """
    Generate and serve Certificate Revocation List (CRL)
    
    Returns: DER-encoded CRL
    """
    try:
        # Create CRL builder
        crl_builder = x509.CertificateRevocationListBuilder()
        crl_builder = crl_builder.issuer_name(ca_cert.subject)
        crl_builder = crl_builder.last_update(datetime.now(timezone.utc))
        crl_builder = crl_builder.next_update(datetime.now(timezone.utc) + timedelta(days=1))
        
        # Add revoked certificates
        for serial in revoked_certs:
            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                serial
            ).revocation_date(
                datetime.now(timezone.utc)
            ).build(default_backend())
            
            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
        
        # Sign CRL with CA key
        crl = crl_builder.sign(
            private_key=ca_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        
        # Export as DER
        crl_data = crl.public_bytes(serialization.Encoding.DER)
        
        logger.info(f"Generated CRL with {len(revoked_certs)} revoked certificates")
        
        return Response(crl_data, mimetype='application/pkix-crl')
        
    except Exception as e:
        logger.error(f"CRL generation error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/api/ca/certificate/pem', methods=['GET'])
def get_ca_cert_pem():
    """Get CA certificate in PEM format"""
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    return Response(ca_pem, mimetype='application/x-pem-file')


@app.route('/api/ca/certificate/der', methods=['GET'])
def get_ca_cert_der():
    """Get CA certificate in DER format (for Windows import)"""
    ca_der = ca_cert.public_bytes(serialization.Encoding.DER)
    return Response(
        ca_der,
        mimetype='application/x-x509-ca-cert',
        headers={'Content-Disposition': 'attachment; filename=ca_cert.crt'}
    )


@app.route('/api/certificates', methods=['GET'])
def list_certificates():
    """
    List all issued certificates (for debugging/administration)
    
    Response:
    {
        "certificates": [
            {
                "serial": 123456,
                "username": "user@example.com",
                "issued_at": "2025-10-25T10:00:00",
                "expires_at": "2025-10-25T10:05:00",
                "revoked": false
            }
        ]
    }
    """
    cert_list = [
        {
            'serial': cert['serial'],
            'username': cert['username'],
            'user_id': cert['user_id'],
            'issued_at': cert['issued_at'].isoformat(),
            'expires_at': cert['expires_at'].isoformat(),
            'revoked': cert['revoked'] or cert['serial'] in revoked_certs
        }
        for cert in issued_certs
    ]
    return jsonify({'certificates': cert_list, 'count': len(cert_list)}), 200


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'sessions': len(sessions),
        'users': len(users),
        'issued_certificates': len(issued_certs),
        'revoked_certificates': len(revoked_certs)
    }), 200


if __name__ == '__main__':
    print("=" * 60)
    print("RDP QR Authentication Server with Certificate Generation")
    print("Using cryptography library for full X.509 support")
    print("=" * 60)
    
    # Initialize CA
    initialize_ca()
    
    # Load persistent data
    load_revoked_certs()
    load_issued_certs()
    
    # Hardcode test user
    users['testuser001'] = {
        'username': 'ross.green@secretzero.com',
        'sid': 'S-1-5-21-2065755198-886904826-1734203342-1104',
        'registered_at': datetime.now().isoformat()
    }
    logger.info("Hardcoded test user: ross.green@secretzero.com")
    
    print(f"Starting server...")
    print(f"Host: {config['server']['host']}")
    print(f"Port: {config['server']['port']}")
    print(f"Session timeout: {SESSION_TIMEOUT} seconds")
    print(f"Certificate validity: {CERT_VALIDITY_MINUTES} minutes")
    print(f"CRL URL: {CRL_URL}")
    print(f"CA Certificate: {config['certificates']['ca_cert_path']}")
    print(f"Revoked Certs: {config['storage']['revoked_certs_path']}")
    print(f"Issued Certs: {config['storage']['issued_certs_path']}")
    print("=" * 60)
    print("\nIMPORTANT: Install CA certificate on Windows:")
    print(f"  Download: http://localhost:{config['server']['port']}/api/ca/certificate/der")
    print("  Add to NTAuth store using certutil")
    print("=" * 60)
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_expired_sessions, daemon=True)
    cleanup_thread.start()
    
    # Run server
    app.run(
        host=config['server']['host'],
        port=config['server']['port'],
        debug=config['server']['debug']
    )