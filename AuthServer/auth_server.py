"""
RDP QR Authentication Server
Handles authentication sessions, user registration, and challenge-response validation
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import secrets
import time
import threading
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import json
import yaml
import logging
from pathlib import Path

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
        'security': {'session_timeout': 120, 'max_sessions': 1000}
    }

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# In-memory storage (use database in production)
sessions = {}  # session_id -> AuthSession
users = {}     # user_id -> {public_key, username}

SESSION_TIMEOUT = config['security']['session_timeout']
MAX_SESSIONS = config['security']['max_sessions']


class AuthSession:
    """Represents an authentication session"""
    
    def __init__(self, session_id, challenge, server_id):
        self.session_id = session_id
        self.challenge = challenge
        self.server_id = server_id
        self.timestamp = datetime.now()
        self.status = 'pending'  # pending, authenticated, expired
        self.user_id = None
        self.auth_token = None


def cleanup_expired_sessions():
    """Background thread to clean up expired sessions"""
    while True:
        time.sleep(30)
        now = datetime.now()
        expired = [
            sid for sid, sess in sessions.items() 
            if (now - sess.timestamp).seconds > SESSION_TIMEOUT
        ]
        for sid in expired:
            sessions[sid].status = 'expired'
            logger.info(f"Session {sid} expired")
            
        # Remove very old sessions to prevent memory leak
        if len(sessions) > MAX_SESSIONS:
            sorted_sessions = sorted(
                sessions.items(), 
                key=lambda x: x[1].timestamp
            )
            to_remove = len(sessions) - MAX_SESSIONS
            for sid, _ in sorted_sessions[:to_remove]:
                del sessions[sid]
                logger.info(f"Removed old session {sid} (memory management)")


# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_sessions, daemon=True)
cleanup_thread.start()


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'active_sessions': len([s for s in sessions.values() if s.status == 'pending']),
        'registered_users': len(users)
    })


@app.route('/api/session/create', methods=['POST'])
def create_session():
    """
    Create a new authentication session
    
    Request body:
    {
        "server_id": "RDP-SERVER-NAME"
    }
    
    Response:
    {
        "session_id": "unique_session_id",
        "qr_data": "{json data for QR code}",
        "expires_in": 120
    }
    """
    try:
        data = request.json
        server_id = data.get('server_id', 'RDP-SERVER')
        
        # Generate cryptographically secure random session ID and challenge
        session_id = secrets.token_urlsafe(32)
        challenge = secrets.token_urlsafe(32)
        
        # Create session object
        session = AuthSession(session_id, challenge, server_id)
        sessions[session_id] = session
        
        # Prepare QR code data (this will be encoded in QR code)
        qr_data = {
            'session_id': session_id,
            'challenge': challenge,
            'server_id': server_id,
            'timestamp': session.timestamp.isoformat()
        }
        
        logger.info(f"Created session: {session_id} for server: {server_id}")
        
        return jsonify({
            'session_id': session_id,
            'qr_data': json.dumps(qr_data),
            'expires_in': SESSION_TIMEOUT
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating session: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/session/status/<session_id>', methods=['GET'])
def check_session_status(session_id):
    """
    Check authentication status of a session
    Called by Credential Provider to poll for authentication
    
    Response:
    {
        "status": "pending|authenticated|expired",
        "user_id": "user001",  # if authenticated
        "username": "DOMAIN\\username",  # if authenticated
        "auth_token": "token"  # if authenticated
    }
    """
    session = sessions.get(session_id)
    
    if not session:
        logger.warning(f"Session not found: {session_id}")
        return jsonify({'error': 'Session not found'}), 404
    
    # Check if expired
    if (datetime.now() - session.timestamp).seconds > SESSION_TIMEOUT:
        session.status = 'expired'
    
    if session.status == 'expired':
        return jsonify({'status': 'expired'}), 200
    
    if session.status == 'authenticated':
        response = {
            'status': 'authenticated',
            'user_id': session.user_id,
            'username': users[session.user_id]['username'],
            'auth_token': session.auth_token
        }
        
        # Clean up session after successful retrieval
        # This ensures one-time use
        del sessions[session_id]
        logger.info(f"Session {session_id} completed and removed")
        
        return jsonify(response), 200
    
    # Still pending
    return jsonify({'status': 'pending'}), 200


@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    """
    Authenticate a user for a session
    Called by QR Scanner App after scanning QR code
    
    Request body:
    {
        "session_id": "session_id",
        "user_id": "user001",
        "signature": "base64_encoded_signature"
    }
    
    Response:
    {
        "success": true,
        "message": "Authentication successful"
    }
    """
    try:
        data = request.json
        session_id = data.get('session_id')
        user_id = data.get('user_id')
        signature_b64 = data.get('signature')
        
        # Validate required fields
        if not all([session_id, user_id, signature_b64]):
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
        
        # Verify signature using public key cryptography
        try:
            signature = base64.b64decode(signature_b64)
            public_key = serialization.load_pem_public_key(
                user['public_key'].encode(),
                backend=default_backend()
            )
            
            # Verify the signature of the challenge
            # This proves the user has the private key corresponding to their registered public key
            public_key.verify(
                signature,
                session.challenge.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Signature is valid - authenticate the session
            session.status = 'authenticated'
            session.user_id = user_id
            session.auth_token = secrets.token_urlsafe(32)
            
            logger.info(f"User {user_id} ({user['username']}) authenticated for session {session_id}")
            
            return jsonify({
                'success': True,
                'message': 'Authentication successful'
            }), 200
            
        except Exception as e:
            logger.error(f"Signature verification failed for user {user_id}: {e}")
            return jsonify({'error': 'Invalid signature'}), 401
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/user/register', methods=['POST'])
def register_user():
    """
    Register a new user with their public key
    
    Request body:
    {
        "user_id": "user001",
        "username": "DOMAIN\\username" or ".\\username",
        "public_key": "-----BEGIN PUBLIC KEY-----..."
    }
    
    Response:
    {
        "success": true,
        "user_id": "user001",
        "username": "DOMAIN\\username"
    }
    """
    try:
        data = request.json
        user_id = data.get('user_id')
        username = data.get('username')
        public_key_pem = data.get('public_key')
        
        # Validate required fields
        if not all([user_id, username, public_key_pem]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if user_id in users:
            logger.warning(f"Registration attempt for existing user: {user_id}")
            return jsonify({'error': 'User already exists'}), 400
        
        # Validate public key format
        try:
            serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
        except Exception as e:
            logger.error(f"Invalid public key format: {e}")
            return jsonify({'error': 'Invalid public key format'}), 400
        
        # Store user
        users[user_id] = {
            'username': username,
            'public_key': public_key_pem,
            'registered_at': datetime.now().isoformat()
        }
        
        logger.info(f"Registered user: {username} ({user_id})")
        
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
                "username": "DOMAIN\\username",
                "registered_at": "2025-10-25T10:00:00"
            }
        ]
    }
    """
    user_list = [
        {
            'user_id': uid,
            'username': user['username'],
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


if __name__ == '__main__':
    print("=" * 60)
    print("RDP QR Authentication Server")
    print("=" * 60)
    print(f"Starting server...")
    print(f"Host: {config['server']['host']}")
    print(f"Port: {config['server']['port']}")
    print(f"Session timeout: {SESSION_TIMEOUT} seconds")
    print(f"Max sessions: {MAX_SESSIONS}")
    print("=" * 60)
    
    # Run server
    app.run(
        host=config['server']['host'],
        port=config['server']['port'],
        debug=config['server']['debug']
    )
