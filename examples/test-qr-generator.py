"""
Test QR Code Generator
Generates a test QR code for testing the authentication flow
"""

import qrcode
import json
import requests
from datetime import datetime

# Configuration - UPDATE THESE
AUTH_SERVER_URL = 'http://192.168.128.133:5000'
SERVER_ID = 'TEST-SERVER'

def main():
    print("=" * 60)
    print("Test QR Code Generator")
    print("=" * 60)
    
    # Create session on auth server
    print("\n1. Creating session on auth server...")
    response = requests.post(
        f'{AUTH_SERVER_URL}/api/session/create',
        json={'server_id': SERVER_ID}
    )
    
    if response.status_code != 201:
        print(f"Error: {response.text}")
        return
    
    session_data = response.json()
    qr_data = json.loads(session_data['qr_data'])
    
    print(f"   Session ID: {qr_data['session_id']}")
    print(f"   Challenge: {qr_data['challenge'][:20]}...")
    print(f"   Server: {qr_data['server_id']}")
    
    # Generate QR code
    print("\n2. Generating QR code...")
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(json.dumps(qr_data))
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img.save("test_qr.png")
    
    print("   QR code saved as: test_qr.png")
    
    # Poll for authentication
    print("\n3. Waiting for authentication...")
    print("   Scan the QR code with your scanner app!")
    print("   (Polling every 2 seconds for 2 minutes...)")
    
    import time
    for i in range(60):
        time.sleep(2)
        
        status_response = requests.get(
            f'{AUTH_SERVER_URL}/api/session/status/{qr_data["session_id"]}'
        )
        
        if status_response.status_code != 200:
            print(f"\n   Error checking status: {status_response.text}")
            break
        
        status = status_response.json()
        
        if status['status'] == 'authenticated':
            print(f"\n✅ Authentication successful!")
            print(f"   User: {status['username']}")
            print(f"   User ID: {status['user_id']}")
            print(f"   Auth Token: {status['auth_token'][:20]}...")
            break
        elif status['status'] == 'expired':
            print(f"\n❌ Session expired")
            break
        else:
            print(f"   [{i*2}s] Status: {status['status']}")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
