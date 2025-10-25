"""
RDP QR Scanner Client
Scans QR codes from RDP screens and authenticates users
"""

import cv2
from pyzbar import pyzbar
import json
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
from pathlib import Path
import time
import numpy as np
from PIL import Image
import mss
import tkinter as tk
from tkinter import messagebox, simpledialog
import threading
import subprocess
import yaml
import logging

# Load configuration
config_path = Path(__file__).parent / 'config.yaml'
if config_path.exists():
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
else:
    config = {
        'auth_server': 'http://192.168.1.100:5000',
        'user': {'user_id': 'user001', 'username': 'testuser', 'domain': ''},
        'scanner': {'timeout': 90, 'poll_interval': 0.5}
    }

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class QRAuthClient:
    """QR Authentication Client"""
    
    def __init__(self, auth_server_url, user_id, username, domain=None):
        self.auth_server_url = auth_server_url
        self.user_id = user_id
        self.username = username
        self.domain = domain
        self.full_username = f"{domain}\\{username}" if domain else username
        self.private_key = None
        self.public_key = None
        self.key_file = Path(f"user_{user_id}_key.pem")
        self.scanning = False
        
        self.load_or_generate_keys()
    
    def load_or_generate_keys(self):
        """Load existing RSA keys or generate new ones"""
        if self.key_file.exists():
            logger.info(f"Loading existing keys for user {self.user_id}")
            with open(self.key_file, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            self.public_key = self.private_key.public_key()
        else:
            logger.info(f"Generating new RSA key pair for user {self.user_id}")
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            # Save private key
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(self.key_file, 'wb') as f:
                f.write(pem)
            logger.info(f"Keys saved to {self.key_file}")
            
            self.register_with_server()
    
    def register_with_server(self):
        """Register user and public key with auth server"""
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        try:
            response = requests.post(
                f"{self.auth_server_url}/api/user/register",
                json={
                    'user_id': self.user_id,
                    'username': self.full_username,
                    'public_key': public_pem
                },
                timeout=5
            )
            
            if response.status_code == 201:
                logger.info(f"Successfully registered user {self.full_username}")
                return True
            else:
                logger.error(f"Registration failed: {response.json()}")
                return False
        except Exception as e:
            logger.error(f"Error registering with server: {e}")
            return False
    
    def sign_challenge(self, challenge):
        """Sign the challenge with private key"""
        signature = self.private_key.sign(
            challenge.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def authenticate_session(self, session_data):
        """Send authentication to server"""
        try:
            session_id = session_data['session_id']
            challenge = session_data['challenge']
            
            print(f"\n{'='*60}")
            print(f"🔐 QR Code Detected!")
            print(f"{'='*60}")
            print(f"Session ID: {session_id[:20]}...")
            print(f"Server: {session_data.get('server_id', 'Unknown')}")
            print(f"User: {self.full_username}")
            print(f"{'='*60}")
            
            signature = self.sign_challenge(challenge)
            
            print("📡 Sending authentication request...")
            response = requests.post(
                f"{self.auth_server_url}/api/authenticate",
                json={
                    'session_id': session_id,
                    'user_id': self.user_id,
                    'signature': signature
                },
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"✅ Authentication successful!")
                print(f"{'='*60}\n")
                return True
            else:
                error_msg = response.json().get('error', 'Unknown error')
                print(f"❌ Authentication failed: {error_msg}")
                print(f"{'='*60}\n")
                return False
                
        except Exception as e:
            print(f"❌ Error during authentication: {e}")
            return False
    
    def scan_screen_region(self, monitor_region=None, timeout=60):
        """Scan screen for QR codes"""
        print(f"\n{'='*60}")
        print(f"🎯 Screen Scanner Active")
        print(f"{'='*60}")
        print(f"User: {self.full_username}")
        print(f"Timeout: {timeout} seconds")
        print(f"{'='*60}\n")
        
        print("🔍 Looking for QR codes...")
        
        start_time = time.time()
        last_scan_time = 0
        scan_interval = config['scanner']['poll_interval']
        
        self.scanning = True
        
        with mss.mss() as sct:
            while self.scanning:
                current_time = time.time()
                
                if current_time - start_time > timeout:
                    print(f"\n⏱️  Timeout reached ({timeout}s)")
                    print(f"❌ No QR code found")
                    return False
                
                if current_time - last_scan_time < scan_interval:
                    time.sleep(0.1)
                    continue
                
                last_scan_time = current_time
                
                if monitor_region:
                    screenshot = sct.grab(monitor_region)
                else:
                    screenshot = sct.grab(sct.monitors[1])
                
                img = np.array(screenshot)
                img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
                
                decoded_objects = pyzbar.decode(img)
                
                elapsed = current_time - start_time
                if int(elapsed) % 5 == 0 and elapsed > 0:
                    remaining = timeout - int(elapsed)
                    print(f"⏳ Still scanning... ({remaining}s remaining)")
                
                for obj in decoded_objects:
                    try:
                        qr_data = json.loads(obj.data.decode('utf-8'))
                        
                        if all(k in qr_data for k in ['session_id', 'challenge', 'server_id']):
                            print(f"\n✅ Valid QR code detected!")
                            success = self.authenticate_session(qr_data)
                            self.scanning = False
                            return success
                            
                    except json.JSONDecodeError:
                        pass
                    except Exception as e:
                        logger.error(f"Error processing QR code: {e}")
        
        return False
    
    def start_rdp_and_scan(self, rdp_server_ip, rdp_username=None, scan_timeout=90):
        """Start RDP connection and scan for QR code"""
        print(f"\n{'='*60}")
        print(f"🚀 Starting RDP Connection")
        print(f"{'='*60}")
        print(f"Target: {rdp_server_ip}")
        print(f"{'='*60}\n")
        
        try:
            rdp_file = Path("temp_connection.rdp")
            rdp_content = f"""screen mode id:i:2
desktopwidth:i:1024
desktopheight:i:768
session bpp:i:32
full address:s:{rdp_server_ip}
authentication level:i:2
"""
            if rdp_username:
                rdp_content += f"username:s:{rdp_username}\n"
            
            with open(rdp_file, 'w') as f:
                f.write(rdp_content)
            
            print("🖥️  Launching Remote Desktop Connection...")
            subprocess.Popen(['mstsc', str(rdp_file)])
            
            time.sleep(3)
            
            print("🔍 Starting QR code scanner...")
            success = self.scan_screen_region(timeout=scan_timeout)
            
            if rdp_file.exists():
                rdp_file.unlink()
            
            return success
            
        except Exception as e:
            logger.error(f"Error starting RDP: {e}")
            return False
    
    def stop_scanning(self):
        """Stop the scanning process"""
        self.scanning = False


class QRScannerGUI:
    """GUI for QR Scanner"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("RDP QR Authentication Scanner")
        self.root.geometry("500x450")
        self.client = None
        self.setup_ui()
    
    def setup_ui(self):
        title = tk.Label(self.root, text="🔐 RDP QR Authentication", 
                        font=("Arial", 16, "bold"))
        title.pack(pady=20)
        
        config_frame = tk.Frame(self.root)
        config_frame.pack(pady=10, padx=20, fill="x")
        
        tk.Label(config_frame, text="Auth Server URL:").grid(row=0, column=0, sticky="w", pady=5)
        self.auth_server_entry = tk.Entry(config_frame, width=40)
        self.auth_server_entry.insert(0, config['auth_server'])
        self.auth_server_entry.grid(row=0, column=1, pady=5)
        
        tk.Label(config_frame, text="Your User ID:").grid(row=1, column=0, sticky="w", pady=5)
        self.user_id_entry = tk.Entry(config_frame, width=40)
        self.user_id_entry.insert(0, config['user']['user_id'])
        self.user_id_entry.grid(row=1, column=1, pady=5)
        
        tk.Label(config_frame, text="Your Username:").grid(row=2, column=0, sticky="w", pady=5)
        self.username_entry = tk.Entry(config_frame, width=40)
        self.username_entry.insert(0, config['user']['username'])
        self.username_entry.grid(row=2, column=1, pady=5)
        
        tk.Label(config_frame, text="Domain (optional):").grid(row=3, column=0, sticky="w", pady=5)
        self.domain_entry = tk.Entry(config_frame, width=40)
        self.domain_entry.insert(0, config['user'].get('domain', ''))
        self.domain_entry.grid(row=3, column=1, pady=5)
        
        tk.Label(config_frame, text="RDP Server IP:").grid(row=4, column=0, sticky="w", pady=5)
        self.rdp_server_entry = tk.Entry(config_frame, width=40)
        self.rdp_server_entry.insert(0, "192.168.1.10")
        self.rdp_server_entry.grid(row=4, column=1, pady=5)
        
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=20)
        
        self.connect_btn = tk.Button(button_frame, text="🚀 Connect & Scan", 
                                     command=self.start_connection,
                                     font=("Arial", 12, "bold"),
                                     bg="#4CAF50", fg="white",
                                     padx=20, pady=10)
        self.connect_btn.pack(side="left", padx=10)
        
        self.scan_btn = tk.Button(button_frame, text="🔍 Scan Current Screen", 
                                  command=self.scan_current_screen,
                                  font=("Arial", 12),
                                  padx=20, pady=10)
        self.scan_btn.pack(side="left", padx=10)
        
        self.status_label = tk.Label(self.root, text="Ready", 
                                     font=("Arial", 10),
                                     fg="blue")
        self.status_label.pack(pady=10)
        
        instructions = """
Instructions:
1. Enter your Auth Server URL and credentials
2. Enter the RDP Server IP address
3. Click 'Connect & Scan' to start RDP and automatically scan
   OR click 'Scan Current Screen' if RDP is already open
        """
        tk.Label(self.root, text=instructions, justify="left", 
                font=("Arial", 9)).pack(pady=10)
    
    def initialize_client(self):
        auth_server = self.auth_server_entry.get().strip()
        user_id = self.user_id_entry.get().strip()
        username = self.username_entry.get().strip()
        domain = self.domain_entry.get().strip() or None
        
        if not all([auth_server, user_id, username]):
            messagebox.showerror("Error", "Please fill in all required fields")
            return False
        
        try:
            self.client = QRAuthClient(auth_server, user_id, username, domain)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize client: {e}")
            return False
    
    def start_connection(self):
        if not self.initialize_client():
            return
        
        rdp_server = self.rdp_server_entry.get().strip()
        if not rdp_server:
            messagebox.showerror("Error", "Please enter RDP server IP")
            return
        
        self.status_label.config(text="Starting RDP connection...", fg="orange")
        self.connect_btn.config(state="disabled")
        self.root.update()
        
        def scan_thread():
            success = self.client.start_rdp_and_scan(rdp_server, scan_timeout=90)
            
            self.root.after(0, lambda: self.connect_btn.config(state="normal"))
            
            if success:
                self.root.after(0, lambda: self.status_label.config(
                    text="✅ Authentication successful!", fg="green"))
                self.root.after(0, lambda: messagebox.showinfo(
                    "Success", "Authentication successful!"))
            else:
                self.root.after(0, lambda: self.status_label.config(
                    text="❌ Authentication failed", fg="red"))
                self.root.after(0, lambda: messagebox.showerror(
                    "Failed", "No QR code found or authentication failed."))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def scan_current_screen(self):
        if not self.initialize_client():
            return
        
        self.status_label.config(text="Scanning screen for QR code...", fg="orange")
        self.scan_btn.config(state="disabled")
        self.root.update()
        
        def scan_thread():
            success = self.client.scan_screen_region(timeout=60)
            
            self.root.after(0, lambda: self.scan_btn.config(state="normal"))
            
            if success:
                self.root.after(0, lambda: self.status_label.config(
                    text="✅ Authentication successful!", fg="green"))
                self.root.after(0, lambda: messagebox.showinfo(
                    "Success", "Authentication successful!"))
            else:
                self.root.after(0, lambda: self.status_label.config(
                    text="❌ No QR code found", fg="red"))
                self.root.after(0, lambda: messagebox.showwarning(
                    "Not Found", "No valid QR code found on screen."))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def run(self):
        self.root.mainloop()


def main():
    print("="*60)
    print("RDP QR Authentication Scanner")
    print("="*60)
    
    app = QRScannerGUI()
    app.run()


if __name__ == "__main__":
    main()
