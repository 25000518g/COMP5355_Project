import hashlib
import json
import secrets
import socket
import ssl
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HOST = '127.0.0.1'
PORT = 5555
BASE_DIR = Path(__file__).resolve().parent
TLS_DIR = BASE_DIR / 'tls'
CA_CERT_FILE = TLS_DIR / 'ca_cert.pem'

class SecureClient:
    def __init__(self):
        self.username = None
        self.private_key = None
        self.public_key = None
        self.profile_path = None
        self.profile = {}

    def _default_profile(self):
        return {
            'local_salt': None,
            'encrypted_private_key': None,
            'public_key_pem': None,
            'server_ca_cert_pem': None,
            'server_certificate_pem': None,
            'trusted_public_keys': {},
            'trusted_public_key_fingerprints': {},
            'received_message_ids': [],
        }

    def _canonical_json(self, payload):
        return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    def _fingerprint_pem(self, pem_text):
        return hashlib.sha256(pem_text.encode('utf-8')).hexdigest()

    def _profile_file(self, username):
        return BASE_DIR / f'{username}_profile.json'

    def _load_profile(self, username):
        path = self._profile_file(username)
        self.profile_path = path
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                stored = json.load(f)
        else:
            stored = {}

        profile = self._default_profile()
        profile.update(stored)
        profile.setdefault('trusted_public_keys', {})
        profile.setdefault('trusted_public_key_fingerprints', {})
        profile.setdefault('received_message_ids', [])
        self.profile = profile
        return profile

    def _save_profile(self):
        if not self.profile_path:
            return
        with open(self.profile_path, 'w', encoding='utf-8') as f:
            json.dump(self.profile, f, indent=4)

    def _load_tls_context(self):
        if not CA_CERT_FILE.exists():
            return None, {'status': 'error', 'message': 'TLS trust store not found. Start the server first so it can generate the CA certificate.'}

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cafile=str(CA_CERT_FILE))
        context.check_hostname = True
        return context, None

    def _write_request(self, secure_socket, payload):
        secure_socket.sendall((json.dumps(payload) + '\n').encode('utf-8'))

    def _read_response(self, secure_socket):
        buffer = b''
        while not buffer.endswith(b'\n'):
            chunk = secure_socket.recv(4096)
            if not chunk:
                break
            buffer += chunk
        if not buffer:
            return None
        return json.loads(buffer.decode('utf-8').strip())

    def _get_profile_trust_state(self):
        self.profile.setdefault('trusted_public_keys', {})
        self.profile.setdefault('trusted_public_key_fingerprints', {})
        self.profile.setdefault('received_message_ids', [])
        return self.profile

    def _pin_or_verify_public_key(self, username, public_key_pem):
        trust_state = self._get_profile_trust_state()
        fingerprint = self._fingerprint_pem(public_key_pem)
        known_fingerprint = trust_state['trusted_public_key_fingerprints'].get(username)

        if known_fingerprint is None:
            trust_state['trusted_public_key_fingerprints'][username] = fingerprint
            trust_state['trusted_public_keys'][username] = public_key_pem
            self._save_profile()
            return True, fingerprint

        if known_fingerprint != fingerprint:
            return False, fingerprint

        trust_state['trusted_public_keys'][username] = public_key_pem
        return True, fingerprint

    def _get_user_public_key(self, target_user):
        payload = {'action': 'get_key', 'target_user': target_user}
        res = self.send_request(payload)
        if res.get('status') == 'success':
            public_key_pem = res['public_key']
            ok, _ = self._pin_or_verify_public_key(target_user, public_key_pem)
            if not ok:
                return None, f"Security error: public key for '{target_user}' changed unexpectedly."
            return serialization.load_pem_public_key(public_key_pem.encode('utf-8')), None
        return None, res.get('message', f"User '{target_user}' not found.")

    def _hash_password(self, password, salt=None):
        """Hashes the password securely using PBKDF2 to prevent dictionary/passive database attacks."""
        if salt is None:
            salt = secrets.token_bytes(16)
        else:
            salt = bytes.fromhex(salt)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        hashed_password = kdf.derive(password.encode('utf-8'))
        return hashed_password.hex(), salt.hex()

    def send_request(self, payload):
        try:
            context, error = self._load_tls_context()
            if error:
                return error

            with socket.create_connection((HOST, PORT)) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=HOST) as secure_socket:
                    self._write_request(secure_socket, payload)
                    response = self._read_response(secure_socket)
                    if response is None:
                        return {'status': 'error', 'message': 'No response from server.'}
                    return response
        except Exception as e:
            return {'status': 'error', 'message': f'Connection failed: {e}'}

    def register(self, username, password):
        # 1. Generate identity cryptographic keys
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # 2. Hash the password with a fresh salt for the server verification
        pwd_hash, pwd_salt = self._hash_password(password)

        payload = {
            "action": "register",
            "username": username,
            "password_hash": pwd_hash,
            "password_salt": pwd_salt,
            "public_key": public_pem
        }
        
        res = self.send_request(payload)
        if res.get("status") == "success":
            # 3. Protect the local private key file using the user's password
            # If anyone steals this file, they still need the password to decrypt it
            local_salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=local_salt, iterations=100000)
            encryption_key = kdf.derive(password.encode('utf-8'))
            
            encrypted_private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(encryption_key)
            )
            
            # Save the local profile
            server_ca_cert_pem = CA_CERT_FILE.read_text(encoding='utf-8') if CA_CERT_FILE.exists() else None
            profile_data = {
                "local_salt": local_salt.hex(),
                "encrypted_private_key": encrypted_private_pem.decode('utf-8'),
                "public_key_pem": public_pem,
                "server_ca_cert_pem": server_ca_cert_pem,
                "server_certificate_pem": None,
                "trusted_public_keys": {
                    username: public_pem
                },
                "trusted_public_key_fingerprints": {
                    username: self._fingerprint_pem(public_pem)
                },
                "received_message_ids": []
            }
            with open(f"{username}_profile.json", "w") as f:
                json.dump(profile_data, f)
                
            return "Registration successful! Profile and keys created securely."
        return res.get("message")

    def login(self, username, password):
        # 1. Request password salt from the server
        salt_req = {"action": "get_auth_salt", "username": username}
        salt_res = self.send_request(salt_req)
        
        if salt_res.get("status") != "success":
            return salt_res.get("message", "User look-up failed.")
            
        # 2. Hash the input password using the server's tracking salt
        server_salt = salt_res["password_salt"]
        computed_hash, _ = self._hash_password(password, salt=server_salt)

        # 3. Request Login Token verification
        login_req = {
            "action": "login",
            "username": username,
            "password_hash": computed_hash
        }
        res = self.send_request(login_req)
        
        if res.get("status") == "success":
            # 4. Authenticated with server! Now decrypt the local private key for E2EE messaging
            try:
                profile = self._load_profile(username)
                
                local_salt = bytes.fromhex(profile["local_salt"])
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=local_salt, iterations=100000)
                decryption_key = kdf.derive(password.encode('utf-8'))
                
                self.private_key = serialization.load_pem_private_key(
                    profile["encrypted_private_key"].encode('utf-8'),
                    password=decryption_key
                )
                self.public_key = self.private_key.public_key()
                self.username = username
                profile["public_key_pem"] = profile.get("public_key_pem") or self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                profile["server_ca_cert_pem"] = profile.get("server_ca_cert_pem") or (
                    CA_CERT_FILE.read_text(encoding='utf-8') if CA_CERT_FILE.exists() else None
                )
                profile.setdefault("trusted_public_keys", {})
                profile.setdefault("trusted_public_key_fingerprints", {})
                profile.setdefault("received_message_ids", [])
                if username not in profile["trusted_public_keys"]:
                    profile["trusted_public_keys"][username] = profile["public_key_pem"]
                if username not in profile["trusted_public_key_fingerprints"]:
                    profile["trusted_public_key_fingerprints"][username] = self._fingerprint_pem(profile["public_key_pem"])
                self.profile = profile
                self._save_profile()
                return "Login successful! Session unlocked."
            except Exception:
                return "Login Error: Could not unlock local cryptographic keys. Corrupted profile or bad local context."
        
        return res.get("message", "Invalid credentials.")

    def logout(self):
        if not self.username:
            return "No active session to log out from."
        user = self.username
        self.username = None
        self.private_key = None
        self.public_key = None
        return f"User '{user}' logged out successfully."

    def get_recipient_key(self, target_user):
        public_key, error = self._get_user_public_key(target_user)
        if error:
            return None
        return public_key

    def _build_envelope(self, recipient, message_text):
        timestamp = int(time.time())
        message_id = secrets.token_hex(16)

        payload_dict = {
            "msg": message_text,
            "timestamp": timestamp,
            "sender": self.username,
            "recipient": recipient,
            "message_id": message_id,
        }
        aad_fields = {
            "version": 1,
            "sender": self.username,
            "recipient": recipient,
            "timestamp": timestamp,
            "message_id": message_id,
        }
        serialized_payload = self._canonical_json(payload_dict)
        aad = self._canonical_json(aad_fields)

        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, serialized_payload, aad)

        return {
            "version": 1,
            "sender": self.username,
            "recipient": recipient,
            "timestamp": timestamp,
            "message_id": message_id,
            "encrypted_aes_key": None,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "aad": aad.hex(),
            "signature": None,
            "_aes_key": aes_key,
        }

    def send_message(self, recipient, message_text):
        if not self.username:
            return "Error: You must be logged in to send messages."
        
        recipient_key = self.get_recipient_key(recipient)
        if not recipient_key:
            return f"Error: Recipient '{recipient}' not found."

        envelope = self._build_envelope(recipient, message_text)
        aes_key = envelope.pop("_aes_key")

        # Protect AES session key using recipient's public identity key
        encrypted_aes_key = recipient_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        envelope["encrypted_aes_key"] = encrypted_aes_key.hex()

        signed_fields = {
            key: envelope[key]
            for key in ["version", "sender", "recipient", "timestamp", "message_id", "encrypted_aes_key", "nonce", "ciphertext", "aad"]
        }
        signature = self.private_key.sign(
            self._canonical_json(signed_fields),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        envelope["signature"] = signature.hex()

        secure_package = {
            key: envelope[key]
            for key in ["version", "sender", "recipient", "timestamp", "message_id", "encrypted_aes_key", "nonce", "ciphertext", "aad", "signature"]
        }
        
        route_req = {
            "action": "send_msg",
            "sender": self.username,
            "recipient": recipient,
            "packet": secure_package
        }
        
        res = self.send_request(route_req)
        return res.get("message")

    def receive_messages(self):
        if not self.username:
            return "Error: You must be logged in to fetch messages."
            
        req = {"action": "fetch_messages", "username": self.username}
        res = self.send_request(req)
        
        if res.get("status") != "success":
            return res.get("message")
            
        packets = res.get("messages", [])
        if not packets:
            return "Your inbox is empty."
            
        decrypted_messages = []
        seen_message_ids = set(self.profile.get("received_message_ids", []))
        for index, pkg in enumerate(packets, 1):
            try:
                sender = pkg["sender"]
                recipient_name = pkg["recipient"]
                message_id = pkg["message_id"]
                version = pkg.get("version", 1)

                if recipient_name != self.username:
                    raise ValueError("Packet recipient mismatch")

                sender_key, error = self._get_user_public_key(sender)
                if error:
                    raise ValueError(error)

                signed_fields = {
                    key: pkg[key]
                    for key in ["version", "sender", "recipient", "timestamp", "message_id", "encrypted_aes_key", "nonce", "ciphertext", "aad"]
                }
                sender_key.verify(
                    bytes.fromhex(pkg["signature"]),
                    self._canonical_json(signed_fields),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )

                if message_id in seen_message_ids:
                    decrypted_messages.append(f"[{index}] [WARNING: Replay detected; duplicate message ignored]")
                    continue

                encrypted_aes_key = bytes.fromhex(pkg["encrypted_aes_key"])
                nonce = bytes.fromhex(pkg["nonce"])
                ciphertext = bytes.fromhex(pkg["ciphertext"])
                aad = bytes.fromhex(pkg["aad"])
                
                # Decrypt AES Key using Private RSA Identity Key
                aes_key = self.private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decrypt body context
                aesgcm = AESGCM(aes_key)
                decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
                payload = json.loads(decrypted_bytes.decode('utf-8'))

                if payload.get("message_id") != message_id or payload.get("sender") != sender or payload.get("recipient") != self.username:
                    raise ValueError("Payload metadata mismatch")

                if version != 1:
                    raise ValueError("Unsupported message version")
                
                # Handle replay attacks using per-client message ID tracking.
                if int(time.time()) - int(payload["timestamp"]) > 86400:
                    decrypted_messages.append(f"[{index}] [WARNING: Message expired or Replayed]")
                else:
                    seen_message_ids.add(message_id)
                    decrypted_messages.append(f"[{index}] From {payload['sender']}: {payload['msg']}")
            except Exception:
                decrypted_messages.append(f"[{index}] [ERROR: Tampering/Corrupted Data Payload detected]")

        self.profile["received_message_ids"] = sorted(seen_message_ids)
        self._save_profile()
        return "\n".join(decrypted_messages)


def main():
    client = SecureClient()
    print("==================================================")
    print("      INTERACTIVE PASS-SECURED MESSENGER CLIENT   ")
    print("==================================================")
    
    while True:
        status = f"Logged in as: {client.username}" if client.username else "Status: Logged Out"
        print(f"\n--- {status} ---")
        print("1. Register Account")
        print("2. Login")
        print("3. Logout")
        print("4. Send Secure Message")
        print("5. Check Inbox (Receive)")
        print("6. Exit")
        
        choice = input("Option: ").strip()
        
        if choice == "1":
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            if user and password:
                print(client.register(user, password))
        elif choice == "2":
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            if user and password:
                print(client.login(user, password))
        elif choice == "3":
            print(client.logout())
        elif choice == "4":
            to_user = input("Send to user: ").strip()
            msg = input("Message: ").strip()
            if to_user and msg:
                print(client.send_message(to_user, msg))
        elif choice == "5":
            print("\n--- Inbox Messages ---")
            print(client.receive_messages())
        elif choice == "6":
            break

if __name__ == "__main__":
    main()