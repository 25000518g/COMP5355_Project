import ipaddress
import json
import os
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HOST = '127.0.0.1'
PORT = 5555
BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / 'database.json'
TLS_DIR = BASE_DIR / 'tls'
CA_KEY_FILE = TLS_DIR / 'ca_key.pem'
CA_CERT_FILE = TLS_DIR / 'ca_cert.pem'
SERVER_KEY_FILE = TLS_DIR / 'server_key.pem'
SERVER_CERT_FILE = TLS_DIR / 'server_cert.pem'

db_lock = threading.Lock()


def ensure_json_database_exists():
    if not DB_FILE.exists():
        with open(DB_FILE, 'w', encoding='utf-8') as f:
            json.dump({"users": {}, "messages": {}}, f, indent=4)


def load_db():
    ensure_json_database_exists()
    with open(DB_FILE, 'r', encoding='utf-8') as f:
        db = json.load(f)
    db.setdefault('users', {})
    db.setdefault('messages', {})
    return db


def save_db(data):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)


def _write_private_key(path, key):
    with open(path, 'wb') as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _write_certificate(path, cert):
    with open(path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def ensure_tls_material():
    TLS_DIR.mkdir(parents=True, exist_ok=True)

    if CA_KEY_FILE.exists() and CA_CERT_FILE.exists() and SERVER_KEY_FILE.exists() and SERVER_CERT_FILE.exists():
        return

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'TW'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'COMP5355 Project'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'COMP5355 Project Root CA'),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'TW'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'COMP5355 Project'),
        x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1'),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    _write_private_key(CA_KEY_FILE, ca_key)
    _write_certificate(CA_CERT_FILE, ca_cert)
    _write_private_key(SERVER_KEY_FILE, server_key)
    _write_certificate(SERVER_CERT_FILE, server_cert)


def create_tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(SERVER_CERT_FILE), keyfile=str(SERVER_KEY_FILE))
    return context


def _read_json_line(reader):
    line = reader.readline()
    if not line:
        return None
    return json.loads(line.decode('utf-8'))


def _write_json_line(writer, payload):
    writer.write((json.dumps(payload) + '\n').encode('utf-8'))
    writer.flush()


def handle_client(raw_socket, tls_context):
    try:
        with tls_context.wrap_socket(raw_socket, server_side=True) as client_socket:
            reader = client_socket.makefile('rb')
            writer = client_socket.makefile('wb')

            while True:
                try:
                    request = _read_json_line(reader)
                    if request is None:
                        break

                    action = request.get('action')

                    with db_lock:
                        db = load_db()
                        response = {'status': 'error', 'message': 'Unknown action'}

                        if action == 'register':
                            username = request.get('username')
                            if username in db['users']:
                                response = {'status': 'error', 'message': 'Username already exists.'}
                            else:
                                db['users'][username] = {
                                    'password_hash': request.get('password_hash'),
                                    'password_salt': request.get('password_salt'),
                                    'public_key': request.get('public_key'),
                                }
                                db['messages'].setdefault(username, [])
                                save_db(db)
                                response = {'status': 'success'}

                        elif action == 'get_auth_salt':
                            username = request.get('username')
                            if username in db['users']:
                                response = {
                                    'status': 'success',
                                    'password_salt': db['users'][username]['password_salt'],
                                }
                            else:
                                response = {'status': 'error', 'message': 'User not found.'}

                        elif action == 'login':
                            username = request.get('username')
                            pwd_hash = request.get('password_hash')
                            if username in db['users'] and db['users'][username]['password_hash'] == pwd_hash:
                                response = {'status': 'success'}
                            else:
                                response = {'status': 'error', 'message': 'Invalid username or password.'}

                        elif action == 'get_key':
                            target_user = request.get('target_user')
                            if target_user in db['users']:
                                response = {'status': 'success', 'public_key': db['users'][target_user]['public_key']}
                            else:
                                response = {'status': 'error', 'message': 'User not found.'}

                        elif action == 'send_msg':
                            recipient = request.get('recipient')
                            if recipient in db['users']:
                                db['messages'].setdefault(recipient, [])
                                db['messages'][recipient].append(request.get('packet'))
                                save_db(db)
                                response = {'status': 'success', 'message': 'Message dispatched into mailbox.'}
                            else:
                                response = {'status': 'error', 'message': 'Recipient not found.'}

                        elif action == 'fetch_messages':
                            username = request.get('username')
                            response = {'status': 'success', 'messages': db['messages'].get(username, [])}

                    _write_json_line(writer, response)
                except json.JSONDecodeError:
                    _write_json_line(writer, {'status': 'error', 'message': 'Invalid JSON payload.'})
                except Exception as exc:
                    print(f'Error handling client request: {exc}')
                    break
    except ssl.SSLError as exc:
        print(f'TLS error: {exc}')
    except Exception as exc:
        print(f'Connection error: {exc}')
    finally:
        try:
            raw_socket.close()
        except Exception:
            pass


def main():
    ensure_json_database_exists()
    ensure_tls_material()

    tls_context = create_tls_context()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f'[*] TLS server listening on {HOST}:{PORT}')
    print(f'[*] CA certificate: {CA_CERT_FILE}')

    while True:
        client_sock, addr = server.accept()
        print(f'[*] Accepted connection from {addr[0]}:{addr[1]}')
        thread = threading.Thread(target=handle_client, args=(client_sock, tls_context), daemon=True)
        thread.start()


if __name__ == '__main__':
    main()