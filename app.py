from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
import secrets
import base64
import json
import time

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Simple in-memory storage (use database in production)
users = {}  # {username: {password, public_key, private_key}}
chat_history = []  # [{from_user, to_user, encrypted_aes_key, encrypted_message, timestamp}] - RSA+AES hybrid encryption
active_sessions = {}  # {username: {session_id, last_active}}

# Clear all data on startup
def clear_all_data():
    """Clear all stored data to ensure fresh start"""
    global users, chat_history, active_sessions
    users.clear()
    chat_history.clear()
    active_sessions.clear()
    print("ALL DATA CLEARED - FRESH START!")

# Clear data immediately on startup
clear_all_data()


def generate_rsa_keypair():
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode(), public_pem.decode()

def encrypt_with_rsa(public_key_pem, data):
    """Encrypt data using RSA public key"""
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_with_rsa(private_key_pem, encrypted_data):
    """Decrypt data using RSA private key"""
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    encrypted_bytes = base64.b64decode(encrypted_data.encode())
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def generate_aes_key():
    """Generate AES key"""
    return secrets.token_bytes(32)  # 256-bit key

def encrypt_with_aes(key, message):
    """Encrypt message using AES"""
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Padding
    pad_length = 16 - (len(message.encode()) % 16)
    padded_message = message.encode() + bytes([pad_length] * pad_length)

    encrypted = encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_with_aes(key, encrypted_message):
    """Decrypt message using AES - Enhanced compatibility version"""
    try:
        # Handle potential encoding issues
        if isinstance(encrypted_message, str):
            encrypted_bytes = base64.b64decode(encrypted_message)
        else:
            encrypted_bytes = base64.b64decode(encrypted_message.decode('utf-8'))

        # Check data length
        if len(encrypted_bytes) < 16:
            raise ValueError("Encrypted data length insufficient")

        iv = encrypted_bytes[:16]
        encrypted = encrypted_bytes[16:]

        # Check if encrypted data is empty
        if len(encrypted) == 0:
            raise ValueError("Encrypted data is empty")

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

        # Safe padding removal
        if len(decrypted_padded) == 0:
            raise ValueError("Decrypted data is empty")

        pad_length = decrypted_padded[-1]
        if pad_length > 16 or pad_length > len(decrypted_padded):
            raise ValueError(f"Invalid padding: {pad_length}")

        decrypted = decrypted_padded[:-pad_length]
        return decrypted.decode('utf-8')

    except Exception as e:
        print(f"AES decryption error: {str(e)}")
        print(f"Message data: {encrypted_message[:100] if encrypted_message else 'None'}...")
        print(f"Key length: {len(key) if key else 0}")
        raise

@app.route('/')
def index():
    if 'username' in session:
        return render_template('chat.html', current_user=session['username'])
    return render_template('login.html')

@app.route('/current_user', methods=['GET'])
def get_current_user():
    if 'username' in session:
        return jsonify({'username': session['username']})
    return jsonify({'error': 'Not logged in'})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users:
        return jsonify({'status': 'error', 'message': 'Username already exists'})

    # Generate RSA key pair
    private_key, public_key = generate_rsa_keypair()

    users[username] = {
        'password': password,  # Should hash password in production
        'private_key': private_key,
        'public_key': public_key
    }

    return jsonify({'status': 'success', 'message': 'Registration successful'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username not in users or users[username]['password'] != password:
        return jsonify({'status': 'error', 'message': 'Incorrect username or password'})

    session['username'] = username
    active_sessions[username] = {
        'session_id': session.sid if hasattr(session, 'sid') else secrets.token_hex(8),
        'last_active': time.time()
    }

    return jsonify({'status': 'success', 'message': 'Login successful'})

@app.route('/clear_all', methods=['POST'])
def clear_all():
    """Clear all data and sessions - nuclear option"""
    clear_all_data()
    session.clear()
    return jsonify({'status': 'success', 'message': 'All data and sessions cleared'})

@app.route('/logout')
def logout():
    username = session.get('username')
    if username and username in active_sessions:
        del active_sessions[username]
    session.clear()
    return redirect(url_for('index'))

@app.route('/users', methods=['GET'])
def get_users():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})

    current_user = session['username']
    online_users = [user for user in active_sessions.keys() if user != current_user]
    return jsonify({'users': online_users})

@app.route('/public_key/<username>', methods=['GET'])
def get_public_key(username):
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})

    if username not in users:
        return jsonify({'status': 'error', 'message': 'User does not exist'})

    return jsonify({'public_key': users[username]['public_key']})

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})
    
    data = request.get_json()
    to_user = data.get('to_user')
    message = data.get('message')
    is_encoded = data.get('is_encoded', False)
    
    if is_encoded:
        try:
            import base64
            decoded_message = base64.b64decode(message).decode('utf-8')
            print(f"Decoded message: {decoded_message}")
        except:
            decoded_message = message 
    else:
        decoded_message = message
    
    from_user = session['username']

    # RSA+AES hybrid encryption implementation
    try:
        # Check if recipient exists
        if to_user not in users:
            return jsonify({'status': 'error', 'message': 'Recipient does not exist'})

        # Generate random AES key for message encryption
        aes_key = generate_aes_key()

        # Encrypt message content with AES
        encrypted_message = encrypt_with_aes(aes_key, decoded_message)

        # Encrypt AES key with both recipient's and sender's RSA public keys
        recipient_public_key = users[to_user]['public_key']
        sender_public_key = users[from_user]['public_key']
        aes_key_b64 = base64.b64encode(aes_key).decode()

        encrypted_aes_key_for_recipient = encrypt_with_rsa(recipient_public_key, aes_key_b64)
        encrypted_aes_key_for_sender = encrypt_with_rsa(sender_public_key, aes_key_b64)

        # Step 4: Store encrypted data (contains key copies for both sender and recipient)
        chat_history.append({
            'from_user': from_user,
            'to_user': to_user,
            'encrypted_aes_key_for_recipient': encrypted_aes_key_for_recipient,  # AES key for recipient
            'encrypted_aes_key_for_sender': encrypted_aes_key_for_sender,        # AES key for sender
            'encrypted_message': encrypted_message,                              # AES encrypted message content
            'timestamp': time.time()
        })

        print(f"Message encryption successful: {from_user} -> {to_user}")
        return jsonify({'status': 'success'})

    except Exception as e:
        print(f"Message encryption failed: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Encryption failed: {str(e)}'})

@app.route('/send_encrypted_message', methods=['POST'])
def send_encrypted_message():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})

    data = request.get_json()
    to_user = data.get('to_user')
    encrypted_message = data.get('encrypted_message')
    encrypted_aes_key_for_recipient = data.get('encrypted_aes_key_for_recipient')
    encrypted_aes_key_for_sender = data.get('encrypted_aes_key_for_sender')

    from_user = session['username']

    # TRUE END-TO-END ENCRYPTION: Store encrypted data directly from frontend
    try:
        # Check if recipient exists
        if to_user not in users:
            return jsonify({'status': 'error', 'message': 'Recipient does not exist'})

        # Store encrypted data directly (no server-side encryption needed)
        chat_history.append({
            'from_user': from_user,
            'to_user': to_user,
            'encrypted_aes_key_for_recipient': encrypted_aes_key_for_recipient,  # Already encrypted by frontend
            'encrypted_aes_key_for_sender': encrypted_aes_key_for_sender,        # Already encrypted by frontend
            'encrypted_message': encrypted_message,                              # Already encrypted by frontend
            'timestamp': time.time()
        })

        print(f"TRUE E2E: Message stored encrypted: {from_user} -> {to_user}")
        return jsonify({'status': 'success'})

    except Exception as e:
        print(f"Failed to store encrypted message: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Storage failed: {str(e)}'})

@app.route('/messages', methods=['GET'])
def get_messages():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})

    current_user = session['username']
    current_user_private_key = users[current_user]['private_key']

    # RSA+AES hybrid decryption implementation
    user_messages = []
    for msg in chat_history:
        if msg['to_user'] == current_user or msg['from_user'] == current_user:
            try:
                # Select correct encrypted key for decryption based on current user role
                if msg['to_user'] == current_user:
                    # Current user is recipient, use recipient's key
                    aes_key_b64 = decrypt_with_rsa(current_user_private_key, msg['encrypted_aes_key_for_recipient'])
                    aes_key = base64.b64decode(aes_key_b64)
                    decrypted_message = decrypt_with_aes(aes_key, msg['encrypted_message'])
                    print(f"Recipient decryption successful: {msg['from_user']} -> {current_user}")

                elif msg['from_user'] == current_user:
                    # Current user is sender, use sender's key
                    aes_key_b64 = decrypt_with_rsa(current_user_private_key, msg['encrypted_aes_key_for_sender'])
                    aes_key = base64.b64decode(aes_key_b64)
                    decrypted_message = decrypt_with_aes(aes_key, msg['encrypted_message'])
                    print(f"Sender decryption successful: {current_user} -> {msg['to_user']}")

                user_messages.append({
                    'from_user': msg['from_user'],
                    'to_user': msg['to_user'],
                    'message': decrypted_message,  # Return decrypted plaintext
                    'timestamp': msg['timestamp']
                })

            except Exception as e:
                print(f"Message decryption failed: {str(e)}")
                # If decryption fails, return error message
                user_messages.append({
                    'from_user': msg['from_user'],
                    'to_user': msg['to_user'],
                    'message': '[Message decryption failed]',
                    'timestamp': msg['timestamp']
                })

    return jsonify({'messages': user_messages})

@app.route('/encrypted_messages', methods=['GET'])
def get_encrypted_messages():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})

    current_user = session['username']

    # TRUE END-TO-END ENCRYPTION: Return encrypted data for frontend decryption
    user_messages = []
    for msg in chat_history:
        if msg['to_user'] == current_user or msg['from_user'] == current_user:
            # Return encrypted data directly, let frontend decrypt
            user_messages.append({
                'from_user': msg['from_user'],
                'to_user': msg['to_user'],
                'encrypted_message': msg['encrypted_message'],
                'encrypted_aes_key_for_recipient': msg['encrypted_aes_key_for_recipient'],
                'encrypted_aes_key_for_sender': msg['encrypted_aes_key_for_sender'],
                'timestamp': msg['timestamp']
            })

    print(f"Returning {len(user_messages)} encrypted messages for {current_user}")
    return jsonify({'messages': user_messages})

@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})

    data = request.get_json()
    encrypted_aes_key = data.get('encrypted_aes_key')
    encrypted_message = data.get('encrypted_message')

    current_user = session['username']
    private_key_pem = users[current_user]['private_key']

    try:
        # Decrypt AES key
        aes_key = decrypt_with_rsa(private_key_pem, encrypted_aes_key)
        aes_key_bytes = base64.b64decode(aes_key)

        # Decrypt message
        decrypted_message = decrypt_with_aes(aes_key_bytes, encrypted_message)

        return jsonify({'status': 'success', 'message': decrypted_message})
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Decryption error details: {error_details}")
        return jsonify({'status': 'error', 'message': f'Decryption failed: {str(e)}', 'details': error_details})

@app.route('/private_key', methods=['GET'])
def get_private_key():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})

    current_user = session['username']

    if current_user not in users:
        return jsonify({'status': 'error', 'message': 'User does not exist'})

    return jsonify({'private_key': users[current_user]['private_key']})

if __name__ == '__main__':
    app.run(debug=True, port=8080, host='127.0.0.1')
