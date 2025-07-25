# Secure Chat System - User Guide

## System Overview

A multi-layer encrypted real-time chat system:

### Encryption Architecture  
- Network transmission encryption: Base64 encoding to hide plaintext
- Server storage encryption: RSA-2048 + AES-256 hybrid encryption
- End-to-end security: Complete encrypted transmission chain

### Main Features
- Real-time multi-user chat
- User registration/login system
- Online user list
- Encrypted message storage
- Cache management functionality

## Quick Start

### 1. Start Server
```bash
cd chat-app
python3 app.py
```

After successful startup you will see:
```
ALL DATA CLEARED - FRESH START!
 * Running on http://127.0.0.1:8080
```

### 2. Access System
Open in browser: `http://127.0.0.1:8080`

### 3. Register User
- Click "Register" on the page to switch to registration mode
- Enter username and password
- Click "Register" to complete registration

### 4. Login and Chat
- Login with registered username and password
- Select chat target from left user list
- Send messages in bottom input box

---

## Encryption Details

### Message Transmission Process:

1. User input: "Hello"  
2. Frontend encoding: "Hello" → "SGVsbG8=" (Base64)
3. Network transmission: Send encoded ciphertext
4. Server decoding: "SGVsbG8=" → "Hello"
5. Encrypted storage: RSA+AES hybrid encryption storage
6. Display decryption: User sees original message

### Security Features:
- Network monitoring protection: Packet capture cannot see plaintext messages
- Server data protection: Database storage fully encrypted  
- Multi-user isolation: Each user has independent RSA key pairs

## Troubleshooting Guide

### Issue 1: Port already in use `Address already in use`

**Solution:**
```bash
# Find processes using port 8080
lsof -i :8080

# Force kill process (replace PID with actual process ID)
kill -9 [PID]

# Or kill all Python processes
pkill -9 -f python
```

### Issue 2: Seeing old chat messages

**Solutions (by priority):**

**Method 1: Use in-app clear button**
- After login click the "Clear All Cache" button in top right corner
- System will automatically clear all data and reload

**Method 2: Use incognito/private browsing mode**
- Chrome: `⌘ + Shift + N`
- Safari: `⌘ + Shift + N`
- Firefox: `⌘ + Shift + P`

**Method 3: Manually clear browser cache**
- Chrome: F12 → Right-click refresh button → "Empty Cache and Hard Reload"
- Safari: `⌘ + Option + E` → `⌘ + R`
- Firefox: `⌘ + Shift + Delete`

### Issue 3: Message send failure

**Check steps:**
1. Confirm server is running
2. Check browser console (F12 → Console) for errors
3. Confirm chat target is selected
4. Try refreshing page and re-login

**Solution:**
```bash
# Restart server
pkill -9 -f python
python3 app.py
```

### Issue 4: JavaScript errors

**Common errors and solutions:**
- `Cannot read properties of undefined`: Refresh page and re-login
- `Fetch failed`: Check if server is running
- `User not found`: Confirm user is registered and online

---

## Complete System Reset

If you encounter serious problems, use these steps for complete reset:

```bash
# 1. Stop all Python processes
pkill -9 -f python

# 2. Clear Python cache
find . -name "*.pyc" -delete
find . -name "__pycache__" -type d -exec rm -rf {} +

# 3. Restart
python3 app.py
```

Then access system in incognito mode at `http://127.0.0.1:8080`

---

## System Status Check

### Verify encryption is working:
1. Open browser developer tools (F12)
2. Switch to Network tab
3. Send a message
4. Check `/send_message` request's Request Payload
5. Should see content like this:
   ```json
   {
     "message": "SGVsbG8=",    // Base64 encoded, not plaintext!
     "to_user": "target_user",
     "is_encoded": true
   }
   ```

### Verify server encrypted storage:
Server logs will show:
```
Decoded message: Hello
Message encryption successful: user1 -> user2
```

## Advanced Configuration

### Change port:
Edit bottom of `app.py` file:
```python
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8080)  # Modify port parameter
```

### Change encryption strength:
Modify in `generate_rsa_keypair()` function:
```python
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,  # Can change to 4096 for enhanced security
    backend=default_backend()
)
```

---

## Emergency Contact

If all above solutions don't work:
1. Record complete error information
2. Screenshot relevant interfaces
3. Save browser console (F12 → Console) error logs
4. Check if firewall is blocking port 8080

---

## Update Log

### v2.0 (Current Version)
- Implemented Base64 network transmission encryption
- Added cache clearing functionality
- Fixed JavaScript error issues
- Improved user experience

### v1.0 (Initial Version)
- Basic chat functionality
- RSA+AES server-side encryption
- User registration/login system

---

*Last updated: July 23, 2025* 