# Project Structure

```
chat-app/
├── README.md              # Complete usage guide and troubleshooting
├── QUICK_REFERENCE.md     # Quick reference for common issues
├── PROJECT_STRUCTURE.md   # Project structure documentation (this file)
├── requirements.txt       # Python dependencies
├── install_and_run.sh     # Installation and startup script
├── app.py                 # Flask main application with encryption logic
└── templates/             # HTML template directory
    ├── chat.html          # Chat interface with Base64 encoding
    └── login.html         # Login and registration page
```

## File Descriptions

### Setup Files
- `install_and_run.sh` - Automated installation and server startup script
- `requirements.txt` - Python package dependencies

### Documentation
- `README.md` - Main documentation with detailed usage instructions and troubleshooting
- `QUICK_REFERENCE.md` - Quick solutions for common problems
- `PROJECT_STRUCTURE.md` - This file, explains project organization

### Core Application Files
- `app.py` - Flask backend server with RSA+AES encryption implementation
- `templates/chat.html` - Chat interface with Base64 frontend encoding
- `templates/login.html` - User authentication interface

## Usage Priority

### New Users - Quick Start:
1. Run `./install_and_run.sh`
2. Open `http://127.0.0.1:8080`

### Troubleshooting - Check Documentation:
1. **Quick fixes**: See `QUICK_REFERENCE.md`
2. **Detailed diagnosis**: See `README.md`

### Developers - Understanding Structure:
1. **Project overview**: This file
2. **Core logic**: `app.py`
3. **Frontend implementation**: `templates/`

## Encryption Implementation Locations

| Feature | Location | Description |
|---------|----------|-------------|
| Base64 frontend encoding | `chat.html` | Obscures plaintext in network transmission |
| RSA key generation | `app.py` | Generated during user registration |
| AES message encryption | `app.py` | Server-side storage encryption |
| Hybrid encryption storage | `app.py` | RSA+AES dual protection |

Project size: ~30KB | Files: 7 | Languages: Python + JavaScript 