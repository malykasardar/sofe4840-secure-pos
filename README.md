# Secure Purchase Order System
**SOFE4840U - Software & Computer Security | Group 5 | CRN: 73812**

| Name | Student ID | Role |
|------|-----------|------|
| Abdallah Hanoosh | 100749026 | Backend: Auth & Database |
| Malyka Sardar | 100752640 | Backend: Crypto Module |
| Mohammad Al-Lozy | 100829387 | Backend: Order Workflow & Audit Log |
| Destiny Mekwunye | 100825222 | Frontend & Presentation |

## About
A secure purchase order system using RSA-2048 encryption, SHA-256 hashing, and digital signatures to ensure purchase orders remain protected from eavesdropping, forgery, tampering, and repudiation.

## Tech Stack
- Python 3 + Flask
- PyCryptodome (RSA, AES-GCM, SHA-256, PSS signatures)
- bcrypt (password hashing)
- SQLite (database)
- HTML + Bootstrap 5 + JavaScript

## Setup
```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/sofe4840-secure-pos.git
cd sofe4840-secure-pos

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate        # Mac/Linux
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```
Then open http://localhost:5000 in your browser.

## Branches
- `abdallah/auth` - Auth, database schema, RBAC
- `malyka/crypto` - Cryptography module
- `mohammad/routes` - Order workflow routes, audit log
- `destiny/frontend` - HTML templates, presentation
