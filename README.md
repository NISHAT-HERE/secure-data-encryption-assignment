# Secure Data Encryption System

A secure data storage and retrieval system built with Streamlit that allows users to encrypt and store their data with unique passkeys.

## Features

- 🔒 Secure data encryption
- 🔑 Unique passkey protection
- 🛡️ Multiple security layers
- 📱 User-friendly interface
- 🔐 Account lockout after multiple failed attempts

## Local Installation

1. Clone this repository:
```bash
git clone <your-repository-url>
cd secure-data-encryption-assignment
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
streamlit run secure_data_encryption_assignment.py
```

## Deploying to Streamlit Cloud

1. Push your code to a GitHub repository

2. Go to [Streamlit Cloud](https://streamlit.io/cloud)

3. Click "New app"

4. Select your repository, branch, and main file path

5. Click "Deploy"

## Requirements

- Python 3.7+
- Streamlit
- Cryptography

## Security Features

- Password hashing using PBKDF2
- Fernet symmetric encryption
- Account lockout after 3 failed attempts
- Secure session management

## File Structure

- `secure_data_encryption_assignment.py` - Main application file
- `requirements.txt` - Python dependencies
- `secure_data.json` - Encrypted data storage (created automatically)

## Note

This application stores data locally in a JSON file. For production use, consider implementing a more robust storage solution. 
