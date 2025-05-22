# Secure data encryption assignment

import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Constants
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# Page configuration
st.set_page_config(
    page_title="Secure Data Encryption System",
    page_icon="🔒",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stButton>button {
        width: 100%;
        background-color: #4CAF50;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
    }
    .stTextInput>div>div>input {
        border-radius: 5px;
    }
    .stTextArea>div>div>textarea {
        border-radius: 5px;
    }
    </style>
    """, unsafe_allow_html=True)

# Session state initialization
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:   
    st.session_state.failed_attempts = 0 
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)   
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)  

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()  

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

stored_data = load_data()

# Navigation
st.sidebar.title("🔒 Secure Data System")
menu = ["🏠 Home", "📝 Register", "🔑 Login", "💾 Store Data", "📤 Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home Page
if choice == "🏠 Home":
    st.title("Welcome to Secure Data Encryption System")
    st.markdown("""
    ### 🔐 Secure Data Storage and Retrieval System
    
    This system provides:
    - 🔒 Secure data encryption
    - 🔑 Unique passkey protection
    - 🛡️ Multiple security layers
    - 📱 User-friendly interface
    
    Get started by registering a new account or logging in to an existing one.
    """)
    
    col1, col2 = st.columns(2)
    with col1:
        st.info("New User? Register to get started!")
    with col2:
        st.info("Existing User? Login to access your data!")

# Registration Page
elif choice == "📝 Register":
    st.title("Create New Account")
    with st.form("registration_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submit = st.form_submit_button("Register")

        if submit:
            if not username or not password:
                st.error("All fields are required.")
            elif password != confirm_password:
                st.error("Passwords do not match.")
            elif username in stored_data:
                st.warning("Username already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("Registration successful! Please login.")

# Login Page
elif choice == "🔑 Login":
    st.title("User Login")
    
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⚠️ Account temporarily locked. Please wait {remaining} seconds.")
        st.stop()

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")

        if submit:
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"Welcome back, {username}! 👋")
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"Invalid credentials. {remaining} attempts remaining.")
                
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("Account locked for 60 seconds due to multiple failed attempts.")
                    st.stop()

# Store Data Page
elif choice == "💾 Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login to access this feature.")
    else:
        st.title("Store Encrypted Data")
        with st.form("store_data_form"):
            data = st.text_area("Enter data to encrypt", height=150)
            passkey = st.text_input("Encryption key (passkey)", type="password")
            submit = st.form_submit_button("Encrypt and Save")

            if submit:
                if data and passkey:
                    encrypted = encrypt_text(data, passkey)
                    stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                    save_data(stored_data)
                    st.success("✅ Data encrypted and saved successfully!")
                else:
                    st.error("All fields are required.")

# Retrieve Data Page
elif choice == "📤 Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login to access this feature.")
    else:
        st.title("Retrieve Encrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No encrypted data found for this user.")
        else:
            st.subheader("Your Encrypted Data Entries")
            for i, item in enumerate(user_data, 1):
                with st.expander(f"Entry #{i}"):
                    st.code(item, language="text")

            st.subheader("Decrypt Data")
            with st.form("decrypt_form"):
                encrypted_input = st.text_area("Enter encrypted text to decrypt")
                passkey = st.text_input("Enter passkey to decrypt", type="password")
                submit = st.form_submit_button("Decrypt")

                if submit:
                    if encrypted_input and passkey:
                        result = decrypt_text(encrypted_input, passkey)
                        if result:
                            st.success("Decryption successful!")
                            st.info(f"Decrypted data: {result}")
                        else:
                            st.error("Invalid passkey or encrypted data.")
                    else:
                        st.error("All fields are required.")    
