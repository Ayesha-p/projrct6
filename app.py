import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (In production, store this securely)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory storage
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encryption function
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decryption function
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# App UI
st.title("🔐 Secure Data Encryption System")

# Navigation menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Menu", menu)

# Pages
if choice == "Home":
    st.header("🏠 Welcome!")
    st.markdown("This app lets you securely **store** and **retrieve** data with encryption and passkey.")

elif choice == "Store Data":
    st.header("📂 Store Data")
    user_data = st.text_area("Enter Data to Encrypt")
    passkey = st.text_input("Enter a Passkey", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and stored securely!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3 and not st.session_state.is_logged_in:
        st.warning("🚨 Too many failed attempts. Redirecting to Login...")
        st.experimental_rerun()

    st.header("🔍 Retrieve Data")
    encrypted_input = st.text_area("Enter Encrypted Data")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success("✅ Decrypted Text:")
                st.code(result, language="text")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔐 Too many failed attempts! Redirecting to Login.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.header("🔑 Login Required")
    login_pass = st.text_input("Enter Master Password", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # For demo purposes
            st.session_state.failed_attempts = 0
            st.session_state.is_logged_in = True
            st.success("✅ Login successful. You may now retry.")
        else:
            st.error("❌ Incorrect password!")
