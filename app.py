import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Fixed encryption key (DO NOT regenerate each run)
KEY = b'3JZDW3uRE0U8ZtUROb2P7hd31fpT-3bn2FEhtOiW2yk='  # Generate once using Fernet.generate_key()
cipher = Fernet(KEY)

# Initialize session state for security
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = True  # True on first load, False after 3 wrong attempts

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    stored = st.session_state.stored_data.get(encrypted_text)

    if stored and stored["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        st.session_state.authorized = True
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        if st.session_state.failed_attempts >= 3:
            st.session_state.authorized = False
        return None

# --- Streamlit UI ---

st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# -------------------- Home --------------------
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# -------------------- Store Data --------------------
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data encrypted and stored securely!")
            st.text("Here is your encrypted text (save this to retrieve later):")
            st.code(encrypted_text)
        else:
            st.error("⚠️ Both fields are required!")

# -------------------- Retrieve Data --------------------
elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔐 Too many failed attempts. Please log in again.")
        st.switch_page("Login")

    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Paste Encrypted Text:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success(f"✅ Decrypted Data: {result}")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                if not st.session_state.authorized:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

# -------------------- Login Page --------------------
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Change this to a secure method in production
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Reauthorized successfully!")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
