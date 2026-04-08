import streamlit as st
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
import os
import base64
import json
import hashlib


# CONFIG

st.set_page_config(page_title="Cipher Vault", page_icon="🔐")

# USER DATABASE

USER_DB = "users.json"

if not os.path.exists(USER_DB):
    with open(USER_DB, "w") as f:
        json.dump({}, f)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    with open(USER_DB, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f)

# SESSION INIT

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = None

if "flash_message" not in st.session_state:
    st.session_state.flash_message = None

# MESSAGE 
if st.session_state.flash_message:
    st.success(st.session_state.flash_message)
    st.session_state.flash_message = None

# AUTHORIZATION

def auth_ui():
    st.title("Cipher Vault 🔐")

    option = st.radio("Select Option", ["Login", "Register"])
    users = load_users()

    with st.form(key="auth_form", clear_on_submit=True):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button(option)

        if submit:
            if option == "Register":
                if not username or not password:
                    st.error("Please fill all fields.")
                elif username in users:
                    st.error("User already exists.")
                else:
                    users[username] = hash_password(password)
                    save_users(users)
                    st.session_state.flash_message = "Registration successful! Please login."
                    st.rerun()

            if option == "Login":
                if username in users and users[username] == hash_password(password):
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.flash_message = "Login successful!"
                    st.rerun()
                else:
                    st.error("Invalid credentials.")

def logout():
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.flash_message = "Logged out successfully."
    st.rerun()
    
# LOGIN CHECK

if not st.session_state.logged_in:
    auth_ui()
else:
    
    # FOLDERS 
    
    user_enc_folder = os.path.join("locker", st.session_state.username)
    user_dec_folder = os.path.join("decrypted", st.session_state.username)

    os.makedirs(user_enc_folder, exist_ok=True)
    os.makedirs(user_dec_folder, exist_ok=True)

    # MAIN UI

    st.title("CipherVault 🔐")
    st.write(f"Welcome, {st.session_state.username}")
    st.sidebar.button("Logout", on_click=logout)

    menu = st.radio("Choose Operation", ["Encrypt File", "Decrypt File"])
    st.markdown("---")

    # CRYPTO FUNCTIONS
    
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_file(file_bytes: bytes, password: str) -> bytes:
        salt = os.urandom(16)
        key = derive_key(password, salt)
        encrypted = Fernet(key).encrypt(file_bytes)
        return salt + encrypted

    def decrypt_file(file_bytes: bytes, password: str) -> bytes:
        salt = file_bytes[:16]
        encrypted_data = file_bytes[16:]
        key = derive_key(password, salt)
        return Fernet(key).decrypt(encrypted_data)


    # ENCRYPT SECTION
    
    if menu == "Encrypt File":

        st.subheader("Encrypt File📁")

        with st.form(key="encrypt_form", clear_on_submit=True):
            uploaded = st.file_uploader("Upload file")
            password = st.text_input("Password", type="password")
            confirm = st.text_input("Confirm Password", type="password")
            submit = st.form_submit_button("Encrypt")

            if submit:
                if not uploaded:
                    st.error("Upload a file.")
                elif not password:
                    st.error("Enter password.")
                elif password != confirm:
                    st.error("Passwords do not match.")
                else:
                    encrypted_data = encrypt_file(uploaded.read(), password)
                    file_path = os.path.join(user_enc_folder, uploaded.name + ".locked")

                    with open(file_path, "wb") as f:
                        f.write(encrypted_data)

                    st.session_state.flash_message = "File encrypted and saved in locker."
                    st.rerun()

    # DECRYPT SECTION
    
    elif menu == "Decrypt File":

        st.subheader("Decrypt File🔓")

        enc_files = os.listdir(user_enc_folder)

        if not enc_files:
            st.info("No encrypted files found.")
        else:
            with st.form(key="decrypt_form", clear_on_submit=True):
                selected = st.selectbox("Select encrypted file", enc_files)
                password = st.text_input("Password", type="password")
                submit = st.form_submit_button("Decrypt")

                if submit:
                    try:
                        with open(os.path.join(user_enc_folder, selected), "rb") as f:
                            file_data = f.read()

                        decrypted_data = decrypt_file(file_data, password)

                        output_path = os.path.join(
                            user_dec_folder,
                            selected.replace(".locked", "")
                        )

                        with open(output_path, "wb") as f:
                            f.write(decrypted_data)

                        st.session_state.flash_message = "File decrypted and saved in decrypted folder."
                        st.rerun()

                    except InvalidToken:
                        st.error("Wrong password.")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")