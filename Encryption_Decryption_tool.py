import os
import base64
import secrets
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Constants for PBKDF2
SALT_SIZE = 16
ITERATIONS = 100000

# Generate RSA key pair and save
def generate_rsa_key_pair(filename="rsa_key.pem"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    with open(filename, "wb") as key_file:
        key_file.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        public_key = key.public_key()
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Load RSA private key for decryption
def load_rsa_private_key(filename="rsa_key.pem"):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

# Generate an encrypted Fernet key using RSA public key
def generate_encrypted_fernet_key(public_key, filename="encrypted_fernet.key"):
    fernet_key = Fernet.generate_key()
    encrypted_key = public_key.encrypt(
        fernet_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    with open(filename, "wb") as key_file:
        key_file.write(encrypted_key)
    return Fernet(fernet_key)

# Load and decrypt the Fernet key using RSA private key
def load_decrypted_fernet_key(rsa_private_key, filename="encrypted_fernet.key"):
    with open(filename, "rb") as key_file:
        encrypted_key = key_file.read()
    fernet_key = rsa_private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    return Fernet(fernet_key)

# Derive key from password using PBKDF2
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt data with password
def encrypt_data_with_password(password: str, data: bytes) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted_data = salt + fernet.encrypt(data)
    return encrypted_data

# Decrypt data with password
def decrypt_data_with_password(password: str, encrypted_data: bytes) -> bytes:
    salt = encrypted_data[:SALT_SIZE]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data[SALT_SIZE:])
    return decrypted_data

# Encrypt text using Fernet
def encrypt_text(fernet, text):
    return fernet.encrypt(text.encode())

# Decrypt text using Fernet
def decrypt_text(fernet, encrypted_text):
    return fernet.decrypt(encrypted_text).decode()

# Encrypt image using Fernet
def encrypt_image(fernet, image_path, output_path="encrypted_image.enc"):
    with open(image_path, "rb") as img_file:
        image_data = img_file.read()
    encrypted_image = fernet.encrypt(image_data)
    with open(output_path, "wb") as enc_file:
        enc_file.write(encrypted_image)

# Decrypt image using Fernet
def decrypt_image(fernet, encrypted_image_path, output_path="decrypted_image.png"):
    with open(encrypted_image_path, "rb") as enc_file:
        encrypted_data = enc_file.read()
    decrypted_image = fernet.decrypt(encrypted_data)
    with open(output_path, "wb") as img_file:
        img_file.write(decrypted_image)

# Log output in the output area
def log(message):
    output_area.insert(tk.END, message + "\n")
    output_area.see(tk.END)

# Clear the output area
def clear_output():
    output_area.delete(1.0, tk.END)

# Custom Password Dialog (Ensures the dialog is modal and in front of the main window)
def prompt_password(action="Enter", parent=None):
    password = simpledialog.askstring("Password", f"{action} password:", show='*', parent=parent)
    if not password:
        messagebox.showerror("Error", "Password is required!", parent=parent)
    return password

# GUI Actions for Text Encryption
def encrypt_text_gui():
    text = simpledialog.askstring("Encrypt Text", "Enter text to encrypt:", parent=root)
    if text:
        encrypted_text = encrypt_text(fernet, text)
        encrypted_text_str = encrypted_text.decode()
        password = prompt_password("Enter", root)
        if password:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            log(f"Encrypted Text: {encrypted_text_str}, Password Hash: {password_hash}")
            messagebox.showinfo("Encrypted Text", f"Encrypted Text: {encrypted_text_str}", parent=root)
        else:
            log("No password entered. Encryption not confirmed.")

def decrypt_text_gui():
    encrypted_text = simpledialog.askstring("Decrypt Text", "Enter encrypted text:", parent=root)
    password = prompt_password("Enter", root)
    if encrypted_text and password:
        try:
            decrypted_text = decrypt_text(fernet, encrypted_text.encode())
            messagebox.showinfo("Decrypted Text", f"Decrypted Text: {decrypted_text}", parent=root)
            log(f"Decrypted Text: {decrypted_text}")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e), parent=root)

# GUI Actions for Image Encryption
def encrypt_image_gui():
    image_path = filedialog.askopenfilename(title="Select an Image to Encrypt", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
    if image_path:
        output_path = filedialog.asksaveasfilename(title="Save Encrypted Image As", defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
        if output_path:
            encrypt_image(fernet, image_path, output_path)
            password = prompt_password("Enter", root)
            if password:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                log(f"Image encrypted and saved as {output_path}, Password Hash: {password_hash}")
            else:
                log("No password entered. Encryption not confirmed.")

def decrypt_image_gui():
    encrypted_image_path = filedialog.askopenfilename(title="Select an Encrypted Image to Decrypt", filetypes=[("Encrypted Files", "*.enc")])
    if encrypted_image_path:
        output_path = filedialog.asksaveasfilename(title="Save Decrypted Image As", defaultextension=".png", filetypes=[("PNG Files", "*.png")])
        if output_path:
            password = prompt_password("Enter", root)
            if password:
                try:
                    decrypt_image(fernet, encrypted_image_path, output_path)
                    log(f"Image decrypted and saved as {output_path}")
                except Exception as e:
                    messagebox.showerror("Decryption Error", str(e), parent=root)

# GUI Actions for File Encryption using Password
def encrypt_file_with_password_gui():
    password = prompt_password("Enter", root)
    if password:
        file_path = filedialog.askopenfilename(title="Select a File to Encrypt")
        if file_path:
            output_path = filedialog.asksaveasfilename(title="Save Encrypted File As", defaultextension=".enc")
            if output_path:
                with open(file_path, "rb") as f:
                    data = f.read()
                encrypted_data = encrypt_data_with_password(password, data)
                with open(output_path, "wb") as enc_file:
                    enc_file.write(encrypted_data)
                log(f"Encrypted file saved as {output_path}")

def decrypt_file_with_password_gui():
    password = prompt_password("Enter", root)
    if password:
        encrypted_file_path = filedialog.askopenfilename(title="Select an Encrypted File to Decrypt")
        if encrypted_file_path:
            output_path = filedialog.asksaveasfilename(title="Save Decrypted File As", defaultextension=".dec")
            with open(encrypted_file_path, "rb") as enc_file:
                encrypted_data = enc_file.read()
            try:
                decrypted_data = decrypt_data_with_password(password, encrypted_data)
                with open(output_path, "wb") as dec_file:
                    dec_file.write(decrypted_data)
                log(f"Decrypted file saved as {output_path}")
            except Exception as e:
                messagebox.showerror("Decryption Error", str(e), parent=root)

# Initialization and GUI setup
if not os.path.exists("rsa_key.pem"):
    generate_rsa_key_pair()

# Load the RSA private key
rsa_private_key = load_rsa_private_key("rsa_key.pem")

# Load the public key from the private key
public_key = rsa_private_key.public_key()

# Check if the encrypted Fernet key exists; if not, generate it
if not os.path.exists("encrypted_fernet.key"):
    generate_encrypted_fernet_key(public_key)

# Load the decrypted Fernet key
fernet = load_decrypted_fernet_key(rsa_private_key)

# Creating the main window
root = tk.Tk()
root.title("Text, Image, and File Encryptor/Decryptor")

# Creating a tab control
tab_control = ttk.Notebook(root)

# Text Tab
text_tab = ttk.Frame(tab_control)
tab_control.add(text_tab, text="Text Operations")

# Image Tab
image_tab = ttk.Frame(tab_control)
tab_control.add(image_tab, text="Image Operations")

# File Tab
file_tab = ttk.Frame(tab_control)
tab_control.add(file_tab, text="File Operations")

tab_control.pack(expand=1, fill="both")

# Layout for Text Tab
tk.Label(text_tab, text="Text Operations", font=("Arial", 14)).pack(pady=10)
tk.Button(text_tab, text="Encrypt Text", command=encrypt_text_gui, width=20, font=("Arial", 12)).pack(pady=5)
tk.Button(text_tab, text="Decrypt Text", command=decrypt_text_gui, width=20, font=("Arial", 12)).pack(pady=5)

# Layout for Image Tab
tk.Label(image_tab, text="Image Operations", font=("Arial", 14)).pack(pady=10)
tk.Button(image_tab, text="Encrypt Image", command=encrypt_image_gui, width=20, font=("Arial", 12)).pack(pady=5)
tk.Button(image_tab, text="Decrypt Image", command=decrypt_image_gui, width=20, font=("Arial", 12)).pack(pady=5)

# Layout for File Tab
tk.Label(file_tab, text="File Operations", font=("Arial", 14)).pack(pady=10)
tk.Button(file_tab, text="Encrypt File", command=encrypt_file_with_password_gui, width=20, font=("Arial", 12)).pack(pady=5)
tk.Button(file_tab, text="Decrypt File", command=decrypt_file_with_password_gui, width=20, font=("Arial", 12)).pack(pady=5)

# Clear Output Button
tk.Button(root, text="Clear Output", command=clear_output, width=20, font=("Arial", 12)).pack(pady=5)

# Output Area
output_area = tk.Text(root, height=10, width=80, wrap=tk.WORD)
output_area.pack(pady=10, padx=10)

# Running the main loop
root.mainloop()
