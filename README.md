# E-D_Tool
This Python program is a graphical user interface (GUI) application for encrypting and 
decrypting text, images, and files. It employs robust encryption techniques using the Cryptography
 library and provides functionalities such as RSA key pair generation, Fernet key encryption, and password-based encryption. 
The program is implemented using the Tkinter library for GUI components.

Key Features
Encryption/Decryption Methods:

RSA Encryption:
Generates an RSA key pair (private and public keys).
Encrypts a Fernet key using the public key.
Decrypts the Fernet key using the private key.
Fernet Encryption:
Used for symmetric encryption/decryption of text, images, and files.
Password-Based Encryption:
Derives an encryption key from a user-provided password using PBKDF2 (Password-Based Key Derivation Function 2).
Supports encrypting and decrypting files with a password.
File and Image Operations:

Image Encryption and Decryption:
Encrypts image files using the Fernet key.
Decrypts encrypted image files back to their original format.
File Encryption with Password:
Encrypts any file using password-based encryption.
Decrypts password-encrypted files.
GUI Components:

Text Operations:
Encrypt and decrypt text.
Image Operations:
Encrypt and decrypt images.
File Operations:
Encrypt and decrypt generic files using passwords.
Output Area:
Logs actions and messages.
Tab-based Navigation:
Organized into tabs for text, image, and file operations.
Password Handling:

Prompts users for passwords securely using a modal dialog box.
Ensures user-entered passwords are required for encryption/decryption operations.
Key Management:

Checks for existing RSA keys and Fernet keys on startup.
Generates new keys if they do not exist.
Encryption Workflow
RSA Key Pair Generation:

Creates a 2048-bit RSA private key (rsa_key.pem).
Extracts the public key for encrypting the Fernet key.
Fernet Key Management:

Generates a Fernet key if it doesn’t already exist.
Encrypts the Fernet key using the RSA public key.
Decrypts the Fernet key using the RSA private key during runtime.
Password-Based Encryption:

Derives a secure encryption key from a password using a salt and PBKDF2.
Encrypts and decrypts files with the derived key.
GUI Actions:

Text Operations:
Encrypts plaintext input to a secure ciphertext.
Decrypts ciphertext back to plaintext.
Image Operations:
Encrypts and decrypts image files using the Fernet key.
File Operations:
Encrypts and decrypts any file using password-based encryption.
Code Modules
Encryption Functions:

encrypt_text, decrypt_text: Encrypt and decrypt text using the Fernet key.
encrypt_image, decrypt_image: Encrypt and decrypt image files using the Fernet key.
encrypt_data_with_password, decrypt_data_with_password: Handle password-based encryption and decryption.
Key Management:

generate_rsa_key_pair: Generates and saves RSA keys.
load_rsa_private_key: Loads the RSA private key.
generate_encrypted_fernet_key: Creates a Fernet key and encrypts it using RSA public key.
load_decrypted_fernet_key: Decrypts the Fernet key with the RSA private key.
GUI Components:

Tabs for text, image, and file operations.
File dialogs for selecting files/images to encrypt or decrypt.
Output area for logs and feedback.
Strengths
Secure Design: Combines RSA, Fernet, and password-based encryption for robust security.
User-Friendly GUI: Tab-based interface for easy navigation of different operations.
Modular Architecture: Functions for different tasks are well-structured and reusable.
Error Handling: Includes exception handling for decryption errors and user input validation.
Potential Improvements
Error Logging:
Add more detailed logging for debugging purposes.
Password Strength Validation:
Validate the strength of user-entered passwords for better security.
Key Storage:
Implement secure storage mechanisms (e.g., hardware security modules) for private keys and sensitive data.
File Format Restrictions:
Include safeguards to handle unsupported file formats gracefully.
Cross-Platform Testing:
Ensure consistent behavior across different operating systems.
