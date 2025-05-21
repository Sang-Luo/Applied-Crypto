# Implementation of alice.py
# This script will simulate Alice's part in secure communication using RSA and AES encryption.
# Alice performs the following steps:
# 1. Loads Bob's public RSA key from a PEM file.
# 2. Generates a random AES session key to encrypt her message.
# 3. Encrypts the AES session key using Bob's public RSA key.
# 4. Encrypts her message using AES with the generated session key.
# 5. Saves the encrypted session key and message to files for Bob to retrieve and decrypt.


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding
import os

# Paths for Bob's public key and encrypted data files
bob_public_key_path = './bob_public_key.pem'
encrypted_session_key_path = './encrypted_session_key.bin'
encrypted_message_path = './encrypted_message.bin'


# Part 1: Load Bob's Public Key
def load_bobs_public_key():
    with open(bob_public_key_path, 'rb') as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())
    return public_key


# Part 2: Generate Session Key for AES Encryption
def generate_session_key():
    return os.urandom(32)  # Generate a random 256-bit key for AES


# Part 3: Encrypt session key with RSA and message with AES
# Encrypts a message for Bob by:
# 1. Encrypting an AES session key with Bob's public RSA key.
# 2. Encrypting the message with AES using the session key.
# 3. The encrypted session key and message are saved to files.
def encrypt_data(message):
    # Load Bob's public key
    public_key = load_bobs_public_key()

    # Generate AES session key
    session_key = generate_session_key()

    # Encrypt the session key using RSA
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # This was for debugging. I ran into an error where I realized it was because I forgot I was generating the key over
    # again in bob,py as I had not created a UI and was just directly running the code.
    # print("Encrypted Session Key:", encrypted_session_key.hex())  # Debug: Print encrypted session key

    # Encrypt the message with AES using the session key
    cipher = Cipher(algorithms.AES(session_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Part 4: Encrypts her message using AES with the generated session key.
    # Add padding to the message to make it compatible with AES block size
    padder = aes_padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode('utf-8')) + padder.finalize()
    # Perform AES encryption on the padded message
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Same debugging reason as above, to compare keys
    # print("Encrypted Message:", encrypted_message.hex())  # Debug: Print encrypted message

    # Part 5: Saves the encrypted session key and message to files for Bob to retrieve and decrypt.
    with open(encrypted_session_key_path, 'wb') as enc_sess_file:
        enc_sess_file.write(encrypted_session_key)

    with open(encrypted_message_path, 'wb') as enc_msg_file:
        enc_msg_file.write(encrypted_message)


# Execute encryption
encrypt_data("Hello Bob, this is a secure message from Alice.")


"Encryption complete: Encrypted session key and message saved."
