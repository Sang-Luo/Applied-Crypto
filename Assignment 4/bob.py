# Implementation of bob.py
# This script will simulate Bob's part in secure communication using RSA and AES encryption.
# Bob can:
# 1. Generate an RSA key pair
# 2. Save the public key to a file to share with Alice.
# 3. Accept the encrypted session key and the encrypted message (read from files).
# 4. Decrypt the session key using Bob's private key.
# 5. Use the decrypted session key to decrypt the actual message using AES decryption and display the original message.

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding

# Define paths for Bob's key and message files
bob_private_key_path = './bob_private_key.pem'
bob_public_key_path = './bob_public_key.pem'
encrypted_session_key_path = './encrypted_session_key.bin'
encrypted_message_path = './encrypted_message.bin'


# Part 1: Generate an RSA key pair
def generate_rsa_keys():
    # Check if keys already exist to avoid overwriting
    if os.path.exists(bob_private_key_path) and os.path.exists(bob_public_key_path):
        print("Keys already exist. Use Option 2 to decrypt.")
        return
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save private key
    with open(bob_private_key_path, 'wb') as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Part 2: Save the public keys to a file to share with Alice.

    # Save public key
    with open(bob_public_key_path, 'wb') as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Keys generated and saved successfully.")


def decrypt_data():
    # Part 3: Accept the encrypted session key and the encrypted message (read from files).
    if not os.path.exists(bob_private_key_path) or not os.path.exists(encrypted_session_key_path) or not os.path.exists(
            encrypted_message_path):
        print("Required files for decryption are missing.")
        return None

    # Load Bob's private key
    with open(bob_private_key_path, 'rb') as priv_file:
        private_key = serialization.load_pem_private_key(priv_file.read(), password=None, backend=default_backend())

    # Read encrypted session key
    with open(encrypted_session_key_path, 'rb') as enc_sess_file:
        encrypted_session_key = enc_sess_file.read()
    # print("Encrypted Session Key (loaded by Bob):", encrypted_session_key.hex())  # Debug: Print loaded session key

    # Part 4: Decrypt session key with RSA
    try:
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # print("Decrypted Session Key:", session_key.hex())  # Debug: Print decrypted session key
    except ValueError as e:
        print("Decryption failed:", e)
        return None

    # Read encrypted message
    with open(encrypted_message_path, 'rb') as enc_msg_file:
        encrypted_message = enc_msg_file.read()

    # Decrypt message with AES using the decrypted session key
    cipher = Cipher(algorithms.AES(session_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Remove padding
    unpadder = aes_padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    print("Decrypted Message:", decrypted_message.decode('utf-8'))
    return decrypted_message.decode('utf-8')


# Command-line interface for Bob's operations
def main():
    while True:
        print("\nSelect an option:")
        print("1. Generate RSA Key Pair")
        print("2. Decrypt Message")
        print("3. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            generate_rsa_keys()

        # Part 5: Decrypt the message and display
        elif choice == "2":
            decrypt_data()
        elif choice == "3":
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")


# Run the command-line interface
if __name__ == "__main__":
    main()
