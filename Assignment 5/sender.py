from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import os
import time

def sender_encrypt(file_content, sender_name):
    # Load sender's private key and recipient's public key
    with open(f"{sender_name}_private_key.pem", "rb") as key_file:
        sender_private_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    with open("bob_public_key.pem", "rb") as key_file:
        recipient_public_key = load_pem_public_key(key_file.read(), backend=default_backend())

    # Generate AES key, HMAC key, and IV
    aes_key = os.urandom(16)
    hmac_key = os.urandom(16)
    iv = os.urandom(16)

    # Sign AES key, IV, and HMAC key
    keys_to_sign = aes_key + iv + hmac_key
    signature = sender_private_key.sign(
        keys_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Encrypt keys and IV using recipient's RSA public key
    encrypted_keys = recipient_public_key.encrypt(
        keys_to_sign,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Save the encrypted keys to a file
    with open("encrypted_keys.bin", "wb") as keys_file:
        keys_file.write(encrypted_keys)

    # Prepare data to encrypt (sender's name, file content, timestamp, and signature)
    timestamp = str(time.time())
    data_to_encrypt = sender_name + "\n" + file_content + "\n" + timestamp + "\n" + signature.hex()

    # Encrypt using AES in CTR mode
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.CTR(iv),
        backend=default_backend()
    ).encryptor()
    encrypted_message = encryptor.update(data_to_encrypt.encode()) + encryptor.finalize()

    # Save encrypted message
    with open("encrypted_message.bin", "wb") as enc_file:
        enc_file.write(encrypted_message)

    # Generate HMAC for integrity
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_message)
    hmac_message = h.finalize()

    # Save the HMAC to a file
    with open("hmac_message.bin", "wb") as hmac_file:
        hmac_file.write(hmac_message)

if __name__ == "__main__":
    # Read the content of the secret file
    with open("secret.txt", "r") as file:
        content = file.read()
    # Encrypt the file content as Alice
    sender_encrypt(content, "alice")
