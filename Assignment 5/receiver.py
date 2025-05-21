from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend

def receiver_decrypt():
    # Load receiver's private key
    with open("bob_private_key.pem", "rb") as key_file:
        recipient_private_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    # Load encrypted keys
    with open("encrypted_keys.bin", "rb") as keys_file:
        encrypted_keys = keys_file.read()

    # Decrypt AES key, IV, and HMAC key
    keys_to_sign = recipient_private_key.decrypt(
        encrypted_keys,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aes_key, iv, hmac_key = keys_to_sign[:16], keys_to_sign[16:32], keys_to_sign[32:]

    # Load encrypted message
    with open("encrypted_message.bin", "rb") as enc_file:
        encrypted_message = enc_file.read()

    # Verify HMAC
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_message)
    with open("hmac_message.bin", "rb") as hmac_file:
        received_hmac = hmac_file.read()
    try:
        h.verify(received_hmac)
    except Exception:
        print("HMAC verification failed!")
        return

    # Decrypt message
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.CTR(iv),
        backend=default_backend()
    ).decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Extract data
    sender_name, file_content, timestamp, signature = decrypted_message.decode().split("\n", 3)
    print(f"Sender: {sender_name}")
    print(f"File content: {file_content}")

if __name__ == "__main__":
    # Decrypt the file and verify integrity/authenticity as Bob
    receiver_decrypt()
