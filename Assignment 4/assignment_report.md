# **Assignment 4 Report: Implementing RSA Encryption with File-Based Communication** #

### CSCI/CSCY 3800: Applied Crypto (Fall 2024) ###

--- 

## Overview - ##

The goal of this assignment is to implement a secure communication protocol between two users, Alice and Bob.This system 
uses RSA (an asymmetric cryptographic algorithm) for securely exchanging an AES (symmetric encryption) session key, which
Alice then uses to encrypt her actual message. AES encryption is faster for larger data blocks, making this hybrid 
approach both secure and efficient. By using RSA for secure key exchange and AES for efficient message encryption, 
this system provides integrity and efficiency for data sent over a channel.

---

## An Understanding of Why RSA and AES: ##

RSA is an asymmetric cryptographic algorithm based on the mathematical challenge of factoring large prime numbers. 
It involves two keys:

**Public Key:** Used to encrypt data, which can be shared openly.

**Private Key:** Used to decrypt data, which must be kept secure by the owner (in this case, Bob).

RSA is ideal for securely exchanging keys over an insecure channel, as only Bob’s private key can decrypt data encrypted
with his public key. However, RSA is computationally intensive, so it’s typically used to encrypt only small data. 
This is where AES comes into play. AES is a symmetric algorithm, which means the same key is used for both encryption 
and decryption. AES is fast and efficient, especially for encrypting larger messages. This is chosen for encrypting the 
main message because it is computationally efficient and secure, especially when combined with RSA for key exchange.


## Implementation ##

The implementation consists of two main files, alice.py and bob.py, simulating the communication process between Alice 
(the sender) and Bob (the receiver):

- bob.py  
: Bob’s program will generate RSA keys, save the public key for Alice, and decrypt Alice’s messages all based on user
input as well as generated files from alice.

- alice.py 
: Alice’s program will load Bob’s public key, generate and encrypt a session key, encrypt her message, and save the 
encrypted data for Bob to retrieve and decrypt.

### Detailed Process Explanation - ###

### RSA Key Generation and Storage: ###

In bob.py, Bob generates an RSA key pair and saves them for future use:

- RSA Key Pair Generation: 
: Matching an example from lab 4, a 2048-bit RSA key pair is generated with a public exponent of 65537. This ensures 
high security.

- PEM Format Key Storage: 
: The private key is saved as bob_private_key.pem and the public key as bob_public_key.pem, both 
in PEM format. This format ensures compatibility with secure applications and libraries. 

In bob.py allows users to choose the following operations:

Option 1: Generates RSA keys and saves them, if they do not already exist.

Option 2: Proceeds to decryption if the keys and encrypted data are present.

Code of Key Generation:

```aiignore
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
```

### Message Encryption Process: ###

The encryption process in alice.py involves several steps:

- **Loading Bob’s Public Key:** Alice loads Bob’s public key from the PEM file (bob_public_key.pem) to securely encrypt an 
AES session key. This enables secure key exchange since only Bob’s private key can decrypt the data.

```aiignore
# Part 1: Load Bob's Public Key
def load_bobs_public_key():
    with open(bob_public_key_path, 'rb') as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())
    return public_key
```


- **Session Key Generation:** Alice generates a random 256-bit session key for AES encryption. AES is chosen due to its 
efficiency in message encryption.

```aiignore
def generate_session_key():
    return os.urandom(32)  # Generate a random 256-bit key for AES
```

- **Encrypting the Session Key with RSA:** Alice encrypts the AES session key using RSA with OAEP padding and SHA-256. 
Only Bob, who has the corresponding private key, can decrypt this session key.

```aiignore
    # Encrypt the session key using RSA
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
```

- **AES Message Encryption:** Alice encrypts her message using AES with the session key in ECB mode, padding the message to 
fit the AES block size (128 bits). Although ECB has limitations regarding patterns in data, it’s used here for simplicity.

```aiignore
    # Part 4: Encrypts her message using AES with the generated session key.
    # Add padding to the message to make it compatible with AES block size
    padder = aes_padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode('utf-8')) + padder.finalize()
    # Perform AES encryption on the padded message
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
```

- **Saving Encrypted Data:** The encrypted session key and AES-encrypted message are saved as encrypted_session_key.bin and 
encrypted_message.bin.

```aiignore
    with open(encrypted_session_key_path, 'wb') as enc_sess_file:
        enc_sess_file.write(encrypted_session_key)

    with open(encrypted_message_path, 'wb') as enc_msg_file:
        enc_msg_file.write(encrypted_message)
```


### Message Decryption Process: ###

After Alice’s encrypted files are available, Bob uses bob.py to decrypt and read the message:

- **Loading Encrypted Files and RSA Decryption of  Session Key:** Bob reads the encrypted_session_key.bin file and 
decrypts it with his private key, revealing the AES session key.

- **AES Decryption of Message:** Bob uses the decrypted AES session key to decrypt the encrypted_message.bin file, 
retrieving Alice’s original message. PKCS7 unpadding is applied to remove padding added during encryption.

```aiignore
    # Decrypt message with AES using the decrypted session key
    cipher = Cipher(algorithms.AES(session_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Remove padding
    unpadder = aes_padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
```

---

## File-Based Communication ##

File-based communication plays a vital role in simulating secure message exchange between Alice and Bob, allowing for 
asynchronous and offline message exchange. Here’s how each file is used:

- **Public Key File (bob_public_key.pem):** This file contains Bob’s public key, which Alice accesses to encrypt her AES 
session key.

- **Encrypted Session Key File (encrypted_session_key.bin):** Alice saves the RSA-encrypted session key in this file for Bob
to retrieve.

- **Encrypted Message File (encrypted_message.bin):** Stores the AES-encrypted message, which only Bob can decrypt using the
session key.

This approach provides a secure and convenient way to store and exchange encrypted data.

---

## Testing and Validation Approach ##

To ensure the integrity, security, and functionality of the implementation, I followed a comprehensive testing approach:

1. Key Integrity Check:

: The RSA keys were checked for correct generation and were only generated once, ensuring that Alice could use the 
original keys for consistent encryption and decryption. This is crucial as I ran into an error when first creating my 
code as I was just running the generation each time. This meant that the RSA key pair was being regenerated each time 
meaning the key pair Alice used was not matching when it tried to decrypt. This I should've seen from lab 4, but just 
didn't notice, so I had to debug for a bit to find reason why my code was not running as it should.

2. File Existence Validation:

: Before proceeding with encryption or decryption, both programs check if required files are available. Especially in  
bob.py, which helps avoid re-generating keys unintentionally.

3. Encryption and Decryption Verification:

: After encryption in alice.py, the encrypted session key and message files were checked to confirm they contained 
encrypted data. Decryption in bob.py was validated by comparing the output with the original plaintext message.

4. Debugging with Print Statements:

: Debug print statements were added to ensure the encrypted session key and encrypted message were correctly generated,
saved, loaded, and decrypted. These statements do still exist and are commented out, if you want you can uncomment them.
In which they will print out the keys soI can check that the public keys were matching. 

5. Error Handling for Missing Files:

: The interface in bob.py checks for missing files and displays user-friendly messages.

---

## Conclusion ##

This secure communication system combines RSA and AES encryption to provide confidentiality and integrity in message 
exchange between Alice and Bob. By using RSA for key exchange and AES for message encryption, this assigment displays 
both integrity and efficiency.
