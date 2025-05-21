# **Assignment 5 Report**

---

## 1. Introduction

In this assignment, I implemented a secure communication system for Alice and Bob to exchange a file (secret.txt) over 
an insecure channel. The system ensures confidentiality, integrity, and authenticity by combining RSA, AES, and HMAC in 
a multistep cryptographic process. The solution makes use of RSA for key exchange and digital signatures, AES for 
efficient encryption of the file content, and HMAC to verify data integrity. The goal was to design a file-based
system demonstrating some of cryptographic best practices.

---

## 2. Coding Process

### 2.1 Key Generation (`key_manager.py`)

- Implementation:
: I used the cryptography.hazmat.backends module to generate RSA key pairs for both Alice and Bob. Each key pair 
consists of a private and public key. The keys are saved in PEM format using serialization standards being PKCS8 for 
private keys and SubjectPublicKeyInfo for public keys.

- Challenges:
: Handling file permissions and ensuring the generated PEM files were correctly saved required careful validation. Using
the NoEncryption scheme simplified the process by avoiding key file passwords. This scheme is used to make it easy to use
in the assignment, as no password is required when loading private keys. In sense of a real world application though,
I would not do this. 

### 2.2 File Sending (`sender.py`)

- Key and IV Generation:
: I generated a random AES key, HMAC key, and IV using os.urandom. These keys are used for symmetric encryption (AES) 
and integrity checking (HMAC).

- Signing and Encryption:
: The AES key, IV, and HMAC key were together and signed with the sender's private RSA key using PSS padding and 
SHA-256. The signed keys were then encrypted using the recipient's public RSA key with OAEP padding, ensuring only the 
recipient could decrypt them.

- File Encryption:
: The file content was encrypted using AES in CTR mode to ensure confidentiality.

- HMAC Generation:
: I generated an HMAC of the encrypted file content using the HMAC key and saved it separately. This ensures the 
integrity of the encrypted content during transmission.

### 2.3 File Receiving (`receiver.py`)

- Key Decryption:
: The recipient decrypted the encrypted AES key, HMAC key, and IV using their private RSA key. This allowed the 
recipient to access the symmetric keys required for file decryption and integrity checking.

- HMAC Verification:
: The recipient verified the HMAC of the encrypted file content to ensure that the file had not been tampered with. If 
there was any mismatch in the HMAC values, it would've raised an integrity error.

- File Decryption:
: The file content was decrypted using AES in CTR mode with the decrypted AES key and IV. The decrypted content included
the sender’s name, timestamp, and the original file content.

- Signature Verification:
: The recipient verified the digital signature using the sender's public RSA key. This step confirmed the authenticity 
of the sender and ensured the integrity of the keys used.


---

## 3. Testing and Validation

### 3.1 Testing Process

- Component Testing:

  - RSA Key Generation: Verified that the keys generated for Alice and Bob were functional and correctly saved.
  - HMAC Verification: Simulated tampered data to ensure that invalid HMACs raised integrity errors
    (This is done by modifying encrypted_message.bin).
  - Signature Verification: Used mismatched public keys to confirm that signature validation failed.
  - Decryption: Ensured that correct keys and HMACs successfully decrypted the file content.

- Test Cases:

    1. Successful encryption and decryption of the file.
    2. Failed HMAC verification due to tampered encrypted data.
    3. Failed signature verification due to mismatched public keys.
    4. Handling missing or corrupted files.

### 3.2 Validation Results

- Positive test cases passed, confirming the correctness of encryption, HMAC generation, and signature verification.
- Negative cases, such as tampered files, correctly raised errors.

---

## 4. Questions and Explanations

**1. What is the purpose of including a timestamp in the file content?**  

The timestamp protects against replay attacks, ensuring that the message is valid only for a specific time frame. This 
adds another layer of security.

**2. Are we using Sign-then-Encrypt or Encrypt-then-Sign in this assignment? Explain why this approach was chosen.**  

We are using Sign-then-Encrypt. The keys are first signed with the sender’s private RSA key, then encrypted using the 
recipient's public RSA key. This ensures both authenticity and confidentiality.

**3. Are we using Encrypt-then-MAC or MAC-then-Encrypt in this assignment? Explain the choice and its implications.**  

We are using Encrypt-then-MAC. The encrypted content is passed through the HMAC process. This approach ensures that 
integrity is verified before decryption, ensuring no tampering in the ciphertext.

**4. Why are we using both AES and RSA? Why not use RSA to encrypt the entire file content directly?**  

RSA is computationally expensive and inefficient for encrypting large files. AES, a symmetric cipher, is optimized for 
encrypting large data efficiently. To be efficient we combine both of their strengths.

**5. Explain the difference between using RSA for encryption/decryption and using RSA for digital signing/verification.**  

- RSA Encryption: Uses the recipient's public key to encrypt data, which only the recipient's private key can decrypt.
- RSA Signing: Uses the sender's private key to sign data, which anyone with the sender's public key can verify.

**6. Explain why we sign first and then encrypt, instead of encrypting first and then signing.**  

Signing first ensures the authenticity of the plaintext data, as encryption would obscure the data if applied first. 
This approach also avoids exposing the signature to unintended recipients.

---

## 5. Reflection

**1. What are three key lessons you learned from this assignment?**  

- The importance of combining symmetric and asymmetric encryption for efficiency and security.
- The significance of HMAC for verifying data integrity before decryption.
- The role of digital signatures in ensuring authenticity in secure communication.

**2. How would you approach a similar problem differently in the future?**
In this solution, I included some error handling to deal with cases like missing files or failed HMAC and signature 
verifications. For example, the program uses try-except blocks to handle situations like tampered data or incorrect 
keys. However, in the future, I would improve how these errors are communicated to users. Right now, the program raises 
general errors, but I could make the error messages more specific and user-friendly, such as explaining why the 
decryption failed. Additionally, I would add error handling for other possible issues, like invalid file formats or 
permission errors when opening files. This would make the program more robust and easier to debug.
 

---

## 6. Conclusion

This assignment demonstrated the integration of multiple cryptographic techniques to build a secure communication 
system. The solution effectively addressed confidentiality, integrity, and authenticity. With additional time, I would 
implement a secure protocol for handling key storage and investigate any type of optimizations that would help elevate 
this.

--- 
