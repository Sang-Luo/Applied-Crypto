
---

# Password Manager: Cryptographic Design and Implementation

## **1. Introduction**
This project implements a secure password manager leveraging cryptographic principles learned in the **Applied Cryptography** course. It focuses on providing confidentiality, integrity, and recoverability for sensitive user credentials while maintaining user-friendliness.

---

## **2. Cryptographic Techniques Used**

### **2.1 Hashing and Salting**
- **Purpose**: Protect the master password by hashing it securely.
- **Implementation**:
  - Used `Scrypt` for key derivation with the following parameters:
    - **Salt**: Random 16 bytes.
    - **Key Length**: 32 bytes.
    - **Work Factor (n)**: \(2^{14}\).
  - The salt and hashed password are stored in `master_pass.txt`.
- **Reason**: Scrypt is memory-intensive, making brute-force and dictionary attacks expensive.

---

### **2.2 AES Encryption**
- **Purpose**: Encrypt service credentials (passwords) for confidentiality.
- **Implementation**:
  - **AES-CTR**:
    - Encrypts passwords with a unique 128-bit nonce.
  - **AES-ECB**:
    - Encrypts service names for consistent storage.
- **Reason**:
  - AES-CTR ensures secure encryption with a unique nonce for each service.
  - AES-ECB simplifies searching for encrypted service names.

---

### **2.3 HMAC for Integrity**
- **Purpose**: Ensure stored data (service name and password) has not been tampered with.
- **Implementation**:
  - Generated HMACs using a separate key derived via `Scrypt`.
  - Used `SHA-256` as the hash function for HMAC.
- **Reason**:
  - Protects against data corruption or malicious tampering.

---

### **2.4 RSA for Master Key Backup**
- **Purpose**: Enable recovery of the master key if the user forgets the master password.
- **Implementation**:
  - Generated a 2048-bit RSA key pair.
  - Encrypted the master key with the public key and stored it in `backup_key.txt`.
  - Stored the private key in `user_private_key.pem`.
- **Reason**:
  - Asymmetric encryption provides a secure way to back up and recover sensitive material.

---

## **3. Design Choices**

### **3.1 Storage**
- Service credentials and their HMACs are stored in `master.txt`. This ensures all sensitive data is encrypted and integrity-checked.

### **3.2 Password Management**
- Implemented features to add, retrieve, update, and delete services.
- Simplifies user experience while maintaining data security.

### **3.3 Master Password Recovery**
- Using RSA ensures that the master key can be recovered without storing the master password in plaintext.

---

## **4. Security Considerations**

### **4.1 Nonce Reuse**
- Ensured a unique 128-bit nonce is generated for each password encryption to prevent attacks on AES-CTR.

### **4.2 HMAC Key Separation**
- Derived a separate HMAC key from the master password to avoid key reuse vulnerabilities.

### **4.3 Key Management**
- RSA private and public keys are securely stored, and access to the private key is restricted to the user.

---

## **5. Implementation Challenges**

### **5.1 Scrypt Parameters**
- Finding optimal parameters (e.g., \(n=2^{14}\)) that balance security with performance.

### **5.2 Testing and Debugging**
- Ensuring all cryptographic components (hashing, encryption, HMAC) integrate seamlessly without exposing vulnerabilities.

---

## **6. Future Enhancements**
- **Database Storage**:
  - Replace `master.txt` with an SQL database for scalability.
- **Graphical User Interface (GUI)**:
  - Develop a GUI to improve user experience.
- **Multi-User Support**:
  - Extend functionality to allow multiple users with separate master passwords.

---

## **7. Conclusion**
This password manager demonstrates the practical application of cryptographic principles to real-world problems. It ensures confidentiality, integrity, and recoverability, making it a robust tool for secure password management.
