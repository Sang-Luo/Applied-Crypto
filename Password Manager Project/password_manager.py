# Import Statements
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from getpass import getpass
# Other imports might be needed. Use cryptography and other well-used libraries discussed throughout the course.

# Constants
SALT_SIZE = 16  # 16 bytes for salt
NONCE_SIZE = 16  # 16 bytes for AES-CTR nonce
BLOCK_SIZE = 16  # AES block size

# Function to securely hash and salt the master password
def hash_master_password(master_password):
    """
    Derives a hashed and salted version of the master password using Scrypt.
    This provides enhanced security against brute-force and dictionary attacks.

    :param master_password: Plaintext master password provided by the user
    :return: A tuple containing:
             - salt: Randomly generated salt used during the hashing process
             - hashed_password: The derived key (hashed password) using Scrypt
    """
    salt = os.urandom(SALT_SIZE)  # Generate a random salt of defined size
    # Use Scrypt for secure key derivation with computational cost
    kdf = Scrypt(
        salt=salt,
        length=32,  # Length of the derived key
        n=2**14,  # Work factor (determines computational cost)
        r=8,  # Block size (affects memory usage)
        p=1,  # Parallelism factor (threads used)
        backend=default_backend()
    )
    hashed_password = kdf.derive(master_password)  # Derive the key
    return salt, hashed_password

# Function to validate the master password against the stored hash
def validate_master_password(input_password, stored_salt, stored_hash):
    """
    Validates the master password provided during login by deriving its hash using
    Scrypt with the stored salt, and comparing it to the stored hash.

    :param input_password: The plaintext password entered by the user
    :param stored_salt: Salt stored during the sign-up process
    :param stored_hash: Hashed password stored during the sign-up process
    :return: Boolean indicating whether the password is valid (True/False)
    """
    print("Validating master password...")
    try:
        kdf = Scrypt(
            salt=stored_salt,
            length=32,
            n=2**14,  # Reduce n for faster testing
            r=8,
            p=1,
            backend=default_backend()
        )
        kdf.verify(input_password.encode(), stored_hash)
        print("Password validation succeeded.")
        return True
    except Exception as e:
        print(f"Password validation failed: {e}")
        return False


# Function to backup the master key using RSA encryption
def backup_master_key(master_key):
    """
    Encrypts the master key using RSA public key encryption and stores it in a
    backup file. This ensures the master key can be recovered if the user forgets
    their master password.

    :param master_key: Derived key generated from the master password using Scrypt
    """
    # Generate a new RSA key pair (private and public keys)
    private_key, public_key = generate_rsa_keys()

    # Encrypt the master key using the RSA public key
    encrypted_master_key = public_key.encrypt(
        master_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function
            algorithm=hashes.SHA256(),  # Hash algorithm for padding
            label=None
        )
    )

    # Save the encrypted master key to a backup file
    with open('backup_key.txt', 'wb') as writer:
        writer.write(encrypted_master_key)

    # Save the RSA private and public keys to files for future recovery
    save_key_to_file(private_key, 'user_private_key.pem', is_private=True)
    save_key_to_file(public_key, 'user_public_key.pem')


# Function to read the master password hash and salt from the file
def read_master_password():
    with open("master_pass.txt", "rb") as f:
        data = f.read()
        return data[:SALT_SIZE], data[SALT_SIZE:]  # First part is salt, second is hashed password

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_to_file(key, filename, is_private=False):
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(filename, 'wb') as key_file:
        key_file.write(pem)
    return

# Function for the signup process to set a new master password
def signup():
    """
    Sign-up process to create a new master password, derive a key, and store it securely.
    """
    # Prompt the user to set a new master password
    password = input("Enter Password: ").encode()

    # Hash and salt the master password using Scrypt
    salt, hashed_pass = hash_master_password(password)

    # Write the salt and hashed password to the master_pass.txt file
    with open('master_pass.txt', 'wb') as writer:
        writer.write(salt + hashed_pass)  # Combine salt and hashed password for storage

    # Derive the encryption key from the master password
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    master_key = kdf.derive(password)  # Derive the master key

    # Generate RSA key pairs for master key backup
    private_key, public_key = generate_rsa_keys()

    # Encrypt the master key using the RSA public key
    encrypted_master_key = public_key.encrypt(
        master_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the encrypted master key to the backup_key.txt file
    with open('backup_key.txt', 'wb') as writer:
        writer.write(encrypted_master_key)

    # Save the RSA private and public keys to their respective files
    save_key_to_file(private_key, 'user_private_key.pem', is_private=True)
    save_key_to_file(public_key, 'user_public_key.pem')

    print("Master password created and securely stored.")


# Function for signout
def signout():
    """
    Securely unloads sensitive data from memory and performs clean-up operations.
    Ensures encryption keys and other sensitive material are not retained in memory.
    """
    # Clear sensitive variables
    global encryption_key, hmac_key
    encryption_key = None
    hmac_key = None

    # Perform additional clean-up if needed
    print("All sensitive data has been securely unloaded from memory.")

# Function to load or generate encryption and HMAC keys using Scrypt
def load_encryption_key(master_password):
    """
    Derives two keys (encryption and HMAC) from the master password using Scrypt.
    These keys are used for encrypting/decrypting passwords and ensuring integrity.

    :param master_password: The plaintext master password
    :return: A tuple containing:
             - encryption_key: The key used for AES encryption/decryption
             - hmac_key: The key used for generating/verifying HMACs
    """
    # Retrieve the salt stored during sign-up
    salt, _ = read_master_password()

    # Derive a single 64-byte key using Scrypt, split into encryption and HMAC keys
    kdf = Scrypt(
        salt=salt,
        length=64,  # Generate a 64-byte key
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    derived_key = kdf.derive(master_password.encode())  # Derive key material

    # Split the derived key into two 32-byte keys
    encryption_key = derived_key[:32]  # First 32 bytes for encryption
    hmac_key = derived_key[32:]  # Next 32 bytes for HMAC
    return encryption_key, hmac_key

# Function to encrypt the service name using AES-ECB
def encrypt_servicename(service_name, encryption_key):
    '''
    Encrypt the service name using AES-ECB with the given encryption key.
    :param service_name: string
    :param encryption_key: encryption key
    :return: encrypted service name
    '''
    from cryptography.hazmat.primitives import padding  # Ensure PKCS7 is from the correct module
    padder = padding.PKCS7(BLOCK_SIZE * 8).padder()  # BLOCK_SIZE should be correctly defined
    padded_service_name = padder.update(service_name.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_service_name) + encryptor.finalize()


# Function to decrypt the service name using AES-ECB
def decrypt_servicename(encrypted_service_name, encryption_key):
    '''
    Decrypt the service name using AES-ECB with the given encryption key.
    :param encrypted_service_name: encrypted service name
    :param encryption_key: encryption key
    :return: decrypted service name
    '''
    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_service_name) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize().decode()



# Function to encrypt the password
def encrypt_password(password, encryption_key):
    '''
    Encrypt the password using AES-CTR encryption.
    :return: encrypted_password, nonce
    '''
    nonce = os.urandom(NONCE_SIZE)  # Generate a random nonce
    cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(password.encode()) + encryptor.finalize()
    return encrypted_password, nonce



# Function to decrypt the password using AES-CTR
def decrypt_password(encrypted_password, nonce, encryption_key):
    '''
    Decrypt the password using the encryption key and nonce.
    :return: decrypted password
    '''
    cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
    return decrypted_password.decode()  # Convert bytes to string


# Function to recover the master key using RSA
def recover_master_key():
    """Recovers the master key by decrypting the RSA-encrypted backup using the private key.
    Recreates the master_pass.txt file with a new password."""
    private_key_path = input("Enter the path to your private key file: ")
    try:
        # Load the private key
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

    try:
        # Read the encrypted master key from backup
        with open('backup_key.txt', 'rb') as f:
            encrypted_master_key = f.read()
        # Decrypt the master key
        master_key = private_key.decrypt(
            encrypted_master_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Master key recovered successfully!")

        # Prompt user to set a new master password
        new_master_password = input("Enter a new master password: ").encode()

        # Create a new salt and hash the new password
        salt, hashed_password = hash_master_password(new_master_password)

        # Save the new master_pass.txt
        with open("master_pass.txt", "wb") as f:
            f.write(salt + hashed_password)

        print("New master_pass.txt created successfully!")
        return master_key

    except Exception as e:
        print(f"Error decrypting master key: {e}")
        return None

'''
These two functions were already asked, and basically asking same thing as previous named one.
I am just gonna comment this out.
# Function to encrypt the password
def encrypt_password(password, encryption_key):

    Encrypt the password using strong password (e.g AES-CTR).


    pass

# Function to decrypt a password using AES or Fernet.
def decrypt_password(encrypted_password, encryption_key):

    Decrypt the password using the encryption key.


    pass
'''

# Function to add HMAC for integrity check.
def add_hmac(encrypted_service_name, encrypted_password, key):
    """Generate an HMAC using the service name and encrypted password to ensure the integrity of the stored data."""
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_service_name)
    service_hmac = h.finalize()
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_password)
    password_hmac = h.finalize()
    print(f"Debug - Generated HMACs: Service HMAC: {service_hmac}, Password HMAC: {password_hmac}")
    return service_hmac, password_hmac

# Function to verify the integrity using the HMAC
def verify_hmac(encrypted_service_name, encrypted_password, service_hmac, password_hmac, key):
    """Verify the HMAC to ensure the integrity of stored data."""
    try:
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(encrypted_service_name)
        h.verify(service_hmac)
        print("Debug - Service HMAC verification succeeded.")
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(encrypted_password)
        h.verify(password_hmac)
        print("Debug - Password HMAC verification succeeded.")
    except Exception as e:
        print(f"Debug - HMAC verification failed: {e}")
        raise

# Function to add a new service, username, and password.
def add_service(service_name, username, password, encryption_key, hmac_key):
    """Add a new service with encrypted password and HMAC."""
    encrypted_service_name = encrypt_servicename(service_name, encryption_key)
    encrypted_password, nonce = encrypt_password(password, encryption_key)
    service_hmac, password_hmac = add_hmac(encrypted_service_name, encrypted_password, hmac_key)

    entry = (
            encrypted_service_name + b"||" +
            encrypted_password + b"||" +
            nonce + b"||" +
            service_hmac + b"||" +
            password_hmac
    )

    print(f"Debug - Writing to master.txt: {entry}")  # Debugging
    with open("master.txt", "ab") as f:
        f.write(entry + b"\n")

# Function to retrieve a password
def retrieve_service(service_name, encryption_key, hmac_key):
    """Retrieve the password for a given service by decrypting it."""
    encrypted_service_name = encrypt_servicename(service_name, encryption_key)
    print(f"Debug - Encrypted service name for retrieval: {encrypted_service_name}")  # Debugging
    with open("master.txt", "rb") as f:
        for line in f:
            try:
                # Unpack fields
                stored_service, stored_password, nonce, service_hmac, password_hmac = line.strip().split(b"||")
                print(f"Debug - Stored values: {stored_service}, {stored_password}, {nonce}, {service_hmac}, {password_hmac}")
            except ValueError:
                print("Malformed entry found in master.txt. Skipping...")  # Debugging
                continue

            if stored_service == encrypted_service_name:
                try:
                    verify_hmac(stored_service, stored_password, service_hmac, password_hmac, hmac_key)
                    return decrypt_password(stored_password, nonce, encryption_key)
                except Exception as e:
                    print(f"Debug - Integrity check failed: {e}")  # Debugging
                    return "Data integrity check failed."
    print("Service not found.")
    return "Service not found."



# Function to update a password for a service
def update_service(service_name, new_password, encryption_key, hmac_key):
    """
    Update the password for an existing service and re-generate HMAC.
    :param service_name: Service name
    :param new_password: New password to be updated
    :param encryption_key: Encryption key derived from master password
    :param hmac_key: HMAC key derived from master password
    """
    print(f"Debug - Starting update for service: {service_name}")
    delete_service(service_name, encryption_key, hmac_key)  # Remove old entry
    print(f"Debug - Old service deleted: {service_name}")
    add_service(service_name, "N/A", new_password, encryption_key, hmac_key)  # Add updated entry
    print(f"Debug - New service added: {service_name}")

# Function to delete a service's stored credentials
def delete_service(service_name, encryption_key, hmac_key):
    """
    Delete the stored credentials for a service.
    :param service_name: Service name
    :param encryption_key: Encryption key derived from master password
    :param hmac_key: HMAC key derived from master password (not used in deletion)
    """
    encrypted_service_name = encrypt_servicename(service_name, encryption_key)
    new_lines = []
    with open("master.txt", "rb") as f:
        for line in f:
            stored_service, *_ = line.strip().split(b"||")
            if stored_service != encrypted_service_name:
                new_lines.append(line)
    with open("master.txt", "wb") as f:
        print(f"Debug - Rewriting master.txt with {len(new_lines)} remaining entries")
        f.writelines(new_lines)
    print(f"Debug - Service deletion completed")


# Main Driver Function
def main():
    """
    Main function to drive the Password Manager.
    Handles user authentication and provides options for managing passwords.
    """
    print("Starting the Password Manager...")  # Debugging message

    if os.path.exists("master_pass.txt"):
        print("Master password file found. Attempting login...")  # Debugging message

        # Authenticate the user if a master password exists
        master_password = input("Enter master password: ")
        print("Reading master_pass.txt...")
        salt, stored_hash = read_master_password()
        print(f"Salt: {salt}, Hashed Password: {stored_hash}")

        # Validate the master password
        if validate_master_password(master_password, salt, stored_hash):
            print("Master password validated!")
            # Load encryption and HMAC keys for the session
            encryption_key, hmac_key = load_encryption_key(master_password)
        else:
            print("Invalid master password.")
            return
    else:
        # If no master password exists, prompt the user to set one
        print("No master password found. Redirecting to sign-up...")
        signup()
        print("Sign-up completed. Please restart the program.")
        return

        # Password Manager menu
    while True:
        print(  # Main menu display
            "\nPassword Manager Options:\n"
            "1. Add New Service\n"
            "2. Retrieve Password\n"
            "3. Update Service\n"
            "4. Delete Service\n"
            "5. Backup Master Key\n"
            "6. Recover Master Key\n"
            "7. Exit"
        )
        choice = input("Enter your choice: ")

        if choice == "1":
            # Add a new service
            print("Adding a new service...")  # Debugging message
            service_name = input("Enter the service name: ")
            username = input("Enter the username: ")
            password = input("Enter the password: ")
            add_service(service_name, username, password, encryption_key, hmac_key)
            print(f"Service '{service_name}' added successfully!")

        elif choice == "2":
            # Retrieve a stored password
            # Check if master.txt file exists
            if not os.path.exists('master.txt'):
                print('master.txt file does not exist.')
                continue
            print("Retrieving a password...")  # Debugging message
            service_name = input("Enter the service name: ")
            # Check that there is a service with the inputted name
            if retrieve_service(service_name, encryption_key, hmac_key) == "Service not found.":
                continue
            retrieved_password = retrieve_service(service_name, encryption_key, hmac_key)
            if retrieved_password:
                print(f"Password for '{service_name}': {retrieved_password}")
            else:
                print(f"Service '{service_name}' not found or data integrity compromised.")

        elif choice == "3":
            # Update an existing password
            # Check if master.txt file exists
            if not os.path.exists('master.txt'):
                print('master.txt file does not exist.')
                continue
            print("Updating a password...")  # Debugging message
            service_name = input("Enter the service name: ")
            # Check that there is a service with the inputted name
            if retrieve_service(service_name, encryption_key, hmac_key) == "Service not found.":
                continue
            new_password = input("Enter the new password: ")
            update_service(service_name, new_password, encryption_key, hmac_key)
            print(f"Password for '{service_name}' updated successfully!")

        elif choice == "4":
            # Delete stored credentials for a service
            # Check if master.txt file exists
            if not os.path.exists('master.txt'):
                print('master.txt file does not exist.')
                continue
            print("Deleting a service...")  # Debugging message
            service_name = input("Enter the service name: ")
            # Check that there is a service with the inputted name
            if retrieve_service(service_name, encryption_key, hmac_key) == "Service not found.":
                continue
            delete_service(service_name, encryption_key, hmac_key)
            print(f"Service '{service_name}' deleted successfully!")

        elif choice == "5":
            # Backup the master key securely
            print("Backing up the master key...")  # Debugging message
            backup_master_key(encryption_key)
            print("Master key backed up successfully!")

        elif choice == "6":
            # Recover the master key using the RSA private key
            print("Recovering the master key...")  # Debugging message
            recovered_master_key = recover_master_key()
            if recovered_master_key:
                print("Master key recovered successfully!")
            else:
                print("Failed to recover the master key.")

        elif choice == "7":
            # Exit the program
            print("Exiting the program...")
            signout()
            print("Goodbye!")
            break

        else:
            print("Invalid input, please try again.")


if __name__ == "__main__":
    main()
