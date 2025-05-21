from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Class modes codes based off Class EncryptionManager
# ECB Image Encrypytor Class
class ECBImageEncryptor:
    def __init__(self, key):
        # Initialization with AES Key
        self.key = key
        # Create the AES cipher into ECB mode
        self.cipher = Cipher(algorithms.AES(self.key),
                             modes.ECB(),
                             backend=default_backend())
        # Initialize encryptor and decryptor
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()
        # PKCS7 padding, this will handle the data not a multiple of 16 bytes
        self.padder = padding.PKCS7(128).padder()
        self.unpadder = padding.PKCS7(128).unpadder()

    def encrypt(self, img_data):
        # Extract the first 54 bytes, so we can leave it unchanged
        header = img_data[:54]
        # This is the rest of the image data, which will be encrypted
        body = img_data[54:]
        # Apply the padding to the image body, to ensure image data is 16 bytes
        padded_body = self.padder.update(body) + self.padder.finalize()
        # Encrypted the body
        encrypted_body = self.encryptor.update(padded_body) + self.encryptor.finalize()
        # This will return the header with the encrypted body
        return header + encrypted_body

    def decrypt(self, enc_data):
        # Extract the header, and the body.
        header = enc_data[:54]
        body = enc_data[54:]
        # Decrypt the body
        decrypted_body = self.decryptor.update(body) + self.decryptor.finalize()
        # Remove the padding to body
        unpadded_body = self.unpadder.update(decrypted_body) + self.unpadder.finalize()
        # Return the original body without padding with the header
        return header + unpadded_body

# CBC Image Encryptor Class
class CBCImageEncryptor:
    def __init__(self, key):
        self.key = key
        # Generate an IV of 16 bytes
        self.iv = os.urandom(16)
        # Create the AES cipher into CBC mode
        self.cipher = Cipher(algorithms.AES(self.key),
                             modes.CBC(self.iv),
                             backend=default_backend())
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()
        self.padder = padding.PKCS7(128).padder()
        self.unpadder = padding.PKCS7(128).unpadder()

    def encrypt(self, img_data):
        header = img_data[:54]
        body = img_data[54:]
        # Apply padding
        padded_body = self.padder.update(body) + self.padder.finalize()
        # Encrypt body
        encrypted_body = self.encryptor.update(padded_body) + self.encryptor.finalize()
        # Return the header, IV, and encrypted body
        return header + self.iv + encrypted_body

    def decrypt(self, enc_data):
        # Extract the header, and IV
        header = enc_data[:54]
        # The IV is stored in the first 16 bytes after the header, because it is 16 bytes
        iv = enc_data[54:70]
        body = enc_data[70:]
        # Re-create the cipher object using the extracted IV
        cipher = Cipher(algorithms.AES(self.key),
                        modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        # Decrypt the body
        decrypted_body = decryptor.update(body) + decryptor.finalize()
        # Remove the padding
        unpadded_body = self.unpadder.update(decrypted_body) + self.unpadder.finalize()
        return header + unpadded_body

# CTR Image Encryptor Class
class CTRImageEncryptor:
    def __init__(self, key):
        self.key = key
        # Generate a nonce of 16 bytes
        self.nonce = os.urandom(16)
        self.cipher = Cipher(algorithms.AES(self.key),
                             modes.CTR(self.nonce),
                             backend=default_backend())
        # CTR does not need padding.
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()

    def encrypt(self, img_data):
        header = img_data[:54]
        body = img_data[54:]
        encrypted_body = self.encryptor.update(body) + self.encryptor.finalize()
        return header + self.nonce + encrypted_body

    def decrypt(self, enc_data):
        header = enc_data[:54]
        # The nonce is stored in the first 16 bytes after the header
        nonce = enc_data[54:70]
        body = enc_data[70:]
        cipher = Cipher(algorithms.AES(self.key),
                        modes.CTR(nonce),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_body = decryptor.update(body) + decryptor.finalize()
        return header + decrypted_body

# This function will read an image as binary data
def read_image_as_bytes(image_path):
    with open(image_path, 'rb') as img_file:
        return img_file.read()

# This function will save binary data back into an image file
def save_image_from_bytes(image_bytes, output_path):
    with open(output_path, 'wb') as img_file:
        img_file.write(image_bytes)

# These function will encrypt and decrypt based on the given input
def encrypt_image(image_path, output_path, encryptor):
    img_data = read_image_as_bytes(image_path)
    encrypted_data = encryptor.encrypt(img_data)
    save_image_from_bytes(encrypted_data, output_path)

def decrypt_image(image_path, output_path, decryptor):
    img_data = read_image_as_bytes(image_path)
    decrypted_data = decryptor.decrypt(img_data)
    save_image_from_bytes(decrypted_data, output_path)


# This is our random 32 byte AES key
key = os.urandom(32)

# Encrypt with ECB
ecb_encryptor = ECBImageEncryptor(key)
encrypt_image('top_secret.bmp', 'encrypted_ecb.bmp', ecb_encryptor)

# Decrypt with ECB
decrypt_image('encrypted_ecb.bmp', 'decrypted_ecb.bmp', ecb_encryptor)

# Encrypt with CBC
cbc_encryptor = CBCImageEncryptor(key)
encrypt_image('top_secret.bmp', 'encrypted_cbc.bmp', cbc_encryptor)

# Decrypt with CBC
decrypt_image('encrypted_cbc.bmp', 'decrypted_cbc.bmp', cbc_encryptor)

# Encrypt with CTR
ctr_encryptor = CTRImageEncryptor(key)
encrypt_image('top_secret.bmp', 'encrypted_ctr.bmp', ctr_encryptor)

# Decrypt with CTR
decrypt_image('encrypted_ctr.bmp', 'decrypted_ctr.bmp', ctr_encryptor)

# For Part 2 I had written the security comparison in the report, but as I went along further into
# part 3, I realized that the questions were asking for the analysis in part 2. So my answers are kind of
# throughout the report, and I just mentioned in was answer in part 2 section I had written out already.