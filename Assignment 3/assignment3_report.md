# **Assignment 3 Report: Image Encryption with ECB, CBC, and CTR Modes** #

### CSCI/CSCY 3800: Applied Crypto (Fall 2024) ###

--- 

## Part 2: Security Comparison - ##

- **Explain why ECB mode is insecure for encrypting structured data like images:**
: ECB mode is insecure for encrypting structured data like images due to the way it functions.
Ti works as a block-based encryption with no randomness, this meaning that there will be identical
patterns once encrypted. This can be seen from the encrypted image as you can still see the word
'top secret' visually.

- **Discuss how CBC mode improves security by introducing an IV:**
: CBC mode improves security by the introduction of IV as it is unique for each encryption.
The IV in for this cipher ensures that even if we were to encrypt this image multiple times the
resulting ciphertext will be different. In addition, we know that CBC works in a chaining way,
so each block of ciphertext depends on the previous blocks and the IV. This will result in masking
patterns, thus making it more secure than EBC. This can be seen in the encrypted CBC image file.
where the image is scrambled, not displaying a pattern that represents the original image.

- **Highlight the advantages of CTR mode for encrypting large or streaming data:**
: As we know, CTR mode works as a stream cipher. This is because CTR mode works by generating a
key stream using a nonce, which is XOR'd with the plaintext. This ensures that the image ends up
with different results in ciphertext. But, what is really important to know is that CTR does not
need padding. Thus, this mode can be more parallelized, meaning it can handle large data more 
efficiently.

___

## Part 3: Complete the Report ##

### **Description of Image Encryption:**

- ECB Mode:
: For ECB mode, the image is first divided into a 16 byte blocks. Each block is going to be encrypted
using the same AES key generated. And if the image data is not a multiple of the block size, padding is
added to the last block to make it the block size. Though, due to lack of randomness, the result is preserved
patterns in which looks like the original image.

- CBC Mode:
: For CBC mode, we first generate a IV for each encryption. The IV is combined with the first block of plaintext
using XOR and then gets encrypted. Then it does chaining, where for each subsequent block, each block of plaintext
is XOR'd with ciphertext of the previous block before being encrypted. In addition, padding is added if it does
not meet the block size. Though encryption speed can be slower than ECB since each block is dependent on the previous
blocks.

- CTR Mode:
: For CTR mode, a random nonce is generated which is used to create a keystream. The plaintext is XOR'd with the
generated keystream to produce a ciphertext. Padding is not needed as CTR is a stream cipher, which means it is
processing the image byte by byte.

### **Visual and Security Analysis:**

- ECB Mode:
: **Visual Output:**
As we have discussed many times already, ECB mode will result in to identical image from the original plaintext. This
can be seen in the encrypted image of EBC as it has identical ciphertext blocks which still represents the original
image.

- CBC Mode:
: **Visual Output:**
CBC using the IV and XORing each block with the previous ciphertext breaks patterns. As we see in the encrypted image
that it appearance is scrambled and does not hold a resemblance to the original image.

- CTR Mode:
: **Visual Output:**
CTR is much like CBC where the visual output is also scrambled and does not hold a resemblance to the original image.


- Most Visually Secure Mode:
: The most visually secure mode would be CTR or CBC modes. ECB is not visually secure as it hold resemblance to the 
original image. FOr CBC and CTR they do not produce matching patterns to the original, so when it comes down you would
want to use either of these depending on the type of files you are working on. 

- Security Differences:
: **ECB mode:**
ECB mode does not have any randomness.
: **CBC mode:**
CBC has IV for randomness, and chains blocks together. One change would result in a avalanche effect. It is more secure
than EBC but it is slower for large data.
: **CTR mode:**
CTR has each byte of plaintext XOR's with a keystream, this ensures high randomness. Due to it being a stream cipher, it
is able to provide high secuirty while being able to handle large data.

#### **Answer the Following Questions:**

- Why is ECB mode unsuitable for encrypting structured data like images?
: I had started Part 2, and answered above. I realized that the same discussion is asked again. Like for the next question
in my original answer I already had compared ECB and CBC.

- How does CBC mode enhance security compared to ECB?
: This was answered in part 2.

- What are the primary advantages of CTR mode, and in what scenarios is it preferable to CBC or ECB?
: I've already discussed the advantages of CTR mode in part 2. I will list them off again real quick and discuss the rest
of the question. The advantages of CTR is that it runs in parallel, does not need padding, and offers randomness. Thus 
knowing what it is good for, the scenarios it is preferable in would most likely for encrypting large datasets and streaming
data, since due to how it runs in parallel it will be able to be much faster than CBC, and more secure than ECB.

- If you were encrypting confidential image data, which mode would you choose and why?
: Clearly, as stated above, CTR mode would most likely be the mode I would choose. This is because it will efficiently,
and securely encrypt the image data. In addition, if the image data is large, it is even more of a reason to use CTR, as 
CBC would be slower. ECB is just not a viable option for confidential image data, due to it preserving patterns.

### **Additional Questions:**

- Is padding necessary for each mode? Why or why not?
: It depends on the mode. For CBC and ECB it is necessary since they run on fixed-size blocks. If they didn't match the 
block size, than the encryption would simply not work. However, for CTR mode, padding is not needed as it works by encrypting
data byte by byte without needing to fit the data into blocks. 

- How does handling the Initialization Vector (IV) differ between CBC and CTR modes?
: CBC Mode:
In CBC mode, the IV is used to randomize onl the first block of plaintext. Since the way CBC works, the next block is 
then randomized based on the previous ciphertext block.  The IV is also stored with the ciphertext for decryption. 
: CTR Mode:
In CTR mode, it uses a nonce which generates a keystream which is XOR'd with the plaintext to produce ciphertext. The 
nonce is combined with a counter that increments for each block of plaintext. Each block is processed independently, using
a unique part of the generated key stream. But the nonce, is also stored with the ciphertext, but since it is unique for
each encryption, it can be sadely included with the encrypted data.

___