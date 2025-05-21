# **Assignment 2 Report: Blockchain Simulation with Proof of Work (PoW)**

### CSCI/CSCY 3800: Applied Crypto (Fall 2024)

## **Report:**

The code that was designed functions to simulate a blockchain by implementing the core components of blocks, 
cryptographic hashing, and Proof of Work (PoW). It allows users to create and store blocks, each containing 
data and a unique cryptographic hash that links it to the previous block. The PoW algorithm ensures that each 
block added to the blockchain requires an amount of computational effort by finding a nonce that, when combined 
with the block's data and the previous block's hash, produces a hash value below a specified target. The reasoning 
for this, is that this process makes it difficult to tamper with the blockchain. For this report, I will be going 
over the specific explanations of key points asked for.

### **How PoW Works in the Context of this Assignment:**

For this assignment, the way the PoW is used is to add new blocks which would simulate a blockchain. The PoW involves
finding a special number, called a "nonce," which, when combined with the previous block's hash and the new block's 
data, produces a SHA-256 hash that is smaller than a predefined target. If I were to explain this, this is what it is
doing step by step:

1. For every new block, the program tries to find a special number called a “nonce.” This "nonce" starts with the value of 0.

2. This nonce is combined with the information in the block and the hash of the previous block. This can be seen in the
with the code, " input_str = f"{nonce}{previous_hash}{user_input}" ".

3. The program then puts this combination and computes the SHA-256 hash of this string.

4. If this hash is smaller than a specific target number (like having fewer than a certain number of zeros at the start), 
then the nonce is accepted, and the new block is added to the blockchain.

5. However, if the hash doesn’t meet the target, the program increments the nonce until it is valid.

This process ensures that creating a new block requires some work, making it hard for anyone to change the information in
the blockchain. Thus, maintaining the integrity of the blockchain.

### **Impact of Adjusting the PoW Target:**

The difficulty of the PoW is directly based on the target value. If we were given a lower target, the more difficult it 
is to find a valid nonce. For example, if we took the target, and reduce it from 2^250 to 2^249, the number of possible 
valid hashes is halved, effectively doubling the difficulty. If I were to discuss the findings of this knowledge we
would look at the difficulty of different target values.

#### **Findings:**

- Target = 2^250 
 : This value would allow for moderate difficulty, and finding a valid nonce would take a reasonable amount of time.

- Target = 2^249
 : By reducing the target value to this amount, it would be twice as hard to solve. This meaning, it  will take roughly 
 twice as many attempts to find a valid nonce.

- Target = 2^240
 : Lowering the target to this value would significantly increase the difficulty, making it exponentially harder to find
  a valid nonce. The time required to find a solution can become very long.
 
Looking at the values above, it illustrates how small changes to the target can have a large impact on computational 
effort. Knowing this, by reducing the target value it would increase the security of the blockchain by making it more resistant 
to attacks. However, it also increases the computational resources required, which can become a factor that limits it 
capabilities.

### **Challenges Encountered During Implementation Challenges Faced:**

The main challenges I faced during this implementation would be just overall understanding the assignment. As I know a
few people in the class seems to have already some background knowledge, I am still digesting a lot of the information of
why, how and for what reasons we are doing these. But slowly while writing out these assignments I am understanding more of
the logic that is being implemented and for the reason why. Now I really am understanding the PoW and how these
smaller target values are increase the difficulty.