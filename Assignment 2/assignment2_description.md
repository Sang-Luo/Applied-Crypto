# Assignment 2: Blockchain Simulation with Proof of Work (PoW)

## Overview

In this assignment, you will simulate a simple blockchain by implementing the core components: blocks, cryptographic hashing, and Proof of Work (PoW). You will write a Python program that builds a blockchain, solves PoW puzzles, and keeps track of all blocks in the chain. You will also implement a way to print the entire blockchain and verify its integrity.

The purpose of this assignment is to help you understand how a blockchain works, how PoW ensures block integrity, and how cryptographic hashes secure blockchain systems like Bitcoin.

## Key Concepts
- **Blockchain**: A chain of blocks where each block contains a unique cryptographic hash, data (e.g., transactions), and a link to the previous block's hash.
- **Proof of Work (PoW)**: A computational challenge miners solve to add a block to the chain. In this assignment, you will find a nonce such that the hash of `(nonce + previous_block_hash + data)` is smaller than a target (e.g., \(2^{250}\)).
- **Nonce**: A number that, when combined with the data and previous block's hash, results in a valid hash that meets the PoW criteria.
- **SHA-256 Hashing**: A cryptographic function used to generate a unique hash for each block. You will use Python's `hashlib` library for this.

## Learning Objectives
By completing this assignment, you will:
- Gain practical experience in implementing a **blockchain** from scratch.
- Understand how **Proof of Work (PoW)** ensures security in blockchain systems.
- Learn how to use **SHA-256** to securely link blocks together.
- Practice working with **cryptographic functions** and **Python programming** in the context of real-world applications.

## Overall Problem Statement

You will create a Python program that:
1. **Simulates a blockchain** by creating blocks.
2. **Solves a Proof of Work (PoW) puzzle** to add a valid block to the blockchain.
3. **Stores all blocks** in a list and allows users to view the chain.
4. Provides a menu with three options:
   - Create a new block by solving PoW.
   - Print the entire blockchain.
   - Exit the simulation.

## Detailed Instructions

### Program Requirements:

1. **Blockchain Simulation**:
   - The blockchain starts with a **genesis block** (the first block) that has an arbitrary previous hash (e.g., all zeros).
   - Every subsequent block contains:
     - The **data** entered by the user (e.g., transactions).
     - The **nonce** found by the PoW algorithm.
     - The **hash of the previous block**.
     - The **current block's hash**.

2. **Proof of Work (PoW)**:
   - The PoW algorithm should find a **nonce** such that the SHA-256 hash of `(nonce + previous_block_hash + user_data)` is smaller than a threshold \(e.g., 2^{250}\).
   - The `solve_proof_of_work` function should iterate over possible nonces until it finds a valid one.
   
3. **Menu Options**:
   - **Create a new block**: Ask the user to enter the data for the block and then solve the PoW puzzle to create the block. Append the block to the blockchain.
   - **Print all blocks**: Display details (index, nonce, data, previous hash, current hash) of each block in the blockchain.
   - **Exit**: Exit the simulation.

4. **Block Structure**:
   - Each block should contain the following fields:
     - **Index**: The position of the block in the blockchain.
     - **Nonce**: The value that solves the PoW puzzle.
     - **Data**: The user-provided data.
     - **Previous Hash**: The hash of the previous block.
     - **Current Hash**: The hash of the current block (calculated using the nonce, previous hash, and data).

### Example Menu:
---- Blockchain Simulation ----

1. Create a new block

2. Print all blocks

3. Exit

### Example Block Print Output:

    Block 0:
    
    Nonce: 127
    
    Data: 1
    
    Previous Hash: 0000000000000000000000000000000000000000000000000000000000000000
    
    Current Hash: 02827cc5f71db5dcb5ed8c3ce15a95755e0a2e67285ae9d76e89dda7390c600b
    
    \-----
    
    Block 1:
    
    Nonce: 29
    
    Data: 2
    
    Previous Hash: 02827cc5f71db5dcb5ed8c3ce15a95755e0a2e67285ae9d76e89dda7390c600b
    
    Current Hash: 022de634dcb636c6eba230e7351ae6a27f80849b9f749a714737ded80feb2762

## Deliverables

1. **Python Program**: complete `assignment2_pow.py` (starter code provided) 
   - The program should implement the blockchain, PoW, and block creation as described above.
   - The program should store and display blocks, and handle multiple user interactions through a simple menu.

2. **Report**: complete `assignment2_report.md` using MarkDown style
   - Briefly explain how PoW works in the context of this assignment.
   - Discuss the impact of adjusting the PoW target (e.g., reducing it from \(2^{250}\) to \(2^{249}\), ..., until \(2^{240}\)). Discuss your findings. How did the difficulty of the puzzle changed?  
   - Discuss any challenges you encountered during implementation.

