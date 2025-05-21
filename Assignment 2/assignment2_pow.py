import hashlib



# Function to calculate hash value
def sha256(text): #complete this function to return hash value of the given text.
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


# Proof of Work Puzzle Solver
def solve_proof_of_work(previous_hash, user_input):
    target = 2 ** 250  # Puzzle target, we need hash < 2^250
    nonce = 0  # Start from nonce 0
    while True:
        # Concatenate nonce, previous block hash, and user input
        input_str = f"{nonce}{previous_hash}{user_input}"
        # Convert hash result to an integer
        hash_result = sha256(input_str)
        hash_int = int(hash_result, 16)
        # compare hash result against target
        if hash_int < target:
            # Return the nonce if condition is met (hash < target)
            return nonce, hash_result
        nonce += 1  # Increment nonce for the next attempt


# Define the block structure
class Block:
    def __init__(self, index, nonce, data, previous_hash, current_hash):
        self.index = index
        self.nonce = nonce
        self.data = data
        self.previous_hash = previous_hash
        self.current_hash = current_hash

    def __str__(self):
        return f"Block {self.index}:\nNonce: {self.nonce}\nData: {self.data}\nPrevious Hash: {self.previous_hash}\nCurrent Hash: {self.current_hash}\n"


# Main program loop
def main():
    previous_hash = "0" * 64  # Genesis block's "previous hash"
    blockchain = []  # List to store all blocks
    block_index = 0  # Index for each block

    while True:
        print("\n---- Blockchain Simulation ----")
        print("1. Create a new block")
        print("2. Print all blocks")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "3":
            print("Exiting...")
            break
        elif choice == "1":
            user_input = input("Enter data for the block: ")
            print("Solving proof of work...")
            nonce, current_hash = solve_proof_of_work(previous_hash, user_input)  # Find the valid nonce
            new_block = Block(block_index, nonce, user_input, previous_hash, current_hash)  # Create a new block
            blockchain.append(new_block)  # Append the block to the blockchain
            print(f"New block created with nonce: {nonce}")
            print(f"Hash of the new block: {current_hash}")
            previous_hash = current_hash  # Update the hash for the next block
            block_index += 1
        elif choice == "2":
            print("Listing all blocks")
            for block in blockchain:
                print(block)  # Print each block
        else:
            print("Invalid choice, please try again.")



if __name__ == "__main__":
    main()
