# Supply Chain Blockchain System

A command-line blockchain implementation for supply chain tracking, featuring cryptographic security and transaction verification.

## Features

- Secure blockchain implementation with RSA cryptography
- Automatic ID generation for supply chain items
- Digital signatures for transaction verification
- Proof-of-work mining system
- Full chain verification capabilities
- Command-line interface for easy interaction

### Installing Dependencies

```bash
sudo apt-get update
sudo apt-get install gcc libssl-dev
```

## Compilation

To compile the program:

```bash
gcc blockchain.c -o blockchain -lcrypto -lssl
```

## Running the Program

Execute the compiled program:

```bash
./blockchain
```

## Available Commands

- `create_blockchain` - Initialize a new blockchain
- `add_transaction <description>` - Add a new transaction
- `mine_block` - Mine a new block with pending transactions
- `print_blockchain` - Display the entire blockchain
- `verify_blockchain` - Verify the integrity of the chain
- `help` - Show available commands
- `exit` - Exit the program

## Usage Example

```bash
> create_blockchain
New blockchain created successfully!

> add_transaction Received 100 units of product X
Transaction added successfully! Generated ID: ITEM_1707019420_1

> add_transaction Shipped 50 units to Warehouse A
Transaction added successfully! Generated ID: ITEM_1707019425_2

> mine_block
Block mined successfully!

> verify_blockchain
Blockchain verification successful! All blocks are valid.

> print_blockchain
[Displays the blockchain with all transactions]
```

## Security Features

- 2048-bit RSA key pairs for digital signatures
- SHA-256 hashing for block integrity
- Cryptographic verification of all transactions
- Proof-of-work mining algorithm
- Chain integrity verification

## Technical Details

- Maximum transactions per block: 10
- Proof-of-work difficulty: 4 leading zeros
- RSA key length: 2048 bits
- Hash algorithm: SHA-256

## Notes

- Each item in the supply chain receives a unique, auto-generated ID
- All transactions are cryptographically signed
- The blockchain maintains an immutable record of all supply chain events
- Chain integrity can be verified at any time using the verify_blockchain command

## Error Handling

The program includes comprehensive error handling for:

- Full transaction pools
- Invalid signatures
- Chain verification failures
- Memory allocation errors
- Cryptographic operation failures
