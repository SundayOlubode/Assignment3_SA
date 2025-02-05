#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <ctype.h>

#define MAX_TRANSACTIONS 10
#define HASH_LENGTH 64
#define DIFFICULTY 4
#define MAX_DESCRIPTION 256
#define MAX_ID_LENGTH 64
#define MAX_CMD_LENGTH 512
#define SIGNATURE_LENGTH 256
#define KEY_LENGTH 2048

// Structure for public-private key pair
typedef struct
{
	RSA *private_key;
	RSA *public_key;
} KeyPair;

// Structure for transaction
typedef struct
{
	char item_id[MAX_ID_LENGTH];
	char description[MAX_DESCRIPTION];
	time_t timestamp;
	unsigned char signature[SIGNATURE_LENGTH];
	size_t signature_length;
} Transaction;

typedef struct Block
{
	time_t timestamp;
	Transaction transactions[MAX_TRANSACTIONS];
	int transaction_count;
	unsigned char previous_hash[SHA256_DIGEST_LENGTH];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned int nonce;
	struct Block *next;
} Block;

typedef struct
{
	Block *head;
	Transaction pending_transactions[MAX_TRANSACTIONS];
	int pending_count;
	KeyPair keys;
} Blockchain;

// Function to initialize OpenSSL
void init_openssl()
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
}

// Function to cleanup OpenSSL
void cleanup_openssl()
{
	EVP_cleanup();
	ERR_free_strings();
}

// Generate RSA key pair
KeyPair generate_key_pair()
{
	KeyPair pair = {NULL, NULL};
	RSA *rsa = NULL;
	BIGNUM *bne = NULL;

	// Generate key pair
	bne = BN_new();
	BN_set_word(bne, RSA_F4);
	rsa = RSA_new();
	RSA_generate_key_ex(rsa, KEY_LENGTH, bne, NULL);

	// Create copies for public and private keys
	pair.private_key = RSAPrivateKey_dup(rsa);
	pair.public_key = RSAPublicKey_dup(rsa);

	// Cleanup
	RSA_free(rsa);
	BN_free(bne);

	return pair;
}

// Free key pair
void free_key_pair(KeyPair *pair)
{
	if (pair->private_key)
		RSA_free(pair->private_key);
	if (pair->public_key)
		RSA_free(pair->public_key);
}

// Calculate hash of data
void calculate_hash(const unsigned char *data, size_t length, unsigned char *hash)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, data, length);
	EVP_DigestFinal_ex(ctx, hash, NULL);
	EVP_MD_CTX_free(ctx);
}

// Sign data using private key
int sign_data(RSA *private_key, const unsigned char *data, size_t data_len,
	      unsigned char *signature, size_t *signature_len)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_PKEY *priv_key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(priv_key, RSAPrivateKey_dup(private_key));

	if (EVP_SignInit(ctx, EVP_sha256()) != 1)
		return 0;
	if (EVP_SignUpdate(ctx, data, data_len) != 1)
		return 0;
	if (EVP_SignFinal(ctx, signature, signature_len, priv_key) != 1)
		return 0;

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(priv_key);
	return 1;
}

// Verify signature using public key
int verify_signature(RSA *public_key, const unsigned char *data, size_t data_len,
		     const unsigned char *signature, size_t signature_len)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_PKEY *pub_key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pub_key, RSAPublicKey_dup(public_key));

	if (EVP_VerifyInit(ctx, EVP_sha256()) != 1)
		return 0;
	if (EVP_VerifyUpdate(ctx, data, data_len) != 1)
		return 0;
	int result = EVP_VerifyFinal(ctx, signature, signature_len, pub_key);

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pub_key);
	return result == 1;
}

// Calculate block hash
void calculate_block_hash(Block *block, unsigned char *hash)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

	// Add timestamp
	EVP_DigestUpdate(ctx, &block->timestamp, sizeof(time_t));

	// Add transactions
	for (int i = 0; i < block->transaction_count; i++)
	{
		EVP_DigestUpdate(ctx, &block->transactions[i], sizeof(Transaction));
	}

	// Add previous hash and nonce
	EVP_DigestUpdate(ctx, block->previous_hash, SHA256_DIGEST_LENGTH);
	EVP_DigestUpdate(ctx, &block->nonce, sizeof(unsigned int));

	EVP_DigestFinal_ex(ctx, hash, NULL);
	EVP_MD_CTX_free(ctx);
}

// Initialize blockchain with cryptographic keys
Blockchain *create_blockchain()
{
	init_openssl();

	Blockchain *blockchain = (Blockchain *)malloc(sizeof(Blockchain));
	if (!blockchain)
		return NULL;

	// Generate keys
	blockchain->keys = generate_key_pair();
	if (!blockchain->keys.private_key || !blockchain->keys.public_key)
	{
		free(blockchain);
		return NULL;
	}

	// Create genesis block
	Block *genesis = (Block *)calloc(1, sizeof(Block));
	if (!genesis)
	{
		free_key_pair(&blockchain->keys);
		free(blockchain);
		return NULL;
	}

	genesis->timestamp = time(NULL);
	genesis->transaction_count = 0;
	memset(genesis->previous_hash, 0, SHA256_DIGEST_LENGTH);
	genesis->next = NULL;

	// Mine genesis block
	unsigned char target[SHA256_DIGEST_LENGTH] = {0};
	do
	{
		genesis->nonce++;
		calculate_block_hash(genesis, genesis->hash);
	} while (memcmp(genesis->hash, target, DIFFICULTY) != 0);

	blockchain->head = genesis;
	blockchain->pending_count = 0;

	return blockchain;
}

// Generate unique ID for transaction
void generate_unique_id(char *id_buffer, size_t buffer_size)
{
	static unsigned long long counter = 0;
	time_t current_time = time(NULL);
	counter++;
	snprintf(id_buffer, buffer_size, "ITEM_%lld_%llu", (long long)current_time, counter);
}

// Add new transaction
int add_transaction(Blockchain *blockchain, const char *description, char *generated_id)
{
	if (blockchain->pending_count >= MAX_TRANSACTIONS)
		return -1;

	Transaction *transaction = &blockchain->pending_transactions[blockchain->pending_count];

	// Generate unique ID
	generate_unique_id(transaction->item_id, MAX_ID_LENGTH);
	strncpy(generated_id, transaction->item_id, MAX_ID_LENGTH);

	// Set description and timestamp
	strncpy(transaction->description, description, MAX_DESCRIPTION - 1);
	transaction->description[MAX_DESCRIPTION - 1] = '\0';
	transaction->timestamp = time(NULL);

	// Create and sign transaction data
	unsigned char data[512];
	size_t data_len = sprintf((char *)data, "%s%s%ld",
				  transaction->item_id,
				  transaction->description,
				  transaction->timestamp);

	if (!sign_data(blockchain->keys.private_key, data, data_len,
		       transaction->signature, &transaction->signature_length))
	{
		return -2;
	}

	blockchain->pending_count++;
	return 1;
}

// Mine pending transactions into new block
int mine_pending_transactions(Blockchain *blockchain)
{
	if (blockchain->pending_count == 0)
		return 0;

	Block *current = blockchain->head;
	while (current->next)
		current = current->next;

	Block *new_block = (Block *)calloc(1, sizeof(Block));
	if (!new_block)
		return 0;

	new_block->timestamp = time(NULL);
	memcpy(new_block->previous_hash, current->hash, SHA256_DIGEST_LENGTH);

	// Copy pending transactions
	for (int i = 0; i < blockchain->pending_count; i++)
	{
		memcpy(&new_block->transactions[i],
		       &blockchain->pending_transactions[i],
		       sizeof(Transaction));
	}
	new_block->transaction_count = blockchain->pending_count;

	// Mine block
	unsigned char target[SHA256_DIGEST_LENGTH] = {0};
	do
	{
		new_block->nonce++;
		calculate_block_hash(new_block, new_block->hash);
	} while (memcmp(new_block->hash, target, DIFFICULTY) != 0);

	current->next = new_block;
	blockchain->pending_count = 0;
	return 1;
}

// Verify block integrity
int verify_block(Block *block, RSA *public_key)
{
	// Verify hash
	unsigned char calculated_hash[SHA256_DIGEST_LENGTH];
	calculate_block_hash(block, calculated_hash);
	if (memcmp(block->hash, calculated_hash, SHA256_DIGEST_LENGTH) != 0)
	{
		return 0;
	}

	// Verify each transaction signature
	for (int i = 0; i < block->transaction_count; i++)
	{
		Transaction *tx = &block->transactions[i];
		unsigned char data[512];
		size_t data_len = sprintf((char *)data, "%s%s%ld",
					  tx->item_id,
					  tx->description,
					  tx->timestamp);

		if (!verify_signature(public_key, data, data_len,
				      tx->signature, tx->signature_length))
		{
			return 0;
		}
	}

	return 1;
}

// Print blockchain
void print_blockchain(Blockchain *blockchain)
{
	Block *current = blockchain->head;
	int block_num = 0;

	while (current)
	{
		printf("\nBlock #%d\n", block_num++);
		printf("Timestamp: %s", ctime(&current->timestamp));
		printf("Previous Hash: ");
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		{
			printf("%02x", current->previous_hash[i]);
		}
		printf("\nHash: ");
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		{
			printf("%02x", current->hash[i]);
		}
		printf("\nNonce: %u\n", current->nonce);

		printf("Transactions:\n");
		for (int i = 0; i < current->transaction_count; i++)
		{
			printf("  - Item ID: %s\n", current->transactions[i].item_id);
			printf("    Description: %s\n", current->transactions[i].description);
			printf("    Timestamp: %s", ctime(&current->transactions[i].timestamp));

			// Verify transaction signature
			if (verify_block(current, blockchain->keys.public_key))
			{
				printf("    Signature: Valid\n");
			}
			else
			{
				printf("    Signature: INVALID!\n");
			}
		}

		current = current->next;
	}
}

// Free blockchain memory
void free_blockchain(Blockchain *blockchain)
{
	Block *current = blockchain->head;
	while (current)
	{
		Block *temp = current;
		current = current->next;
		free(temp);
	}

	free_key_pair(&blockchain->keys);
	free(blockchain);
	cleanup_openssl();
}

// CLI Functions
void trim(char *str)
{
	char *start = str;
	char *end = str + strlen(str) - 1;

	while (isspace(*start))
		start++;
	while (end > start && isspace(*end))
		end--;

	*(end + 1) = '\0';
	memmove(str, start, end - start + 2);
}

char **parse_command(char *cmd, int *arg_count)
{
	char **args = malloc(sizeof(char *) * 10); // Maximum 10 arguments
	*arg_count = 0;
	int cmd_len = strlen(cmd);
	int start = 0;
	int i = 0;

	while (i < cmd_len && *arg_count < 10)
	{
		// Skip leading spaces
		while (i < cmd_len && cmd[i] == ' ')
		{
			i++;
		}
		start = i;

		// Find end of current argument
		while (i < cmd_len && cmd[i] != ' ')
		{
			i++;
		}

		// If we found an argument
		if (i > start)
		{
			int arg_len = i - start;
			args[*arg_count] = malloc(arg_len + 1);
			strncpy(args[*arg_count], &cmd[start], arg_len);
			args[*arg_count][arg_len] = '\0';
			(*arg_count)++;
		}
	}

	return args;
}

void free_args(char **args, int arg_count)
{
	for (int i = 0; i < arg_count; i++)
	{
		free(args[i]);
	}
	free(args);
}

void print_help()
{
	printf("\nAvailable commands:\n");
	printf("  create_blockchain              - Initialize a new blockchain\n");
	printf("  add_transaction <description>  - Add a new transaction (ID will be auto-generated)\n");
	printf("  mine_block                     - Mine a new block\n");
	printf("  print_blockchain               - Display the entire blockchain\n");
	printf("  verify_blockchain              - Verify the integrity of the entire blockchain\n");
	printf("  help                           - Show this help message\n");
	printf("  exit                           - Exit the program\n");
}

int verify_entire_blockchain(Blockchain *blockchain)
{
	if (!blockchain || !blockchain->head)
		return 0;

	Block *current = blockchain->head;
	unsigned char previous_hash[SHA256_DIGEST_LENGTH] = {0}; // Genesis block has all zeros

	while (current)
	{
		// Verify previous hash matches
		if (memcmp(current->previous_hash, previous_hash, SHA256_DIGEST_LENGTH) != 0)
		{
			printf("Previous hash mismatch in block!\n");
			return 0;
		}

		// Verify block integrity and signatures
		if (!verify_block(current, blockchain->keys.public_key))
		{
			printf("Block verification failed!\n");
			return 0;
		}

		// Store current hash for next iteration
		memcpy(previous_hash, current->hash, SHA256_DIGEST_LENGTH);
		current = current->next;
	}

	return 1;
}

void handle_command(Blockchain **blockchain, char *cmd)
{
	int arg_count;
	char **args = parse_command(cmd, &arg_count);

	if (arg_count == 0)
	{
		free_args(args, arg_count);
		return;
	}

	if (strcmp(args[0], "create_blockchain") == 0)
	{
		if (*blockchain != NULL)
		{
			printf("Blockchain already exists!\n");
		}
		else
		{
			*blockchain = create_blockchain();
			if (*blockchain != NULL)
			{
				printf("New blockchain created successfully!\n");
			}
			else
			{
				printf("Failed to create blockchain!\n");
			}
		}
	}
	else if (strcmp(args[0], "add_transaction") == 0)
	{
		if (*blockchain == NULL)
		{
			printf("Please create a blockchain first!\n");
		}
		else if (arg_count < 2)
		{
			printf("Usage: add_transaction <description>\n");
		}
		else
		{
			// Combine all arguments as description
			char description[MAX_DESCRIPTION] = "";
			for (int i = 1; i < arg_count; i++)
			{
				strcat(description, args[i]);
				if (i < arg_count - 1)
					strcat(description, " ");
			}

			char generated_id[MAX_ID_LENGTH];
			int result = add_transaction(*blockchain, description, generated_id);
			switch (result)
			{
			case 1:
				printf("Transaction added successfully! Generated ID: %s\n", generated_id);
				break;
			case -1:
				printf("Failed: Transaction pool is full!\n");
				break;
			case -2:
				printf("Failed: Error generating signature!\n");
				break;
			default:
				printf("Failed to add transaction!\n");
			}
		}
	}
	else if (strcmp(args[0], "mine_block") == 0)
	{
		if (*blockchain == NULL)
		{
			printf("Please create a blockchain first!\n");
		}
		else if (mine_pending_transactions(*blockchain))
		{
			printf("Block mined successfully!\n");
		}
		else
		{
			printf("No pending transactions to mine or mining failed!\n");
		}
	}
	else if (strcmp(args[0], "print_blockchain") == 0)
	{
		if (*blockchain == NULL)
		{
			printf("Please create a blockchain first!\n");
		}
		else
		{
			print_blockchain(*blockchain);
		}
	}
	else if (strcmp(args[0], "verify_blockchain") == 0)
	{
		if (*blockchain == NULL)
		{
			printf("Please create a blockchain first!\n");
		}
		else if (verify_entire_blockchain(*blockchain))
		{
			printf("Blockchain verification successful! All blocks are valid.\n");
		}
		else
		{
			printf("Blockchain verification failed! Chain may be compromised.\n");
		}
	}
	else if (strcmp(args[0], "help") == 0)
	{
		print_help();
	}
	else if (strcmp(args[0], "exit") == 0)
	{
		if (*blockchain != NULL)
		{
			free_blockchain(*blockchain);
			*blockchain = NULL;
		}
		free_args(args, arg_count);
		exit(0);
	}
	else
	{
		printf("Unknown command. Type 'help' for available commands.\n");
	}

	free_args(args, arg_count);
}

int main()
{
	Blockchain *blockchain = NULL;
	char cmd[MAX_CMD_LENGTH];

	printf("Supply Chain Blockchain CLI\n");
	printf("Type 'help' for available commands\n");

	while (1)
	{
		printf("\n> ");
		if (fgets(cmd, sizeof(cmd), stdin) == NULL)
		{
			break;
		}

		// Remove newline
		cmd[strcspn(cmd, "\n")] = 0;

		// Trim whitespace
		trim(cmd);

		// Skip empty lines
		if (strlen(cmd) == 0)
		{
			continue;
		}

		handle_command(&blockchain, cmd);
	}

	if (blockchain != NULL)
	{
		free_blockchain(blockchain);
	}

	return 0;
}