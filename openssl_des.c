#include "openssl_des.h"
#include <openssl/evp.h>
#include <string.h>

#define DEBUG 0

void openssl_des_main(char* message, char* key, int msgLen, int keyLen) {
	char source[] = "This source was brought to you by Raid: Shadow Legends+Ninechars";
	char* target;
	char* output;
	int in_len, out_len;

	//Declaring EVP variables
	char mykey[16] = "This key was bro";
	// strncpy_s(mykey, key, sizeof(mykey - 1), 16);
	// mykey[strlen(mykey) - 1] = '\0'; // terminate string
	char iv[8] = "anivvina";

	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();

	target = malloc(sizeof(source));
	output = malloc(sizeof(source));
	in_len = strlen(source);

	if (DEBUG) {
		printf("This is the text before ciphering: %s\n", source);
		printf("The length of the string is: %d\n", in_len);
	}

	//starting the encryption process
	EVP_CIPHER_CTX_init(ctx);

	EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, mykey, iv);
	EVP_EncryptUpdate(ctx, &target, &out_len, &source, &in_len);
	EVP_EncryptFinal_ex(ctx, target, &out_len);

	if (DEBUG) {
		printf("The length of encrypted text is: %d\n", out_len);
		printf("The char array contains: %s\n", source);
		printf("The ouput contains: %s\n", output);
	}

	in_len = strlen(&target);
	out_len= strlen(&output);

	//starting the decryption process
	EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, mykey, iv);
	EVP_DecryptUpdate(ctx, output, &out_len, &target, in_len);
	EVP_DecryptFinal_ex(ctx, output, &out_len);

	//Terminating The Buffer with Null Terminator
	output[out_len] = '\0';

	if (DEBUG) {
		printf("The Decipher text is : %s\n", &output);
		printf("The length of the decipher text is: %d\n", strlen(&output));
		printf("Program is working\n");
	}

	EVP_CIPHER_CTX_free(ctx);
}