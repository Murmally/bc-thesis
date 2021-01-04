#include "openssl_des.h"
#include <openssl/evp.h>
#include <string.h>

#define DEBUG 1

void openssl_des_main(char* message, char* key, int msgLen, int keyLen) {
	// keyLen = 16
	// msgLen = 64
	char source[] = "This source was brought to you by Raid: Shadow Legends+Ninechars";
	char* target;
	char* output;
	int in_len, out_len;

	//Declaring EVP variables
	char mykey[16] = "This key was bro";
	char iv[4] = "aniv";
	EVP_CIPHER_CTX *ctx;

	target = malloc(sizeof(source));
	output = malloc(sizeof(source));
	in_len = strlen(source);

	if (DEBUG) {
		printf("This is the text before ciphering: %s\n", source);
		printf("The length of the string is: %d\n", in_len);
	}

	//starting the encryption process
	ctx = EVP_CIPHER_CTX_new();
	// EVP_CIPHER_CTX_init(ctx);

	EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, mykey, iv);
	EVP_EncryptUpdate(ctx, target, &out_len, source, in_len);
	EVP_EncryptFinal_ex(ctx, target, &out_len);

	// out_len is now in bytes
	if (DEBUG){ printf("The length of encrypted text is %d bits\n", out_len * 8); }
	
	// in_len = strlen(target);
	// out_len=strlen(output);

	//printf("The ouput contains: %s\n",output);	
	//starting the decryption process
	EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, mykey, iv);
	EVP_DecryptUpdate(ctx, output, &out_len, target, in_len);
	EVP_DecryptFinal_ex(ctx, output, &out_len);

	//Terminating The Buffer with Null Terminator
	output[msgLen] = '\0';

	if (DEBUG) {
		printf("The Decipher text is : %s\n", output);
		printf("The length of the decipher text is: %d\n", strlen(output));
		printf("Program is working\n");
	}
}