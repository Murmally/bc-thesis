#include "openssl_des.h"
#include <openssl/evp.h>
#include <string.h>

#define DEBUG 0

// TODOx - this does not work correctly. Consider using unsigned char[] instead of char*
void openssl_des_main(char * source, char* target, char* output, int msgLen) {
	int in_len, out_len;

	//Declaring EVP variables
	// char mykey[8] = { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF };
	char mykey[8] = { "hahahaha" };
	char iv[8] = "anivaniv";
	EVP_CIPHER_CTX *ctx;

	in_len = strlen(source);

	if (DEBUG) {
		printf("This is the text before ciphering: %s\n", source);
		printf("The length of the string is: %d\n", in_len);
	}

	//starting the encryption process
	ctx = EVP_CIPHER_CTX_new();

	EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, mykey, iv);
	EVP_EncryptUpdate(ctx, target, &out_len, source, in_len);
	EVP_EncryptFinal_ex(ctx, target, &out_len);

	// out_len is now in bytes
	if (DEBUG){ printf("The length of encrypted text is %d bits\n", out_len * 8); }
	
	in_len = strlen(target);
	
	//starting the decryption process
	EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, mykey, iv);
	EVP_DecryptUpdate(ctx, output, &out_len, target, in_len);
	EVP_DecryptFinal_ex(ctx, output, &out_len);

	//Terminating The Buffer with Null Terminator
	output[msgLen] = '\0';

	if (DEBUG) {
		printf("The Decipher text is : %s\n", output);
		printf("The length of the decipher text is: %d\n", strlen(output));
	}
}