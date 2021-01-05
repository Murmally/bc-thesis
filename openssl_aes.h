#include <openssl/aes.h>
#include <openssl/evp.h>

void openssl_aes_main(unsigned char* input);

void print_data(const char* title, const void* data, int len);