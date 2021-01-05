#include "openssl_des.h"
#include <openssl/evp.h>
#include <string.h>

#define DEBUG 0
#define FREE_MEMORY 0
#define KEY_LEN 16 // 128b key


#define uchar unsigned char

int encrypt_data(const char* _key, const char* _vt, char* _raw_ptr, size_t _raw_size
	, char** _dst_buf, size_t* _dst_size) {
	DES_key_schedule schedule;
	uchar key1[KEY_LEN];
	DES_cblock* iv3;
	int pading;
	size_t i, vt_size;
	char* mid_buf;
	memset(key1, 0, KEY_LEN);
	memcpy(key1, _key, KEY_LEN);
	DES_set_key_unchecked((const_DES_cblock*)&key1, &schedule);
	vt_size = strlen(_vt);
	iv3 = (DES_cblock*)malloc(vt_size * sizeof(uchar));
	memcpy(iv3, _vt, vt_size);
	pading = 8 - (_raw_size % 8);
	*_dst_size = _raw_size + pading;
	mid_buf = (char*)malloc(*_dst_size);
	memcpy(mid_buf, _raw_ptr, _raw_size);
	for (i = _raw_size; i < *_dst_size; i++) {
		mid_buf[i] = pading;
	}

	*_dst_buf = (char*)malloc(*_dst_size);
	DES_cbc_encrypt((const uchar*)mid_buf, (unsigned char*)*_dst_buf, *_dst_size, &schedule, iv3, DES_ENCRYPT);
	if (FREE_MEMORY) {
		free(iv3);
		free(mid_buf);
	}

	return 1;
}

int decrypt_data(const char* _key, const char* _vt, char* _raw_ptr, 
	size_t _raw_size, char** _dst_buf, size_t* _dst_size) 
{
	DES_key_schedule schedule;
	uchar key1[KEY_LEN];
	DES_cblock* iv3;
	int pading;
	size_t i, vt_size;
	char* mid_buf;
	memset(key1, 0, KEY_LEN);
	memcpy(key1, _key, KEY_LEN);
	DES_set_key_unchecked((const_DES_cblock*)&key1, &schedule);
	vt_size = strlen(_vt);
	iv3 = (DES_cblock*)malloc(vt_size * sizeof(uchar));
	memcpy(iv3, _vt, vt_size);
	*_dst_buf = (char*)malloc(_raw_size);
	DES_cbc_encrypt((const uchar*)_raw_ptr, *_dst_buf, _raw_size, 
		&schedule, iv3, DES_DECRYPT);

	if (FREE_MEMORY) { free(iv3); }
	return 1;
}

void openssl_des_main(char* message, int msgLen) {
	char* _key = "jkl;!@#$jkl;!@#$";	// 128b key
	char* _vt = "asdf!@#$";
	char* _raw_ptr;
	char* _dst_buf;
	size_t _dst_size;
	char* _final_buf;
	size_t _final_size;

	encrypt_data(_key, _vt, message, msgLen, &_dst_buf, &_dst_size);
	decrypt_data(_key, _vt, _dst_buf, _dst_size, &_final_buf, &_final_size);
	if (FREE_MEMORY) { free(_dst_buf); }
	return 0;
}