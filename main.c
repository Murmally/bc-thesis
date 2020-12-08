#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "openssl_aes.h"
#include "tiny_aes.h"
#include "rosetta_des.h"
#include "programmingalgorithms_des.h"

int pkcs7_padding_pad_buffer(uint8_t* buffer, size_t data_length, size_t buffer_size, uint8_t modulus) {
    uint8_t pad_byte = modulus - (data_length % modulus);
    if (data_length + pad_byte > buffer_size) {
        return -pad_byte;
    }
    int i = 0;
    while (i < pad_byte) {
        buffer[data_length + i] = pad_byte;
        i++;
    }

    return pad_byte;
}

void tiny_aes(char* report, char* key, uint8_t* iv) {
    int dlen = strlen(report);
    int klen = strlen(key);
    uint8_t i;

    //Proper Length of report
    int dlenu = dlen;
    if (dlen % 16) {
        dlenu += 16 - (dlen % 16);
    }

    //Proper length of key
    int klenu = klen;
    if (klen % 16) {
        klenu += 16 - (klen % 16);
    }

    // Make the uint8_t arrays
    // uint8_t hexarray[dlenu];
    // uint8_t kexarray[klenu];

    uint8_t hexarray[64];
    uint8_t kexarray[64];

    // Initialize them with zeros
    memset(hexarray, 0, dlenu);
    memset(kexarray, 0, klenu);

    // Fill the uint8_t arrays
    for (int i = 0;i < dlen;i++) {
        hexarray[i] = (uint8_t)report[i];
    }
    for (int i = 0;i < klen;i++) {
        kexarray[i] = (uint8_t)key[i];
    }

    int reportPad = pkcs7_padding_pad_buffer(hexarray, dlen, sizeof(hexarray), 16);
    int keyPad = pkcs7_padding_pad_buffer(kexarray, klen, sizeof(kexarray), 16);

    //start the encryption
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, kexarray, iv);

    // encrypt
    AES_CBC_encrypt_buffer(&ctx, hexarray, dlenu);

    // reset the iv !! important to work!
    AES_ctx_set_iv(&ctx, iv);

    // start decryption
    AES_CBC_decrypt_buffer(&ctx, hexarray, dlenu);
}

void print_output(char* description, int runs, clock_t start, clock_t end) {
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf("~~~~~ %s ~~~~~\nTime elapsed: %f\nAverage time per run: %f\n\n",
        description, time_spent, time_spent / runs);
}

void measure_tiny_aes(int runs, char* message, char* key, uint8_t iv[]) {
    clock_t tiny_aes_start = clock();
    for (int i = 0; i < runs; i++) {
        tiny_aes(message, key, iv);
    }

    clock_t tiny_aes_end = clock();
    print_output("tiny AES", runs, tiny_aes_start, tiny_aes_end);
}

void measure_openssl_aes(int runs, char* message, char* key) {

}

void measure_aes(int runs, char* message, char* key, uint8_t iv[]) {
    printf("========== AES ==========\n");
    measure_tiny_aes(runs, message, key, iv); // TODOx - zmenit implementaci pro ruzne velikosti klice
}

void measure_rosetta_des(int runs, char* key) {
    clock_t start = clock();
    for (int i = 0; i < runs; i++) {
        rosetta_main(key);
    }
    clock_t end = clock();
    print_output("rosetta DES", runs, start, end);
}

void measure_programmingalgorithms_des(int runs) {
    clock_t start = clock();
    for (int i = 0; i < runs; i++) {
        programmingalrorithms_des();
    }

    clock_t end = clock();
    print_output("programmingalgorithms DES", runs, start, end);
}

// TODOx
void measure_des(int runs, char* message, char* key, uint8_t iv[]) {
    printf("========== DES ==========\n");
    measure_rosetta_des(runs, key);
    measure_programmingalgorithms_des(runs);
}

int main() {
    // both message and key are 64 characters long
    // TODOx - prepsat delku klice na 128 znaku
    // TODOx - prepsat delku zpravy na alespon trojnasobek delky klice
    char* message = "This source was brought to you by Raid: Shadow Legends+Ninechars";
    char* key = "This key was brought to you by NordVPN.Keep your privacy online.";
    int encryption_runs = 1000;

    uint8_t iv[] = { 0x75, 0x52, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x21, 0x21 };

    printf("Ecryption runs: %i\n", encryption_runs);
    measure_aes(encryption_runs, message, key, iv);
    measure_des(encryption_runs, message, key, iv);
    return 0;
}
