#include <sodium.h>

#define MESSAGE (const unsigned char *) "This source was brought to you by Raid: Shadow Legends+Ninechars"
#define MESSAGE_LEN 64
#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 6

void libsodium_aes_main() {
    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
    unsigned char ciphertext[MESSAGE_LEN + crypto_aead_aes256gcm_ABYTES];
    unsigned long long ciphertext_len;

    sodium_init();
    if (crypto_aead_aes256gcm_is_available() == 0) {
        abort(); /* Not available on this CPU */
    }

    crypto_aead_aes256gcm_keygen(key);
    randombytes_buf(nonce, sizeof nonce);

    crypto_aead_aes256gcm_encrypt(ciphertext, &ciphertext_len,
        MESSAGE, MESSAGE_LEN,
        ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
        NULL, nonce, key);

    unsigned char decrypted[MESSAGE_LEN];
    unsigned long long decrypted_len;
    if (ciphertext_len < crypto_aead_aes256gcm_ABYTES ||
        crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
            NULL,
            ciphertext, ciphertext_len,
            ADDITIONAL_DATA,
            ADDITIONAL_DATA_LEN,
            nonce, key) != 0) {
        /* message forged! */
    }
}