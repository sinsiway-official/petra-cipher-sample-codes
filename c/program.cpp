#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "PcAPIL.h"

#define MAX_TEXT_LENGTH 1024

int main(int argc, char const *argv[])
{
    // Initialize Petra Cipher library with configuration file path.
    // Note: This function is optional. If not called, default values will be used.
    PcAPI_initialize("petra_cipher_api.conf", "");

    // Initialize variables for encryption and decryption.
    unsigned char encryptText[MAX_TEXT_LENGTH];
    unsigned char decryptText[MAX_TEXT_LENGTH];

    // Get session ID from key server.
    int sid = PcAPI_getSession("");

    if (sid < 0) {
        printf("Failed to get session ID.\n");
        return -1;
    }

    petracipher_version();

    // Set encryption key name and plain text for encryption.
    char *keyName = "ARIA_256_B64";
    const char *plainText = "sinsiway petra cipher";
    unsigned int plainTextLen = strlen(plainText);
    unsigned int encryptTextLen = MAX_TEXT_LENGTH;
    unsigned int decryptTextLen = MAX_TEXT_LENGTH;

    // Initialize encryption and decryption buffers.
    memset(encryptText, 0, encryptTextLen);
    memset(decryptText, 0, decryptTextLen);

    // Encrypt plain text using Petra Cipher library.
    int rtn = PcAPI_encrypt_name(sid, keyName, (unsigned char *)plainText, plainTextLen, encryptText, &encryptTextLen);
    if (rtn < 0) {
        printf("Encryption failed with error code %d.\n", rtn);
        return -1;
    }

    // Decrypt encrypted text using Petra Cipher library.
    rtn = PcAPI_decrypt_name(sid, keyName, encryptText, encryptTextLen, decryptText, &decryptTextLen);
    if (rtn < 0) {
        printf("Decryption failed with error code %d.\n", rtn);
        return -1;
    }
    decryptText[decryptTextLen] = '\0';

    // Print original, encrypted, and decrypted texts.
    printf("Original text: %s\n", plainText);
    printf("Encrypted text: %s\n", encryptText);
    printf("Decrypted text: %s\n", decryptText);

    return 0;
}