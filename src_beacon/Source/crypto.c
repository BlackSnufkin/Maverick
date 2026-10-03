/*
 * Maverick — RC4 Encryption
 *
 * RC4 stream cipher used for encrypting all C2 communication.
 * Output size equals input size (no padding).
 * Key is 16 bytes, generated randomly at agent startup.
 *
 * Must match the Go implementation in pl_crypto.go (both listener and agent plugin).
 */

#include <windows.h>
#include "includes/crypto.h"

/* DFR declarations */
DECLSPEC_IMPORT void * __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memcpy(void *, const void *, size_t);

/* RC4 Key Scheduling Algorithm */
static void rc4_init(unsigned char *S, unsigned char *key, int key_len) {
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) & 0xFF;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
}

/* RC4 Pseudo-Random Generation Algorithm — XOR data in place */
static void rc4_process(unsigned char *S, unsigned char *data, int len) {
    int i = 0, j = 0;
    for (int k = 0; k < len; k++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        data[k] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

unsigned char *rc4_encrypt(unsigned char *data, int data_len, unsigned char *key, int *out_len) {
    if (!data || !key || data_len <= 0) { *out_len = 0; return NULL; }
    unsigned char *buf = (unsigned char *)MSVCRT$malloc(data_len);
    if (!buf) { *out_len = 0; return NULL; }
    MSVCRT$memcpy(buf, data, data_len);
    unsigned char S[256];
    rc4_init(S, key, RC4_KEY_SIZE);
    rc4_process(S, buf, data_len);
    *out_len = data_len;
    return buf;
}

unsigned char *rc4_decrypt(unsigned char *data, int data_len, unsigned char *key, int *out_len) {
    if (!data || !key || data_len <= 0) { *out_len = 0; return NULL; }
    unsigned char *buf = (unsigned char *)MSVCRT$malloc(data_len);
    if (!buf) { *out_len = 0; return NULL; }
    MSVCRT$memcpy(buf, data, data_len);
    unsigned char S[256];
    rc4_init(S, key, RC4_KEY_SIZE);
    rc4_process(S, buf, data_len);
    *out_len = data_len;
    return buf;
}
