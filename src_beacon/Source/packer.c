/*
 * Maverick — Binary Packer / Parser
 *
 * PackBuf: dynamic buffer for building binary packets (big-endian, used for sending to server).
 * Parser:  sequential reader for parsing server responses (little-endian int32, length-prefixed strings).
 *
 * Must match the Go packer in pl_packer.go (agent plugin).
 */

#include <windows.h>
#include "includes/packer.h"

/* DFR declarations */
DECLSPEC_IMPORT void * __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void * __cdecl MSVCRT$realloc(void *, size_t);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memcpy(void *, const void *, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char *);

static void pb_ensure(PackBuf *pb, int need) {
    while (pb->len + need > pb->cap) {
        int new_cap = pb->cap * 2;
        unsigned char *new_data = (unsigned char *)MSVCRT$realloc(pb->data, new_cap);
        if (!new_data) return;
        pb->data = new_data;
        pb->cap = new_cap;
    }
}

void pb_init(PackBuf *pb) {
    pb->cap  = 1024;
    pb->len  = 0;
    pb->data = (unsigned char *)MSVCRT$malloc(pb->cap);
}

void pb_pad(PackBuf *pb, unsigned char *data, int size) {
    pb_ensure(pb, size);
    MSVCRT$memcpy(pb->data + pb->len, data, size);
    pb->len += size;
}

void pb_byte(PackBuf *pb, unsigned char val) {
    pb_ensure(pb, 1);
    pb->data[pb->len++] = val;
}

void pb_int16be(PackBuf *pb, unsigned short val) {
    pb_ensure(pb, 2);
    pb->data[pb->len++] = (val >> 8) & 0xFF;
    pb->data[pb->len++] = val & 0xFF;
}

void pb_int32be(PackBuf *pb, unsigned int val) {
    pb_ensure(pb, 4);
    pb->data[pb->len++] = (val >> 24) & 0xFF;
    pb->data[pb->len++] = (val >> 16) & 0xFF;
    pb->data[pb->len++] = (val >> 8) & 0xFF;
    pb->data[pb->len++] = val & 0xFF;
}

void pb_bytes(PackBuf *pb, unsigned char *data, int size) {
    pb_int32be(pb, (unsigned int)size);
    if (size > 0) pb_pad(pb, data, size);
}

void pb_str(PackBuf *pb, char *str) {
    int slen = str ? (int)MSVCRT$strlen(str) : 0;
    if (slen > 0) {
        pb_int32be(pb, (unsigned int)(slen + 1));
        pb_pad(pb, (unsigned char *)str, slen);
        pb_byte(pb, 0);
    } else {
        pb_int32be(pb, 0);
    }
}

unsigned char parser_byte(Parser *p) {
    if (p->pos >= p->len) return 0;
    return p->buf[p->pos++];
}

unsigned int parser_int32le(Parser *p) {
    if (p->pos + 4 > p->len) return 0;
    unsigned int val = (unsigned int)p->buf[p->pos]
                     | ((unsigned int)p->buf[p->pos + 1] << 8)
                     | ((unsigned int)p->buf[p->pos + 2] << 16)
                     | ((unsigned int)p->buf[p->pos + 3] << 24);
    p->pos += 4;
    return val;
}

unsigned char *parser_str(Parser *p, int *out_len) {
    unsigned int size = parser_int32le(p);
    if (size == 0 || p->pos + (int)size > p->len) {
        *out_len = 0;
        return NULL;
    }
    unsigned char *data = p->buf + p->pos;
    p->pos += size;
    *out_len = (int)size;
    return data;
}

unsigned char *parser_raw(Parser *p, int size) {
    if (p->pos + size > p->len) return NULL;
    unsigned char *data = p->buf + p->pos;
    p->pos += size;
    return data;
}
