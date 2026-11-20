#include "util-extract.h"


unsigned char
e_next_byte(struct ebuf_t *ebuf) {
    if (ebuf->offset + 1 > ebuf->max)
        return -1;
    
    return ebuf->buf[ebuf->offset++];
}

unsigned short
e_next_short16(struct ebuf_t *ebuf, int endian) {
    const unsigned char *buf = ebuf->buf;
    size_t offset = ebuf->offset;
    unsigned short result;
    
    if (ebuf->offset + 2 > ebuf->max)
        return -1;

    if (endian == EBUF_BE) {
        result = buf[offset+0]<<8 | buf[offset+1];
    } else {
        result = buf[offset+1]<<8 | buf[offset+0];
    }
    ebuf->offset += 2;
    return result;
}
unsigned e_next_int32(struct ebuf_t *ebuf, int endian) {
    const unsigned char *buf = ebuf->buf;
    size_t offset = ebuf->offset;
    unsigned result;
    
    if (ebuf->offset + 4 > ebuf->max)
        return -1;

    if (endian == EBUF_BE) {
        result = (unsigned)buf[offset+0]<<24 | buf[offset+1] << 16
                    | buf[offset+2]<<8 | buf[offset+3] << 0;
    } else {
        result = (unsigned)buf[offset+3]<<24 | buf[offset+2] << 16
                    | buf[offset+1]<<8 | buf[offset+0] << 0;
    }
    ebuf->offset += 4;
    return result;
}
unsigned long long
e_next_long64(struct ebuf_t *ebuf, int endian) {
    const unsigned char *buf = ebuf->buf;
    size_t offset = ebuf->offset;
    unsigned long long hi;
    unsigned long long lo;
    
    if (ebuf->offset + 8 > ebuf->max)
        return -1ll;

    if (endian == EBUF_BE) {
        hi = (unsigned)buf[offset+0]<<24 | buf[offset+1] << 16
                    | buf[offset+2]<<8 | buf[offset+3] << 0;
        lo = (unsigned)buf[offset+4]<<24 | buf[offset+5] << 16
                    | buf[offset+6]<<8 | buf[offset+7] << 0;
    } else {
        lo = (unsigned)buf[offset+3]<<24 | buf[offset+2] << 16
                    | buf[offset+1]<<8 | buf[offset+0] << 0;
        hi = (unsigned)buf[offset+7]<<24 | buf[offset+6] << 16
                    | buf[offset+5]<<8 | buf[offset+4] << 0;
    }
    ebuf->offset += 8;
    return hi<<32ull | lo;

}

int util_extract_selftest(void)
{
    static const unsigned char data[] = {0x80, 0x01, 0x02, 0x03, 0xfe, 0xdc, 0xba, 0x98};
    struct ebuf_t ebuf = {data, 0, sizeof(data)};

    if (e_next_int32(&ebuf, EBUF_BE) != 0x80010203u)
        return 1;
    if (e_next_int32(&ebuf, EBUG_LE) != 0x98badcfeu)
        return 1;

    ebuf.offset = 0;
    if (e_next_long64(&ebuf, EBUF_BE) != 0x80010203fedcba98ull)
        return 1;
    ebuf.offset = 0;
    if (e_next_long64(&ebuf, EBUG_LE) != 0x98badcfe03020180ull)
        return 1;

    return 0;
}


