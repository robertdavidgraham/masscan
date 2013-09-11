#ifndef PROTO_SSH_H
#define PROTO_SSH_H
struct Banner1;

unsigned
banner_ssh(  struct Banner1 *banner1,
        unsigned state,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max);

#endif
