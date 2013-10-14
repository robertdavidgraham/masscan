#ifndef MAIN_SRC_H
#define MAIN_SRC_H

struct Source
{
    struct {
        unsigned first;
        unsigned last;
        unsigned range;
    } ip;
    struct {
        unsigned first;
        unsigned last;
        unsigned range;
    } port;
};

int is_myself(const struct Source *src, unsigned ip, unsigned port);
int is_my_ip(const struct Source *src, unsigned ip);
int is_my_port(const struct Source *src, unsigned ip);



#endif
