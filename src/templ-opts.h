#ifndef TEMPL_OPTS_H
#define TEMPL_OPTS_H
#include "massip-addr.h"

#ifdef _MSC_VER
#pragma warning(disable:4214)
#endif

/**
 * This tells us whether we should add, remove, or leave default
 * a field in the packet headers.
 * FIXME: not all of these are supported
 */
typedef enum {Default, Add, Remove} addremove_t;

struct TemplateOptions {
    struct {
        addremove_t is_badsum:4; /* intentionally bad checksum */
        addremove_t is_tsecho:4; /* enable timestamp echo */
        addremove_t is_tsreply:4; /* enable timestamp echo */
        addremove_t is_flags:4;
        addremove_t is_ackno:4;
        addremove_t is_seqno:4;
        addremove_t is_win:4;
        addremove_t is_mss:4;
        addremove_t is_sackok:4;
        addremove_t is_wscale:4;
        unsigned flags;
        unsigned ackno;
        unsigned seqno;
        unsigned win;
        unsigned mss;
        unsigned sackok;
        unsigned wscale;
        unsigned tsecho;
        unsigned tsreply;
    } tcp;

    struct {
        addremove_t is_badsum:4; /* intentionally bad checksum */
    } udp;

    struct {
        addremove_t is_sender_mac:4;
        addremove_t is_sender_ip:4;
        addremove_t is_target_mac:4;
        addremove_t is_target_ip:4;
        macaddress_t sender_mac;
        ipaddress sender_ip;
        macaddress_t target_mac;
        ipaddress target_ip;
    } arp;
    
    struct {
        addremove_t is_badsum:4; /* intentionally bad checksum */
        addremove_t is_tos:4;
        addremove_t is_ipid:4;
        addremove_t is_df:4;
        addremove_t is_mf:4;
        addremove_t is_ttl:4;

        unsigned tos;
        unsigned ipid;
        unsigned ttl;

    } ipv4;
};

#endif

