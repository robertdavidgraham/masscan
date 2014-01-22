#ifndef SCRIPT_H
#define SCRIPT_H
#include <stdio.h>
struct TemplatePacket;

struct MassScript
{
    const char *name;
    
    /**
     * A list of default port ranges that should be used in case that none
     * are specified.
     */
    const char *ports;
    
    const unsigned char *packet;
    
    unsigned packet_length;
    
    void (*set_target)(struct TemplatePacket *tmpl,
                         unsigned ip_them, unsigned port_them,
                         unsigned ip_me, unsigned port_me,
                         unsigned seqno,
                         unsigned char *px, size_t sizeof_px, 
                         size_t *r_length);
};

/**
 * Lookup the script based on the name
 * @param name
 *      The name of the script.
 * @return
 *      The desired script if found, NULL if the script doesn't exist
 */
struct MassScript *
script_lookup(const char *name);

#endif
