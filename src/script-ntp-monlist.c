#include "script.h"
#include "templ-pkt.h"
#include "unusedparm.h"


/*****************************************************************************
 *****************************************************************************/
static void 
set_target(struct TemplatePacket *tmpl,
                   unsigned ip_them, unsigned port_them,
                   unsigned ip_me, unsigned port_me,
                   unsigned seqno,
                   unsigned char *px, size_t sizeof_px, 
                   size_t *r_length)
{
    unsigned offset_tcp = tmpl->offset_tcp;
    unsigned offset_ip = tmpl->offset_ip;
    unsigned xsum;

    UNUSEDPARM(r_length);
    UNUSEDPARM(sizeof_px);
    UNUSEDPARM(seqno);
    UNUSEDPARM(ip_me);
    UNUSEDPARM(ip_them);
    
    px[offset_tcp+ 0] = (unsigned char)(port_me >> 8);
    px[offset_tcp+ 1] = (unsigned char)(port_me & 0xFF);
    px[offset_tcp+ 2] = (unsigned char)(port_them >> 8);
    px[offset_tcp+ 3] = (unsigned char)(port_them & 0xFF);
    px[offset_tcp+ 4] = (unsigned char)((tmpl->length - tmpl->offset_app + 8)>>8);
    px[offset_tcp+ 5] = (unsigned char)((tmpl->length - tmpl->offset_app + 8)&0xFF);
    
    px[offset_tcp+6] = (unsigned char)(0);
    px[offset_tcp+7] = (unsigned char)(0);
    xsum = udp_checksum2(px, offset_ip, offset_tcp, tmpl->length - offset_tcp);
    xsum = ~xsum;
    px[offset_tcp+6] = (unsigned char)(xsum >>  8);
    px[offset_tcp+7] = (unsigned char)(xsum >>  0);
}

/*****************************************************************************
 *****************************************************************************/
static unsigned char packet_template[] =
"\0\1\2\3\4\5"  /* Ethernet: destination */
"\6\7\x8\x9\xa\xb"  /* Ethernet: source */
"\x08\x00"      /* Ethernet type: IPv4 */
"\x45"          /* IP type */
"\x00"
"\x00\x4c"      /* total length = 28 bytes */
"\x00\x00"      /* identification */
"\x00\x00"      /* fragmentation flags */
"\xFF\x11"      /* TTL=255, proto=UDP */
"\xFF\xFF"      /* checksum */
"\0\0\0\0"      /* source address */
"\0\0\0\0"      /* destination address */

"\xfe\xdc"      /* source port */
"\x00\x00"      /* destination port */
"\x00\x38"      /* length */
"\x00\x00"      /* checksum */

"\x17\x00\x03\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

;

/*****************************************************************************
 *****************************************************************************/
struct MassScript script_ntp_monlist = {
    "ntp-monlist",  /* name of this script, matches command-line name */
    "U:123",        /* default ports this script should target */
    packet_template,
    sizeof(packet_template)-1,
    set_target
    
};
