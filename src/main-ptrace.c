#include "main-ptrace.h"
#include "proto-preprocess.h"
#include "pixie-timer.h"
#include "util-safefunc.h"


/***************************************************************************
 * Print packet info, when using nmap-style --packet-trace option
 ***************************************************************************/
void
packet_trace(FILE *fp, double pt_start, const unsigned char *px, size_t length, unsigned is_sent)
{
    unsigned x;
    struct PreprocessedInfo parsed;
    char from[64];
    char to[64];
    char sz_type[32];
    unsigned type;
    double timestamp = 1.0 * pixie_gettime() / 1000000.0;
    unsigned offset;
    const char *direction;
    ipaddress_formatted_t fmt;

    if (is_sent)
        direction = "SENT";
    else
        direction = "RCVD";

    /* parse the packet */
    x = preprocess_frame(px, (unsigned)length, 1, &parsed);
    if (!x)
        return;
    offset = parsed.found_offset;


    /* format the IP addresses into fixed-width fields */
    fmt = ipaddress_fmt(parsed.src_ip);
    snprintf(from, sizeof(from), "[%s]:%u", fmt.string, parsed.port_src);

    fmt = ipaddress_fmt(parsed.dst_ip);
    snprintf(to, sizeof(to), "[%s]:%u", fmt.string, parsed.port_dst);

    switch (parsed.found) {
        case FOUND_ARP:
            type = px[offset+6]<<8 | px[offset+7];
            *strchr(to, ':') = '\0';
            *strchr(from, ':') = '\0';
            switch (type) {
                case 1:safe_strcpy(sz_type, sizeof(sz_type), "request"); break;
                case 2:safe_strcpy(sz_type, sizeof(sz_type), "response"); break;
                default: snprintf(sz_type, sizeof(sz_type), "unknown(%u)", type); break;
            }
            fprintf(fp, "%s (%5.4f) ARP  %-21s > %-21s %s\n", direction,
                    timestamp - pt_start, from, to, sz_type);
            break;
        case FOUND_DNS:
        case FOUND_UDP:
            fprintf(fp, "%s (%5.4f) UDP  %-21s > %-21s \n", direction,
                    timestamp - pt_start, from, to);
            break;
        case FOUND_ICMP:
            fprintf(fp, "%s (%5.4f) ICMP %-21s > %-21s \n", direction,
                    timestamp - pt_start, from, to);
            break;
        case FOUND_TCP:
            type = px[offset+13];
            switch (type) {
                case 0x00: safe_strcpy(sz_type, sizeof(sz_type), "NULL"); break;
                case 0x01: safe_strcpy(sz_type, sizeof(sz_type), "FIN"); break;
                case 0x11: safe_strcpy(sz_type, sizeof(sz_type), "FIN-ACK"); break;
                case 0x19: safe_strcpy(sz_type, sizeof(sz_type), "FIN-ACK-PSH"); break;
                case 0x02: safe_strcpy(sz_type, sizeof(sz_type), "SYN"); break;
                case 0x12: safe_strcpy(sz_type, sizeof(sz_type), "SYN-ACK"); break;
                case 0x04: safe_strcpy(sz_type, sizeof(sz_type), "RST"); break;
                case 0x14: safe_strcpy(sz_type, sizeof(sz_type), "RST-ACK"); break;
                case 0x15: safe_strcpy(sz_type, sizeof(sz_type), "RST-FIN-ACK"); break;
                case 0x10: safe_strcpy(sz_type, sizeof(sz_type), "ACK"); break;
                case 0x18: safe_strcpy(sz_type, sizeof(sz_type), "ACK-PSH"); break;
                default:
                    snprintf(sz_type, sizeof(sz_type),
                              "%s%s%s%s%s%s%s%s",
                              (type&0x01)?"FIN":"",
                              (type&0x02)?"SYN":"",
                              (type&0x04)?"RST":"",
                              (type&0x08)?"PSH":"",
                              (type&0x10)?"ACK":"",
                              (type&0x20)?"URG":"",
                              (type&0x40)?"ECE":"",
                              (type&0x80)?"CWR":""
                              );
                    break;
            }
            if (parsed.app_length)
            fprintf(fp, "%s (%5.4f) TCP  %-21s > %-21s %s %u-bytes\n", direction,
                    timestamp - pt_start, from, to, sz_type, parsed.app_length);
            else
            fprintf(fp, "%s (%5.4f) TCP  %-21s > %-21s %s\n", direction,
                    timestamp - pt_start, from, to, sz_type);
            break;
        case FOUND_IPV6:
            break;
        default:
            fprintf(fp, "%s (%5.4f) UNK  %-21s > %-21s [%u]\n", direction,
                    timestamp - pt_start, from, to, parsed.found);
            break;
    }


}
