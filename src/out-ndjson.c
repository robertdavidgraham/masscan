#include "output.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "string_s.h"
#include <ctype.h>


/****************************************************************************
 ****************************************************************************/
static void
ndjson_out_open(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
}


/****************************************************************************
 ****************************************************************************/
static void
ndjson_out_close(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp); 
}

//{ ip: "124.53.139.201", ports: [ {port: 443, proto: "tcp", status: "open", reason: "syn-ack", ttl: 48} ] }
/****************************************************************************
 ****************************************************************************/
static void
ndjson_out_status(struct Output *out, FILE *fp, time_t timestamp, int status,
                 unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    char reason_buffer[128];
    UNUSEDPARM(out);
    //UNUSEDPARM(timestamp);

    fprintf(fp, "{");
    fprintf(fp, "\"ip\":\"%u.%u.%u.%u\",",
            (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>> 8)&0xFF, (ip>> 0)&0xFF);
    fprintf(fp, "\"timestamp\":\"%d\",\"port\":%u,\"proto\":\"%s\",\"rec_type\":\"status\",\"data\":{\"status\":\"%s\","
                "\"reason\":\"%s\",\"ttl\":%u}",
                (int) timestamp,
                port,
                name_from_ip_proto(ip_proto),
                status_string(status),
                reason_string(reason, reason_buffer, sizeof(reason_buffer)),
                ttl
            );
    fprintf(fp, "}\n");


}

/*****************************************************************************
 * Remove bad characters from the banner, especially new lines and HTML
 * control codes.
 *
 * Keeping this here since we may need to change the behavior from what 
 * is done in the sister `normalize_json_string` function. It's unlikely
 * but it's a small function and will save time later if needed. Could also
 * set it up to base64 encode the banner payload.
 *****************************************************************************/
static const char *
normalize_ndjson_string(const unsigned char *px, size_t length,
                       char *buf, size_t buf_len)
{
    size_t i=0;
    size_t offset = 0;


    for (i=0; i<length; i++) {
        unsigned char c = px[i];

        if (isprint(c) && c != '<' && c != '>' && c != '&' && c != '\\' && c != '\"' && c != '\'') {
            if (offset + 2 < buf_len)
                buf[offset++] = px[i];
        } else {
            if (offset + 7 < buf_len) {
                buf[offset++] = '\\';
                buf[offset++] = 'u';
                buf[offset++] = '0';
                buf[offset++] = '0';
                buf[offset++] = "0123456789abcdef"[px[i]>>4];
                buf[offset++] = "0123456789abcdef"[px[i]&0xF];
            }
        }
    }

    buf[offset] = '\0';

    return buf;
}

/******************************************************************************
 ******************************************************************************/
static void
ndjson_out_banner(struct Output *out, FILE *fp, time_t timestamp,
                 unsigned ip, unsigned ip_proto, unsigned port,
                 enum ApplicationProtocol proto,
                 unsigned ttl,
                 const unsigned char *px, unsigned length)
{
    char banner_buffer[65536];

    UNUSEDPARM(ttl);
    //UNUSEDPARM(timestamp);

    fprintf(fp, "{");
    fprintf(fp, "\"ip\":\"%u.%u.%u.%u\",",
            (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>> 8)&0xFF, (ip>> 0)&0xFF);
    fprintf(fp, "\"timestamp\":\"%d\",\"port\":%u,\"proto\":\"%s\",\"rec_type\":\"banner\",\"data\":{\"service_name\":\"%s\",\"banner\":\"%s\"}",
            (int) timestamp,
            port,
            name_from_ip_proto(ip_proto),
            masscan_app_to_string(proto),
            normalize_ndjson_string(px, length, banner_buffer, sizeof(banner_buffer))
            );
    // fprintf(fp, "\"timestamp\":\"%d\",\"ports\":[{\"port\":%u,\"proto\":\"%s\",\"service\":{\"name\":\"%s\",\"banner\":\"%s\"}}]",
    //         (int) timestamp,
    //         port,
    //         name_from_ip_proto(ip_proto),
    //         masscan_app_to_string(proto),
    //         normalize_ndjson_string(px, length, banner_buffer, sizeof(banner_buffer))
    //         );
    fprintf(fp, "}\n");

    UNUSEDPARM(out);

/*    fprintf(fp, "<host endtime=\"%u\">"
            "<address addr=\"%u.%u.%u.%u\" addrtype=\"ipv4\"/>"
            "<ports>"
            "<port protocol=\"%s\" portid=\"%u\">"
            "<state state=\"open\" reason=\"%s\" reason_ttl=\"%u\" />"
            "<service name=\"%s\" banner=\"%s\"></service>"
            "</port>"
            "</ports>"
            "</host>"
            "\r\n",
            (unsigned)timestamp,
            (ip>>24)&0xFF,
            (ip>>16)&0xFF,
            (ip>> 8)&0xFF,
            (ip>> 0)&0xFF,
            name_from_ip_proto(ip_proto),
            port,
            reason, ttl,
            masscan_app_to_string(proto),
            normalize_string(px, length, banner_buffer, sizeof(banner_buffer))
            );*/
}

/****************************************************************************
 ****************************************************************************/
const struct OutputType ndjson_output = {
    "ndjson",
    0,
    ndjson_out_open,
    ndjson_out_close,
    ndjson_out_status,
    ndjson_out_banner
};
