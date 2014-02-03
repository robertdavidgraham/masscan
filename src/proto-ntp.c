/*
    NTP protocol handler
*/
#include "proto-ntp.h"
#include <stdint.h>
#include <stdlib.h>
#include "smack.h"
#include "string_s.h"
#include "output.h"
#include "masscan-app.h"
#include "proto-preprocess.h"
#include "proto-banner1.h"
#include "syn-cookie.h"
#include "templ-port.h"
#include "unusedparm.h"



/****************************************************************************
 ****************************************************************************/
unsigned
ntp_set_cookie(unsigned char *px, size_t length, uint64_t seqno)
{
    UNUSEDPARM(px);
    UNUSEDPARM(length);
    UNUSEDPARM(seqno);
    return 0;
}
struct Val2String {
    unsigned value;
    const char *string;
};

static const struct Val2String request_codes[] = {
	{ 0,		"PEER_LIST" },
	{ 1,		"PEER_LIST_SUM" },
	{ 2,		"PEER_INFO" },
	{ 3,		"PEER_STATS" },
	{ 4,		"SYS_INFO" },
	{ 5,		"SYS_STATS" },
	{ 6,		"IO_STATS" },
	{ 7,		"MEM_STATS" },
	{ 8,		"LOOP_INFO" },
	{ 9,		"TIMER_STATS" },
	{ 10,		"CONFIG" },
	{ 11,		"UNCONFIG" },
	{ 12,		"SET_SYS_FLAG" },
	{ 13,		"CLR_SYS_FLAG" },
	{ 16,		"GET_RESTRICT" },
	{ 17,		"RESADDFLAGS" },
	{ 18,		"RESSUBFLAGS" },
	{ 19,		"UNRESTRICT" },
	{ 20,		"MON_GETLIST" },
	{ 21,		"RESET_STATS" },
	{ 22,		"RESET_PEER" },
	{ 23,		"REREAD_KEYS" },
	{ 26,		"TRUSTKEY" },
	{ 27,		"UNTRUSTKEY" },
	{ 28,		"AUTHINFO" },
	{ 29,		"TRAPS" },
	{ 30,		"ADD_TRAP" },
	{ 31,		"CLR_TRAP" },
	{ 32,		"REQUEST_KEY" },
	{ 33,		"CONTROL_KEY" },
	{ 34,		"GET_CTLSTATS" },
	{ 36,		"GET_CLOCKINFO" },
	{ 37,		"SET_CLKFUDGE" },
	{ 38,		"GET_KERNEL" },
	{ 39,		"GET_CLKBUGINFO" },
	{ 42,		"MON_GETLIST_1" },
	{ 43,		"HOSTNAME_ASSOCID" },
    { 0, 0}
};

struct Val2String error_codes[] = {
    {0, "No Error"},
    {1, "Incompatable Implementation Number"},
    {2, "Unimplemented Request Code"},
    {3, "Format Error"},
    {4, "No Data Available"},
    {7, "Authentication Failure"},
    {0,0}
};

/*****************************************************************************
 *****************************************************************************/
static const char *
val2string_lookup(const struct Val2String *list, unsigned val)
{
    unsigned i;
    for (i=0; list[i].string; i++) {
        if (list[i].value == val)
            return list[i].string;
    }
    return 0;
}

/*****************************************************************************
 *****************************************************************************/
static void
ntp_modlist_parse(const unsigned char *px,
             unsigned length,
             struct BannerOutput *banout,
             unsigned *request_id)
{
    unsigned offset = 4;
    unsigned errcode;
    unsigned record_count;
    unsigned record_size;
 
    UNUSEDPARM(request_id);

    if (offset + 4 >= length)
        return;
    
    errcode = (px[offset]>>4)&0xF;
    record_count = (px[offset+0]&0xF) << 8 | px[offset+1];
    record_size = (px[offset+2]&0xF) << 8 | px[offset+3];

    if (errcode) {
        char foo[12];
        const char *errmsg = val2string_lookup(error_codes, errcode);
        if (errmsg == 0)
            errmsg = "Bogus Error Code";
        sprintf_s(foo, sizeof(foo), "%u", errcode);
        banout_append(banout, PROTO_NTP, "Response was NTP Error Code ", AUTO_LEN);
        banout_append(banout, PROTO_NTP, foo, AUTO_LEN);
        banout_append(banout, PROTO_NTP, " - \"", AUTO_LEN);
        banout_append(banout, PROTO_NTP, errmsg, AUTO_LEN);
        banout_append(banout, PROTO_NTP, "\"", AUTO_LEN);
        return;
    }

    if (4 + record_count * record_size > length) {
        banout_append(banout, PROTO_NTP, "response-too-big", AUTO_LEN);
        return;
    }
    if (record_count * record_size > 500) {
        banout_append(banout, PROTO_NTP, "response-too-big", AUTO_LEN);
        return;
    }

    offset += 4;

    {
        char msg[128];

        sprintf_s(msg, sizeof(msg), " response-size=%u-bytes more=%s",
            record_count * record_size, ((px[0]>>6)&1)?"true":"false");

        banout_append(banout, PROTO_NTP, msg, AUTO_LEN);
    }
}

/*****************************************************************************
 *****************************************************************************/
static void
ntp_priv(const unsigned char *px,
             unsigned length,
             struct BannerOutput *banout,
             unsigned *request_id)
{
    unsigned implementation = px[2];
    unsigned request_code = px[3];
    const char *request_string;
    
    switch (implementation) {
        case 0: banout_append(banout, PROTO_NTP, "UNIV", 4); return;
        case 2: banout_append(banout, PROTO_NTP, "XNTPD-OLD", 9); return;
        case 3: banout_append(banout, PROTO_NTP, "XNTPD", 5); break;
        default:
            return;
    }
    
    request_string = val2string_lookup(request_codes, request_code);
    if (request_string) {
        banout_append(banout, PROTO_NTP, " ", 1);
        banout_append(banout, PROTO_NTP, request_string, strlen(request_string));
    }
    
    switch (request_code) {
        case 42:
            ntp_modlist_parse(px, length, banout, request_id);
            break;
    }    
    
}

/*****************************************************************************
 *****************************************************************************/
static void
ntp_v2_parse(const unsigned char *px,
           unsigned length,
           struct BannerOutput *banout,
           unsigned *request_id)
{
    unsigned mode;
    
    if (length < 4)
        return;
    
    /* Validate: response bit is set */
    if ((px[0]>>7) != 1)
        return;
        
    /* Validate: this is version 2 */
    if (((px[0]>>3)&7) != 2)
        return;
    
    /* Extract: mode */
    mode = px[0] & 7;
    switch (mode) {
        case 6: /* control */
            break;
        case 7:
            ntp_priv(px, length, banout, request_id);
            break;
    }
    
    
    
}


/*****************************************************************************
 * Handles an NTP response.
 *****************************************************************************/
unsigned
ntp_handle_response(struct Output *out, time_t timestamp,
            const unsigned char *px, unsigned length,
            struct PreprocessedInfo *parsed,
            uint64_t entropy
            )
{
    unsigned ip_them;
    unsigned request_id = 0;
    struct BannerOutput banout[1];
    unsigned offset = parsed->app_offset;
    
    UNUSEDPARM(length);
    UNUSEDPARM(entropy);
    
    if (parsed->app_length < 4)
        return 0;
    
    /* Initialize the "banner output" module that we'll use to print
     * pretty text in place of the raw packet */
    banout_init(banout);
    
    /* Parse the packet */
    switch ((px[offset]>>3)&7) {
        case 2:
            ntp_v2_parse(
               px + parsed->app_offset,    /* incoming  response */
               parsed->app_length,         /* length of  response */
               banout,                     /* banner printing */
               &request_id);               /* syn-cookie info */
            break;
        default:
            banout_release(banout);
            return 0;
    }
    
    ip_them = parsed->ip_src[0]<<24 | parsed->ip_src[1]<<16
    | parsed->ip_src[2]<< 8 | parsed->ip_src[3]<<0;
    /*ip_me = parsed->ip_dst[0]<<24 | parsed->ip_dst[1]<<16
    | parsed->ip_dst[2]<< 8 | parsed->ip_dst[3]<<0;*/
    
    /* Validate the "syn-cookie" style information. */
    //seqno = (unsigned)syn_cookie(ip_them, port_them | Templ_UDP, ip_me, port_me);
    //if ((seqno&0x7FFFffff) != request_id)
    //    return 1;
    
    /* Print the banner information, or save to a file, depending */
    output_report_banner(
                         out, timestamp,
                         ip_them, 17, parsed->port_src,
                         PROTO_NTP,
                         parsed->ip_ttl,
                         banout_string(banout, PROTO_NTP),
                         banout_string_length(banout, PROTO_NTP));
    
    /* Free memory for the banner, if there was any allocated */
    banout_release(banout);
    
    return 0;
}



/****************************************************************************
 ****************************************************************************/
int
ntp_selftest(void)
{
    
    
    return 0;
}





