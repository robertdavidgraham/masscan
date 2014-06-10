#include "output.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "string_s.h"
#include <ctype.h>


/****************************************************************************
 ****************************************************************************/
static void
cert_out_open(struct Output *out, FILE *fp)
{
}


/****************************************************************************
 ****************************************************************************/
static void
cert_out_close(struct Output *out, FILE *fp)
{    
    fprintf(fp, "{finished: 1}\n");
}

/******************************************************************************
 ******************************************************************************/
static void
cert_out_status(struct Output *out, FILE *fp, time_t timestamp, int status,
                unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    
}


/******************************************************************************
 ******************************************************************************/
static void
cert_out_banner(struct Output *out, FILE *fp, time_t timestamp,
                unsigned ip, unsigned ip_proto, unsigned port,
                enum ApplicationProtocol proto, 
                unsigned ttl,
                const unsigned char *px, unsigned length)
{
    unsigned i;
    if (length > 5 && memcmp(px, "cert:", 5) == 0) {
        px += 5;
        length -= 5;
    }
    
    printf("-----BEGIN CERTIFICATE-----\n");
    for (i=0; i<length; i += 72) {
        unsigned len = length - i;
        if (len > 72)
            len = 72;
        printf("%.*s\n", len, px+i);
    }
    printf("-----END CERTIFICATE-----\n");
}

/****************************************************************************
 ****************************************************************************/
const struct OutputType certs_output = {
    "cert",
    0,
    cert_out_open,
    cert_out_close,
    cert_out_status,
    cert_out_banner
};

