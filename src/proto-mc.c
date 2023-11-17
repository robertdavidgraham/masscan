#include "proto-mc.h"
#include "proto-banner1.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "stack-tcp-api.h"
#include "output.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

static unsigned char hand_shake_ptr[128];

static unsigned char *
hand_shake(uint16_t port, const char* ip, size_t ip_len)
{
    size_t tlen = 10+ip_len;
    unsigned char * ret = (unsigned char *)calloc(1,tlen);
    ret[0] = (unsigned char)(7+ip_len);
    ret[2] = 0xf7;
    ret[3] = 5;
    ret[4] = (unsigned char)ip_len;
    memcpy(ret+5,ip,ip_len);
    ret[tlen-5] = (unsigned char)(port>>8);
    ret[tlen-4] = (unsigned char)(port&0xff);
    ret[tlen-3] = 1;
    ret[tlen-2] = 1;
    ret[tlen-1] = 0;
    return ret;
}

static void *
memstr(void * mem, size_t len, char * str)
{
    size_t i;
    size_t stlen = strlen(str);
    if(len < stlen)
        return 0;
    for(i = 0; i < len-stlen; i++) {
        if(!memcmp((char*)mem+i,str,stlen))
            return (char*)mem+i;
    }
    return 0;
}

/***************************************************************************
 ***************************************************************************/
static void
mc_parse(  const struct Banner1 *banner1,
          void *banner1_private,
          struct StreamState *pstate,
          const unsigned char *px, size_t length,
          struct BannerOutput *banout,
          struct stack_handle_t *socket)
{
    size_t i;
    struct MCSTUFF *mc = &pstate->sub.mc;
    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);
    for(i = 0; i < length; i++) {
        if(px[i] == '{')
            mc->brackcount++;
        if(px[i] == '}')
            mc->brackcount--;
    }
    if(mc->brackcount <= 0)
        tcpapi_close(socket);

    if((mc->imgstart&&mc->imgend) || mc->brackcount <= 0) { // we already found and removed image data
        banout_append(banout, PROTO_MC,px,length);
    } else {
        mc->banmem = realloc(mc->banmem,mc->totalLen+length+1); // expand to add new memory for added paket
        memcpy(mc->banmem+mc->totalLen,px,length); // copy in new packet
        mc->banmem[mc->totalLen] = 0; // add ending 0 for str
        mc->totalLen+=length;
        if(!mc->imgstart) { // dont search again if we found start
            mc->imgstart = (size_t)memstr(mc->banmem,mc->totalLen,"data:image/png;base64");
            if(mc->imgstart)
                mc->imgstart-=(size_t)mc->banmem;
        } else { // we found start but not the end
            mc->imgend = (size_t)memchr(mc->banmem+mc->imgstart,'\"',mc->totalLen-mc->imgstart);
            if(mc->imgend){ // we found the end
                mc->imgend-=(size_t)mc->banmem;
                memcpy(mc->banmem+mc->imgstart,mc->banmem+mc->imgend,(mc->totalLen-mc->imgend)+1); // copy data after B64
                mc->totalLen=mc->imgstart+(mc->totalLen-mc->imgend); // shrink length to subtract B64 image
                banout_append(banout, PROTO_MC,mc->banmem,mc->totalLen); // print out banner minus image data
                free(mc->banmem); // we dont need to keep track of this any more.
            }
        }
    }
}

/***************************************************************************
 ***************************************************************************/
static void *
mc_init(struct Banner1 *banner1)
{
    unsigned char * tmp = hand_shake(25565,"localhost",9);
    memcpy(hand_shake_ptr,tmp,tmp[0]+3);
    free(tmp);
    banner_mc.hello = hand_shake_ptr;
    banner_mc.hello_length = hand_shake_ptr[0]+3;
    banner1->payloads.tcp[25565] = (void*)&banner_mc;
    return 0;
}

/***************************************************************************
 ***************************************************************************/
static int
mc_selftest(void)
{
    return 0;
}

/***************************************************************************
 ***************************************************************************/
struct ProtocolParserStream banner_mc = {
    "mc", 25565, 0, 0, 0,
    mc_selftest,
    mc_init,
    mc_parse,
};
