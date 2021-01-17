#include "proto-oproto.h"
#include "unusedparm.h"

void
handle_oproto(struct Output *out, time_t timestamp,
              const unsigned char *px, unsigned length,
              struct PreprocessedInfo *parsed,
              uint64_t entropy)
{
    UNUSEDPARM(entropy);
    UNUSEDPARM(parsed);
    UNUSEDPARM(length);
    UNUSEDPARM(px);
    UNUSEDPARM(timestamp);
    UNUSEDPARM(out);
}
