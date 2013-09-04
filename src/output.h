#ifndef OUTPUT_H
#define OUTPUT_H
struct Masscan;
struct Output;

struct Output *output_create(struct Masscan *masscan);
void output_destroy(struct Output *output);

void output_report(struct Output *output, int status, unsigned ip, unsigned port, unsigned reason, unsigned ttl);


typedef void (*OUTPUT_REPORT_BANNER)(
                struct Output *output, 
                unsigned ip, unsigned port, 
                unsigned proto,
                const unsigned char *px, unsigned length);

void output_report_banner(
                struct Output *output, 
                unsigned ip, unsigned port, 
                unsigned proto,
                const unsigned char *px, unsigned length);


#endif
