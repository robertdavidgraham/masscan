#include <dlfcn.h>

/* we don't nee no stinking #includes */
struct pfring;
typedef struct pfring pfring;
pfring *(*pfring_open)(const char *, int, int);
int (*pfring_set_direction)(pfring *, int);
int (*pfring_enable_ring)(pfring *);
int (*pfring_send)(pfring *, const unsigned char *, int, int);

int main(int argc, char *argv[])
{
    /* Runtime link to library. Requires 'libpfring.so' to
     * be somewhere like /usr/local/lib */
    void *lib = dlopen("libpfring.so", RTLD_LAZY);
    pfring_open = dlsym(lib, "pfring_open");
    pfring_set_direction = dlsym(lib, "pfring_set_direction");
    pfring_enable_ring = dlsym(lib, "pfring_enable_ring");
    pfring_send = dlsym(lib, "pfring_send");
    
    
    /* say "Hi!" to the network. Requires pf_ring.ko and the
     * DNA-version of ixgbe.ko to be loaded into kernel */
    pfring *p = pfring_open(argv[0], 1600, 0);
    pfring_set_direction(p, 1);
    pfring_enable_ring(p);
    for (;;) {
        pfring_send(p, 
                    "\xFF\xFF\xFF\xFF\xFF\xFF"
                    "Hello world!\n", 
                    19, 0); 
    }
    
}