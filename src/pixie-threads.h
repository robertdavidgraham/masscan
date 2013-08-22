#ifndef PORT_THREADS_H
#define PORT_THREADS_H
#include <stdio.h>

size_t pixie_begin_thread(void (*worker_thread)(void*), unsigned flags, void *worker_data);



#endif
