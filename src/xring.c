#include "xring.h"
#include "pixie-threads.h"
#include "pixie-timer.h"
#include "string_s.h"
#include <stdio.h>


typedef uint64_t Element;

#define XRING_SIZE 16

struct XRing
{
    volatile unsigned long long head;
    volatile unsigned long long tail;
    volatile Element ring[XRING_SIZE];
};



/***************************************************************************
 ***************************************************************************/
static Element
xring_remove(struct XRing *xring)
{
    volatile Element *ring = xring->ring;
    Element num;

    if (xring->tail >= xring->head)
        return 0;


    num = ring[xring->tail & (XRING_SIZE-1)];
    if (num) {
        ring[xring->tail & (XRING_SIZE-1)] = 0;
        xring->tail++;
        return num;
        /*
        int x = pixie_locked_CAS64(&ring[xring->tail & (XRING_SIZE-1)], 0, num);
        if (x) {
            xring->tail++;
            return num;
        } else {
            goto again;
        }*/
    } else {
        return 0;
    }
}

enum {XringSuccess, XringFailure};
/***************************************************************************
 ***************************************************************************/
static int
xring_add(struct XRing *xring, Element value)
{
    volatile Element *ring = xring->ring;
    Element num;

    if (value == 0) {
        return XringFailure;
    }

    if (xring->head >= xring->tail + XRING_SIZE) {
        //printf("-");
        return XringFailure;
    }
    num = xring->ring[xring->head & (XRING_SIZE-1)];
    if (num == 0) {
        ring[xring->head & (XRING_SIZE-1)] = value;
        xring->head++;
        return XringSuccess;
        /*int x = pixie_locked_CAS64(&ring[xring->head & (XRING_SIZE-1)], value, 0);
        if (x) {
            xring->head++;
            return XringSuccess;
        } else {
            return XringFailure;
        }*/
    }
    return XringFailure;
}

/***************************************************************************
 ***************************************************************************/
struct Test
{
    struct XRing xring[1];
    unsigned producer_started;
    unsigned producer_done;
    unsigned consumer_done;
    unsigned long long total_count;
    volatile int not_active;
};

/***************************************************************************
 ***************************************************************************/
static void
test_consumer_thread(void *v)
{
    struct Test *test = (struct Test *)v;
    struct XRing *xring = test->xring;


    while (!test->not_active) {
        Element e;

        e = xring_remove(xring);
        if (e == 0)
            ;
        else {
            test->total_count += e;
        }
    }

    while (xring->tail < xring->head) {
        Element e;

        e = xring_remove(xring);
        if (e == 0)
            ;
        else {
            test->total_count += e;
        }
    }

    test->consumer_done = 1;
}

/***************************************************************************
 ***************************************************************************/
static void
test_producer_thread(void *v)
{
    struct Test *test = (struct Test *)v;
    unsigned i = 1000;
    struct XRing *xring = test->xring;

    pixie_locked_add_u32(&test->producer_started, 1);
    while (i) {
        while (xring_add(xring, i) == XringFailure)
            ;
        i--;
    }
    pixie_locked_add_u32(&test->producer_done, 1);
}

/***************************************************************************
 ***************************************************************************/
static uint64_t
run_test(struct Test *test)
{
    unsigned i;
    const unsigned THREADS = 1;

    memset(test, 0, sizeof(*test));

    /* Generate producer threads */
    for (i=0; i<THREADS; i++) {
        pixie_begin_thread(test_producer_thread, 0, test);
    }

    /* Wait for threads to start */
    while (test->producer_started < THREADS)
        pixie_usleep(10);
    /* Now start consuming */
    pixie_begin_thread(test_consumer_thread, 0, test);

    /* Wait for producer threads to end */
    while (test->producer_done < THREADS)
        pixie_usleep(10);


    /* Tell consumer thread to end */
    test->not_active = 1;


    /* Wait for consumer thread to end */
    while (!test->consumer_done)
        pixie_usleep(10);

    return test->total_count;
}


/***************************************************************************
 ***************************************************************************/
int
xring_selftest(void)
{
    unsigned i;

    for (i=0; i<1000; i++) {
        uint64_t result;
        struct Test test[1];

        result = run_test(test);
        if (result != 500500) {
            printf("xring: selftest failed with %" PRIu64 "\n", result);
            return 1;
        } else
            ;
    }

    return 0;
}




