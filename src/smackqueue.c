#include "smackqueue.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/****************************************************************************
 * Build a queue so that we can do a breadth-first enumeration of the
 * sub-patterns
 ****************************************************************************/
struct QueueElement
{
    unsigned m_data;
    struct QueueElement *m_next;
};
struct Queue
{
    struct QueueElement *m_head;
    struct QueueElement *m_tail;
};

struct Queue *
queue_create(void)
{
    struct Queue *queue;
    queue = (struct Queue *)malloc(sizeof(*queue));
    if (queue == NULL) {
        fprintf(stderr, "%s: out of memory error\n", "smack");
        exit(1);
    }
    memset(queue, 0, sizeof(*queue));
    return queue;
}

void
queue_destroy(struct Queue * queue)
{
    if (queue == NULL)
        return;
    while (queue_has_more_items(queue))
        dequeue(queue);
    free(queue);
}

void
enqueue(struct Queue *queue, unsigned data)
{
    struct QueueElement *element;

    element = (struct QueueElement *)malloc(sizeof (struct QueueElement));
    if (element == NULL) {
        fprintf(stderr, "%s: out of memory error\n", "smack");
        exit(1);
    }

    if (queue->m_head == NULL) {
        /* If nothing in the queue, initialize the queue with the
         * first data */
        queue->m_head = element;
    } else {
        /* Else, add the data to the the tail of the queue */
        queue->m_tail->m_next = element;
    }

    element->m_data = data;
    element->m_next = NULL;
    queue->m_tail = element;
}

unsigned
dequeue(struct Queue *queue)
{
    if (queue->m_head == NULL)
        return 0;
    else {
        struct QueueElement *element;
        unsigned result;

        element = queue->m_head;
        result = element->m_data;
        queue->m_head = element->m_next;

        free(element);
        return result;
    }
}

unsigned queue_has_more_items(struct Queue * queue)
{
  return queue->m_head != NULL;
}
