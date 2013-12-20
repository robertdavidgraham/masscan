#ifndef SMACKQUEUE_H
#define SMACKQUEUE_H

struct Queue *
queue_create(void);


void
queue_destroy(struct Queue *queue);


void
enqueue(struct Queue *queue, unsigned data);


unsigned
dequeue(struct Queue *queue);


unsigned
queue_has_more_items(struct Queue *queue);


#endif
