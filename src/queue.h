#ifndef QUEUE_H
#define QUEUE_H

typedef struct Node
{
    void* data;
    struct Node* next;
} node;

typedef struct Queue
{
    node* tail;
    node* head;
    unsigned int count;
} queue;

void q_append(queue* q, void* data);
void* q_pop_left(queue* q);

void q_destroy_queue(queue* q);

#endif