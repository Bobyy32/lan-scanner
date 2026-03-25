#include "queue.h"

#include "debug.h"

#include <stdio.h>
#include <stdlib.h>

void append(queue *q, void *data)
{
    node* new = (node*)calloc(1, sizeof(node));
    if (new == NULL)
    {
        debug_printf("Failed to allocate node\n");
        return;
    }

    new->data = data;

    if (q->head == NULL)
    {
        q->head = new;
        q->tail = new;
    }
    else
    {
        q->tail->next = new;
        q->tail = new;
    }

    q->count++;
}

void *pop_left(queue *q)
{

    if (q->head == NULL)
    {
        return NULL;
    }

    node* temp = q->head;
    q->head = q->head->next;
    void* data = temp->data;
    free(temp);   
    q->count--;

    return data;
}

void destroy_queue(queue *q)
{
    while (q->head)
    {
        void* data = pop_left(q);
        free(data);
    }

    free(q);
}
