

#include <stdio.h>
#include <stdlib.h>

#include "../src/thread_pool.h"

#define _BSD_SOURCE


void test(void *arg)
{
    int *val = arg;
    int  old = *val;

    *val += 1000;
    printf("tid=%p, old=%d, val=%d\n", pthread_self(), old, *val);

    if (*val % 2)
    {
        usleep(100000);
    }
}

int main(void)
{
    const unsigned int num_threads = 4;
    const unsigned int num_items = 100;
    
    thread_pool* pool = init_thread_pool(num_threads);

    int* vals = NULL;

    vals = calloc(num_items, sizeof(*vals));

    for (int i = 0; i < num_items; ++i) {
        vals[i] = i;
        add_work_thread_pool(pool, test, vals + i);
    }

    wait_thread_pool(pool);

    for (int i = 0; i < num_items; ++i) 
    {
        printf("%d\n", vals[i]);
    }

    free(vals);
    destroy_thread_pool(pool);

    return 0;
}