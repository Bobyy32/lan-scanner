#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <stdbool.h> 
#include <pthread.h>

#include "queue.h"


// https://markc.su/posts/threadpool_c
// https://nachtimwald.com/2019/04/12/thread-pool-in-c/

typedef void (*job_fn)(void *args);

typedef struct Job
{
    job_fn function;
    void* args;
} job;

typedef struct Thread_Pool
{
    unsigned int thread_count;
    unsigned int thread_working;

    pthread_mutex_t mutex;

    pthread_cond_t work_cond;
    pthread_cond_t finish_cond;

    bool shutdown;

    queue work_queue;

} thread_pool;

thread_pool* init_thread_pool(unsigned int num_threads);
void destroy_thread_pool(thread_pool* t_pool);
void wait_thread_pool(thread_pool* t_pool);
void add_work_thread_pool(thread_pool* t_pool, job_fn function, void* args);

#endif