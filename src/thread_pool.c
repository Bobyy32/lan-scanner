#include "thread_pool.h"

#include <stdlib.h>

static void* thread_work_loop(void *t_pool_arg);
static job* create_job(job_fn function, void *args);

thread_pool *init_thread_pool(unsigned int num_threads)
{
    thread_pool* new_t_pool = (thread_pool*)calloc(1, sizeof(thread_pool));
    pthread_t thread;

    new_t_pool->thread_count = num_threads;

    pthread_mutex_init(&new_t_pool->mutex, NULL);
    pthread_cond_init(&new_t_pool->work_cond, NULL);
    pthread_cond_init(&new_t_pool->finish_cond, NULL);

    new_t_pool->shutdown = false;

    new_t_pool->work_queue.head = NULL;
    new_t_pool->work_queue.tail = NULL;

    for (unsigned int i = 0; i < num_threads; ++i)
    {
        pthread_create(&thread, NULL, thread_work_loop, new_t_pool);
        pthread_detach(thread);
    }

    return new_t_pool;
}

void destroy_thread_pool(thread_pool* t_pool)
{
    pthread_mutex_lock(&t_pool->mutex);
    
    t_pool->shutdown = true;
    pthread_cond_broadcast(&t_pool->work_cond);

    while (t_pool->thread_count > 0)
    {
        pthread_cond_wait(&t_pool->finish_cond, &t_pool->mutex);
    }

    pthread_mutex_unlock(&t_pool->mutex);

    pthread_mutex_destroy(&t_pool->mutex);
    pthread_cond_destroy(&t_pool->work_cond);
    pthread_cond_destroy(&t_pool->finish_cond);

    if (t_pool->work_queue.count > 0)
    {
        while (t_pool->work_queue.head)
        {
            void* data = q_pop_left(&t_pool->work_queue);
            free(data);
        }
    }

    free(t_pool);
}

void wait_thread_pool(thread_pool *t_pool)
{
    if (t_pool == NULL)
    {
        return;
    }

    pthread_mutex_lock(&t_pool->mutex);
    while (t_pool->thread_working > 0 || t_pool->work_queue.head != NULL)
    {
        pthread_cond_wait(&t_pool->finish_cond, &t_pool->mutex);
    }
    pthread_mutex_unlock(&t_pool->mutex);
}

void add_work_thread_pool(thread_pool *t_pool, job_fn function, void *args)
{
    job* new_job = create_job(function, args);
    pthread_mutex_lock(&t_pool->mutex);
    q_append(&t_pool->work_queue, new_job);
    pthread_cond_signal(&t_pool->work_cond);
    pthread_mutex_unlock(&t_pool->mutex);
}

static void* thread_work_loop(void *t_pool_arg)
{
    thread_pool* t_pool = (thread_pool*)t_pool_arg;

    while (1)
    {
        job* todo = NULL;

        pthread_mutex_lock(&t_pool->mutex);
        while (t_pool->work_queue.head == NULL && !t_pool->shutdown)
        {
            pthread_cond_wait(&t_pool->work_cond, &t_pool->mutex);
        }

        if (t_pool->shutdown)
        {
            --t_pool->thread_count;
            pthread_cond_signal(&t_pool->finish_cond);
            pthread_mutex_unlock(&t_pool->mutex);
            break;
        }

        todo = q_pop_left(&t_pool->work_queue);
        ++t_pool->thread_working;

        pthread_mutex_unlock(&t_pool->mutex);

        if (todo != NULL)
        {
            todo->function(todo->args);
            free(todo);
        }

        pthread_mutex_lock(&t_pool->mutex);
        --t_pool->thread_working;
        if (!t_pool->shutdown && t_pool->thread_working == 0 && t_pool->work_queue.head == NULL)
        {
            pthread_cond_signal(&t_pool->finish_cond);
        }
        pthread_mutex_unlock(&t_pool->mutex);
    }

    return NULL;
}

static job *create_job(job_fn function, void *args)
{
    job* new_job = (job*)malloc(sizeof(job));

    new_job->args = args;
    new_job->function = function;

    return new_job;
}


