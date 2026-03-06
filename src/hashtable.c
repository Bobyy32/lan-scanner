#include "hashtable.h"

static void ht_set_helper(struct HashTable* ht, const char* key, void* value);
static bool ht_resize(struct HashTable* ht);

uint64_t ht_hash(const char *data)
{
    // start with offset
    uint64_t hash = 14695981039346656037UL;

    for (const char* p = data; *p; ++p)
    {
        hash ^= (uint32_t )(unsigned char)(*p);
        hash *= 1099511628211UL; // prime number
    }
    
    return hash;
}

struct HashTable *ht_create()
{
    struct HashTable* ht = malloc(sizeof(struct HashTable));


    ht->capacity = 16;
    ht->num_buckets = 0;

    ht->table = (bucket**)calloc(ht->capacity, sizeof(bucket*));

    pthread_mutex_init(&ht->mutex, NULL);

    return ht;
}

void ht_destroy(struct HashTable *ht, void (*destroy_value)(void*))
{
    for (int i = 0; i < ht->capacity; ++i)
    {
        if (ht->table[i] != NULL)
        {
            free((void*)ht->table[i]->key);
            if (destroy_value)
                destroy_value(ht->table[i]->value);
            free(ht->table[i]);
        }
    }

    free(ht->table);
    pthread_mutex_destroy(&ht->mutex);
    free(ht);
}

void* ht_get(struct HashTable* ht, const char* key)
{
    pthread_mutex_lock(&ht->mutex);
    uint64_t hash = ht_hash(key);
    size_t index = (size_t)(hash & (uint64_t)(ht->capacity - 1));
    void* res = NULL;
 
    while (ht->table[index] != NULL)
    {
        if (strcmp(ht->table[index]->key, key) == 0)
        {
            res =  ht->table[index]->value;
            break;
        }
        
        ++index;
        if (index >= ht->capacity)
        {
           index = 0;
        } 
    }
    pthread_mutex_unlock(&ht->mutex);

    return res;
}

void ht_set(struct HashTable* ht, const char* key, void* value)
{
    pthread_mutex_lock(&ht->mutex);
    ht_set_helper(ht, key, value);
    float load_factor = (float)ht->num_buckets / ht->capacity;
    if (load_factor > 0.70f)
    {
        ht_resize(ht);
    }
    pthread_mutex_unlock(&ht->mutex);
}

static void ht_set_helper(struct HashTable *ht, const char *key, void *value)
{
    uint64_t hash = ht_hash(key);
    size_t index = (size_t)(hash & (uint64_t)(ht->capacity - 1));

    while (ht->table[index] != NULL)
    {
        if (strcmp(ht->table[index]->key, key) == 0)
        {
            ht->table[index]->value = value;
            return;
        }

        ++index;

        if (index >= ht->capacity)
        {
           index = 0;
        } 
    }

    bucket* new = malloc(sizeof(bucket));
    new->key = strdup(key);
    new->value = value;
    ht->table[index] = new;
    ht->num_buckets++;
}

static bool ht_resize(struct HashTable *ht)
{
    size_t new_capacity = ht->capacity * 2;
    bucket** new_table = (bucket**)calloc(new_capacity, sizeof(bucket*));

    if (new_table == NULL)
    {
        return false;
    }

    bucket** old_table = ht->table;
    size_t old_capacity = ht->capacity;


    ht->table = new_table;
    ht->capacity = new_capacity;
    ht->num_buckets = 0;

    for (size_t i = 0; i < old_capacity; ++i)
    {
        if(old_table[i] != NULL)
        {
            ht_set_helper(ht, old_table[i]->key, old_table[i]->value);
            free((void*)old_table[i]->key);
            free(old_table[i]);
        }
    }

    free(old_table);
    return true;
}
