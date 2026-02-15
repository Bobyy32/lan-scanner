#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#define HASH_FACTOR 

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct Bucket
{
    const char* key;
    void* value;
}bucket;

struct HashTable
{
    size_t capacity;
    unsigned int num_buckets;

    bucket** table;
};



static uint64_t ht_hash(const char* data);

struct HashTable* ht_create();
void ht_destroy(struct HashTable* ht);

void* ht_get(struct HashTable* ht, const char* key);
void ht_set(struct HashTable* ht, const char* key, void* value);
static void ht_set_helper(struct HashTable* ht, const char* key, void* value);

static bool ht_resize(struct HashTable* ht);

#endif