#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#define HASH_FACTOR 

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "device.h"

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

struct HashTable* ht_create();
void ht_destroy(struct HashTable* ht);

void* ht_get(struct HashTable* ht, const char* key);
void ht_set(struct HashTable* ht, const char* key, void* value);

#endif