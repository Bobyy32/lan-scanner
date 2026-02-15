#ifndef HASH_TABLE_H
#define HASH_TABLE_H


struct Bucket
{
    const char* key;
    void* value;

    struct Bucket* next;
};

struct HashTable
{
    unsigned int capacity;
    unsigned int num_buckets;
    float load_factor;

    Bucket** table;
};



unsigned int ht_hash(const char* data);

HashTable* ht_create();
void ht_destroy();

void ht_set();
void ht_get();

#endif