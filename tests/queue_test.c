#include "../src/queue.h"
#include "../src/debug.h"

#include <stdio.h>

int main(void)
{
    queue q = { 0 };

    int a = 1;
    int b = 6;
    int c = 9;

    append(&q, &a);
    append(&q, &b);
    append(&q, &c);

    int* res = NULL;

    printf("Count: %d\n", q.count);

    while ((res = (int*)pop_left(&q)))
    {
        printf("Number: %d\n", *res);
    }

    printf("Count: %d\n", q.count);
    
    return 0;
}