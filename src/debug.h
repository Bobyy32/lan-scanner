
// from https://sqlpey.com/c/c-cpp-debugging-macros/

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG > 0
#include <stdio.h>
#define debug_printf(fmt, ...) \
    do { \
        fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    } while (0)
#else
#define debug_printf(fmt, ...) do {} while (0)
#endif