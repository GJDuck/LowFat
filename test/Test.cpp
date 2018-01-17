/*
 *   _|                                      _|_|_|_|            _|
 *   _|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
 *   _|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
 *   _|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
 *   _|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|
 * 
 * Gregory J. Duck.
 *
 * Copyright (c) 2017 The National University of Singapore.
 * All rights reserved.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See the LICENSE file for details.
 */

/*
 * Note: this program does OOB-reads.
 */

#include <stdint.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <lowfat.h>

#define NOINLINE    __attribute__((__noinline__))

extern "C"
{
    extern void *__libc_malloc(size_t);
}

static size_t total = 0;
static size_t passed = 0;
static size_t failed = 0;
static bool thread = false;

#define STRING0(x)      #x
#define STRING(x)       STRING0(x)

#define TEST(statement, expErrs)                                            \
    do {                                                                    \
        total++;                                                            \
        unsigned numErrs0 = (unsigned)lowfat_get_num_errors();              \
        statement;                                                          \
        unsigned numErrs1 = (unsigned)lowfat_get_num_errors();              \
        printf("[%.4zu] ", total);                                          \
        unsigned gotErrs = numErrs1 - numErrs0;                             \
        if (gotErrs != expErrs) {                                           \
            printf("\33[31mFAILED\33[0m " STRING(statement) " "             \
                "\33[33m[excepted %u error(s); got %u]\33[0m\n",            \
                expErrs, gotErrs);                                          \
            failed++;                                                       \
        } else {                                                            \
            printf("\33[32mpassed\33[0m: " STRING(statement) " "            \
                "\33[33m[got %u error(s)]\33[0m\n",                         \
                expErrs);                                                   \
            passed++;                                                       \
        }                                                                   \
    } while (false)

#define TEST_KIND(ptr, kind)                                                \
    do {                                                                    \
        total++;                                                            \
        printf("[%.4zu] ", total);                                          \
        if (!lowfat_is_##kind##_ptr(ptr)) {                                 \
            printf("\33[31mFAILED\33[0m %p is a " STRING(kind) " ptr "      \
                "\33[33m[got %s]\33[0m\n",                                  \
                (ptr), getKind(ptr));                                       \
            failed++;                                                       \
        } else {                                                            \
            printf("\33[32mpassed\33[0m: %p isa " STRING(kind) " ptr\n",    \
                (ptr));                                                     \
            passed++;                                                       \
        }                                                                   \
    } while (false)


void *ptr = nullptr;
char buf[1000];

template <typename T>
struct Test
{
    T f1;
    T f2;
    T f3;
    T f4;
    T f5;
    T f6;
    T f7;
    T f8;
};

template <typename T> extern T **getptr(void);
template <typename T> extern T get(T *ptr, int offset);
template <typename T> extern void set(T *ptr, int offset, T val);
template <typename T> extern void escape(T *ptr);
extern void escape(uintptr_t i);
template <typename T> extern T *doreturn(T *ptr, int offset);
extern size_t id(size_t size);

static uint8_t global8xi8[8];
static uint16_t global4xi16[4];
static uint32_t global4xi32[4];
static uint64_t global4xi64[4];

static bool lowfat_is_nonfat_ptr(const void *ptr)
{
    return !lowfat_is_ptr(ptr);
}

static NOINLINE const char *getKind(const void *ptr)
{
    const char *kind = "nonfat";
    if (lowfat_is_heap_ptr(ptr))
        kind = "heap";
    else if (lowfat_is_stack_ptr(ptr))
        kind = "stack";
    else if (lowfat_is_global_ptr(ptr))
        kind = "global";
    return kind;
}

template <typename T, int SIZE>
static NOINLINE T testBuffer(T *xs)
{
    const char *kind = getKind((void *)xs);
    unsigned NUM = (lowfat_is_ptr(xs)? 1: 0);
    printf("\n\33[35m*** BUFFER xs=%p (%s), SIZE=%d, T=(uint%zu_t) "
        "thread=%s ***\33[0m\n",
        (void *)xs, kind, SIZE, sizeof(T) * 8, (thread? "true": "false"));
    const int END = 2 * SIZE + 1;
    TEST(memset(xs, 0, SIZE * sizeof(T)), 0);
    TEST(memcpy(buf, (void *)xs, SIZE * sizeof(T)), 0);
    TEST(memcpy(buf, (void *)xs, END * sizeof(T)), NUM);
    for (int i = 0; i < SIZE; i++)
        TEST(xs[i] = i, 0);
    T sum = 0;
    for (int i = 0; i < SIZE; i++)
        TEST(sum += xs[i], 0);
    for (int i = 1; i < sizeof(T)-1; i++)
        TEST(sum += *(T *)((char *)xs + i), 0);
    for (int i = 0; i < SIZE; i++)
        TEST(get<T>(xs, i), 0);
    TEST(sum += get<T>(xs, -1), NUM);
    TEST(sum += get<T>(xs, END), NUM);
    for (int i = 0; i < SIZE-1; i++)
        TEST(sum += get<T>((xs+SIZE/2), i-(SIZE/2+1)), (i == 0? NUM: 0));
    for (int i = 0; i < SIZE; i++)
        TEST(set<T>(xs, i, 3), 0);
    TEST(escape<T>(xs), 0);
    TEST(escape<T>(xs+SIZE/2), 0);
    TEST(escape<T>(xs-1), NUM);
    TEST(escape<T>(xs+END), NUM);
    TEST(doreturn<T>(xs, 0), 0);
    TEST(doreturn<T>(xs, SIZE/2), 0);
    TEST(doreturn<T>(xs, -1), NUM);
    TEST(doreturn<T>(xs, END), NUM);
    uintptr_t i = 0;
    TEST(i = (uintptr_t)xs, 0); escape(i);
    TEST(i = (uintptr_t)(xs+SIZE/2), 0); escape(i);
    TEST(i = (uintptr_t)(xs-1), NUM); escape(i);
    TEST(i = (uintptr_t)(xs+END), NUM); escape(i);
    T **ptr = getptr<T>();
    TEST(*ptr = xs, 0);
    TEST(*ptr = (xs+SIZE/2), 0);
    TEST(*ptr = (xs-1), NUM);
    TEST(*ptr = (xs+END), NUM);
    return sum;
}

template <typename T>
static NOINLINE T testField(Test<T> &t)
{
    const char *kind = getKind((void *)&t);
    unsigned NUM = (lowfat_is_ptr(&t)? 1: 0);
    printf("\n\33[35m*** FIELD &t=%p (%s), T=(uint%zu_t) thread=%s ***\33[0m\n",
        (void *)&t, kind, sizeof(T) * 8, (thread? "true": "false"));
    T sum = 0;
    TEST(sum += t.f1, 0);
    TEST(sum += t.f2, 0);
    TEST(sum += t.f8, NUM);
    TEST(sum += get<T>(&t.f1, 0), 0);
    TEST(sum += get<T>(&t.f2, 0), 0);
    TEST(sum += get<T>(&t.f1, 1), 0);
    TEST(sum += get<T>(&t.f2, -1), 0);
    TEST(sum += get<T>(&t.f1, 7), NUM);
    TEST(sum += get<T>(&t.f8, -7), 2 * NUM);
    TEST(escape<T>(&t.f1), 0);
    TEST(escape<T>(&t.f8), NUM);
    TEST(doreturn<T>(&t.f1, 0), 0);
    TEST(doreturn<T>(&t.f1, 7), NUM);
    T **ptr = getptr<T>();
    uintptr_t i = 0;
    TEST(i = (uintptr_t)&t.f1, 0); escape(i);
    TEST(i = (uintptr_t)&t.f8, NUM); escape(i);
    TEST(*ptr = &t.f1, 0);
    TEST(*ptr = &t.f8, NUM);
    return sum;
}

static NOINLINE uint64_t testEdge(void *ptr)
{
    const char *kind = getKind(ptr);
    unsigned NUM = (lowfat_is_ptr(ptr)? 1: 0);
    uint8_t *end = nullptr;
    if (lowfat_is_ptr(ptr))
        end = (uint8_t *)ptr + lowfat_size(ptr);
    else
        end = (uint8_t *)ptr + 16;
    printf("\n\33[35m*** EDGE base=%p (%s) end=%p, thread=%s ***\33[0m\n",
        ptr, kind, end, (thread? "true": "false"));
    uint64_t sum = 0;
    TEST(sum += *end, NUM);
    TEST(sum += *(end-1), 0);
    TEST(sum += *(end-2), 0);
    TEST(sum += *(uint16_t *)end, NUM);
    TEST(sum += *(uint16_t *)(end-1), NUM);
    TEST(sum += *(uint16_t *)(end-2), 0);
    TEST(sum += *(uint16_t *)(end-3), 0);
    TEST(sum += *(uint32_t *)end, NUM);
    TEST(sum += *(uint32_t *)(end-1), NUM);
    TEST(sum += *(uint32_t *)(end-2), NUM);
    TEST(sum += *(uint32_t *)(end-3), NUM);
    TEST(sum += *(uint32_t *)(end-4), 0);
    TEST(sum += *(uint32_t *)(end-5), 0);
    TEST(sum += *(uint64_t *)end, NUM);
    TEST(sum += *(uint64_t *)(end-1), NUM);
    TEST(sum += *(uint64_t *)(end-2), NUM);
    TEST(sum += *(uint64_t *)(end-3), NUM);
    TEST(sum += *(uint64_t *)(end-4), NUM);
    TEST(sum += *(uint64_t *)(end-5), NUM);
    TEST(sum += *(uint64_t *)(end-6), NUM);
    TEST(sum += *(uint64_t *)(end-7), NUM);
    TEST(sum += *(uint64_t *)(end-8), 0);
    TEST(sum += *(uint64_t *)(end-9), 0);
    return sum;
}

static NOINLINE size_t testString(const char *str)
{
    const char *kind = getKind((void *)str);
    unsigned NUM = (lowfat_is_ptr(str)? 1: 0);
    printf("\n\33[35m*** STRING str=%p (%s), thread=%s ***\33[0m\n",
        str, kind, (thread? "true": "false"));
    size_t sum = 0;
    for (int i = 0; ; i++)
    {
        char c = false;
        TEST(c = str[i], 0);
        if (c == '\0')
            break;
        sum += c;
    }
    int len = (lowfat_is_ptr(str)? lowfat_size(str): 8);
    for (int i = -3, j = 0; i < len+3; i++, j++)
    {
        unsigned NUM2 = (i >= 0 && i < len? 0: NUM);
        TEST(buf[j] = str[i], NUM2);
    }
    return sum;
}

static void *worker(void *arg)
{
    uint32_t sum = 0;
    {
        const int SIZE = 8;
        uint8_t *xs = (uint8_t *)__libc_malloc(SIZE * sizeof(uint8_t));
        sum += testBuffer<uint8_t, SIZE>(xs);
        TEST_KIND(xs, nonfat);
        free(xs);
    }
    {
        const int SIZE = 4;
        uint16_t *xs = (uint16_t *)__libc_malloc(SIZE * sizeof(uint16_t));
        sum += testBuffer<uint16_t, SIZE>(xs);
        TEST_KIND(xs, nonfat);
        free(xs);
    }
    {
        const int SIZE = 4;
        uint32_t *xs = (uint32_t *)__libc_malloc(SIZE * sizeof(uint32_t));
        sum += testBuffer<uint32_t, SIZE>(xs);
        TEST_KIND(xs, nonfat);
        free(xs);
    }
    {
        const int SIZE = 4;
        uint64_t *xs = (uint64_t *)__libc_malloc(SIZE * sizeof(uint64_t));
        sum += testBuffer<uint64_t, SIZE>(xs);
        TEST_KIND(xs, nonfat);
        free(xs);
    }
    {
        const int SIZE = 8;
        uint8_t *xs = (uint8_t *)malloc(SIZE * sizeof(uint8_t));
        sum += testBuffer<uint8_t, SIZE>(xs);
        TEST_KIND(xs, heap);
        free(xs);
    }
    {
        const int SIZE = 4;
        uint16_t *xs = (uint16_t *)malloc(SIZE * sizeof(uint16_t));
        sum += testBuffer<uint16_t, SIZE>(xs);
        TEST_KIND(xs, heap);
        free(xs);
    }
    {
        const int SIZE = 4;
        uint32_t *xs = (uint32_t *)malloc(SIZE * sizeof(uint32_t));
        sum += testBuffer<uint32_t, SIZE>(xs);
        TEST_KIND(xs, heap);
        free(xs);
    }
    {
        const int SIZE = 4;
        uint64_t *xs = (uint64_t *)malloc(SIZE * sizeof(uint64_t));
        sum += testBuffer<uint64_t, SIZE>(xs);
        TEST_KIND(xs, heap);
        free(xs);
    }
    {
        const int SIZE = 8;
        uint8_t xs[SIZE];
        sum += testBuffer<uint8_t, SIZE>(xs);
        TEST_KIND(xs, stack);
    }
    {
        const int SIZE = 4;
        uint16_t xs[SIZE];
        sum += testBuffer<uint16_t, SIZE>(xs);
        TEST_KIND(xs, stack);
    }
    {
        const int SIZE = 4;
        uint32_t xs[SIZE];
        sum += testBuffer<uint32_t, SIZE>(xs);
        TEST_KIND(xs, stack);
    }
    {
        const int SIZE = 4;
        uint64_t xs[SIZE];
        sum += testBuffer<uint64_t, SIZE>(xs);
        TEST_KIND(xs, stack);
    }
#ifndef _LOWFAT_LEGACY
    {
        const int SIZE = 8;
        uint8_t xs[id(SIZE)];
        sum += testBuffer<uint8_t, SIZE>(xs);
        TEST_KIND(xs, stack);
    }
    {
        const int SIZE = 4;
        uint16_t xs[id(SIZE)];
        sum += testBuffer<uint16_t, SIZE>(xs);
        TEST_KIND(xs, stack);
    }
    {
        const int SIZE = 4;
        uint32_t xs[id(SIZE)];
        sum += testBuffer<uint32_t, SIZE>(xs);
        TEST_KIND(xs, stack);
    }
    {
        const int SIZE = 4;
        uint64_t xs[id(SIZE)];
        sum += testBuffer<uint64_t, SIZE>(xs);
        TEST_KIND(xs, stack);
    }
#endif
    {
        const int SIZE = 8;
        sum += testBuffer<uint8_t, SIZE>(global8xi8);
        TEST_KIND(global8xi8, global);
    }
    {
        const int SIZE = 4;
        sum += testBuffer<uint16_t, SIZE>(global4xi16);
        TEST_KIND(global4xi16, global);
    }
    {
        const int SIZE = 4;
        sum += testBuffer<uint32_t, SIZE>(global4xi32);
        TEST_KIND(global4xi32, global);
    }
    {
        const int SIZE = 4;
        sum += testBuffer<uint64_t, SIZE>(global4xi64);
        TEST_KIND(global4xi64, global);
    }
    {
        Test<uint32_t> *t = (Test<uint32_t> *)__libc_malloc(8);
        sum += testField<uint32_t>(*t);
        TEST_KIND(t, nonfat);
        free(t);
    }
    {
        Test<uint64_t> *t = (Test<uint64_t> *)__libc_malloc(8);
        sum += testField<uint64_t>(*t);
        TEST_KIND(t, nonfat);
        free(t);
    }
    {
        Test<uint32_t> *t = (Test<uint32_t> *)malloc(8);
        sum += testField<uint32_t>(*t);
        TEST_KIND(t, heap);
        free(t);
    }
    {
        Test<uint64_t> *t = (Test<uint64_t> *)malloc(8);
        sum += testField<uint64_t>(*t);
        TEST_KIND(t, heap);
        free(t);
    }
    {
        char tmp[8];
        Test<uint32_t> *t = (Test<uint32_t> *)tmp;
        sum += testField<uint32_t>(*t);
        TEST_KIND(t, stack);
    }
    {
        char tmp[8];
        Test<uint64_t> *t = (Test<uint64_t> *)tmp;
        sum += testField<uint64_t>(*t);
        TEST_KIND(t, stack);
    }
#ifndef _LOWFAT_LEGACY
    {
        char tmp[id(8)];
        Test<uint32_t> *t = (Test<uint32_t> *)tmp;
        sum += testField<uint32_t>(*t);
        TEST_KIND(t, stack);
    }
    {
        char tmp[id(8)];
        Test<uint64_t> *t = (Test<uint64_t> *)tmp;
        sum += testField<uint64_t>(*t);
        TEST_KIND(t, stack);
    }
#endif
    {
        Test<uint32_t> *t = (Test<uint32_t> *)&global8xi8;
        sum += testField<uint32_t>(*t);
        TEST_KIND(t, global);
    }
    {
        Test<uint64_t> *t = (Test<uint64_t> *)&global8xi8;
        sum += testField<uint64_t>(*t);
        TEST_KIND(t, global);
    }
    {
        void *ptr = __libc_malloc(8);
        sum += testEdge(ptr);
        TEST_KIND(ptr, nonfat);
        free(ptr);
    }
    {
        void *ptr = malloc(8);
        sum += testEdge(ptr);
        TEST_KIND(ptr, heap);
        free(ptr);
    }
    {
        char tmp[8];
        sum += testEdge((void *)tmp);
        TEST_KIND(tmp, stack);
    }
#ifndef _LOWFAT_LEGACY
    {
        char tmp[id(8)];
        sum += testEdge((void *)tmp);
        TEST_KIND(tmp, stack);
    }
#endif
    {
        sum += testEdge((void *)global8xi8);
        TEST_KIND(global8xi8, global);
    }
    {
        char *str = (char *)__libc_malloc(15);
        strcpy(str, "Hello World!");
        sum += testString(str);
        TEST_KIND(str, nonfat);
        free(str);
    }
    {
        char *str = (char *)malloc(15);
        strcpy(str, "Hello World!");
        sum += testString(str);
        TEST_KIND(str, heap);
        free(str);
    }
    {
        char str[] = "Hello World!";
        sum += testString(str);
        TEST_KIND(str, stack);
    }
    {
        const char *str = "Hello World!";
        sum += testString(str);
        TEST_KIND(str, global);
    }

    return (void *)(uintptr_t)sum;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--show-errors") == 0)
        /*NOP*/;
    else if (argc != 1)
    {
        fprintf(stderr, "usage: %s [--show-errors]\n", argv[0]);
        return EXIT_FAILURE;
    }
    else
    {
        if (freopen("/dev/null", "w", stderr) == NULL)
        {
            printf("error: failed to redirect stderr\n");
            return EXIT_FAILURE;
        }
    }

    pid_t pid = fork();
    if (pid != 0)
    {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        else
            return EXIT_FAILURE;
    }
    else if (pid < 0)
    {
        printf("error: fork failed\n");
        return EXIT_FAILURE;
    }

    // Create space for under/overflows:
    for (int n = 1; n <= 512; n += 16)
    {
        void **ptrs = (void **)buf;
        const int SIZE = 10;
        for (int i = 0; i < SIZE; i++)
        {
            ptrs[i] = malloc(n);
        }
        for (int i = SIZE/2; i < SIZE; i++)
        {
            free(ptrs[i]);
        }
    }

    worker(nullptr);
    thread = true;
    pthread_t thread;
    int err = pthread_create(&thread, NULL, worker, NULL);
    if (err != 0)
    {
        printf("error: pthread_create failed\n");
        return EXIT_FAILURE;
    }
    err = pthread_join(thread, NULL);
    if (err != 0)
    {
        printf("error: pthread_join failed\n");
        return EXIT_FAILURE;
    }

    printf("\n\33[1;35mpassed\33[0m: (%zu/%zu) = \33[1m%.2f%%\33[0m\n\n",
        passed, total, ((double)passed / (double)total) * 100.0);

    return (passed == total? EXIT_SUCCESS: EXIT_FAILURE);
}

