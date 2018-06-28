/*
 *   _|                                      _|_|_|_|            _|
 *   _|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
 *   _|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
 *   _|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
 *   _|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|
 * 
 * Gregory J. Duck.
 *
 * Copyright (c) 2018 The National University of Singapore.
 * All rights reserved.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See the LICENSE file for details.
 */

#include <stddef.h>

#ifdef LOWFAT_NO_THREADS

typedef int lowfat_mutex_t;

static inline bool lowfat_mutex_init(lowfat_mutex_t *mutex)
{
    return true;
}
static inline void lowfat_mutex_lock(lowfat_mutex_t *mutex)
{
    return;
}
static inline void lowfat_mutex_unlock(lowfat_mutex_t *mutex)
{
    return;
}

#elif defined(LOWFAT_WINDOWS)

typedef HANDLE lowfat_mutex_t;

static inline bool lowfat_mutex_init(lowfat_mutex_t *mutex)
{
    *mutex = CreateMutex(NULL, FALSE, NULL);
    return (*mutex != NULL);
}
static inline void lowfat_mutex_lock(lowfat_mutex_t *mutex)
{
    WaitForSingleObject(*mutex, INFINITE);
}
static inline void lowfat_mutex_unlock(lowfat_mutex_t *mutex)
{
    ReleaseMutex(*mutex);
}

#else   /* !LOWFAT_NO_THREADS && !LOWFAT_WINDOWS */

typedef pthread_mutex_t lowfat_mutex_t;

static inline bool lowfat_mutex_init(lowfat_mutex_t *mutex)
{
    return (pthread_mutex_init(mutex, NULL) == 0);
}
static inline void lowfat_mutex_lock(lowfat_mutex_t *mutex)
{
    pthread_mutex_lock(mutex);
}
static inline void lowfat_mutex_unlock(lowfat_mutex_t *mutex)
{
    pthread_mutex_unlock(mutex);
}

#endif  /* !LOWFAT_NO_THREADS && !LOWFAT_WINDOWS */

#ifndef LOWFAT_STANDALONE

#define LOWFAT_NUM_THREAD_STACKS                                            \
    (LOWFAT_STACK_MEMORY_SIZE / LOWFAT_STACK_SIZE)
#define LOWFAT_STACKS_START                                                 \
    ((void *)((LOWFAT_STACK_REGION * LOWFAT_REGION_SIZE) +                  \
        LOWFAT_STACK_MEMORY_OFFSET))
#define LOWFAT_STACK_GUARD         (32 * LOWFAT_PAGE_SIZE)

#define LOWFAT_STACK_BASE(ptr)                                              \
    ((void *)((const uint8_t *)(ptr) - ((uintptr_t)(ptr) % LOWFAT_STACK_SIZE)))

struct lowfat_stack_freelist_s
{
    pthread_t thread;
    struct lowfat_stack_freelist_s *next;
};

static LOWFAT_DATA size_t lowfat_stack_freeidx = 0;
static LOWFAT_DATA struct lowfat_stack_freelist_s *lowfat_stack_freelist = NULL;
static LOWFAT_DATA lowfat_mutex_t lowfat_stack_mutex;
static LOWFAT_DATA uint16_t lowfat_stack_perm[LOWFAT_NUM_THREAD_STACKS] = {0};

/*
 * Initialize lowfat thread handling.  Call after malloc init.
 */
static bool lowfat_threads_init(void)
{
    for (size_t i = 0; i < LOWFAT_NUM_THREAD_STACKS; i++)
        lowfat_stack_perm[i] = i;
    // Fisher-Yates shuffle:
    for (size_t i = LOWFAT_NUM_THREAD_STACKS-1; i > 0; i--)
    {
        uint16_t j;
        lowfat_rand(&j, sizeof(j));
        j = j % (i + 1);
        size_t tmp = lowfat_stack_perm[i];
        lowfat_stack_perm[i] = lowfat_stack_perm[j];
        lowfat_stack_perm[j] = tmp;
    }
    return lowfat_mutex_init(&lowfat_stack_mutex);
}

/*
 * Tests if the given thread is still alive or not.
 *
 * This is a horrible hack that depends on libpthread internals.
 * 
 * Assumptions:
 * - The `pthread_t' structure is allocated from the thread's stack itself,
 *   and thus will still "exist" even after the thread terminates.
 * - LOWFAT_TID_OFFSET is the offset of the `tid' field in a pthread_t
 * - LOWFAT_JOINID_OFFSET is the offset of the `joinid' field in a pthread_t
 * - When a thread terminates, the kernel zeroes the `tid'.
 * - When a terminated thread is joined, `tid' is set to (-1), and this is a
 *   final state.
 * - Else, if a thread is detached, then `joinid' will be set to `thread',
 *   thus (tid==0 && joinid==thread) is another final state.
 * - Any other state and the thread is still alive, or is waiting to be
 *   joined.
 *
 * NOTE: The magic constants LOWFAT_TID_OFFSET and LOWFAT_JOINID_OFFSET can
 *       be determined by disassembling the libpthread pthread_detach()
 *       function.
 */
static bool lowfat_is_thread_dead(pthread_t thread)
{
    pid_t *tid_ptr = (pid_t *)((uint8_t *)thread + LOWFAT_TID_OFFSET);
    pthread_t *joinid_ptr =
        (pthread_t *)((uint8_t *)thread + LOWFAT_JOINID_OFFSET);
    if (*tid_ptr > 0)
        return false;       // Thread is still active
    else if (*tid_ptr != 0)
        return true;        // Thread is dead + joined
    else if (*joinid_ptr == thread)
        return true;        // Thread is dead + detached
    else
        return false;       // Thread is a zombie waiting to be joined.
}
static void lowfat_force_thread_dead(pthread_t thread)
{
    pid_t *tid_ptr = (pid_t *)((uint8_t *)thread + LOWFAT_TID_OFFSET);
    *tid_ptr = -1;
}

/*
 * Allocate a new stack.
 */
static void *lowfat_stack_alloc(void)
{
    lowfat_mutex_lock(&lowfat_stack_mutex);

    // STEP (1): Search the freelist for a free stack:
    uint8_t *stack = NULL;
    struct lowfat_stack_freelist_s *prev = NULL;
    struct lowfat_stack_freelist_s *curr = lowfat_stack_freelist;
    while (curr != NULL)
    {
        if (lowfat_is_thread_dead(curr->thread))
        {
            if (prev != NULL)
                prev->next = curr->next;
            else
                lowfat_stack_freelist = curr->next;
            stack = (uint8_t *)LOWFAT_STACK_BASE(curr);
            lowfat_mutex_unlock(&lowfat_stack_mutex);
            return stack;
        }
        prev = curr;
        curr = curr->next;
    }

    // STEP (2): Else, allocate a new stack:
    if (lowfat_stack_freeidx >= LOWFAT_NUM_THREAD_STACKS)
    {
        lowfat_mutex_unlock(&lowfat_stack_mutex);
        errno = ENOMEM;
        return NULL;
    }
    size_t stack_idx = lowfat_stack_freeidx;
    lowfat_stack_freeidx++;

    lowfat_mutex_unlock(&lowfat_stack_mutex);
    
    stack_idx = lowfat_stack_perm[stack_idx];
    stack = (uint8_t *)LOWFAT_STACKS_START + stack_idx * LOWFAT_STACK_SIZE;
    uint8_t *stack_lo = stack + LOWFAT_STACK_GUARD;
    uint8_t *stack_hi = stack + LOWFAT_STACK_SIZE;
    size_t idx;
    for (size_t i = 0; (idx = lowfat_stacks[i]) != 0; i++)
    {
        ptrdiff_t diff = (uint8_t *)lowfat_region(LOWFAT_STACK_REGION) -
            (uint8_t *)lowfat_region(idx);
        if (mprotect(stack_lo - diff, stack_hi - stack_lo,
                PROT_READ | PROT_WRITE) != 0)
            return NULL;
    }

    return stack;
}

#ifndef LOWFAT_NO_THREADS

/*
 * Deallocate an old stack (used by `thread').  Note: the stack is not truely
 * deallocated until `thread' exits.
 * NOTE: the pthreads library will already madvise DONT_NEED the stack memory.
 */
static void lowfat_stack_free(pthread_t thread)
{
    uint8_t *nptr = (uint8_t *)LOWFAT_STACK_BASE(thread);
    nptr += LOWFAT_STACK_SIZE - sizeof(struct lowfat_stack_freelist_s);
    struct lowfat_stack_freelist_s *node =
        (struct lowfat_stack_freelist_s *)nptr;
    node->thread = thread;
    lowfat_mutex_lock(&lowfat_stack_mutex);
    node->next = lowfat_stack_freelist;
    lowfat_stack_freelist = node;
    lowfat_mutex_unlock(&lowfat_stack_mutex);
}

/*
 * This is called if/when pthread_create() fails and "thread" does not exist.
 * It creates a fake thread that is "dead" so the stack can be reused.
 */
static void lowfat_force_stack_free(void *stack)
{
    uint8_t *ptr = LOWFAT_STACK_BASE(stack);
    ptr += LOWFAT_STACK_SIZE - LOWFAT_PAGE_SIZE;
    pthread_t fake_thread = (pthread_t)ptr;
    lowfat_force_thread_dead(fake_thread);
    lowfat_stack_free(fake_thread);
}

/*
 * LOWFAT pthread_create()
 */
extern int lowfat_pthread_create(pthread_t *thread,
    const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)
    LOWFAT_ALIAS("pthread_create");
typedef int (*pthread_create_t)(pthread_t *, const pthread_attr_t *,
    void *(*)(void *), void *);
extern int pthread_create(pthread_t *thread,
    const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)
{
    static pthread_create_t real_pthread_create = NULL;
    if (real_pthread_create == NULL)
    {
        lowfat_mutex_init(&lowfat_stack_mutex);
        real_pthread_create =
            (pthread_create_t)dlsym(RTLD_NEXT, "pthread_create");
        if (real_pthread_create == NULL ||
                real_pthread_create == pthread_create)
            lowfat_error("failed to find pthread_create");
    }

    void *stack;
    size_t stack_size;
    pthread_attr_t newattr;
    int err;
    if (attr != NULL)
    {
        err = pthread_attr_getstack(attr, &stack, &stack_size);
        if (err != 0)
            lowfat_error("pthread_attr_getstack failed: %s", strerror(err));
        if (stack != NULL || stack_size != 0)
            lowfat_warning("custom pthread stack will be replaced with a "
                "lowfat stack");
        memcpy(&newattr, attr, sizeof(newattr));
    }
    else
    {
        err = pthread_attr_init(&newattr);
        if (err != 0)
            lowfat_error("pthread_attr_init failed: %s", strerror(errno));
    }

    stack = lowfat_stack_alloc();
    if (stack == NULL)
        lowfat_error("failed to allocate stack for new thread");
    stack_size = LOWFAT_STACK_SIZE - sizeof(struct lowfat_stack_freelist_s);

    err = pthread_attr_setstack(&newattr, stack, stack_size);
    if (err != 0)
        lowfat_error("pthread_attr_setstack failed: %s", strerror(err));

    err = real_pthread_create(thread, &newattr, start_routine, arg);
    if (err != 0)
    {
        lowfat_force_stack_free(stack);
        return err;
    }
    lowfat_stack_free(*thread);     // "Free" the stack.  It is not really
                                    // free until the thread terminates & is
                                    // joined (if applicable).

    return err;
}

#endif  /* LOWFAT_NO_THREADS */

#else   /* LOWFAT_STANDALONE */

#define lowfat_threads_init()   true

#endif  /* LOWFAT_STANDALONE */

