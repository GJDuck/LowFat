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

#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

struct lowfat_fork_info
{
    pthread_mutex_t mutex;
    pthread_cond_t condvar;
    bool done;
    void *stack;
    jmp_buf env;
};

/*
 * Fork wrapper explicitly copies the call stack for the child process.
 */
static int lowfat_fork_child_wrapper(void *arg)
{
    struct lowfat_fork_info *info = (struct lowfat_fork_info *)arg;

    // STEP (0): Reset the RNG:
    lowfat_seed_pos = LOWFAT_PAGE_SIZE;

    // STEP (1): Create a new shared memory object:
    int fd = lowfat_create_shm(LOWFAT_STACK_MEMORY_SIZE);
    size_t idx = lowfat_stacks[0];
    uint8_t *stack_lo = (uint8_t *)lowfat_region(idx) +
        LOWFAT_STACK_MEMORY_OFFSET;
    const int prot = PROT_NONE;
    const int flags = MAP_SHARED | MAP_FIXED | MAP_NORESERVE;
    void *ptr = mmap(stack_lo, LOWFAT_STACK_MEMORY_SIZE, prot, flags,
        fd, 0);
    if (ptr != stack_lo)
    {
        pthread_mutex_lock(&info->mutex);
        info->done = false;
        pthread_cond_signal(&info->condvar);
        pthread_mutex_unlock(&info->mutex);
        mmap_error:
        lowfat_error("failed to mmap memory: %s", strerror(errno));
    }

    // STEP (2): Copy the stack memory:
    uint8_t *copy_lo = (uint8_t *)LOWFAT_PAGES_BASE(info->stack);
    uint8_t *copy_hi = (uint8_t *)LOWFAT_STACK_BASE(info->stack) +
        LOWFAT_STACK_SIZE;
    ptrdiff_t offset = copy_lo - (uint8_t *)LOWFAT_STACKS_START;
    stack_lo = stack_lo + offset;
    uint8_t *stack_hi = (uint8_t *)LOWFAT_STACK_BASE(stack_lo) +
        LOWFAT_STACK_SIZE;
    uint8_t *prot_lo = stack_hi - LOWFAT_STACK_SIZE + LOWFAT_STACK_GUARD;
    if (mprotect(prot_lo, stack_hi - prot_lo, PROT_READ | PROT_WRITE) != 0)
    {
        pthread_mutex_lock(&info->mutex);
        info->done = false;
        pthread_cond_signal(&info->condvar);
        pthread_mutex_unlock(&info->mutex);
        mprotect_error:
        lowfat_error("failed to protect memory: %s", strerror(errno));
    }
    memcpy(stack_lo, copy_lo, copy_hi - copy_lo);

    // STEP (2a): Copy is complete; wake up parent.
    pthread_mutex_lock(&info->mutex);
    info->done = true;
    pthread_cond_signal(&info->condvar);
    pthread_mutex_unlock(&info->mutex);

    // STEP (3): Map the remaining stacks:
    for (size_t i = 1; (idx = lowfat_stacks[i]) != 0; i++)
    {
        uint8_t *stack_lo = (uint8_t *)lowfat_region(idx) +
            LOWFAT_STACK_MEMORY_OFFSET;
        const int prot = PROT_NONE;
        const int flags = MAP_SHARED | MAP_FIXED | MAP_NORESERVE;
        void *ptr = mmap(stack_lo, LOWFAT_STACK_MEMORY_SIZE, prot, flags,
            fd, 0);
        if ((uint8_t *)ptr != stack_lo)
            goto mmap_error;
        stack_lo = stack_lo + offset;
        uint8_t *stack_hi = (uint8_t *)LOWFAT_STACK_BASE(stack_lo) +
            LOWFAT_STACK_SIZE;
        uint8_t *prot_lo = stack_hi - LOWFAT_STACK_SIZE + LOWFAT_STACK_GUARD;
        if (mprotect(prot_lo, stack_hi - prot_lo, PROT_READ | PROT_WRITE) != 0)
            goto mprotect_error;
    }
    if (close(fd) != 0)
        lowfat_error("failed to close object: %s", strerror(errno));

    // STEP (4): Resume normal execution (in the child):
    longjmp(info->env, true);
}

/*
 * Wraps the fork() (a.k.a. clone()) call to protect the stack for copying.
 */
static LOWFAT_NOINLINE pid_t lowfat_fork_wrapper(void *stack_tmp,
    size_t stack_tmp_size, struct lowfat_fork_info *info)
{
    pthread_mutexattr_t mattr;
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&info->mutex, &mattr);
    pthread_condattr_t cattr;
    pthread_condattr_init(&cattr);
    pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
    pthread_cond_init(&info->condvar, &cattr);
    info->done = false;
    info->stack = __builtin_frame_address(0);

    void *stack_tmp_ptr = (uint8_t *)stack_tmp + stack_tmp_size -
        sizeof(__int128) - sizeof(struct lowfat_fork_info);

    pid_t pid = clone(lowfat_fork_child_wrapper, stack_tmp_ptr, SIGCHLD, info);
    pthread_mutex_lock(&info->mutex);
    pthread_cond_wait(&info->condvar, &info->mutex);
    bool done = info->done;
    pthread_mutex_unlock(&info->mutex);

    pthread_mutex_destroy(&info->mutex);
    pthread_mutexattr_destroy(&mattr);
    pthread_cond_destroy(&info->condvar);
    pthread_condattr_destroy(&cattr);
    if (munmap(stack_tmp, stack_tmp_size) != 0)
        lowfat_error("failed to unmap memory: %s", strerror(errno));

    if (!done)
    {
        waitpid(pid, NULL, 0);
        errno = ECHILD;
        return -1;
    }
    return pid;
}

/*
 * LOWFAT fork()
 */
extern pid_t fork(void) LOWFAT_ALIAS("lowfat_fork");
extern pid_t lowfat_fork(void)
{
    // STEP (1): Create a temporary stack for the child:
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_SHARED | MAP_NORESERVE | MAP_ANONYMOUS;
    size_t stack_tmp_size = 4 * LOWFAT_PAGE_SIZE;      // 4 pages
    void *stack_tmp = mmap(NULL, stack_tmp_size, prot, flags, -1, 0);
    if (stack_tmp == MAP_FAILED)
        lowfat_error("failed to allocate new stack: %s", strerror(errno));

    // STEP (2): The child returns here:
    struct lowfat_fork_info *info =
        (struct lowfat_fork_info *)((uint8_t *)stack_tmp + stack_tmp_size -
            sizeof(struct lowfat_fork_info));
    if (setjmp(info->env))
    {
        if (munmap(stack_tmp, stack_tmp_size) != 0)
            lowfat_error("failed to unmap memory: %s", strerror(errno));
        return 0;
    }

    // STEP (3): Clone the current process:
    return lowfat_fork_wrapper(stack_tmp, stack_tmp_size, info);
}

