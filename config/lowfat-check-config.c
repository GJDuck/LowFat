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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "lowfat_config.c"

void *worker(void *arg)
{
    pthread_t thread = pthread_self();
    pid_t tid = syscall(SYS_gettid);
    pid_t *tid_ptr = (pid_t *)((uint8_t *)thread + LOWFAT_TID_OFFSET);
    if (tid != *tid_ptr)
    {
        fprintf(stderr, "error: thread-id offset (0x%x) is wrong!\n",
            LOWFAT_TID_OFFSET);
        exit(EXIT_FAILURE);
    }
    while (true)
        sleep(1);
}

int main(int argc, char **argv)
{
    pthread_t thread;
    int err = pthread_create(&thread, NULL, worker, NULL);
    if (err != 0)
    {
        fprintf(stderr, "error: failed to create a thread (err=%d)\n", err);
        exit(EXIT_FAILURE);
    }
    err = pthread_detach(thread);
    if (err != 0)
    {
        fprintf(stderr, "error: failed to detach thread (err=%d)\n", err);
        exit(EXIT_FAILURE);
    }
    pthread_t *joinid_ptr =
        (pthread_t *)((uint8_t *)thread + LOWFAT_JOINID_OFFSET);
    if (*joinid_ptr != thread)
    {
        fprintf(stderr, "error: joinid offset (0x%x) is wrong!\n",
            LOWFAT_JOINID_OFFSET);
        exit(EXIT_FAILURE);
    }

    printf("OK\n");
    return 0;
}

