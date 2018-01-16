/*
 * Test program for #2 (https://github.com/GJDuck/LowFat/issues/2)
 *
 * Usage:
 *  $ clang -o issue_2 -O2 -fsanitize=lowfat issue_2.c
 *  $ ./issue_2
 * The program should abort with a OOB-read error.
 */

#include <stdio.h>
#include <stdlib.h>

__attribute__((__noinline__)) void foo(int *p, int i)
{
    p[i]++;
}

int main(int argc, char **argv)
{
    int a[100] = {0};
    int b[100] = {0};
    int i = (int)(a - b);
    if (argc >= 2)
        i = atoi(argv[1]);

    printf("i = %d\n", i);
    printf("distance = %ld\n", a - b);

    printf("a[0] = %d\n", a[0]);
    printf("b[0] = %d\n", b[0]);

    foo(b, i);

    printf("a[0] = %d\n", a[0]);
    printf("b[0] = %d\n", b[0]);

    return 0;
}
