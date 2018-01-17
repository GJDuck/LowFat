/*
 * Test program for #6 (https://github.com/GJDuck/LowFat/issues/6)
 *
 * Usage:
 *  $ build sizes2.cfg 32
 *  $ clang -o issue_6 -O2 -fsanitize=lowfat issue_6.c
 *  $ ./issue_6
 * The program should print "1 2 1 2 1 2".
 */

#include <stdio.h>
#include <stdlib.h>

char g1[15];
char g2[31];

int main()
{
    char l1[15];
    char l2[31];
    
    char *h1 = malloc(15);
    char *h2 = malloc(31);
    
    printf("%ld ", (long)l1 >> 35);
    printf("%ld ", (long)l2 >> 35);
    printf("%ld ", (long)g1 >> 35);
    printf("%ld ", (long)g2 >> 35);
    printf("%ld ", (long)h1 >> 35);
    printf("%ld\n", (long)h2 >> 35);
    
    return 0;
}
