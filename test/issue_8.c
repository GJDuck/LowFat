/*
 * Test program for #8 (https://github.com/GJDuck/LowFat/issues/8)
 *
 * Usage:
 *  $ clang -o issue_8 -O2 -fsanitize=lowfat issue_8.c
 *  $ ./issue_8
 * The program should print an OOB error (write).
 */

static __attribute__((__noinline__)) void copy(char *dst, const char *src)
{
    while (*src)
        *dst++ = *src++;
    *dst++ = '\0';
}

int main(int argc, char **argv)
{
    static char dst[15];
    static char src[] = "This is a looooooooooooooooooooooooooong string...";
    copy(dst, src);
    return 0;
}




