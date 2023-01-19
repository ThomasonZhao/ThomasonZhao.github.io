---
title: 6.S081 Lab1 Xv6 and Unix utilities
date: 2023-01-05 21:43:44
category: Independent Learning
tags:
  - MIT 6.S081
---

## Boot xv6 (easy)

We will be using [qemu](https://www.qemu.org/) to emulate our xv6 kernel. Luckily, the `Makefile` has already setup everything for us. Once we clone the repo and follow the instructions to find correct branch. Then we are good to go. 

## sleep (easy)

Just a simple sleep program to hang the process for a user-specified number of ticks through command line argument. Use `sleep` system call will be able to handle this. 

```c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main(int argc, char const *argv[])
{
    int time;

    if (argc != 2)
    {
        fprintf(2, "Usage: %s [TIME]\n", argv[0]);
        exit(1);
    }

    time = atoi(argv[1]);
    sleep(time);

    exit(0);
}
```

> Don't forget to add new user program in the `Makefile`'s `UPROGS` variable

## pingpong (easy)

This section is to get us familiar with `fork` and `pipe` syscall and use pipe to communicate with different processes. We could refer the man page of Linux syscall (or just read the kernel source code). 

```c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main(int argc, char *argv[])
{
    int pid, cpid;
    int pipefd[2];
    char buf[2];
    char *msg = " ";

    if (pipe(pipefd) < 0)
    {
        fprintf(2, "pipe error!\n");
        exit(1);
    }

    if ((cpid = fork()) < 0)
    {
        fprintf(2, "fork error!\n");
        exit(1);
    }
    else if (cpid == 0)
    { /* Child */
        pid = getpid();

        if (read(pipefd[0], buf, 1) != 1)
        {
            fprintf(2, "fail to read in child!\n");
            exit(1);
        }
        close(pipefd[0]);

        printf("%d: received ping\n", pid);

        if (write(pipefd[1], buf, 1) != 1)
        {
            fprintf(2, "fail to write in child!\n");
            exit(1);
        }
        close(pipefd[1]);

        exit(0);
    }
    else
    { /* Parent */
        pid = getpid();

        if (write(pipefd[1], msg, 1) != 1)
        {
            fprintf(2, "fail to write in parent!\n");
            exit(1);
        }
        close(pipefd[1]);

        /* Wait for child to terminate */
        wait(0);

        if (read(pipefd[0], buf, 1) != 1)
        {
            fprintf(2, "fail to read in parent!\n");
            exit(1);
        }
        close(pipefd[0]);

        printf("%d: received pong\n", pid);

        exit(0);
    }
}
```

> Don't forget to check all the return code of all your syscalls!

## primes (moderate)/(hard)

The hardest part in this lab. We need to write a concurrent program (by forking child process) to sieve the prime numbers. The core part is to understand the graph below:

![prime sieve](https://swtch.com/~rsc/thread/sieve.gif)

Each process should sieve out the multiple of the prime number it is priting. It is easy to make us think aobut recurrance relation to fork and sieve processes because each process basically follow the same logic. 

```c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define START 2
#define END 35

void primes(int *pipefd1)
{
    int prime, num, pid;
    int pipefd2[2]; /* Another pipe for child */

    /* Child don't need to write */
    close(pipefd1[1]);

    if (read(pipefd1[0], &prime, sizeof(int)) != sizeof(int))
    {
        fprintf(2, "fail to read!\n");
        exit(1);
    }

    printf("prime %d\n", prime);

    /* Make sure what we read is not the last one */
    if (read(pipefd1[0], &num, sizeof(int)) > 0)
    {
        if (pipe(pipefd2) < 0)
        {
            fprintf(2, "pipe error!\n");
            exit(1);
        }

        if ((pid = fork()) < 0)
        {
            fprintf(2, "fork error!\n");
            exit(1);
        }
        else if (pid == 0)
        { /* Child */
            primes(pipefd2);
        }
        else
        { /* Parent */
            /* Parent don't need to read */
            close(pipefd2[0]);

            do
            {
                if (num % prime != 0)
                    write(pipefd2[1], &num, sizeof(int));
            } while (read(pipefd1[0], &num, sizeof(int)) > 0);

            close(pipefd1[0]);
            close(pipefd2[1]);
            wait(0);
        }
    }
    exit(0);
}

int main(int argc, char const *argv[])
{
    int pid;
    int pipefd[2];

    if (pipe(pipefd) < 0)
    {
        fprintf(2, "pipe error!\n");
        exit(1);
    }

    if ((pid = fork()) < 0)
    {
        fprintf(2, "fork error!\n");
        exit(1);
    }
    else if (pid == 0)
    { /* Child */
        primes(pipefd);
    }
    else
    { /* Parent */
        /* Parent don't need to read */
        close(pipefd[0]);

        for (int i = START; i <= END; i++)
        {
            if (write(pipefd[1], &i, sizeof(int)) != sizeof(int))
            {
                fprintf(2, "fail to write!\n");
                exit(1);
            }
        }

        close(pipefd[1]);
        wait(0);
    }

    exit(0);
}
```

## find (moderate)

This part require us to understand how to manipulate files through syscalls, `fstat`, `read`. We could reference `user/ls.c`. Once we reach a directory, recursively call `find` function to find that directory. 

```c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fs.h"
#include "user/user.h"

char *fmtname(char *path)
{
    static char buf[DIRSIZ + 1];
    char *p;

    // Find first character after last slash.
    for (p = path + strlen(path); p >= path && *p != '/'; p--)
        ;
    p++;

    // Return blank-padded name.
    if (strlen(p) >= DIRSIZ)
        return p;
    memmove(buf, p, strlen(p));
    memset(buf + strlen(p), ' ', DIRSIZ - strlen(p));
    return buf;
}

void find(char *path, char *filename)
{
    char buf[512], *p;
    int fd;
    struct dirent de;
    struct stat st;

    if ((fd = open(path, 0)) < 0)
    {
        fprintf(2, "find: cannot open %s\n", path);
        exit(1);
    }

    if (fstat(fd, &st) < 0)
    {
        fprintf(2, "find: cannot stat %s\n", path);
        close(fd);
        exit(1);
    }

    switch (st.type)
    {
    case T_FILE:
        fprintf(2, "Usage: find [DIR] [FILENAME]\n");
        exit(1);

    case T_DIR:
        if (strlen(path) + 1 + DIRSIZ + 1 > sizeof buf)
        {
            printf("find: path too long\n");
            close(fd);
            exit(1);
        }

        strcpy(buf, path);
        p = buf + strlen(buf);
        if (*(p - 1) != '/')
            *p++ = '/';

        while (read(fd, &de, sizeof(de)) == sizeof(de))
        {
            if (de.inum == 0 ||
                strcmp(de.name, ".") == 0 ||
                strcmp(de.name, "..") == 0)
                continue;

            memmove(p, de.name, DIRSIZ);
            p[DIRSIZ] = 0;
            if (stat(buf, &st) < 0)
            {
                printf("find: cannot stat %s\n", buf);
                continue;
            }

            switch (st.type)
            {
            case T_FILE:
                if (strcmp(de.name, filename) == 0)
                    printf("%s\n", buf);
                break;

            case T_DIR:
                find(buf, filename);
                break;
            }
        }
        break;
    }

    close(fd);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(2, "Usage: %s [DIR] [FILENAME]\n", argv[0]);
        exit(1);
    }

    find(argv[1], argv[2]);

    exit(0);
}
```

## xargs (moderate)

We want to make a simpler version of UNIX `xargs` program by providing the initial arguments for the program and use `stdin` to read additional arguments and append new arguments to the initial arguments and `fork` `exec` the program. 

```c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/param.h"
#include "user/user.h"

/* Maxinum character a line could have */
#define MAXLINE 1024

char *readline(void)
{
    int i, cc;
    char c;
    char *buf;

    buf = malloc(MAXLINE);
    if (buf == 0)
    {
        return 0;
    }

    for (i = 0; i + 1 < MAXLINE;)
    {
        cc = read(0, &c, 1);
        if (cc < 0)
        {
            fprintf(2, "read error!\n");
            exit(1);
        }
        if (cc == 0)
        { /* Nothing read in */
            free(buf);
            return 0;
        }

        if (c == '\n' || c == '\r')
            break;

        buf[i++] = c;
    }

    buf[i] = '\0';
    return buf;
}

int main(int argc, char const *argv[])
{
    char *new_argv[MAXARG], *buf;
    int i, pid;

    if (argc < 2)
    {
        fprintf(2, "Usage: %s [command [initial-arguments]]\n", argv[0]);
        exit(1);
    }

    for (i = 0; i < argc; i++)
    {
        new_argv[i - 1] = malloc(strlen(argv[i]) + 1);
        strcpy(new_argv[i - 1], argv[i]);
    }

    while ((buf = readline()) != 0)
    {
        new_argv[i - 1] = buf;
        new_argv[i] = 0; /* Null termination */

        if ((pid = fork()) < 0)
        {
            fprintf(2, "fork error!\n");
            exit(1);
        }
        else if (pid == 0)
        { /* Child */
            exec(new_argv[0], new_argv);
            fprintf(2, "exec error!\n");
            exit(1);
        }
        else
        { /* Parent */
            wait(0);
        }
    }

    exit(0);
}
```
