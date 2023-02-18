---
title: 'Paper Review: The UNIX Time-Sharing System'
date: 2023-02-13 23:40:37
category: Academic Paper
tags:
    - OS
    - Unix
---

The contents of this blog are primarily my paper review homework for the honor section of the CS537 Operating System course at UW-Madison. But those papers deserve us to spend time reviewing them. In this paper, for example, you could get a glimpse of the modern large operating system's prototype and how it is designed and implemented. So, let's get started!

## Overview & Background

[Unix](https://en.wikipedia.org/wiki/Unix) is a family of multitasking, multiuser computer operating systems that derive from the original AT&T Unix, whose development started in 1969 at the Bell Labs research center by Ken Thompson, Dennis Ritchie, and others.

The paper "The UNIX Time-Sharing System" by D. M. Ritchie and K. Thompson, published in the Communications of the ACM in 1974, reveals the development and design of the Unix operating system. It describes Unix as a time-sharing system, meaning that multiple users can interact with the computer simultaneously and share its resources. The authors aim to present Unix as a more efficient and practical alternative to other existing time-sharing systems.

## Introduction

The paper begins by discussing the current situation of Unix and the hardware and software environment that Unix presents. There have been three versions of Unix before presenting this paper. They are mainly used for research in operating systems, languages, computer networks, and other computer science topics and document preparation in the Bell Labs. 

The third version of Unix is rewritten in C programming language and supports various programs like assembler, text editor based on QED, linking loader, symbolic debugger, the compiler for a language resembling BCPL with types and structures (C), interpreter for a dialect of BASIC, text formatting program, Fortran compiler, Snobol interpreter, top-down compiler-compiler (TMC), bottom-up compiler-compiler (YACC), form letter generator, macro processor (M6), and permuted index program.

> It is hoped, however, the users of UNIX will find that the most important characteristics of the system are its simplicity, elegance, and ease of use.

## File System

Then, the paper describes the design of Unix, starting with the features and detailed implementation of its file system. It divides the storage type into three different categories: ordinary files, directories, and special files. The system will provide protection for every file to make sure no user is doing something unwanted. 

Ordinary files are just normal files that users generally use, for example, text files and executable binary files. It also supports links, which allow multiple names to refer to a single file. This design makes it easy for users to navigate, organize, and share their files. 

Directories make the file system hierarchical. It organizes files in a tree-like structure. All files could be found by tracing the path through a chain of directories. The *root* directory `/`, however, which the system maintained for its own use, is the origin of all other directories. It defines that each directory has at least two entries: `.` represent the current directory, and `..` represent the parent directory. 

Special files are abstractions provided by the operating system. It abstracts I/O devices as special files allowing users to treat I/O devices in the same way as regular files. It also makes it straightforward to mount a new file system from other drive devices to the machine.

With the file system abstraction above, manipulating I/O requests are relatively easy for the user to make. Unix provides four main system calls: `open`, `close`, `read`, and `write`. They allow users to treat every file as a file descriptor, which also abstract by the operating system, and manipulate the data very easily, even if they are I/O devices! 

## Process Management

In the following section, the paper describes the processes and images in Unix, which is responsible for managing the execution of programs. The processes in Unix are supported by different system routines, which makes processes can be easily created, executed, terminated, and communicated with each other. This makes it easy for users to run multiple programs simultaneously and switch between them as needed.

The operating system maintains an image for every process. It includes a core image, general register values, the status of open files, the current directory, and the like. An image is the current state of a pseudo-computer. The core here is an early saying of the Unix kernel. 

Users could easily create processes by calling `fork` system call, which creates a new process with a copy of the current process's image. With another powerful system call `execute`, users may run any program in this newly created process. 

Pipe is also an important feature which allows processes to communicate with each other without continue using `read` and `write` to do expensive I/O on the same file. This channel, like other open files, is passed from parent to child process in the image by the fork call. A read using a pipe file descriptor waits until another process writes using the file descriptor for the same pipe. 

Ternimation of a process is relatively easy. With `exit` system call, the operating system terminates a process, destroys its image, closes its open files, and generally obliterates it. When the parent is notified through the `wait` primitive, the indicated status is available to the parent;

## Unix Shell

On top of the process management feature, the paper describes the ideas and implementations of the shell, which is the interface between the user and the operating system. The shell allows users to enter commands executed by the operating system. With the essential system calls described in the previous section, the shell could easily fork children, do I/O redirection to any files, pipe communication between different processes, or decide a process to run in the background or foreground. 

Another essential feature is the idea of the "init" daemon process, which is created when the system boots and acts as the parent of all processes. It only wakes up when users log in through the typewriter channel. It first forks itself and sets up the standard in, out, and error descriptor, then transfer control to the user by executing the shell program.

## Trap / System Call

Furthermore, the paper introduces the idea of traps. Rather than call them "traps," I prefer to call them "signals" directly. The paper presents an operating system prototype using signals to interact and manipulate the processes. In this design, the operating system will control the process once a hardware interrupt, fault, or specific signal is received. It will treat the process differently based on the fault type or signal type.

## Summary

Finally, the paper concludes by summarizing the strengths of Unix and how it compares to other time-sharing systems. They explain that Unix is a simple, flexible, and efficient time-sharing system for programmers to use and maintain itself.

Overall, the paper provides a comprehensive overview of the design and implementation of the Unix operating system. The authors effectively explain the critical features of Unix and why it is a more efficient and practical alternative to other time-sharing systems.

## Reference

O. M. Ritchie and K. Thompson, "The UNIX time-sharing system," in *The Bell System Technical Journal*, vol. 57, no. 6, pp. 1905-1929, July-Aug. 1978, doi: 10.1002/j.1538-7305.1978.tb02136.x.

PDF: https://dsf.berkeley.edu/cs262/unix.pdf
