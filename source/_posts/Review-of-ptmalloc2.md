---
title: Review of ptmalloc2
date: 2023-02-18 17:22:32
category: Independent Learning
tags:
    - GNU C Library
---

Since we are done with our own dynamic memory allocator in the [malloc lab](https://thomasonzhao.cn/2023/01/03/CSAPP-malloclab/) a while ago, it's good to look at the real one used in GNU C Library (glibc): `ptmalloc2`. It will help us better understand how real world allocator worked compare to our simple naive allocator. But I have to admit that the lab is designed so well so that we could make it really close to the real world allocator if we spend two more weeks in this lab to optimize the performace.  

## Allocator Overview

There are varies dynamic memory allocator in use. Alough every allocators claim they are fast and general use allocators, not all allocator could fit your application. Or in other words, each of them have slightly different implementations which may have different performance issues. But in this blog, we will only talk about glibc allocator `ptmalloc2`

```
dlmalloc  – General purpose allocator
ptmalloc2 – glibc
jemalloc  – FreeBSD and Firefox
tcmalloc  – Google
libumem   – Solaris
```

`ptmalloc2` was forked form `dlmalloc`. After fork, multi-thread concurrent allocation support was added to it and released at 2006. After the official release, `ptmalloc2` was integrated/merged into glibc source code. Since then, code changes were made directly to glibc malloc source code itself. 

## Heap

Generally speaking, heap is a part of memory (or a memory segment) that avaliable for program to dynamically allocate or free. Many run time data structures are stored in the heap because their size is highly depend on run time workload. In the context of currency, each thread will have their own heap managed by the heap allocator so threads will not interupt each other when allocating memory.

There are two ways to ask operating system for more heap space: `brk&sbrk` and `mmap`. The details of these two system calls can be found on their man page: [brk&sbrk](https://man7.org/linux/man-pages/man2/sbrk.2.html) and [mmap](https://man7.org/linux/man-pages/man2/mmap.2.html). 

Specifically, in `ptmalloc2`'s data structure, heap usually indicate a part of contiguous memory containing `malloc_chunk`. `heap_info` indicates the start of a heap, or a heap header. It contains all the information for this part of contiguous blocks of memory. 

```c
/* A heap is a single contiguous memory region holding (coalesceable)
   malloc_chunks.  It is allocated with mmap() and always starts at an
   address aligned to HEAP_MAX_SIZE.  */

typedef struct _heap_info
{
  mstate ar_ptr; /* Arena for this heap. */
  struct _heap_info *prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size; /* Size in bytes that has been mprotected
                           PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;
```

## Arena

Arena contains the information for a heap allocation of a thread (could be main thread or any other thread) or process, for example, information about bins, top chunk, last remainder chunk... There are two different arena used in `ptmalloc2`: `main_arena` and `non_main_arena`, also mean `thread_arena`. 

Each arena is connected by a circular linked list. They use mutex lock to ensure that only one thread will be access this arena. When a thread call `malloc` to allocate memory, `ptmalloc2` will first check if that thread already have an arena. If it does have its own thread arena, it will try to access that arena and lock it. If it fails, it will traverse the circular linked list to find any possiable arena that not being locked by other threads. If it still can't find it, a new arena will be created and inserted to the circular linked list.  

```c
struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  */
  struct malloc_state *next_free;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
/* There are several instances of this struct ("arenas") in this
   malloc.  If you are adapting this malloc in a way that does NOT use
   a static or mmapped malloc_state, you MUST explicitly zero-fill it
   before using. This malloc relies on the property that malloc_state
   is initialized to all zeroes (as is true of C statics).  */

static struct malloc_state main_arena =
{
  .mutex = _LIBC_LOCK_INITIALIZER,
  .next = &main_arena,
  .attached_threads = 1
};
```

## Chunks

According to glibc source code (latest version glibc 2.37), a malloc chunk have mainly three parts: `size` for both previous chunk and current chunk, `ptr` for doubly linked free list, and `next size` for adjacent (in the doubly linked list) chunks in doubly linked list. 

```c
/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

The struct definition is a bit abstract and misleading for us to truly understand how the chunk is manipulated in the memory. So glibc also provide us with a more detailed documentation for allocated chunks and free chunks.

### Allocated Chunks

```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk, if unallocated (P clear)  |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             User data starts here...                          .
	    .                                                               .
	    .             (malloc_usable_size() bytes)                      .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             (size of chunk, but used for application data)    |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of next chunk, in bytes                |A|0|1|
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`prev_size`: Previous chunk size. This part will be user data if the previous chunk is allocated, which indicate by the `P` bit.

`size`: Current chunk size

To increase CPU performance when access memory, `ptmalloc2` choose to use 8 byte alignment, which gives us 3 unuse bits for bit indicators:

- `P` (PREV_INUSE) bit: if the previous block is used
- `M` (IS_MMAPED) bit: if the chunk allocated via `mmap`
- `A` (NON_MAIN_ARENA) bit: if this chunk is **not** in `main_arena`. If it is set, this chunk belongs to `thread_arena` 

### Free Chunks

```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk, if unallocated (P clear)  |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |A|0|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Forward pointer to next chunk in list             |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Back pointer to previous chunk in list            |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Unused space (may be 0 bytes long)                .
	    .                                                               .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of next chunk, in bytes                |A|0|0|
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Similar to allocated chunks, free chunks also have the similar fields:

`prev_size`: Previous chunk size. This part will be user data if the previous chunk is allocated, which indicate by the `P` bit.

`size`: Current chunk size

`fd_ptr` & `bk_ptr`: indicate adjacent free chunks in the doubly linked free list.  

Bit map is the same.

## Bins

Bins are used to locate free or unallocated chunks, or explicit free lists. As shown in the [Free Chunks](#free-chunks) section, each bin is doubly linked. There are total 128 bins for different free chunk sizes. Free chunks in the bins are kept in size order. Since each bin is relatively small, the traversal cost can be ignored. For more details, we could check the comments in the source code:

```c
/*
   Bins

    An array of bin headers for free chunks. Each bin is doubly
    linked.  The bins are approximately proportionally (log) spaced.
    There are a lot of these bins (128). This may look excessive, but
    works very well in practice.  Most bins hold sizes that are
    unusual as malloc request sizes, but are more usual for fragments
    and consolidated sets of chunks, which is what these bins hold, so
    they can be found quickly.  All procedures maintain the invariant
    that no consolidated chunk physically borders another one, so each
    chunk in a list is known to be preceeded and followed by either
    inuse chunks or the ends of memory.

    Chunks in bins are kept in size order, with ties going to the
    approximately least recently used chunk. Ordering isn't needed
    for the small bins, which all contain the same-sized chunks, but
    facilitates best-fit allocation for larger chunks. These lists
    are just sequential. Keeping them in order almost never requires
    enough traversal to warrant using fancier ordered data
    structures.

    Chunks of the same size are linked with the most
    recently freed at the front, and allocations are taken from the
    back.  This results in LRU (FIFO) allocation order, which tends
    to give each chunk an equal opportunity to be consolidated with
    adjacent freed chunks, resulting in larger free chunks and less
    fragmentation.

    To simplify use in double-linked lists, each bin header acts
    as a malloc_chunk. This avoids special-casing for headers.
    But to conserve space and improve locality, we allocate
    only the fd/bk pointers of bins, and then use repositioning tricks
    to treat these as the fields of a malloc_chunk*.
 */
```

We could see that it is very similar to the free list we have done in the malloc lab. 

```c
/*
   Indexing
    Bins for sizes < 512 bytes contain chunks of all the same size, spaced
    8 bytes apart. Larger bins are approximately logarithmically spaced:
    64 bins of size       8
    32 bins of size      64
    16 bins of size     512
     8 bins of size    4096
     4 bins of size   32768
     2 bins of size  262144
     1 bin  of size what's left
    There is actually a little bit of slop in the numbers in bin_index
    for the sake of speed. This makes no difference elsewhere.
    The bins top out around 1MB because we expect to service large
    requests via mmap.
    Bin 0 does not exist.  Bin 1 is the unordered list; if that would be
    a valid chunk size the small bins are bumped up one.
 */
```

There are 4 kinds of bins maintained by `ptmalloc2`:

- Fast bin
- Small bin
- Large bin
- Unsorted bin

### TCache & Fast Bin

```c
/*
   Fastbins
    An array of lists holding recently freed small chunks.  Fastbins
    are not doubly linked.  It is faster to single-link them, and
    since chunks are never removed from the middles of these lists,
    double linking is not necessary. Also, unlike regular bins, they
    are not even processed in FIFO order (they use faster LIFO) since
    ordering doesn't much matter in the transient contexts in which
    fastbins are normally used.
    Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
 */
```

### Small Bin

### Large Bin

### Unsorted Bin

## Allocation

## Free

## Concurrent Allocation

## Reference

https://elixir.bootlin.com/glibc/glibc-2.37/source/malloc/malloc.c

https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/

https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/

https://ctf-wiki.org/en/pwn/linux/user-mode/heap/ptmalloc2/implementation/overview/

https://littlecsd.net/2019/02/14/csapp-Malloclab/

https://blog.csdn.net/z_ryan/article/details/79950737
