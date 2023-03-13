---
title: 'Paper Review: Memory Resource Management in VMware ESX server'
date: 2023-03-13 16:43:34
category: Academic Paper
tags:
    - Operating System
    - Virtual Memory
---

The paper "Memory Resource Management in VMware ESX Server" discusses the challenges of memory virtualization in the context of server consolidation. The authors introduce several novel mechanisms and policies for memory management, including ballooning, idle memory tax, content-based page sharing, and hot I/O page remapping. For the context of this paper, the author treats each guest OS as a special process, which may need larger memory and more hardware support, running on the host OS to provide another layer of abstraction for memory virtualization. 

![Vmware ESXi](https://documentation.axsguard.com/images/vspherelogo.png)

## Memory Ballooning

The ballooning technique works by loading a small balloon module into the guest operating system as a pseudo-device driver or kernel service. It has no external interface within the guest and communicates with ESX Server via a private channel. When the server wants to reclaim memory, it instructs the driver to "inflate" by allocating pinned physical pages within the VM, using appropriate native interfaces. Similarly, the server may "deflate" the balloon by instructing it to deallocate pages. Thus, ballooning allows ESX Server to reclaim pages from the guest OS for more efficient use by other virtual machines that need more memory. 

## Idle Memory Tax

The memory tax is a mechanism to encourage efficient memory utilization while maintaining performance isolation guarantees. It works by imposing a tax on idle memory by periodically scanning the physical memory of each virtual machine and identifying pages that have not been accessed recently. These pages are then marked as idle and taxed at a higher rate than active pages. The tax rate is dynamically adjusted based on the overall system load and the amount of idle memory in each virtual machine. This technic encourages virtual machines to release unused memory back to the system for more efficient use by other virtual machines that need more memory. Combine with ballooning, it is very similar to the demand paging in modern OS implementation, which only allocate memory when processes, or guest OS in this context, really need.

## Content-based page sharing

Content-based page sharing is a technique to conserve memory by identifying and sharing identical pages between virtual machines. The basic idea is to identify page copies by their contents. Pages with identical contents can be shared regardless of when, where, or how those contents were generated. This general-purpose approach has two key advantages. First, it eliminates the need to modify, hook, or even understand guest OS code. Second, it can identify more opportunities for sharing; by definition, all potentially shareable pages can be identified by their contents. 

## Hot I/O page remapping

Hot I/O page remapping is a technique to reduce copying overheads and improve performance in large-memory systems. It uses hardware support for transparent page remapping to map the physical page containing the I/O buffer to a different physical address that is not currently mapped by any other virtual machine. This allows ESX Server to avoid copying the data between pages while still maintaining isolation guarantees between virtual machines, therefore, improve performance and reduce resource usage in server consolidation scenarios where multiple virtual machines are running similar workloads. Combine with content-based sharing, it becomes a prototype of the memory sharing policy in modern OS, which avoid multiple copies of same pages. 

## Summary

Overall, the technics shown in this paper foreshadows the development of modern OS memory management. Although it makes some customization for hosting virtual machines with guest OS rather than running processes, the idea of virtualizing memory for different purpose is the same. The newly developed technics and policies discussed in this paper have been implemented in modern OS to manage virtual memory for processes which greatly improved memory utilization among different processes. 

## Reference

C. A. Waldspurger. Memory resource management in vmware esx server. *SIGOPS Oper. Syst. Rev.*, 36(SI):181-194, 2002.

PDF: https://research.cs.wisc.edu/areas/os/Qual/papers/vmware-memory.pdf