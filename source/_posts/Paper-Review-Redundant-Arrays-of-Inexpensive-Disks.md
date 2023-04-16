---
title: 'Paper Review: Redundant Arrays of Inexpensive Disks'
date: 2023-04-15 17:03:51
category: Academic Paper
tags:
    - Operating System
    - Virtual Memory
---

The paper "Redundant Arrays of Inexpensive Disks" discusses the benefits of using RAID technology for data storage. RAID offers significant improvements in performance, reliability, power consumption, and scalability compared to Single Large Expensive Disks (SLED). The paper presents a taxonomy of five different levels of RAID, progressing through a variety of alternatives with differing performance and reliability. Each level offers a different balance of performance, reliability, and cost-effectiveness. The paper also provides examples of industries or applications that would benefit from using RAID storage.

![RAID](https://www.ubackup.com/screenshot/en/acbn/others/fastest-raid-level/raid-storage.png)

## A Better Solution - RAID

### Problem: SLED

The problem that led to the invention of RAID was the need for improved reliability in data storage. In the early days of computing, data was typically stored on SLED, which were large and expensive but offered relatively high reliability. However, as disk drives became smaller and less expensive, it became more cost-effective to use multiple smaller disks instead of a single large one. 

### Possiable Solution

Definitly, multiple small inexpansive disks could simply merge together to become a larger and faster big disk, which is RAID level 0. But the challenge with using multiple disks was that if any one disk failed, all of the data stored on it would be lost. This made data storage less reliable than with SLEDs. To overcome this challenge, researchers developed RAID technology, which uses extra disks containing redundant information to recover the original information when a disk fails. 

By designing the organization of the disks, RAID offers significant improvements in performance, reliability, power consumption, and scalability compared to SLEDs or other alternatives. It provides a better solution for data storage by offering fault tolerance and redundancy at a lower cost per gigabyte than other options.

## RAID Level 1

Since a large chunk of disks may result in a high failure rate, another simple solution to try is to do the backup for each disk, which is RAID level 1 (mirrored disks). In RAID 1, data is written identically to two or more disks, creating a "mirror" of the data. This provides excellent data redundancy since if one disk fails, the other disk(s) can continue to function and provide access to the data. However, RAID 1 requires twice as many disks as other levels of RAID, making it relatively expensive compared to other options. RAID 1 is best suited for applications that require high reliability and low write performance requirements.

## RAID Level 2

To reduce the extensive overhead of securing the RAID, a second RAID was invented, which is RAID level 2 (memory-style error-correcting codes/Hamming codes). RAID 2 uses memory-style error-correcting codes to detect and correct errors in data. It requires a minimum of three disks and is rarely used in practice due to its complexity. In RAID 2, data is divided into small units called "bits," which are then spread across multiple disks. Each disk has a dedicated bit for error correction, which can be used to reconstruct lost data if one of the disks fails. However, RAID 2 still requires a lot of overhead for error correction and is not very efficient for most applications, so it is not commonly used in practice.

## RAID Level 3

To further reduce the overhead, RAID level 3 comes out. RAID 3 uses bit-interleaved parity to provide redundancy. It requires a minimum of three disks and provides good performance for large sequential reads but poor performance for small random writes. In RAID 3, data is divided into blocks, and each block is written to a different disk in the array. One disk is dedicated to storing parity information, which can be used to reconstruct lost data if one of the disks fails. However, since all write operations must update the parity disk, RAID 3 can suffer from a bottleneck on the parity disk and may not be suitable for applications that require high write performance. RAID 3 is not commonly used in practice due to its limitations.

## RAID Level 4

RAID level 4 was designed to cover the shortage of RAID 3. RAID 4 uses block-interleaved parity to provide redundancy. It requires a minimum of three disks and provides better performance for small random writes than RAID 3 but can suffer from a bottleneck on the parity disk. In RAID 4, data is divided into blocks, and each block is written to a different disk in the array. One disk is dedicated to storing parity information, which can be used to reconstruct lost data if one of the disks fails. However, since all write operations must update the parity disk, RAID 4 can suffer from a bottleneck on the parity disk and may not be suitable for applications that require high write performance. RAID 4 is less commonly used than RAID 5 due to its limitations.

## RAID Level 5

Since the parity disk becomes the bottleneck of the whole RAID, RAID level 5 divide uses block-interleaved distributed parity to provide redundancy. It requires a minimum of three disks and provides good performance for both small random writes and large sequential reads. In RAID 5, data is divided into blocks, and each block is written to a different disk in the array. Parity information is also distributed across all disks in the array, so that if one disk fails, the data can be reconstructed using the parity information on the remaining disks. RAID 5 provides good fault tolerance and performance for most applications and is one of the most commonly used RAID levels in practice.

## Conclusion

This paper, as a discovery of the feasibility of RAID, showed us a step-by-step thinking of developments of the RAID levels. It provides a great insight and thoughts behind each level with specific purpose of those RAID solutions. Although the paper was introduced under the thought of hardware improvements of the disk management, it points out that RAID can also be implemented in software, making it accessible to a wide range of users. 

## Reference

D. Patterson, G. Gibson, R. Katz. Redundant Arrays of Inexpensive Disks. SIGMOD 1988.

PDF: https://www.cs.cmu.edu/~garth/RAIDpaper/Patterson88.pdf