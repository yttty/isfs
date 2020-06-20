In Storage Filesystem (ISFS) Using FUSE
=======================================

A toy filesystem for block storage device (e.g. USB drive).

## Features
- Use [FUSE](https://github.com/libfuse/libfuse)
- Directly access the physical block without any operating system level optimization
- The file data can still be accessed after re-mounting ISFS
- Supported shell commands: `cd`, `ls`, `mkdir`, `touch`, `echo to >> file`, `cat`, `rmdir`, `rm`
- Support large file (about 800MB)
- Support large directory (contains a lot of files/subdirectories)
- Buffer cache
    - Implement buffer cache with LRU eviction policy to reduce r/w
    - Write back dirty blocks upon un-mounting
    - Use double-linked list + hash tree to reduce search time for empty cache block
    - The worst case search time will be nearly $sqrt(n)$


## How to run

> **[NOTE]: Run all commands as sudo user**

### Dependency
- On Ubuntu, install
```bash
apt-get install gcc make fuse libfuse-dev pkg-config
```

### Build the filesystem binary

The simplest way is to type ```make```:
```bash
cd code_dir
make # build the isfs binary
```

I provide another option in ```Makefile``` if you need more debug info
```bash
make debug-isfs # to print more info
```

If you want to test buffer cache, please use this option.
```bash
make debug-buffer # to build the test case for buffer cache
```

### Mount the fs
> **[NOTE] that the ISFS will format your disk if the filesystem in your disk is not ISFS**

- The path of block device is ```/dev/sdb1```, please change the path at ```isfs.c:470``` if necessary.
- Assume the mount point is ```/mnt/isfs```, you can mount isfs with this command.
```bash
./isfs -f /mnt/isfs
```
- Then open a new terminal, ```cd``` to ```/mnt/isfs``` and do the testing.


## Test scripts
I provide two two test scripts for ISFS.

### Small things
The ```test-small.py``` script will test all the small operations (e.g. `cd, ls, mkdir, touch, echo to >> file, cat, rmdir, rm`).
```bash
python3 test-small.py /mnt/isfs
```

### Big things
The ```test-big.py``` script will test the support of big file and big dir.
```bash
python3 test-big.py /mnt/isfs
```

## Disk Layout of the ISFS
The first page (page 0, block 0-7) is empty and unused. The second page (page 1, block 8-15) is the superblock area, including superblock metadata and another copy, see below. Page 2-49 is the ibmap, page 50-97 is the dbmap. Each bit in ibmap or dbmap is used to specify the corresponding inode or data block is in use or not. Page 98-99 is the checksum for ibmap and dbmap. Page 100-12,387 (12,288 pages in total) is the inode table area, each inode requires 8 integers (32 bytes). There are 1,572,864 inodes in total. Page 12,388-208,995 (196,608 pages in total) is the data region. The size of data region is 196608 pages = 1,572,864 blocks = 805,306,368 bytes = 768 MB Each inode have two direct data block pointers, one indirect pointer and one double indirect pointer. Each block is 512 bytes so the max size of a big file is (2+128+128^2) * 512 bytes. For directory's data node (files), each entry of file is 32 bytes, the bytes[0-11] are file name, bytes[12-15] are inumber of file (unsigned int) the last bit of byte[31] are the indicator whether the entry is used. The max number of file in a directory is (2+128+128^2) * 512/32. 


## About the buffer
The buffer cache use a double-linked list to track the order of usage and a hash table to accelerate search.
The size of buffer cache is 10446 page * 8 block/page.
The size of hash table is the nearest prime number which is larger than sqrt(SIZE_BUFFER_CACHE), so the theoretical length of each entry of hash table will be smaller than sqrt(SIZE_BUFFER_CACHE).
The worst case of search time will be O(1) + O(sqrt(SIZE_BUFFER_CACHE)), which is smaller than $n/4$


## Screenshots

### Mount
![](https://github.com/yttty/fuse-isfs/blob/master/img/mount.png)

### Commands
![](https://github.com/yttty/fuse-isfs/blob/master/img/cmds.png)

### Small things
![](https://github.com/yttty/fuse-isfs/blob/master/img/small.png)

### Big things
![](https://github.com/yttty/fuse-isfs/blob/master/img/big.png)

### Print cache statistics
![](https://github.com/yttty/fuse-isfs/blob/master/img/cache.png)

### The files are accessible after remount
![](https://github.com/yttty/fuse-isfs/blob/master/img/files.png)