/**
 * In Storage File System (ISFS)
 * Author: Tianyi Yang, 1155116771
 * Date: May 13, 2020
 */

/*                        *Layout of the ISFS*
 * The first page (page 0, block 0-7) is empty and unused.
 *
 * The second page (page 1, block 8-15) is the superblock area, including
 * superblock metadata and another copy, see below.
 *
 * Page 2-49 is the ibmap, page 50-97 is the dbmap. Each bit in ibmap or dbmap
 * is used to specify the corresponding inode or data block is in use or not.
 * Page 98-99 is the checksum for ibmap and dbmap.
 *
 * Page 100-12,387 (12,288 pages in total) is the inode table area, each inode
 * requires 8 integers (32 bytes). There are 1,572,864 inodes in total.
 *
 * Page 12,388-208,995 (196,608 pages in total) is the data region. The size of
 * data region is 196608 pages = 1,572,864 blocks = 805,306,368 bytes = 768 MB
 *
 * Each inode have two direct data block pointers, one indirect pointer and one
 * double indirect pointer. Each block is 512 bytes so the max size of a big file
 * is (2+128+128^2)*512 bytes.
 *
 * For directory's data node (files), each entry of file is 32 bytes, the first
 * bytes[0-11] are file name, bytes[12-15] are inumber of file (unsigned int)
 * the last bit of byte[31] are the indicator whether the entry is used. The
 * max number of file in a directory is (2+128+128^2)*512/32.
 */

#define FUSE_USE_VERSION 30
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fuse.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "buffer.h"

/************************ FS METADATA ************************/

#define BYTES_PER_BLOCK 512  // block_size in my_io.h
#define BLOCKS_PER_PAGE 8
#define SUPERBLOCK_HEADER_PAGE 1
#define SUPERBLOCK_HEADER_BLOCK 0
#define SUPERBLOCK_PAGE 1
#define SUPERBLOCK_BLOCK 1
#define DUP_SUPERBLOCK_HEADER_PAGE 1
#define DUP_SUPERBLOCK_HEADER_BLOCK 6
#define DUP_SUPERBLOCK_PAGE 1
#define DUP_SUPERBLOCK_BLOCK 7

/**
 * Default values (used in initiating a new fs)
 */
#define SIZE_IBMAP 48               // 48 pages
#define SIZE_DBMAP 48               // 48 pages
#define SIZE_INODE 32               // 32 bytes
#define SIZE_FILENAME 12            // 12 bytes
#define SIZE_FILE_ENTRY 32          // 32 bytes
#define ROOT_INUM 0                 // = 0
#define SIZE_DISKPTR 4              // = 4
#define SIZE_DIRECT_PTR 2           // 2 direct ptrs
#define SIZE_INDIRECT_PTR 1         // 1 indirect
#define SIZE_DOUBLE_INDIRECT_PTR 1  // 1 double indirect
#define IBMAP_0 2                   // first page of ibmap
#define DBMAP_0 50                  // first page of dbmap
#define ITABLE_0 100                // first page of itable
#define DATA_0 12388                // first page of data region

/**
 * The superblock takes up the entire second page (aka. page 1)
 * but only use block 0,1 and 6,7 in page 1.
 *
 * Block 0 stores the header of ISFS. Block 6 is a copy of block 0.
 * Block 1 strores serialized superblock. Block 7 is a copy of block 1.
 * Other blocks are set to 0.
 */
typedef struct superblock {
    unsigned size_ibmap;                // 48 pages
    unsigned size_dbmap;                // 48 pages
    unsigned size_inode;                // 32 bytes
    unsigned size_filename;             // 12 bytes
    unsigned size_file_entry;           // 32 bytes
    unsigned root_inum;                 // = 0
    unsigned num_disk_ptrs_per_inode;   // = 4
    unsigned num_direct_ptrs;           // = 2
    unsigned num_indirect_ptrs;         // = 1
    unsigned num_double_indirect_ptrs;  // = 1
    unsigned max_dblk;                  // maximum number of file entry
    unsigned ibmap_0;                   // idx of first ibmap page
    unsigned dbmap_0;                   // idx of first dbmap page
    unsigned itable_0;                  // idx of first itable page
    unsigned data_0;                    // idx of first data page
} superblock;
superblock *super;

/**
 * inodes struct, 32 bytes
 */
typedef struct inode {
    int flag;                    // indicating the type of file, 0 - file, 1 - directory
    unsigned used_blocks_count;  // how many blocks have been used
    unsigned used_size;          // how many bytes have been used
    unsigned links_count;        // # of hard links to this file
    unsigned block[4];           // a set of inum points to data_blocks
} inode;

/* mask the last bit of file entry */
#define DBLK_FILE_MASK 0x1

/* Utility functions */

/**
 * print error message
 *
 * \param err_msg err msg string
 * \param fatal if fatal is true, then the program will exit immediately
 */
int unmount_isfs();
void raise_error(char *err_msg, const bool fatal) {
    printf("[ERROR] operation unsuccessful.\n[MSG] %s\n", err_msg);
    if (fatal) {
        unmount_isfs();
        exit(-1);
    }
}

/**
 * Get physical block idx from page id and block id
 */
unsigned int get_physical_block_id(unsigned int page, unsigned int block);
inline unsigned int get_physical_block_id(unsigned int page, unsigned int block) {
    assert(block >= 0 && block < BLOCKS_PER_PAGE);
    return page * BLOCKS_PER_PAGE + block;
}

/**
 * Wrapper for buffer_write
 */
void fs_write(void *buf, unsigned int page_id, unsigned int block_id);
inline void fs_write(void *buf, unsigned int page_id, unsigned int block_id) {
    buffer_write(buf, get_physical_block_id(page_id, block_id));
}

/**
 * Wrapper for buffer_read
 */
void fs_read(void *buf, unsigned int page_id, unsigned int block_id);
inline void fs_read(void *buf, unsigned int page_id, unsigned int block_id) {
    buffer_read(buf, get_physical_block_id(page_id, block_id));
}

/**
 * Wrapper for buffer_write, write n (n < block_size) bytes from buf (src) to block+offset address
 */
void fs_nwrite(void *buf, unsigned int page_id, unsigned int block_id, unsigned int offset, unsigned int n) {
    assert(offset + n <= BYTES_PER_BLOCK);  // make sure not to overflow the boundry of block
    char write_buf[BYTES_PER_BLOCK];
    buffer_read(write_buf, get_physical_block_id(page_id, block_id));
    memcpy(write_buf + offset, buf, n);
    buffer_write(write_buf, get_physical_block_id(page_id, block_id));
}

/**
 * Wrapper for buffer_read, read n (n < block_size) bytes to buf (dest)
 */
void fs_nread(void *buf, unsigned int page_id, unsigned int block_id, unsigned int offset, unsigned int n) {
    assert(offset + n <= BYTES_PER_BLOCK);  // make sure not to overflow the boundry of block
    char read_buf[BYTES_PER_BLOCK];
    buffer_read(read_buf, get_physical_block_id(page_id, block_id));
    memcpy(buf, read_buf + offset, n);
}

/**
 * memset 512 bytes to 0
 * \param target the starting address of buffer
 */
void clear(void *target);
inline void clear(void *target) { memset(target, 0, BYTES_PER_BLOCK); }

/* Filesystem internal functions */

/**
 * Set bmap[idx] to flag (0 or 1)
 * \param type 'i' - ibmap, 'd' - dbmap
 * \param idx the index in ibmap or dbmap
 * \param flag 0 - set to false and return false, 1 - set to true and return true, 2 - return current value
 */
bool set_bmap(const char type, const int idx, int flag) {
    assert(type == 'i' || type == 'd');
    // locate the block of ibmap
    unsigned int page_id, blk_id, byte_id, res;
    page_id = type == 'd' ? super->dbmap_0 : super->ibmap_0 + idx / (BLOCKS_PER_PAGE * BYTES_PER_BLOCK * 8);
    res = idx % (BLOCKS_PER_PAGE * BYTES_PER_BLOCK * 8);
    blk_id = res / (BYTES_PER_BLOCK * 8);
    res = res % (BYTES_PER_BLOCK * 8);
    byte_id = res / 8;

    // read block
    char buf[BYTES_PER_BLOCK];
    fs_read(buf, page_id, blk_id);

    // write flag
    if (flag == 1) {  // set used
        buf[byte_id] |= 1 << (res % 8);
    } else if (flag == 0) {  // set unused
        buf[byte_id] &= ~(1 << (res % 8));
    }
    fs_write(buf, page_id, blk_id);

    return ((buf[byte_id] >> (res % 8)) & 0x1) == 1;
}

/**
 * Operations on one inode
 *
 * \param opcode 0 - write, 1 - delete, 2 - read
 * \param inumber index of inode to update
 * \param node_p pointer to inode struct, NULL if opcode==1
 *
 * \return 0 means success
 */
int inode_op(const int opcode, const unsigned inumber, inode *node_p) {
    // locate the block of inode in inode table
    unsigned int page_id, blk_id, res;
    page_id = super->itable_0 + inumber / (BLOCKS_PER_PAGE * BYTES_PER_BLOCK / super->size_inode);
    res = inumber % (BLOCKS_PER_PAGE * BYTES_PER_BLOCK / super->size_inode);
    blk_id = res / (BYTES_PER_BLOCK / super->size_inode);
    res = res % (BYTES_PER_BLOCK / super->size_inode);

    switch (opcode) {
        case 0:
            set_bmap('i', inumber, 1);
            // simply copy all from node_p to the inode table
            fs_nwrite(node_p, page_id, blk_id, res * super->size_inode, super->size_inode);
            break;
        case 1:
            set_bmap('i', inumber, 0);
            break;
        case 2:
            // simply copy all to node_p
            fs_nread(node_p, page_id, blk_id, res * super->size_inode, super->size_inode);
            break;
        default:
            // invalid opcode, error
            raise_error("Invalid opcode in inode_op()!", true);
    }
    return 0;
}

/**
 * Operate on one entire data block
 *
 * \param opcode 0 - write, 1 - delete, 2 - read
 * \param idx index of data block to update
 * \param data data block pointer, NULL if not used
 * \return 0 means success
 * WARNING: will write entire block without check boundry
 */
int data_block_op(const int opcode, const int idx, void *data) {
    // locate the block of data in data region
    unsigned int page_id, blk_id;
    page_id = super->data_0 + idx / BLOCKS_PER_PAGE;
    blk_id = idx % BLOCKS_PER_PAGE;

    switch (opcode) {
        case 0:
            /* write data */
            set_bmap('d', idx, 1);
            // simply copy all from data to the data region
            fs_write(data, page_id, blk_id);
            break;
        case 1:
            /* mark blk as unused */
            set_bmap('d', idx, 0);
            break;
        case 2:
            // simply copy all from data region to data
            fs_read(data, page_id, blk_id);
            break;
        default:
            // invalid opcode, error
            raise_error("Invalid opcode in data_block_op()!", true);
    }
    return 0;
}

/**
 * get the data index of data block of a given inode
 * \param node the pointer to inode struct
 * \param idx which data block to retrive
 * \return the block index to use in data_block_op
 */
unsigned int get_dblock_idx(const inode *node, unsigned int idx) {
    unsigned dblk[BYTES_PER_BLOCK / sizeof(unsigned)];
    if (idx >= node->used_blocks_count) {
        raise_error("[A] data block not used!", true);
    }
    if (idx < super->num_direct_ptrs)
        return node->block[idx];
    else if (idx < super->num_direct_ptrs + super->num_indirect_ptrs * (BYTES_PER_BLOCK / sizeof(unsigned))) {
        // in the indirect ptr
        if (node->block[2] == -1) {
            raise_error("[B] data block not used!", true);
        }
        data_block_op(2, node->block[2], (void *) dblk);
        return dblk[idx - super->num_direct_ptrs];
    } else {
        // in the double indirect ptr
        if (node->block[3] == -1) {
            raise_error("[C] data block not used!", true);
        }
        data_block_op(2, node->block[3], (void *) dblk);
        idx -= super->num_direct_ptrs + super->num_indirect_ptrs * (BYTES_PER_BLOCK / sizeof(unsigned));
        unsigned blk_idx = dblk[idx / (BYTES_PER_BLOCK / sizeof(unsigned))];
        data_block_op(2, blk_idx, (void *) dblk);
        idx %= (BYTES_PER_BLOCK / sizeof(unsigned));
        return dblk[idx];
    }
}

/**
 * Format the entire disk, EVERYTHING will lose!
 */
int format_disk() {
    // Write superblock
    char version_string[BYTES_PER_BLOCK];
    clear(version_string);
    time_t t;
    time(&t);
    snprintf(version_string, BYTES_PER_BLOCK, "In Storage File System, Ver 0.1, Created on %s", ctime(&t));

    superblock new_super;
    new_super.size_ibmap = SIZE_IBMAP;
    new_super.size_dbmap = SIZE_DBMAP;
    new_super.size_inode = SIZE_INODE;
    new_super.size_filename = SIZE_FILENAME;
    new_super.size_file_entry = SIZE_FILE_ENTRY;
    new_super.root_inum = ROOT_INUM;
    new_super.num_disk_ptrs_per_inode = SIZE_DISKPTR;
    new_super.num_direct_ptrs = SIZE_DIRECT_PTR;
    new_super.num_indirect_ptrs = SIZE_INDIRECT_PTR;
    new_super.num_double_indirect_ptrs = SIZE_DOUBLE_INDIRECT_PTR;
    new_super.ibmap_0 = IBMAP_0;
    new_super.dbmap_0 = DBMAP_0;
    new_super.itable_0 = ITABLE_0;
    new_super.data_0 = DATA_0;
    new_super.max_dblk =
        (new_super.num_direct_ptrs + new_super.num_indirect_ptrs * BYTES_PER_BLOCK / sizeof(unsigned) +
         new_super.num_double_indirect_ptrs * BYTES_PER_BLOCK / sizeof(unsigned) * BYTES_PER_BLOCK / sizeof(unsigned));

    char sb_buf[BYTES_PER_BLOCK];
    clear(sb_buf);
    memcpy(sb_buf, &new_super, sizeof(superblock));

    fs_write(version_string, SUPERBLOCK_HEADER_PAGE, SUPERBLOCK_HEADER_BLOCK);
    fs_write(version_string, DUP_SUPERBLOCK_HEADER_PAGE, DUP_SUPERBLOCK_HEADER_BLOCK);
    fs_write(sb_buf, SUPERBLOCK_PAGE, SUPERBLOCK_BLOCK);
    fs_write(sb_buf, DUP_SUPERBLOCK_PAGE, DUP_SUPERBLOCK_BLOCK);

    // Copy the new superblock to super
    memcpy(super, &new_super, sizeof(superblock));

    // reset ibmap and dbmap
    clear(version_string);  // simply reuse this buffer
    int page_id, blk_id;
    // write ibmap, dbmap and checksum page
    for (page_id = new_super.ibmap_0; page_id < new_super.dbmap_0 + new_super.size_dbmap + 2; page_id++)
        for (blk_id = 0; blk_id < BLOCKS_PER_PAGE; blk_id++) {
            fs_write(version_string, page_id, blk_id);
        }

    // init root inode
    inode root_node;
    root_node.flag = 1;               // file type is dir
    root_node.used_blocks_count = 1;  // root dir use 1 data block
    root_node.block[0] = 0;           // use data block [0] to store root data
    root_node.block[1] = -1;          // other blocks are unused
    root_node.block[2] = -1;
    root_node.block[3] = -1;
    root_node.links_count = 2;              // 2 links by default
    root_node.used_size = BYTES_PER_BLOCK;  // use one block only
    inode_op(0, super->root_inum, &root_node);

    // init root data blk, contains one file if in DEBUG MODE
    char root_data[BYTES_PER_BLOCK] = {0};
#ifdef DEBUG_ISFS
    char filename[] = "README";
    strcpy(root_data, filename);
    unsigned int file_inumber = 1;                                                  // file1 in inode[1]
    root_data[super->size_file_entry - 1] |= DBLK_FILE_MASK;                        // file mask
    memcpy(root_data + super->size_filename, &file_inumber, sizeof(unsigned int));  // file1 in inode[1]
#endif
    data_block_op(0, root_node.block[0], root_data);

#ifdef DEBUG_ISFS
    // init file1 inode
    inode file_node;
    file_node.flag = 0;               // file type is file
    file_node.used_blocks_count = 1;  // root dir use 1 data block
    file_node.block[0] = 1;           // use data block [1] to store file data
    file_node.block[1] = -1;          // other blocks are unused
    file_node.block[2] = -1;
    file_node.block[3] = -1;
    file_node.links_count = 1;              // 1 link by default
    file_node.used_size = BYTES_PER_BLOCK;  // use one block only
    inode_op(0, file_inumber, &file_node);

    // init file1 data blk
    char file_data[BYTES_PER_BLOCK] = {0};
    char file_content[] = "In Storage File System (CSCI5550 Project)\nAuthor: Tianyi Yang, 1155116771\n";
    strcpy(file_data, file_content);
    data_block_op(0, file_node.block[0], file_data);
#endif

    // Sync buffer to disk
    buffer_sync();
    return 0;
}

/**
 * Load superblock from device
 * \param super pointer to superblock (malloc first)
 * \param format format disk? (always format if fs is broken)
 */
void load_superblock(superblock *super, bool format) {
    char buf[BYTES_PER_BLOCK], buf_dup[BYTES_PER_BLOCK];
    fs_read(buf, SUPERBLOCK_PAGE, SUPERBLOCK_BLOCK);
    fs_read(buf_dup, DUP_SUPERBLOCK_PAGE, DUP_SUPERBLOCK_BLOCK);

    // Check consistency
    if (memcmp(buf, buf_dup, BYTES_PER_BLOCK) != 0 || format) {
        printf("Superblock is broken, formatting entire disk in 1 seconds. Press Ctrl+C to abort!\n");
        sleep(1);
        printf("Start formatting...\n");
        format_disk();
        printf("Successfully formatted 805,306,368 bytes.\n");
        fs_read(buf, SUPERBLOCK_PAGE, SUPERBLOCK_BLOCK);
    }

    // load superblock data
    memcpy((void *) super, (void *) buf, sizeof(superblock));

    fs_read(buf_dup, SUPERBLOCK_HEADER_PAGE, SUPERBLOCK_HEADER_BLOCK);
    printf("Successfully loaded ISFS!\nVersion message: %s\n", buf_dup);
#ifdef DEBUG_ISFS
    printf("size ibmap: %d pages\n", super->size_ibmap);
    printf("size dbmap: %d pages\n", super->size_dbmap);
    printf("size inode: %d bytes\n", super->size_inode);
    printf("size filename: %d bytes\n", super->size_filename);
    printf("root inumber: %d\n", super->root_inum);
    printf("disk ptrs per inode: %d\n", super->num_disk_ptrs_per_inode);
#endif
}

/**
 * Mount isfs, load data from superblock in devide
 */
int mount_isfs() {
    buffer_init("/dev/sdb1");
    super = malloc(sizeof(superblock));
#ifdef DEBUG_ISFS
    load_superblock(super, true);
#else
    load_superblock(super, false);
#endif
    return 0;
}

/**
 * Unmount isfs
 */
int unmount_isfs() {
    buffer_sync();
    buffer_show_reduced_rw();
    free(super);
    return 0;
}

/**
 * Get the inumber of path, use recursive search
 *
 * \param start_inumber from which inode the search start, the inode should be a directory
 * \param path the path, should start with '/'
 *
 * \return the inumber of path if found
 * \return -1 if not found
 * \return 0 undefined
 */
int get_inumber(int start_inumber, const char *path) {
    if (strcmp(path, "/") == 0)
        return super->root_inum;

    if (path[0] != '/') {
        raise_error("in get_inumber(), the input path should start with /", true);
    }
    path++;

    inode node;
    inode_op(2, start_inumber, &node);

    if (node.flag == 1) {
        // input inumber is directory inode
        unsigned len = 0;
        while (path[len] != '\0' && path[len] != '/') {
            len++;
        }
        if (len >= super->size_filename) {
            // if filename is too long, just return not found
            return -1;
        }
        unsigned int file_inumber = 0;
        bool found = false;
        char file_dblk[BYTES_PER_BLOCK];
        unsigned entry = 0;
        for (int i = 0; i < node.used_blocks_count; i++) {
            unsigned dblk_idx = get_dblock_idx(&node, i);
            data_block_op(2, dblk_idx, file_dblk);
            entry = 0;
            while (entry < BYTES_PER_BLOCK / super->size_file_entry) {
                if ((file_dblk[entry * super->size_file_entry + (super->size_file_entry - 1)] & DBLK_FILE_MASK) &&
                    strncmp(file_dblk + entry * super->size_file_entry, path, len) == 0 &&
                    file_dblk[entry * super->size_file_entry + len] == '\0') {
                    memcpy(&file_inumber, file_dblk + entry * super->size_file_entry + super->size_filename,
                           sizeof(unsigned));
                    found = true;
                    break;
                }
                entry++;
            }
            if (found)
                break;
        }
        if (found) {
            if (path[len] == '\0') {
                return file_inumber;
            } else if (path[len] == '/') {
                return get_inumber(file_inumber, path + len);
            }
        } else if (file_inumber == 0) {
            return -1;
        } else {
            raise_error("Unexpected inumber from get_inumber_from_dir_data_block()!", true);
        }
    } else {
        // input inumber is file inode
        raise_error("get file inode, expect directory inode.", true);
    }
    return 0;
}

/**
 * Search algorithm for allocation of inode/datablk, currently use suquential search
 * \param type 'i' - ibmap, 'd' - dbmap
 * \return idx (> 0) if found
 * \return 0 if all are occupied
 */
unsigned search_free(const char type) {
    assert(type == 'i' || type == 'd');
    unsigned max, i;
    if (type == 'i') {
        max = super->size_ibmap * BLOCKS_PER_PAGE * BYTES_PER_BLOCK * 8;
    } else {
        max = super->size_dbmap * BLOCKS_PER_PAGE * BYTES_PER_BLOCK * 8;
    }
    i = 1;
    while (i < max) {
        if (!set_bmap(type, i, 2)) {
            return i;
        }
        i++;
    }
    return 0;
}

/**
 * Allocate a free inode, simply sequentially search for a free one
 *
 * \return 0 if all inodes are occupoed
 * \return inumber if successfully allocated
 */
unsigned allocate_inode() {
    unsigned inumber = search_free('i');
    if (inumber != 0)
        set_bmap('i', inumber, 1);
    return inumber;
}

/**
 * Allocate a free data block, simply sequentially search for a free one
 *
 * \return 0 if all data blocks are occupoed
 * \return inumber if successfully allocated
 */
unsigned allocate_datablock() {
    unsigned dblk_idx = search_free('d');
    if (dblk_idx != 0)
        set_bmap('d', dblk_idx, 1);
    return dblk_idx;
}

/**
 * Operating on data blocks in inode
 * \param p_inumber inumber
 * \param type 0 - add a new data block, 1 - remove the last data block
 * \return the dblk_idx
 */
unsigned inode_dblk_op(const short type, const int p_inumber) {
    assert(type == 0 || type == 1);
    char buf[BYTES_PER_BLOCK];
    unsigned new_indirect_ptr_blk, new_dblk_idx;
    unsigned blk_idx;
    inode p_inode;
    inode_op(2, p_inumber, &p_inode);

    switch (type) {
        case 0:
            // add a new datablock
            if (p_inode.used_blocks_count < super->max_dblk) {
                new_dblk_idx = allocate_datablock();
                if (new_dblk_idx == 0) {
                    raise_error("[0x1] Unable to allocate new datablock, full!", false);
                    return 0;
                } else {
                    // add new_dblk_idx to inode
                    if (p_inode.used_blocks_count == 1 && p_inode.block[1] == -1) {
                        // add to direct ptr
                        p_inode.block[1] = new_dblk_idx;
                    } else if (p_inode.used_blocks_count == 2 && p_inode.block[2] == -1) {
                        // init a indirect ptr blk
                        new_indirect_ptr_blk = allocate_datablock();
                        if (new_indirect_ptr_blk == 0) {
                            raise_error("[0x2] Unable to allocate new datablock, full!", false);
                            return 0;
                        }
                        clear(buf);  // now buf is the new indirect ptr block
                        memcpy(buf, &new_dblk_idx, sizeof(unsigned));
                        data_block_op(0, new_indirect_ptr_blk, buf);
                        p_inode.block[2] = new_indirect_ptr_blk;
                    } else if (p_inode.used_blocks_count > 2 &&
                               p_inode.used_blocks_count <
                                   super->num_direct_ptrs +
                                       super->num_indirect_ptrs * (BYTES_PER_BLOCK / sizeof(unsigned))) {
                        // add to indirect ptr
                        data_block_op(2, p_inode.block[2], buf);
                        memcpy(buf + (p_inode.used_blocks_count - 2) * sizeof(unsigned), &new_dblk_idx,
                               sizeof(unsigned));
                        data_block_op(0, p_inode.block[2], buf);
                    } else if ((p_inode.used_blocks_count ==
                                super->num_direct_ptrs +
                                    super->num_indirect_ptrs * (BYTES_PER_BLOCK / sizeof(unsigned))) &&
                               p_inode.block[3] == -1) {
                        // init double indirect ptr
                        unsigned new_double_indirect_ptr_blk = allocate_datablock();
                        unsigned new_double_indirect_ptr_blk_2 = allocate_datablock();
                        if (new_double_indirect_ptr_blk == 0 || new_double_indirect_ptr_blk_2 == 0) {
                            raise_error("[0x3] Unable to allocate new datablock, full!", false);
                            return 0;
                        }
                        clear(buf);  // now buf is the new indirect ptr 2 block
                        memcpy(buf, &new_dblk_idx, sizeof(unsigned));
                        data_block_op(0, new_double_indirect_ptr_blk_2, buf);
                        memcpy(buf, &new_double_indirect_ptr_blk_2,
                               sizeof(unsigned));  // now buf is the new indirect ptr block
                        data_block_op(0, new_double_indirect_ptr_blk, buf);
                        p_inode.block[3] = new_double_indirect_ptr_blk;
                    } else {
                        // add to double indirect ptr
                        unsigned offset, offset_double_indirect_blk, offset_double_indirect_blk_2;
                        unsigned double_indirect_blk_2;
                        offset =
                            p_inode.used_blocks_count -
                            (super->num_direct_ptrs + super->num_indirect_ptrs * (BYTES_PER_BLOCK / sizeof(unsigned)));
                        offset_double_indirect_blk = offset / (BYTES_PER_BLOCK / sizeof(unsigned));
                        offset_double_indirect_blk_2 = offset % (BYTES_PER_BLOCK / sizeof(unsigned));
                        if (offset_double_indirect_blk_2 == 0) {
                            // need to allocate one more dblk
                            unsigned new_double_indirect_blk = allocate_datablock();
                            if (new_double_indirect_blk == 0) {
                                raise_error("[0x4] Unable to allocate new datablock, full!", true);
                            }
                            clear(buf);
                            data_block_op(0, new_double_indirect_blk, buf);
                            data_block_op(2, p_inode.block[3], buf);
                            memcpy(buf + offset_double_indirect_blk * sizeof(unsigned), &new_double_indirect_blk,
                                   sizeof(unsigned));
                            data_block_op(0, p_inode.block[3], buf);
                        }
                        data_block_op(2, p_inode.block[3], buf);
                        memcpy(&double_indirect_blk_2, buf + offset_double_indirect_blk * sizeof(unsigned),
                               sizeof(unsigned));
                        data_block_op(2, double_indirect_blk_2, buf);
                        memcpy(buf + offset_double_indirect_blk_2 * sizeof(unsigned), &new_dblk_idx, sizeof(unsigned));
                        data_block_op(0, double_indirect_blk_2, buf);
                    }
                    // write the new allocated data block
                    clear(buf);
                    data_block_op(0, new_dblk_idx, buf);
                    // write inode
                    p_inode.used_blocks_count++;
                    inode_op(0, p_inumber, &p_inode);
                    return new_dblk_idx;
                }
            } else {
                raise_error("[0x5] Unable to add new datablock to inode, full block entry!", false);
                return 0;
            }
            break;
        case 1:
            blk_idx = get_dblock_idx(&p_inode, p_inode.used_blocks_count - 1);
            // free the data block
            data_block_op(1, blk_idx, NULL);
            /* WARNING: Here I simply decrease the used_blocks_count.
                        I do not deal with double linked dblk ptr.
                        Will result in disk fragments! */
            if (p_inode.used_blocks_count == 2) {
                p_inode.block[1] = -1;
            } else if (p_inode.used_blocks_count == 3) {
                data_block_op(1, p_inode.block[2], NULL);
                p_inode.block[2] = -1;
            } else if (p_inode.used_blocks_count ==
                       1 + super->num_direct_ptrs + super->num_indirect_ptrs * (BYTES_PER_BLOCK / sizeof(unsigned))) {
                data_block_op(1, p_inode.block[3], NULL);
                p_inode.block[3] = -1;
            }
            p_inode.used_blocks_count--;
            inode_op(0, p_inumber, &p_inode);
            return blk_idx;
            break;
        default:
            break;
    }
    return 0;
}

/**
 * Add fname entry in parent's data node
 *
 * \param p_inumber inumber of parent dir
 * \param fname filename or new dir name
 * \param new_inumber inumber of new file/dir
 *
 * \return -1 if unable to allocate
 * \return 0 if success
 */
int write_parent_dir(const int p_inumber, const char *fname, const unsigned *new_inumber) {
    /*  Steps
        1. try to find an empty entry in parent's data region, return error if unsuccessful
        2. write the fname and new inumber in the empty entry and mark this entry as used  */

    inode p_inode;
    inode_op(2, p_inumber, &p_inode);

    char p_dblk[BYTES_PER_BLOCK];
    unsigned dblk_idx, entry, i;
    // try to add entry to existing data block
    for (i = 0; i < p_inode.used_blocks_count; i++) {
        dblk_idx = get_dblock_idx(&p_inode, i);
        data_block_op(2, dblk_idx, p_dblk);
        entry = 0;
        while (entry < BYTES_PER_BLOCK / super->size_file_entry) {
            // locate unused entry
            if (!(p_dblk[entry * super->size_file_entry + (super->size_file_entry - 1)] & DBLK_FILE_MASK)) {
                memset(p_dblk + entry * super->size_file_entry, 0, super->size_file_entry);  // clear data
                strcpy(p_dblk + entry * super->size_file_entry, fname);  // found a new entry, write fname
                memcpy(p_dblk + entry * super->size_file_entry + super->size_filename, new_inumber,
                       sizeof(unsigned));  // set new inumber
                p_dblk[entry * super->size_file_entry + (super->size_file_entry - 1)] |= DBLK_FILE_MASK;
                data_block_op(0, dblk_idx, p_dblk);
                return 0;
            }
            entry++;
        }
    }

    // all entry in curerent data block are used, but we can just allocate one more data blk
    if (i == p_inode.used_blocks_count && p_inode.used_blocks_count < super->max_dblk) {
        unsigned new_dblk_idx = inode_dblk_op(0, p_inumber);
        if (new_dblk_idx == 0) {
            raise_error("[0x1] Unable to allocate new datablock for parent inode, full!", false);
            return -1;
        } else {
            //  add new_dblk_idx to p_inode's data region
            char *new_dblk = malloc(BYTES_PER_BLOCK);
            clear(new_dblk);
            strcpy(new_dblk, fname);
            memcpy(new_dblk + super->size_filename, new_inumber, sizeof(unsigned));
            new_dblk[super->size_file_entry - 1] |= DBLK_FILE_MASK;
            data_block_op(0, new_dblk_idx, new_dblk);
            free(new_dblk);
            return 0;
        }
    } else {
        raise_error("[0x2] Unable to create file entry in parent inode, full!", false);
        return -1;
    }
}

/**
 * get the index of the last '/'
 * \param path pointer to the full path
 * \return separator index
 */
unsigned get_fname_separator(const char *path) {
    unsigned separator_idx = strlen(path) - 1;
    while (path[separator_idx] != '/') {
        separator_idx--;
    }
    return separator_idx;
}

/**
 * Create file/dir in inode[p_inumber], this operation should be atomic actually
 * \param p_inumber the inode number of the parent dir
 * \param fname name of the new dir
 * \param type file type, 0-file, 1-dir
 *
 * \return 0 if success
 * \return -1 if unsuccess (raise error for now, so it will return 0 anyway)
 */
int add_file(const int p_inumber, const char *fname, const short type) {
    /*  Steps
        1. allocate a free inode and a free data node
        2. update parent dir inode
        3. write new inode */
    assert(type == 0 || type == 1);

    unsigned new_inumber = allocate_inode();
    if (new_inumber == 0) {
        raise_error("Failed to allocate inode, full!", true);
    }
    unsigned new_data_blk = allocate_datablock();
    if (new_data_blk == 0) {
        raise_error("Failed to allocate data block, full!", true);
    }

    if (write_parent_dir(p_inumber, fname, &new_inumber) == -1) {
        raise_error("Unable to add entry in parent inode, full!", true);
    }

    inode new_inode;
    new_inode.block[0] = new_data_blk;
    new_inode.block[1] = -1;
    new_inode.block[2] = -1;
    new_inode.block[3] = -1;
    new_inode.flag = type;
    new_inode.used_blocks_count = 1;
    new_inode.links_count = (new_inode.flag == 0) ? 1 : 2;  // 2 links for dir, one link for file
    if (type == 0) {
        // file
        new_inode.used_size = 0;
    } else {
        // dir
        new_inode.used_size = new_inode.used_blocks_count * BYTES_PER_BLOCK;
    }
    inode_op(0, new_inumber, &new_inode);

    char buf[BYTES_PER_BLOCK];
    clear(buf);
    data_block_op(0, new_inode.block[0], buf);

    return 0;
}

/**
 * \param path the new file path
 * \param type 0 - file, 1 - dir
 */
int add_file_helper(const char *path, unsigned type) {
    assert(type == 0 || type == 1);
    char *t_path = malloc(strlen(path) + 1);
    strcpy(t_path, path);
    unsigned separator_idx = get_fname_separator(t_path);
    char *new_dir_name = t_path + separator_idx + 1;
    if (strlen(new_dir_name) >= 12) {
        if (type == 0) {
            raise_error("File name too long", false);
        } else {
            raise_error("Dir name too long", false);
        }
        return -1;
    }
    int p_inumber;
    if (separator_idx == 0) {
        p_inumber = super->root_inum;
    } else {
        t_path[separator_idx] = '\0';
        p_inumber = get_inumber(0, t_path);
    }
    add_file(p_inumber, new_dir_name, type);
    free(t_path);
    return 0;
}

// /**
//  * write data to inode
//  *
//  * \param inumber the target inode number
//  * \param content the data to write
//  */
// size_t write_data(const int inumber, const char *content, size_t size, off_t offset) {
//     /* Steps
//     1. check the length of content
//     2. clear old data at write
//     3. write new data */

//     char buf[BYTES_PER_BLOCK];
//     inode node;
//     inode_op(2, inumber, &node);

//     unsigned n_dblk_required, n_dblk_written, dblk_idx, written_bytes, len;
//     n_dblk_required = (size % BYTES_PER_BLOCK == 0) ? size / BYTES_PER_BLOCK : size / BYTES_PER_BLOCK + 1;
//     n_dblk_written = 0;
//     written_bytes = 0;

//     while (n_dblk_written < n_dblk_required && n_dblk_written < node.used_blocks_count) {
//         len = size - written_bytes > BYTES_PER_BLOCK ? BYTES_PER_BLOCK : size - written_bytes;
//         if (len != BYTES_PER_BLOCK)
//             clear(buf);
//         memcpy(buf, content + written_bytes, len);
//         written_bytes += len;
//         dblk_idx = get_dblock_idx(&node, n_dblk_written);
//         data_block_op(0, dblk_idx, buf);
//         n_dblk_written++;
//     }

//     if (n_dblk_written < n_dblk_required && n_dblk_written == node.used_blocks_count) {
//         // allocate new data blk and write data
//         while (n_dblk_written < n_dblk_required) {
//             dblk_idx = inode_dblk_op(0, inumber);
//             if (dblk_idx == 0) {
//                 // This rarely happen
//                 raise_error("failed to allocate new data block!", true);
//                 return -1;
//             }
//             len = size - written_bytes > BYTES_PER_BLOCK ? BYTES_PER_BLOCK : size - written_bytes;
//             if (len != BYTES_PER_BLOCK)
//                 clear(buf);
//             memcpy(buf, content + written_bytes, len);
//             written_bytes += len;
//             data_block_op(0, dblk_idx, buf);
//             n_dblk_written++;
//         }
//     } else if (n_dblk_written == n_dblk_required && n_dblk_written < node.used_blocks_count) {
//         unsigned dblk_to_delete;
//         dblk_to_delete = node.used_blocks_count - n_dblk_written;
//         // delete unused data blk, no need to clear data
//         while (dblk_to_delete) {
//             dblk_idx = inode_dblk_op(1, inumber);
//             dblk_to_delete--;
//         }
//     }

//     node.used_size = size;
//     inode_op(0, inumber, &node);
//     return size;
// }

/**
 * Recursively remove the entry inode p_inumber:block p_dblk:entry p_fentry
 *
 * \param p_inumber parent inode inumber
 * \param p_dblk parent data blk
 * \param p_fentry parent data blk file entry
 *
 * \return 0 by default, other values are reserved
 */
int rm_node(const unsigned p_inumber, const unsigned p_dblk_idx, const unsigned p_fentry) {
    char buf[BYTES_PER_BLOCK];
    unsigned f_inumber;  // the inumber to rm
    unsigned blk_idx, blk_fentry;
    inode p_inode, f_inode;
    // read parent data region
    inode_op(2, p_inumber, &p_inode);
    data_block_op(2, get_dblock_idx(&p_inode, p_dblk_idx), buf);
    // make sure the file exists
    if ((buf[p_fentry * super->size_file_entry + super->size_file_entry - 1] & DBLK_FILE_MASK) == 0) {
        return 0;
    }
    memcpy(&f_inumber, buf + p_fentry * super->size_file_entry + super->size_filename, sizeof(unsigned));
    inode_op(2, f_inumber, &f_inode);
    // set this entry in parent data blk to be unused
    buf[p_fentry * super->size_file_entry + super->size_file_entry - 1] &= ~(DBLK_FILE_MASK);
    data_block_op(0, p_inumber, buf);

    if (f_inode.flag == 0) {
        // f is a file, mark the data blk as unused;
        for (blk_idx = 0; blk_idx < f_inode.used_blocks_count; blk_idx++) {
            // remove the last data block of f_inode
            inode_dblk_op(1, f_inumber);
        }
    } else {
        // f is a dir, recursively remove its content
        for (blk_idx = 0; blk_idx < f_inode.used_blocks_count; blk_idx++) {
            for (blk_fentry = 0; blk_fentry < BYTES_PER_BLOCK / super->size_file_entry; blk_fentry++) {
                rm_node(f_inumber, blk_idx, blk_fentry);
            }
        }
    }
    // mark the inode as unused
    inode_op(1, f_inumber, NULL);
    return 0;
}

/**
 * Get entry of fname in p_inumber
 * \param p_inumber parent inumber
 * \param fname file name
 * \param p_dblk out, dblk idx in parent data region
 * \param p_fentry out, entry idx in that data region
 * \return 0 - found, -1 - not found
 */
int get_fentry(const unsigned p_inumber, const char *fname, unsigned *p_dblk, unsigned *p_fentry) {
    char buf[BYTES_PER_BLOCK];
    inode p_inode;
    inode_op(2, p_inumber, &p_inode);

    *p_dblk = 0;
    while (*p_dblk < p_inode.used_blocks_count) {
        data_block_op(2, get_dblock_idx(&p_inode, *p_dblk), buf);
        *p_fentry = 0;
        while (*p_fentry < BYTES_PER_BLOCK / super->size_file_entry) {
            if ((buf[*p_fentry * super->size_file_entry + super->size_file_entry - 1] & DBLK_FILE_MASK) == 1 &&
                (strcmp(fname, buf + *p_fentry * super->size_file_entry) == 0)) {
                return 0;
            }
            (*p_fentry) += 1;
        }
        (*p_dblk) += 1;
    }
    return -1;
}

/**
 * Helper function for rm_node
 * \param path the path to remove
 */
int rm_node_helper(const char *path) {
    char *t_path = malloc(strlen(path) + 1);
    strcpy(t_path, path);
    unsigned separator_idx = get_fname_separator(t_path);
    char *fname = t_path + separator_idx + 1;
    if (strlen(fname) >= 12) {
        raise_error("Invalid filename, too long", false);
        return -1;
    }
    int p_inumber;
    unsigned p_fentry, p_dblk_idx;
    if (separator_idx == 0) {
        // rm file in in root dir
        p_inumber = super->root_inum;
    } else {
        t_path[separator_idx] = '\0';
        p_inumber = get_inumber(0, t_path);
    }
    if (get_fentry(p_inumber, fname, &p_dblk_idx, &p_fentry) == 0) {
        rm_node(p_inumber, p_dblk_idx, p_fentry);
    }
    free(t_path);
    return 0;
}

/* Filesystem interface */

static int do_getattr(const char *path, struct stat *st) {
    // GNU's definitions of the attributes
    // (http://www.gnu.org/software/libc/manual/html_node/Attribute-Meanings.html):
    //    st_uid:         The user ID of the file's owner.
    //    st_gid:         The group ID of the file.
    //    st_atime:       This is the last access time for the file.
    //    st_mtime:       This is the time of the last modification to the contents of the file.
    //    st_mode:        Specifies the mode of the file. This includes file type information (see Testing File
    //    Type) and the file permission bits (see Permission Bits). st_nlink:       The number of hard links to the
    //    file. This count keeps track of how many directories have entries for this file. If the count is ever
    //    decremented to zero, then the file itself is discarded as soon
    //                                    as no process still holds it open. Symbolic links are not counted in the
    //                                    total.
    //    st_size:        This specifies the size of a regular file in bytes. For files that are really devices this
    //    field isn't usually meaningful. For symbolic links this specifies the length of the file name the link
    //    refers to.

    st->st_uid = getuid();      // The owner of the file/directory is the user who mounted the filesystem
    st->st_gid = getgid();      // The group of the file/directory is the same as the group of the user who mounted the
                                // filesystem
    st->st_atime = time(NULL);  // The last "a"ccess of the file/directory is right now
    st->st_mtime = time(NULL);  // The last "m"odification of the file/directory is right now

    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
    } else {
        int inumber = get_inumber(super->root_inum, path);
        if (inumber >= 0) {  // inode found
            // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
            inode node;
            inode_op(2, inumber, &node);
            st->st_nlink = node.links_count;
            if (node.flag == 1) {
                /* is dir */
                st->st_mode = S_IFDIR | 0755;
                st->st_size = 4096;
            } else {
                /* is file */
                st->st_mode = S_IFREG | 0644;
                st->st_size = node.used_size;
            }
        } else {  // inode not found
            return -ENOENT;
        }
    }
    return 0;
}

static int do_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    // system guarantee the path to be a dir
    int inumber = get_inumber(super->root_inum, path);
    inode node;
    inode_op(2, inumber, &node);

    filler(buffer, ".", NULL, 0);   // Current Directory
    filler(buffer, "..", NULL, 0);  // Parent Directory

    char file_dblk[BYTES_PER_BLOCK];
    char fname[13];
    unsigned entry = 0;
    for (int i = 0; i < node.used_blocks_count; i++) {
        unsigned dblk_idx = get_dblock_idx(&node, i);
        data_block_op(2, dblk_idx, file_dblk);
        entry = 0;
        while (entry < BYTES_PER_BLOCK / super->size_file_entry) {
            if (file_dblk[entry * super->size_file_entry + (super->size_file_entry - 1)] & DBLK_FILE_MASK) {
                // here I do not check boundry
                strncpy(fname, file_dblk + entry * super->size_file_entry, super->size_filename);
                filler(buffer, fname, NULL, 0);
            }
            entry++;
        }
    }
    return 0;
}

static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
#ifdef DEBUG_ISFS
    printf("[%ld][read] Called\n", time(NULL));
    printf("--> Trying to read %s, %lu, %lu\n", path, offset, size);
#endif
    /**
     * Read data[offset] - data[offset + size] to buffer
     * size(buffer) = size, usually is 4096
     * offset = the offset of file, the file size might be bigger than buffer size
     */
    char buf[BYTES_PER_BLOCK];
    int inumber = get_inumber(super->root_inum, path);
    inode node;
    inode_op(2, inumber, &node);
    unsigned start_dblk_idx, nbytes_read, end_dblk_idx, len, old_offset;
    nbytes_read = 0;
    if (offset % BYTES_PER_BLOCK != 0) {
        // raise_error("[Read] Offset is not aligned with block size!", true);
        old_offset = offset;
        offset = (offset / BYTES_PER_BLOCK + 1) * BYTES_PER_BLOCK;
        data_block_op(2, get_dblock_idx(&node, old_offset / BYTES_PER_BLOCK), buf);
        len = offset - old_offset;
        memcpy(buffer + nbytes_read, buf + old_offset % BYTES_PER_BLOCK, len);
        nbytes_read += len;
        if (nbytes_read == size)
            return nbytes_read;
    }

    start_dblk_idx = offset / BYTES_PER_BLOCK;
    size = node.used_size - offset < size ? node.used_size - offset : size;
    end_dblk_idx = (size % BYTES_PER_BLOCK == 0 ? 0 : 1) + size / BYTES_PER_BLOCK + start_dblk_idx;
    end_dblk_idx = node.used_blocks_count < end_dblk_idx ? node.used_blocks_count : end_dblk_idx;
    while (start_dblk_idx < end_dblk_idx) {
        data_block_op(2, get_dblock_idx(&node, start_dblk_idx), buf);
        len = size - nbytes_read > BYTES_PER_BLOCK ? BYTES_PER_BLOCK : size - nbytes_read;
        memcpy(buffer + nbytes_read, buf, len);
        nbytes_read += len;
        start_dblk_idx++;
    }
    return nbytes_read;
}

static int do_mkdir(const char *path, mode_t mode) {
    // System will deal with "File exists" error, so we just need to create the true path
    add_file_helper(path, 1);
    return 0;
}

static int do_mknod(const char *path, mode_t mode, dev_t rdev) {
    // System will deal with "File exists" error, so we just need to create the true path
    add_file_helper(path, 0);
    return 0;
}

static int do_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *info) {
#ifdef DEBUG_ISFS
    printf("[%ld][write] Called\n", time(NULL));
    printf("--> Write to File %s, size = %ld, offset = %ld, len(buffer) = %lu.\n", path, size, offset, strlen(buffer));
#endif
    /**
     * Write buffer content to data[offset] - data[offset + size]
     * size(buffer) = size, usually is 4096
     * offset = the offset of file, the file size might be bigger than buffer size
     */
    int inumber = strcmp(path, "/") == 0 ? 0 : get_inumber(super->root_inum, path);
    inode node;
    inode_op(2, inumber, &node);
    char buf[BYTES_PER_BLOCK];
    unsigned start_dblk_idx, nbytes_written, end_dblk_idx, len, dblk_idx, old_offset;
    nbytes_written = 0;
    if (offset % BYTES_PER_BLOCK != 0) {
        // raise_error("[Write] Offset is not aligned with block size!", true);
        old_offset = offset;
        offset = (offset / BYTES_PER_BLOCK + 1) * BYTES_PER_BLOCK;
        data_block_op(2, get_dblock_idx(&node, old_offset / BYTES_PER_BLOCK), buf);
        len = offset - old_offset;
        memcpy(buf + old_offset % BYTES_PER_BLOCK, buffer + nbytes_written, len);
        data_block_op(0, get_dblock_idx(&node, old_offset / BYTES_PER_BLOCK), buf);
        nbytes_written += len;
        if (nbytes_written == size)
            return nbytes_written;
    }

    start_dblk_idx = offset / BYTES_PER_BLOCK;
    if (start_dblk_idx > node.used_blocks_count) {
        raise_error("[Write] Parameter Error!", false);
        return 0;
    }
    end_dblk_idx = (size % BYTES_PER_BLOCK == 0 ? 0 : 1) + size / BYTES_PER_BLOCK + start_dblk_idx;

    while (start_dblk_idx < end_dblk_idx) {
        if (start_dblk_idx < node.used_blocks_count) {
            dblk_idx = get_dblock_idx(&node, start_dblk_idx);
        } else {
            // start_dblk_idx == node.used_blocks_count
            dblk_idx = inode_dblk_op(0, inumber);
        }
        len = size - nbytes_written > BYTES_PER_BLOCK ? BYTES_PER_BLOCK : size - nbytes_written;
        clear(buf);
        memcpy(buf, buffer + nbytes_written, len);
        data_block_op(0, dblk_idx, buf);
        nbytes_written += len;
        start_dblk_idx++;
    }

    // read the latest inode
    inode_op(2, inumber, &node);
    int n_dblk_to_delete = node.used_blocks_count - end_dblk_idx;
    // only happens when truncating file
    while (n_dblk_to_delete > 0) {
        inode_dblk_op(1, inumber);
        n_dblk_to_delete--;
    }
    node.used_size = offset == 0 ? nbytes_written : node.used_size + nbytes_written;

    inode_op(0, inumber, &node);
    return nbytes_written;
}

static int do_unlink(const char *path) {
    rm_node_helper(path);
    return 0;
}

static int do_rmdir(const char *path) {
    // recursively remove everything
    if (strcmp(path, "/") == 0) {
        raise_error("Unable to remove root dir /", false);
        return -1;
    }
    rm_node_helper(path);
    return 0;
}

static struct fuse_operations operations = {.getattr = do_getattr,
                                            .readdir = do_readdir,
                                            .read = do_read,
                                            .mkdir = do_mkdir,
                                            .mknod = do_mknod,
                                            .write = do_write,
                                            .unlink = do_unlink,
                                            .rmdir = do_rmdir};

int main(int argc, char *argv[]) {
    int fuse_stat;
    mount_isfs();
    fuse_stat = fuse_main(argc, argv, &operations, NULL);
    unmount_isfs();
    return fuse_stat;
}
