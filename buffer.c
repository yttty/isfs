#define _GNU_SOURCE
#include "buffer.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "my_io.h"

/************************ BUFFER CACHE START ************************/

#ifndef DEBUG_BUFFER
// The size of buffer cache is 10446 page * 8 block
#define SIZE_BUFFER_CACHE 10446 * 8
/*
 * The size of hash table is the nearest prime number which is larger
 * than sqrt(SIZE_BUFFER_CACHE), so the theoretical length of each entry
 * of hash table will be smaller than sqrt(SIZE_BUFFER_CACHE), so that
 * the worst case of search time will be O(1) + O(sqrt(SIZE_BUFFER_CACHE)),
 * which is smaller than n/4
 */
#define SIZE_HASH_TABLE 293
// Sync every 30s
#define SYNC_DELAY 30
#else
// For debugging only
#define SIZE_BUFFER_CACHE 6
#define SIZE_HASH_TABLE 3
#define SYNC_DELAY 2
#endif

// The file handle of block devide (USB)
int fd;
// Buffer cache
char *buffer_cache = NULL;
// Buffer block
typedef struct buffer_block {
    int physical_block_id;
    bool dirty;
    struct buffer_block *next;
    struct buffer_block *prev;
    char *block_ptr;  // point to the allocated memory address, should not change after init
} buffer_block;
buffer_block buffer_blocks[SIZE_BUFFER_CACHE];
// point to most recently used buffer
buffer_block *buffer_block_head;
// point to least recently used buffer
buffer_block *buffer_block_tail;
// track how many buffer blocks are used, increase only
unsigned int num_used_buffer;

// Hash Table
typedef struct hash_node {
    unsigned int physical_block_id;  // id of the corresponding physical block
    buffer_block *buffer_block_ptr;  // point to the corresponding buffer block
    struct hash_node *next;          // point to next element in hash table
} hash_node;
hash_node *hash_table[SIZE_HASH_TABLE];

// The num_buffer_read_requests & num_buffer_write_requests track the # buffer reads/writes
unsigned int num_buffer_read_requests;
unsigned int num_buffer_write_requests;

// declare inline functions
unsigned int hash_key(int);
void mark_dirty(buffer_block *);
void write_back(buffer_block *);

inline unsigned int hash_key(int pyhsical_block_id) { return pyhsical_block_id % SIZE_HASH_TABLE; }

/**
 * Remove the hash node of physical_block_id
 * WARNING: This function will halt the program if the node is not found
 * \param physical_block_id
 */
void remove_hash_node(unsigned int physical_block_id) {
    unsigned int key = hash_key(physical_block_id);
    hash_node *node = hash_table[key];
    assert(node != NULL);  // the node should exist
    // if the very first node is what we want
    if (node->physical_block_id == physical_block_id) {
        hash_table[key] = node->next;
        free(node);
    } else {
        while (node->next != NULL && node->next->physical_block_id != physical_block_id) {
            node = node->next;
        }
        assert(node->next != NULL && node->next->physical_block_id == physical_block_id);  // the node should exist
        hash_node *node_to_remove = node->next;
        node->next = node_to_remove->next;
        free(node_to_remove);
    }
}

/**
 * Insert a hash node of physical_block_id and buffer_block_ptr to the tail of hash table
 * WARNING: This function do not check duplication, call search_hash_table() in advance
 * \param physical_block_id
 * \param buffer_block_ptr
 */
void insert_hash_node(unsigned int physical_block_id, buffer_block *buffer_block_ptr) {
    hash_node *new_node = malloc(sizeof(hash_node *));
    new_node->physical_block_id = physical_block_id;
    new_node->buffer_block_ptr = buffer_block_ptr;
    new_node->next = NULL;

    unsigned int key = hash_key(physical_block_id);
    if (hash_table[key] == NULL) {
        // directly insert
        hash_table[key] = new_node;
    } else {
        // insert to the tail
        hash_node *node = hash_table[key];
        while (node->next != NULL) {
            node = node->next;
        }
        node->next = new_node;
    }
    return;
}

/**
 * Search for physical_block_id in hash table
 * \param physical_block_id the target
 * \return the node ptr if found
 * \return NULL is not found
 */
hash_node *search_hash_table(unsigned int physical_block_id) {
    unsigned int key = hash_key(physical_block_id);
    hash_node *node = hash_table[key];
    while (node != NULL) {
        if (node->physical_block_id == physical_block_id)
            return node;
        node = node->next;
    }
    return NULL;
}

/**
 * Initiate hash table, set all entry to NULL
 */
void init_hash_table() {
#ifdef DEBUG_BUFFER
    printf("Initiate buffer block hash table.\n");
#endif
    memset(hash_table, 0, sizeof(hash_table));
}

inline void mark_dirty(buffer_block *buffer_block_ptr) {
#ifdef DEBUG_BUFFER
    printf("Mark Dirty block %d.\n", buffer_block_ptr->physical_block_id);
#endif
    buffer_block_ptr->dirty = true;
}

inline void write_back(buffer_block *buffer_block_ptr) {
    if (buffer_block_ptr->dirty) {
#ifdef DEBUG_BUFFER
        printf("Write back block %d.\n", buffer_block_ptr->physical_block_id);
#endif
        io_write(fd, buffer_block_ptr->block_ptr, buffer_block_ptr->physical_block_id);
        buffer_block_ptr->dirty = false;
    }
}

/**
 * Mark the buffer block as most recent used
 * \param buffer_block_ptr the target buffer block
 */
void use_buffer(buffer_block *buffer_block_ptr) {
    // TODO
    buffer_block *old_head = buffer_block_head;
    buffer_block *new_head = buffer_block_ptr;
    if (old_head == new_head) {  // already the most recent used
        return;
    } else {                           // not the most recent used
        if (new_head->next != NULL) {  // new head is not tail
            new_head->next->prev = new_head->prev;
        } else {  // new head is the tail
            buffer_block_tail = new_head->prev;
        }
        new_head->prev->next = new_head->next;
        new_head->next = old_head;
        old_head->prev = new_head;
        new_head->prev = NULL;
        buffer_block_head = new_head;
    }
}

/**
 * Evict least recent used buffer block and return the buffer block index
 * \return the buffer block pointer
 */
buffer_block *evict_buffer() {
#ifdef DEBUG_BUFFER
    printf("Evict physical block %d\n", buffer_block_tail->physical_block_id);
#endif
    if (buffer_block_tail->physical_block_id != -1) {
        remove_hash_node(buffer_block_tail->physical_block_id);
        write_back(buffer_block_tail);
    }
    return buffer_block_tail;
}

/**
 * Load physical block to buffer cache, add to hash table
 * WARNING: make sure target physical block is not loaded
 * \param physical_block_id target physical block
 * \return the ptr to buffer block
 */
buffer_block *load_physical_block(unsigned int physical_block_id) {
#ifdef DEBUG_BUFFER
    printf("Load physical block %d.\n", physical_block_id);
#endif

    // TODO maybe no need to check
    assert(search_hash_table(physical_block_id) == NULL);

    // TODO mutex

    buffer_block *new_buffer_block_ptr;
    if (num_used_buffer < SIZE_BUFFER_CACHE) {
        // Choose an empty block
        unsigned int new_buffer_block_idx = 0;
        while (buffer_blocks[new_buffer_block_idx].physical_block_id != -1) {
            new_buffer_block_idx++;
        }
        new_buffer_block_ptr = &buffer_blocks[new_buffer_block_idx];
        num_used_buffer++;
    } else {  // or Evict a block
        new_buffer_block_ptr = evict_buffer();
    }
    // load data from physical device
    new_buffer_block_ptr->physical_block_id = physical_block_id;
    io_read(fd, new_buffer_block_ptr->block_ptr, physical_block_id);
    // add to hash table
    insert_hash_node(physical_block_id, new_buffer_block_ptr);

    // TODO mutex
    return new_buffer_block_ptr;
}

/**
 * Write everything back to physical block
 */
void buffer_sync() {
    // TODO acquire mutex
    for (int i = 0; i < SIZE_BUFFER_CACHE; i++) {
        if (buffer_blocks[i].dirty) {
#ifdef DEBUG_BUFFER
            printf("In buffer_sync(): Write back buffer block %d to physical block %d and set not dirty\n", i,
                   buffer_blocks[i].physical_block_id);
#endif
            io_write(fd, (void *) buffer_blocks[i].block_ptr, buffer_blocks[i].physical_block_id);
            buffer_blocks[i].dirty = false;
        }
    }
    // TODO release mutex
}

/**
 * \desc Read the `physical_block_id` block in block device into buffer cache,
 *       then copy from buffer cahce to `buf`
 * \param buf the read buffer
 * \param physical_block_id the block index in device (not buffer cache)
 */
void buffer_read(void *buf, unsigned int physical_block_id) {
    num_buffer_read_requests++;
    hash_node *hnode = search_hash_table(physical_block_id);
    if (hnode) {  // find target node
        memcpy(buf, hnode->buffer_block_ptr->block_ptr, block_size);
        use_buffer(hnode->buffer_block_ptr);
    } else {  // not found target node
        buffer_block *node = load_physical_block(physical_block_id);
        memcpy(buf, node->block_ptr, block_size);
        use_buffer(node);
    }
}

/**
 * \desc Write the data in `buf` to buffer cache and
 *       assume write to `physical_block_id` block in device
 * \param buf the write buffer
 * \param physical_block_id the block index in device (not buffer cache)
 */
void buffer_write(void *buf, unsigned int physical_block_id) {
    num_buffer_write_requests++;
    num_buffer_read_requests++;
    // TODO mutex
    hash_node *hnode = search_hash_table(physical_block_id);
    if (hnode) {  // find target node
        memcpy(hnode->buffer_block_ptr->block_ptr, buf, block_size);
        mark_dirty(hnode->buffer_block_ptr);
        use_buffer(hnode->buffer_block_ptr);
    } else {  // not found target node
        buffer_block *node = load_physical_block(physical_block_id);
        memcpy(node->block_ptr, buf, block_size);
        mark_dirty(node);
        use_buffer(node);
    }
}

/**
 * \desc Show reduced r/w
 */
void buffer_show_reduced_rw() {
    printf("----Buffer Statistics----\n");
    printf("Number of read requests: %d\n", num_buffer_read_requests);
    printf("Number of actual read: %d\n", num_read_requests);
    printf("Number of write requests: %d\n", num_buffer_write_requests);
    printf("Number of actual write: %d\n", num_write_requests);
    printf("Number of read reduced: %d\n", num_buffer_read_requests - num_read_requests);
    printf("Number of write reduced: %d\n", num_buffer_write_requests - num_write_requests);
    printf("-----------End-----------\n");
}

/**
 * Initiate buffer cache
 * \param devide the path of device, like /dev/sdb1
 */
void buffer_init(const char *device) {
    // Open block devide
#ifdef DEBUG_BUFFER
    printf("Open device for R/W.\n");
#endif
    if (fd >= 0) {
        close(fd);
    }
    fd = open(device, O_RDWR | O_DIRECT);
    if (fd < 0) {
        perror("Failed to open block device for read and write!\n");
        exit(1);
    }
#ifdef DEBUG_BUFFER
    printf("Device FD is %d.\n", fd);
#endif

    // Allocate the buffer cache in memory
#ifdef DEBUG_BUFFER
    printf("Allocate the buffer cache in memory.\n");
#endif
    int ret;
    ret = posix_memalign((void **) &buffer_cache, block_size, SIZE_BUFFER_CACHE * block_size);
    if (ret != 0) {
        perror("Failed to allocate buffer cache!\n");
        exit(1);
    }

    // Initiate buffer block list
#ifdef DEBUG_BUFFER
    printf("Initiate buffer block list.\n");
#endif
    num_buffer_read_requests = 0;
    num_buffer_write_requests = 0;
    num_used_buffer = 0;
    buffer_block_head = &buffer_blocks[0];
    buffer_block_tail = &buffer_blocks[SIZE_BUFFER_CACHE - 1];
    for (int i = 0; i < SIZE_BUFFER_CACHE; i++) {
        // id of the physical block, -1 means unused
        buffer_blocks[i].physical_block_id = -1;
        buffer_blocks[i].block_ptr = buffer_cache + i * block_size;
        buffer_blocks[i].dirty = false;
        if (i == 0) {
            buffer_blocks[i].prev = NULL;
            buffer_blocks[i].next = &buffer_blocks[i + 1];
        } else if (i == SIZE_BUFFER_CACHE - 1) {
            buffer_blocks[i].prev = &buffer_blocks[i - 1];
            buffer_blocks[i].next = NULL;
        } else {
            buffer_blocks[i].prev = &buffer_blocks[i - 1];
            buffer_blocks[i].next = &buffer_blocks[i + 1];
        }
    }

    // Initiate buffer block hash table
    init_hash_table();

#ifdef DEBUG_BUFFER
    printf("Finished initiation.\n");
#endif
}

#ifdef DEBUG_BUFFER
void test_buffer_cache() {
    buffer_init("/dev/sdb1");

    // test direct IO
    char *sa;
    char *sb;
    posix_memalign((void **) &sa, block_size, 512);
    posix_memalign((void **) &sb, block_size, 512);
    memset(sa, 'A', 512);
    memset(sb, 'B', 512);
    io_write(fd, sa, 100);
    io_read(fd, sb, 100);
    if (memcmp(sa, sb, 512) == 0) {
        printf("[INFO] Direct IO is normal!\n");
    } else {
        perror("[ERROR] Direct IO failed!\n");
        exit(-1);
    }

    printf("Sizeof buffer cache is %d\n", SIZE_BUFFER_CACHE);
    printf("Sizeof hash table is %d\n", SIZE_HASH_TABLE);

    // Use buffer
    char *sc = malloc(512);
    char *sd = malloc(512);
    memset(sc, 'C', 512);
    memset(sd, 'D', 512);
    sc[511] = 0;
    sd[511] = 0;
    buffer_write(sc, 101);
    buffer_write(sc, 102);
    buffer_write(sc, 103);
    buffer_write(sc, 104);
    buffer_write(sc, 105);
    buffer_write(sc, 106);

    buffer_read(sd, 107);
    buffer_read(sd, 108);
    buffer_read(sd, 109);
    buffer_read(sd, 110);
    buffer_read(sd, 111);
    buffer_read(sd, 112);

    buffer_read(sd, 101);
    printf("%s\n", sd);
    buffer_read(sd, 102);
    printf("%s\n", sd);
    buffer_read(sd, 103);
    printf("%s\n", sd);
    buffer_read(sd, 104);
    printf("%s\n", sd);
    buffer_read(sd, 105);
    printf("%s\n", sd);
    buffer_read(sd, 106);
    printf("%s\n", sd);

    // buffer_sync();

    printf("[INFO] Clear all buffer\n");
    init_hash_table();
    memset(buffer_cache, 0, SIZE_BUFFER_CACHE * block_size);
    buffer_block_head = &buffer_blocks[0];
    buffer_block_tail = &buffer_blocks[SIZE_BUFFER_CACHE - 1];
    for (int i = 0; i < SIZE_BUFFER_CACHE; i++) {
        buffer_blocks[i].physical_block_id = -1;
        buffer_blocks[i].block_ptr = buffer_cache + i * block_size;
        buffer_blocks[i].dirty = false;
        if (i == 0) {
            buffer_blocks[i].prev = NULL;
            buffer_blocks[i].next = &buffer_blocks[i + 1];
        } else if (i == SIZE_BUFFER_CACHE - 1) {
            buffer_blocks[i].prev = &buffer_blocks[i - 1];
            buffer_blocks[i].next = NULL;
        } else {
            buffer_blocks[i].prev = &buffer_blocks[i - 1];
            buffer_blocks[i].next = &buffer_blocks[i + 1];
        }
    }

    buffer_read(sd, 102);
    if (memcmp(sc, sd, 512) == 0) {
        printf("[INFO] Buffer IO is normal!\n");
    } else {
        perror("[ERROR] Buffer IO failed!\n");
        printf("%s", sd);
        exit(-1);
    }

    buffer_sync();
    buffer_show_reduced_rw();
}

int main(int argc, char const *argv[]) {
    test_buffer_cache();
    return 0;
}
#endif

/************************ BUFFER CACHE END ************************/
