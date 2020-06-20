#ifndef MY_IO_H
#define MY_IO_H

#include <assert.h>
#include <unistd.h>

unsigned int num_read_requests = 0;
unsigned int num_write_requests = 0;
size_t block_size = 512;  // (bytes)

// The num_read_requests & num_write_requests can be used to show the # reads/writes
// decrease when using buffer cache

void io_read(int fd, void *buf, int index) {
  off_t offset = index * block_size;
  ssize_t read_bytes = pread(fd, buf, block_size, offset);
  assert(read_bytes == block_size);  // the read_bytes should equal to block_size everytime
  num_read_requests++;
}

void io_write(int fd, void *buf, int index) {
  off_t offset = index * block_size;
  ssize_t write_bytes = pwrite(fd, buf, block_size, offset);
  assert(write_bytes == block_size);  // the write_bytes should equal to block_size everytime
  num_write_requests++;
}

#endif