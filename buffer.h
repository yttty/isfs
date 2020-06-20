#ifndef BUFFER_H
#define BUFFER_H

void buffer_init(const char *device);
void buffer_show_reduced_rw();
void buffer_write(void *buf, unsigned int physical_block_id);
void buffer_read(void *buf, unsigned int physical_block_id);
void buffer_sync();

#endif