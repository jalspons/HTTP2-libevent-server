#ifndef UTIL_H
#define UTIL_H

#define TIME_BUF_LEN 30
#define FILE_SIZE_HEADER_LEN 21


void get_file_size(char *dst, const char *path, int len);

int check_path(const char *path);

int ends_with(const char *s, const char *sub);

uint8_t hex_to_uint(uint8_t c);

char *percent_decode(const uint8_t *value, size_t valuelen);

int file_exists(const char *filename);

void get_time(char *dst, int len);


#endif // UTIL_H
