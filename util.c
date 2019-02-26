#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "util.h"

void get_file_size(char *dst, const char *path, int len)
{
    struct stat st;
    memset(dst, 0, len);

    if (path[0] == '/') {
        stat(path + 1, &st);
    } else {
        stat(path, &st);
    }

    snprintf(dst, len, "%ld", st.st_size);
    dst[strlen(dst)] = '\0';

    fprintf(stderr, "Len: %ld, size: %ld\n", strlen(dst), sizeof(dst)); 
}

int check_path(const char *path)
{
    return path[0] && path[0] == '/' && strchr(path, '\\') == NULL &&
        strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
        !ends_with(path, "/..") && !ends_with(path, "/.");
}


int ends_with(const char *s, const char *sub)
{
	size_t slen = strlen(s);
	size_t sublen = strlen(sub);
	if (slen < sublen) {
		return 0;
	}

	return memcmp(s + slen - sublen, sub, sublen) == 0;
}

uint8_t hex_to_uint(uint8_t c)
{
	if ('0' <= c && c <= '9') {
		return (uint8_t)(c - '0');
	}
	if ('A' <= c && c <= 'F') {
		return (uint8_t)(c - 'A' + 10);
	}
	if ('a' <= c && c <= 'f') {
		return (uint8_t)(c - 'a' + 10);
	}

	return 0;
}

char *percent_decode(const uint8_t *value, size_t valuelen)
{
    char *res;

    res = malloc(valuelen + 1);
    if (valuelen > 3) {
        size_t i, j;
        for (i = 0, j = 0; i < valuelen -2;) {
            if (value[i] != '%' || !isxdigit(value[i + 1]) ||
                    !isxdigit(value[i + 2])) {
                res[j++] = (char)value[i++];
                continue;
            }
            res[j++] =
                (char)((hex_to_uint(value[i + 1]) << 4) + hex_to_uint(value[i + 2]));
            i += 3;
        }
        memcpy(&res[j], &value[i], 2);
        res[j + 2] = '\0';
    } else {
        memcpy(res, value, valuelen);
        res[valuelen] = '\0';
    }
 
    return res;
}


int fileExists(const char *filename)
{
    DIR *dp;
    struct dirent *d;
    int file_exists = 0;

    dp = opendir(".");
    if (dp == NULL) {
        fprintf(stderr, "Failed to open current directory: %s\n", strerror(errno));
        return -1;
    }

    while ((d = readdir(dp)) != NULL) {
        if (strncmp(d->d_name, filename, strlen(d->d_name)) == 0) {
            file_exists = 1;
            break;
        }
    }

    return file_exists;
}

void get_time(char *dst, int len)
{
    struct tm result;
    memset(dst, 0, len);
    
    time_t t = time(NULL);
    struct tm *tm_info = localtime_r(&t, &result);
    strftime(dst, len, "%c", tm_info);
    dst[strlen(dst)] = '\0';
}



