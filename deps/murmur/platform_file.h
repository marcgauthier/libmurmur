#ifndef MURMUR_PLATFORM_FILE_H
#define MURMUR_PLATFORM_FILE_H
#include <sys/types.h>
#include <stddef.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#include <direct.h>
#ifdef __cplusplus
extern "C" {
#endif
int murmur_file_stat(const char *path, struct stat *st);
int murmur_file_lstat(const char *path, struct stat *st);
int murmur_file_open(const char *path, int flags, ...);
int murmur_file_mkdir(const char *path, int mode);
int murmur_file_unlink(const char *path);
int murmur_file_rename(const char *from, const char *to);
int murmur_file_link(const char *from, const char *to);
ssize_t murmur_file_pread(int fd, void *data, size_t size, long long offset);
#ifdef __cplusplus
}
#endif
#define stat(path, st) murmur_file_stat(path, st)
#define lstat(path, st) murmur_file_lstat(path, st)
#define open murmur_file_open
#define mkdir murmur_file_mkdir
#define unlink murmur_file_unlink
#define rename murmur_file_rename
#define link murmur_file_link
#define pread murmur_file_pread
#define fsync _commit
#endif
#endif
