#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <windows.h>
#include "platform_file.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s (%d)\n", #x, __LINE__); return 1; } } while (0)
int main(void) {
  char root[MAX_PATH], name[MAX_PATH], moved[MAX_PATH], pin[MAX_PATH];
  CHECK(GetTempPathA(sizeof(root), root));
  snprintf(name, sizeof(name), "%smurmur-%lu-\xc3\xa9.bin", root, GetCurrentProcessId());
  snprintf(moved, sizeof(moved), "%smurmur-%lu moved.bin", root, GetCurrentProcessId());
  snprintf(pin, sizeof(pin), "%smurmur-%lu pin.bin", root, GetCurrentProcessId());
  const char data[] = {'a', '\r', '\n', 0x1a, 'z'};
  int fd = open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(fd >= 0);
  CHECK(write(fd, data, sizeof(data)) == sizeof(data));
  CHECK(fsync(fd) == 0);
  char readback[sizeof(data)];
  CHECK(pread(fd, readback, sizeof(readback), 0) == sizeof(readback));
  CHECK(memcmp(data, readback, sizeof(data)) == 0);
  CHECK(lseek(fd, 0, SEEK_CUR) == sizeof(data));
  CHECK(pread(fd, readback, sizeof(readback), sizeof(data)) == 0);
  CHECK(close(fd) == 0);
  CHECK(link(name, pin) == 0);
  CHECK(rename(name, moved) == 0);
  CHECK(unlink(moved) == 0);
  fd = open(pin, O_RDONLY); CHECK(fd >= 0);
  CHECK(read(fd, readback, sizeof(readback)) == sizeof(readback));
  CHECK(memcmp(data, readback, sizeof(data)) == 0);
  CHECK(close(fd) == 0); CHECK(unlink(pin) == 0);
  return 0;
}
