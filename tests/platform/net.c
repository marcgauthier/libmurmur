#include "platform_net.h"
#include <stdio.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s\n", #x); return 1; } } while (0)
int main(void) {
  murmur_socket_t pair[2];
  char data[8];
  CHECK(murmur_net_start() == 0);
  CHECK(murmur_socket_pair(pair) == 0);
  CHECK(recv(pair[0], data, sizeof(data), 0) < 0);
  CHECK(send(pair[1], "wake", 4, 0) == 4);
  murmur_pollfd p = {0};
  p.fd = pair[0]; p.events = POLLIN;
  CHECK(murmur_poll(&p, 1, 1000) == 1);
  CHECK((p.revents & POLLIN) != 0);
  CHECK(recv(pair[0], data, sizeof(data), 0) == 4);
  CHECK(recv(pair[0], data, sizeof(data), 0) < 0);
  murmur_socket_close(pair[0]); murmur_socket_close(pair[1]);
  murmur_net_stop();
  return 0;
}
