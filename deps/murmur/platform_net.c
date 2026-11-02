#include "platform_net.h"
#include <string.h>
int murmur_net_start(void) {
#ifdef _WIN32
  WSADATA data;
  return WSAStartup(MAKEWORD(2, 2), &data);
#else
  return 0;
#endif
}
void murmur_net_stop(void) {
#ifdef _WIN32
  WSACleanup();
#endif
}
int murmur_socket_nonblocking(murmur_socket_t s) {
#ifdef _WIN32
  u_long enabled = 1;
  return ioctlsocket(s, FIONBIO, &enabled);
#else
  int flags = fcntl(s, F_GETFL, 0);
  return flags < 0 ? -1 : fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif
}
int murmur_socket_pair(murmur_socket_t pair[2]) {
  struct sockaddr_in addresses[2];
  pair[0] = pair[1] = MURMUR_INVALID_SOCKET;
  for (int i = 0; i < 2; ++i) {
    socklen_t length = sizeof(addresses[i]);
    memset(&addresses[i], 0, sizeof(addresses[i]));
    addresses[i].sin_family = AF_INET;
    addresses[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    pair[i] = socket(AF_INET, SOCK_DGRAM, 0);
    if (pair[i] == MURMUR_INVALID_SOCKET ||
        bind(pair[i], (struct sockaddr *)&addresses[i], length) ||
        getsockname(pair[i], (struct sockaddr *)&addresses[i], &length))
      goto fail;
  }
  for (int i = 0; i < 2; ++i) {
    if (connect(pair[i], (struct sockaddr *)&addresses[1-i], sizeof(addresses[0])) ||
        murmur_socket_nonblocking(pair[i]))
      goto fail;
  }
  return 0;
fail:
  for (int i = 0; i < 2; ++i) {
    if (pair[i] != MURMUR_INVALID_SOCKET) murmur_socket_close(pair[i]);
    pair[i] = MURMUR_INVALID_SOCKET;
  }
  return -1;
}
