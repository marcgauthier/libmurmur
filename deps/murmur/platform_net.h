/* Internal socket portability. Socket handles must never be stored in int on Windows. */
#ifndef MURMUR_PLATFORM_NET_H
#define MURMUR_PLATFORM_NET_H
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET murmur_socket_t;
#define MURMUR_INVALID_SOCKET INVALID_SOCKET
#define murmur_socket_close closesocket
#define murmur_poll WSAPoll
typedef WSAPOLLFD murmur_pollfd;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int murmur_socket_t;
#define MURMUR_INVALID_SOCKET (-1)
#define murmur_socket_close close
#define murmur_poll poll
typedef struct pollfd murmur_pollfd;
#endif
#ifdef __cplusplus
extern "C" {
#endif
int murmur_net_start(void);
void murmur_net_stop(void);
int murmur_socket_nonblocking(murmur_socket_t s);
/* Connected UDP sockets form a nonblocking, pollable wakeup channel. */
int murmur_socket_pair(murmur_socket_t pair[2]);
#ifdef __cplusplus
}
#endif
#endif
