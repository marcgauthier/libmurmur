#define _POSIX_C_SOURCE 200809L
#include "tool.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <termios.h>
#endif
#include <unistd.h>

#include "libmurmur.h"
#include "deps/keyring/sha256.h"
#include "deps/murmur/open.h"
#include "sqlite3.h"

int murmur_sqlite_shell_main(int argc, char **argv);

static uint8_t session_key[32];
static int have_key, passphrase_fd = -1, failed, exit_requested, exit_code;
static sqlite3_vfs *platform_vfs;
static int (*native_open)(sqlite3_vfs *, const char *, sqlite3_file *, int, int *);
static size_t native_file_size;

/* Extra space follows the native file object. Only xClose is intercepted;
 * every byte/locking operation still receives the original native object. */
typedef struct {
  sqlite3_io_methods methods;
  const sqlite3_io_methods *native_methods;
  uint64_t store_ref;
  int writable;
} ToolFile;

static void wipe(void *ptr, size_t n) {
  volatile unsigned char *p = ptr;
  while (n--) *p++ = 0;
}

static void clear_key(void) { wipe(session_key, sizeof(session_key)); }

static int error(const char *message) {
  fprintf(stderr, "sqlite3-murmur: %s\n", message);
  return SQLITE_CANTOPEN;
}

int murmur_tool_status(int status) {
  return exit_requested && exit_code ? exit_code : status ? status : failed;
}
void murmur_tool_exit_code(int status) { exit_requested = 1; exit_code = status; }
int murmur_tool_exiting(void) { return exit_requested; }

void murmur_tool_usage(void) {
  fprintf(stderr,
      "Murmur storage: encrypted RocksDB directories only.\n"
      "  --passphrase-fd N   Read one passphrase line from descriptor N\n"
      "Otherwise a hidden passphrase prompt uses /dev/tty, independently of SQL stdin.\n"
      "New stores: AES-256-GCM, zstd3, Argon2id keyring protection.\n"
      "One session credential is used for .open, ATTACH, and encrypted backups.\n"
      "WAL, alternative VFSes, append/ZIP/deserialize database modes,\n"
      ".open --new, and .backup --async are unsupported.\n\n");
}

static volatile sig_atomic_t prompt_signal;
static void cancel_prompt(int signum) { prompt_signal = signum; }

#ifdef _WIN32
static HANDLE prompt_console = INVALID_HANDLE_VALUE;
static DWORD prompt_console_mode;
static BOOL WINAPI cancel_console(DWORD event) {
  if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT ||
      event == CTRL_LOGOFF_EVENT || event == CTRL_SHUTDOWN_EVENT) {
    if (prompt_console != INVALID_HANDLE_VALUE) SetConsoleMode(prompt_console, prompt_console_mode);
    clear_key();
    ExitProcess(130);
  }
  return FALSE;
}

static int console_secret(const char *prompt, char *out, size_t cap) {
  WCHAR wide[4097] = {0};
  DWORD count = 0;
  int rc = -1;
  HANDLE input = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  if (input == INVALID_HANDLE_VALUE) return -1;
  if (!GetConsoleMode(input, &prompt_console_mode)) { CloseHandle(input); return -1; }
  prompt_console = input;
  if (!SetConsoleCtrlHandler(cancel_console, TRUE)) goto done;
  if (!SetConsoleMode(input, (prompt_console_mode | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) & ~ENABLE_ECHO_INPUT)) goto restore;
  fputs(prompt, stderr); fflush(stderr);
  if (ReadConsoleW(input, wide, 4096, &count, NULL) && count) {
    while (count && (wide[count-1] == L'\n' || wide[count-1] == L'\r')) --count;
    if (count && count < 4096) {
      int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, (int)count, out, (int)cap-1, NULL, NULL);
      if (bytes > 0) { out[bytes] = 0; rc = 0; }
    }
  }
restore:
  if (!SetConsoleMode(input, prompt_console_mode)) rc = -1;
  SetConsoleCtrlHandler(cancel_console, FALSE);
done:
  prompt_console = INVALID_HANDLE_VALUE;
  CloseHandle(input);
  wipe(wide, sizeof(wide));
  fputc('\n', stderr);
  return rc;
}
#endif

/* Bounded, unbuffered input: never read ahead into a SQL input stream. */
static int read_secret(int fd, char *out, size_t cap) {
  size_t n = 0;
  int ended = 0;
  while (!prompt_signal) {
    unsigned char ch;
    ssize_t count = read(fd, &ch, 1);
    if (count < 0 && errno == EINTR && !prompt_signal) continue;
    if (count < 0) return -1;
    if (!count || ch == '\n') { ended = 1; break; }
    if (!ch || n + 1 >= cap) return -1;
    out[n++] = (char)ch;
  }
  if (n && out[n - 1] == '\r') --n;
  out[n] = 0;
  return ended && n ? 0 : -1;
}

static int credential(int creating) {
  char secret[4097] = {0}, confirm[4097] = {0};
  int fd = passphrase_fd, rc = -1;
#ifndef _WIN32
  struct termios previous;
  const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
  struct sigaction old_actions[4], action;
  int installed = 0, hidden = 0;
  if (have_key) return SQLITE_OK;
  prompt_signal = 0;
  if (fd < 0) {
    fd = open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (fd < 0) return error("no controlling terminal; use --passphrase-fd N for scripts");
    if (tcgetattr(fd, &previous) != 0) goto done;
  }
  memset(&action, 0, sizeof(action));
  action.sa_handler = cancel_prompt;
  sigemptyset(&action.sa_mask);
  for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i) {
    if (sigaction(signals[i], &action, &old_actions[i]) != 0) goto done;
    ++installed;
  }
  if (passphrase_fd < 0) {
    struct termios quiet = previous;
    quiet.c_lflag &= ~(ECHO | ECHONL);
    if (tcsetattr(fd, TCSAFLUSH, &quiet) != 0) goto done;
    hidden = 1;
    if (write(fd, "Passphrase: ", 12) < 0) goto done;
  }
  if (read_secret(fd, secret, sizeof(secret)) != 0) goto done;
  if (passphrase_fd < 0 && creating) {
    if (write(fd, "\nConfirm passphrase: ", 21) < 0) goto done;
    if (read_secret(fd, confirm, sizeof(confirm)) != 0) goto done;
    if (strcmp(secret, confirm) != 0) {
      error("passphrases do not match");
      goto done;
    }
  }
#else
  if (have_key) return SQLITE_OK;
  prompt_signal = 0;
  if (fd >= 0) {
    if (read_secret(fd, secret, sizeof(secret)) != 0) goto done;
  } else {
    if (console_secret("Passphrase: ", secret, sizeof(secret)) != 0) goto done;
    if (creating && (console_secret("Confirm passphrase: ", confirm, sizeof(confirm)) != 0 ||
                     strcmp(secret, confirm) != 0)) goto done;
  }
#endif
  /* Same convention as murmur-admin, including its 64-hex exception. */
  int raw = strlen(secret) == 64;
  for (int i = 0; raw && i < 32; ++i) {
    unsigned value = 0;
    for (int j = 0; j < 2; ++j) {
      unsigned char c = (unsigned char)secret[2 * i + j];
      int digit = c >= '0' && c <= '9' ? c - '0' :
                  c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                  c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
      if (digit < 0) { raw = 0; break; }
      value = value * 16 + (unsigned)digit;
    }
    session_key[i] = (uint8_t)value;
  }
  if (!raw) murmur_sha256((const uint8_t *)secret, strlen(secret), session_key);
  have_key = 1;
  rc = 0;
done:
  wipe(secret, sizeof(secret));
  wipe(confirm, sizeof(confirm));
#ifndef _WIN32
  if (passphrase_fd < 0) {
    if (hidden) {
      /* Retry restoration if a second signal interrupts tcsetattr. */
      int restored;
      do { restored = tcsetattr(fd, TCSANOW, &previous); } while (restored < 0 && errno == EINTR);
      if (restored < 0) rc = -1;
      if (write(fd, "\n", 1) < 0) rc = -1;
    }
    close(fd);
  }
  if (prompt_signal) rc = -1;
  for (int i = installed - 1; i >= 0; --i)
    (void)sigaction(signals[i], &old_actions[i], NULL);
#endif
  if (rc) {
    clear_key();
    have_key = 0;
    return error("passphrase input failed or was cancelled (nonempty input, maximum 4096 bytes)");
  }
  return SQLITE_OK;
}

/* Reject regular files and unrelated directories before RocksDB can create
 * anything. Empty directories are accepted as new destinations. */
static int classify_store(const char *name, int flags, int *creating) {
  struct stat st;
  *creating = 0;
  if (stat(name, &st) != 0) {
    if (errno != ENOENT) return error("cannot inspect database path");
    *creating = 1;
  } else {
    if (!S_ISDIR(st.st_mode)) return error("database must be a Murmur directory, not a SQLite file");
    char *current = sqlite3_mprintf("%s/CURRENT", name);
    if (!current) return SQLITE_NOMEM;
    int exists = stat(current, &st) == 0;
    int stat_error = exists ? 0 : errno;
    sqlite3_free(current);
    if (stat_error && stat_error != ENOENT) return error("cannot inspect Murmur CURRENT file");
    if (exists && !S_ISREG(st.st_mode)) return error("Murmur CURRENT must be a regular file");
    if (!exists) {
      DIR *dir = opendir(name);
      if (!dir) return error("cannot inspect database directory");
      struct dirent *entry;
      int empty = 1;
      errno = 0;
      while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
          empty = 0;
          break;
        }
      }
      int read_error = errno;
      closedir(dir);
      if (read_error) return error("cannot read database directory");
      if (!empty) return error("directory is not a Murmur store or an empty destination");
      *creating = 1;
    }
  }
  if (*creating && (!(flags & SQLITE_OPEN_CREATE) || (flags & SQLITE_OPEN_READONLY)))
    return error("database does not exist");
  return SQLITE_OK;
}

static int file_pragma(sqlite3_file *file, const char *name, const char *value) {
  char *args[4] = {NULL, (char *)name, (char *)value, NULL};
  int rc = file->pMethods->xFileControl(file, SQLITE_FCNTL_PRAGMA, args);
  sqlite3_free(args[0]);
  return rc;
}

static int tool_close(sqlite3_file *file) {
  ToolFile *extra = (ToolFile *)((unsigned char *)file + native_file_size);
  uint64_t ref = extra->store_ref;
  const sqlite3_io_methods *methods = extra->native_methods;
  /* Closing SQLite has already rolled back unfinished transactions. Unlike
   * the native asynchronous xSync, this barrier reports final flush errors. */
  int rc = extra->writable ? nvStoreFlush(ref) : SQLITE_OK;
  file->pMethods = methods;
  int close_rc = methods->xClose(file);
  int ref_rc = nvCloseStoreRef(ref);
  if (rc == SQLITE_OK) rc = close_rc;
  if (rc == SQLITE_OK) rc = ref_rc;
  if (rc != SQLITE_OK) {
    failed = 1;
    fprintf(stderr, "sqlite3-murmur: store close/flush failed (%d)\n", rc);
  }
  return rc;
}

static int tool_open(sqlite3_vfs *vfs, const char *name, sqlite3_file *file,
                     int flags, int *out_flags) {
  int creating = 0, rc;
  if (!(flags & SQLITE_OPEN_MAIN_DB)) return native_open(vfs, name, file, flags, out_flags);
  file->pMethods = NULL;
  if (!name) return SQLITE_CANTOPEN;
  rc = classify_store(name, flags, &creating);
  if (rc != SQLITE_OK) return rc;
  rc = credential(creating);
  if (rc != SQLITE_OK) return rc;
  rc = native_open(vfs, name, file, flags, out_flags);
  if (rc != SQLITE_OK) {
    error("cannot open Murmur store (check permissions and whether another process holds its lock)");
    return rc;
  }
  char hex[65];
  static const char digits[] = "0123456789abcdef";
  for (int i = 0; i < 32; ++i) {
    hex[2 * i] = digits[session_key[i] >> 4];
    hex[2 * i + 1] = digits[session_key[i] & 15];
  }
  hex[64] = 0;
  rc = file_pragma(file, "key", hex);
  wipe(hex, sizeof(hex));
  if (rc == SQLITE_OK && creating) rc = file_pragma(file, "murmur_kdf", "argon2id");
  if (rc != SQLITE_OK) {
    error("cannot unlock or provision store; check the passphrase and store integrity");
    file->pMethods->xClose(file);
    file->pMethods = NULL;
    return rc;
  }
  ToolFile *extra = (ToolFile *)((unsigned char *)file + native_file_size);
  void *db = NULL, *store = NULL;
  rc = nvOpenStoreRef(name, 0, 0, &extra->store_ref, &db, &store);
  if (rc != SQLITE_OK) {
    file->pMethods->xClose(file);
    file->pMethods = NULL;
    return rc;
  }
  extra->native_methods = file->pMethods;
  extra->methods = *file->pMethods;
  extra->methods.xClose = tool_close;
  extra->writable = !(flags & SQLITE_OPEN_READONLY);
  file->pMethods = &extra->methods;
  return SQLITE_OK;
}

/* Loading extensions is an OS operation, independent of database storage. */
static void *tool_dlopen(sqlite3_vfs *vfs, const char *path) {
  (void)vfs;
  return platform_vfs->xDlOpen(platform_vfs, path);
}
static void tool_dlerror(sqlite3_vfs *vfs, int n, char *out) {
  (void)vfs;
  platform_vfs->xDlError(platform_vfs, n, out);
}
static void (*tool_dlsym(sqlite3_vfs *vfs, void *lib, const char *symbol))(void) {
  (void)vfs;
  return platform_vfs->xDlSym(platform_vfs, lib, symbol);
}
static void tool_dlclose(sqlite3_vfs *vfs, void *lib) {
  (void)vfs;
  platform_vfs->xDlClose(platform_vfs, lib);
}

void murmur_tool_init(void) {
  if (murmur_init() != SQLITE_OK) { error("SQLite initialization failed"); exit(1); }
  platform_vfs = sqlite3_vfs_find(NULL);
  if (!platform_vfs || murmur_vfs_register(0, 0) != SQLITE_OK) {
    error("Murmur VFS registration failed"); exit(1);
  }
  sqlite3_vfs *vfs = sqlite3_vfs_find("sqlite-murmur");
  native_open = vfs->xOpen;
  size_t align = _Alignof(ToolFile);
  native_file_size = ((size_t)vfs->szOsFile + align - 1) / align * align;
  vfs->szOsFile = (int)(native_file_size + sizeof(ToolFile));
  vfs->xOpen = tool_open;
  if (platform_vfs->xDlOpen && platform_vfs->xDlError &&
      platform_vfs->xDlSym && platform_vfs->xDlClose) {
    vfs->xDlOpen = tool_dlopen;
    vfs->xDlError = tool_dlerror;
    vfs->xDlSym = tool_dlsym;
    vfs->xDlClose = tool_dlclose;
  }
  /* Keep the platform object alive for native delegation, but remove public
   * access to alternative disk formats through URI vfs= or -vfs. */
  for (sqlite3_vfs *p = sqlite3_vfs_find(NULL), *next; p; p = next) {
    next = p->pNext;
    if (p != vfs) sqlite3_vfs_unregister(p);
  }
  if (sqlite3_vfs_register(vfs, 1) != SQLITE_OK) { error("cannot select Murmur VFS"); exit(1); }
}

int main(int argc, char **argv) {
  int count = 1;
  atexit(clear_key);
  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--")) {
      while (i < argc) argv[count++] = argv[i++];
      break;
    }
    const char *value = NULL;
    if (!strcmp(argv[i], "--passphrase-fd")) {
      if (++i == argc) return error("--passphrase-fd requires a descriptor") != 0;
      value = argv[i];
    } else if (!strncmp(argv[i], "--passphrase-fd=", 16)) {
      value = argv[i] + 16;
    }
    if (value) {
      char *end = NULL;
      errno = 0;
      long fd = strtol(value, &end, 10);
      if (passphrase_fd >= 0 || !*value || *end || errno || fd < 0 || fd > INT_MAX ||
#ifdef _WIN32
          _get_osfhandle((int)fd) == -1)
#else
          fcntl((int)fd, F_GETFD) < 0)
#endif
        return error("--passphrase-fd requires one valid, open descriptor") != 0;
      passphrase_fd = (int)fd;
    } else {
      argv[count++] = argv[i];
    }
  }
  argv[count] = NULL;
  int rc = murmur_sqlite_shell_main(count, argv);
  murmur_shutdown();
  clear_key();
  return rc ? rc : failed;
}
