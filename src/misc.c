/*
 * misc.c - useful client functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 * Copyright (c) 2008-2009 by Andreas Schneider <asn@cryptomilk.org>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#ifndef _WIN32
/* This is needed for a standard getpwuid_r on opensolaris */
#define _POSIX_PTHREAD_SEMANTICS
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/types.h>

#endif /* _WIN32 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */


#ifdef _WIN32

#ifndef _WIN32_IE
# define _WIN32_IE 0x0501 // SHGetSpecialFolderPath
#endif

#include <winsock2.h> // Must be the first to include
#include <ws2tcpip.h>
#include <shlobj.h>
#include <direct.h>
#include <netioapi.h>

#ifdef HAVE_IO_H
#include <io.h>
#endif /* HAVE_IO_H */

#endif /* _WIN32 */

#include "libssh/priv.h"
#include "libssh/misc.h"
#include "libssh/session.h"

#ifdef HAVE_LIBGCRYPT
#define GCRYPT_STRING "/gcrypt"
#else
#define GCRYPT_STRING ""
#endif

#ifdef HAVE_LIBCRYPTO
#define CRYPTO_STRING "/openssl"
#else
#define CRYPTO_STRING ""
#endif

#ifdef HAVE_LIBMBEDCRYPTO
#define MBED_STRING "/mbedtls"
#else
#define MBED_STRING ""
#endif

#ifdef WITH_ZLIB
#define ZLIB_STRING "/zlib"
#else
#define ZLIB_STRING ""
#endif

#define ARPA_DOMAIN_MAX_LEN 63

#if !defined(HAVE_TIMEGM)
#   if defined(HAVE__MKGMTIME)
#       define timegm _mkgmtime
#   else
#       define timegm portable_timegm
#   endif
#else
    time_t portable_timegm(struct tm *tm);
#endif


/**
 * @defgroup libssh_misc The SSH helper functions
 * @ingroup libssh
 *
 * Different helper functions used in the SSH Library.
 *
 * @{
 */

#ifdef _WIN32
char *ssh_get_user_home_dir(void)
{
  char tmp[PATH_MAX] = {0};
  char *szPath = NULL;

  if (SHGetSpecialFolderPathA(NULL, tmp, CSIDL_PROFILE, TRUE)) {
    szPath = malloc(strlen(tmp) + 1);
    if (szPath == NULL) {
      return NULL;
    }

    strcpy(szPath, tmp);
    return szPath;
  }

  return NULL;
}

/* we have read access on file */
int ssh_file_readaccess_ok(const char *file)
{
    if (_access(file, 4) < 0) {
        return 0;
    }

    return 1;
}

/**
 * @brief Check if the given path is an existing directory and that is
 * accessible for writing.
 *
 * @param[in] path Path to the directory to be checked
 *
 * @return Return 1 if the directory exists and is accessible; 0 otherwise
 * */
int ssh_dir_writeable(const char *path)
{
    struct _stat buffer;
    int rc;

    rc = _stat(path, &buffer);
    if (rc < 0) {
        return 0;
    }

    if ((buffer.st_mode & _S_IFDIR) && (buffer.st_mode & _S_IWRITE)) {
        return 1;
    }

    return 0;
}

#define SSH_USEC_IN_SEC         1000000LL
#define SSH_SECONDS_SINCE_1601  11644473600LL

int ssh_gettimeofday(struct timeval *__p, void *__t)
{
  union {
    unsigned long long ns100; /* time since 1 Jan 1601 in 100ns units */
    FILETIME ft;
  } now;

  GetSystemTimeAsFileTime (&now.ft);
  __p->tv_usec = (long) ((now.ns100 / 10LL) % SSH_USEC_IN_SEC);
  __p->tv_sec  = (long)(((now.ns100 / 10LL ) / SSH_USEC_IN_SEC) - SSH_SECONDS_SINCE_1601);

  return (0);
}

/**
 * @internal
 *
 * @brief Convert time in seconds since the Epoch to broken-down local time
 *
 * This is a helper used to provide localtime_r() like function interface
 * on Windows.
 *
 * @param timer    Pointer to a location storing the time_t which
 *                 represents the time in seconds since the Epoch.
 *
 * @param result   Pointer to a location where the broken-down time
 *                 (expressed as local time) should be stored.
 *
 * @returns        A pointer to the structure pointed to by the parameter
 *                 <tt>result</tt> on success, NULL on error with the errno
 *                 set to indicate the error.
 */
struct tm *ssh_localtime(const time_t *timer, struct tm *result)
{
    errno_t rc;
    rc = localtime_s(result, timer);
    if (rc != 0) {
        return NULL;
    }

    return result;
}

char *ssh_get_local_username(void)
{
    DWORD size = 0;
    char *user = NULL;
    int rc;

    /* get the size */
    GetUserName(NULL, &size);

    user = (char *)malloc(size);
    if (user == NULL) {
        return NULL;
    }

    if (GetUserName(user, &size)) {
        rc = ssh_check_username_syntax(user);
        if (rc == SSH_OK) {
            return user;
        }
    }

    free(user);

    return NULL;
}

int ssh_is_ipaddr_v4(const char *str)
{
    struct sockaddr_storage ss;
    int sslen = sizeof(ss);
    int rc = SOCKET_ERROR;

    /* WSAStringToAddressA thinks that 0.0.0 is a valid IP */
    if (strlen(str) < 7) {
        return 0;
    }

    rc = WSAStringToAddressA((LPSTR) str,
                             AF_INET,
                             NULL,
                             (struct sockaddr*)&ss,
                             &sslen);
    if (rc == 0) {
        return 1;
    }

    return 0;
}

int ssh_is_ipaddr(const char *str)
{
    int rc = SOCKET_ERROR;
    char *s = strdup(str);

    if (s == NULL) {
        return -1;
    }
    if (strchr(s, ':')) {
        struct sockaddr_storage ss;
        int sslen = sizeof(ss);
        char *network_interface = strchr(s, '%');

        /* link-local (IP:v6:addr%ifname). */
        if (network_interface != NULL) {
            rc = if_nametoindex(network_interface + 1);
            if (rc == 0) {
                free(s);
                return 0;
            }
            *network_interface = '\0';
        }
        rc = WSAStringToAddressA((LPSTR) s,
                                 AF_INET6,
                                 NULL,
                                 (struct sockaddr*)&ss,
                                 &sslen);
        if (rc == 0) {
            free(s);
            return 1;
        }
    }

    free(s);
    return ssh_is_ipaddr_v4(str);
}
#else /* _WIN32 */

#ifndef NSS_BUFLEN_PASSWD
#define NSS_BUFLEN_PASSWD 4096
#endif /* NSS_BUFLEN_PASSWD */

char *ssh_get_user_home_dir(void)
{
    char *szPath = NULL;
    struct passwd pwd;
    struct passwd *pwdbuf = NULL;
    char buf[NSS_BUFLEN_PASSWD] = {0};
    int rc;

    rc = getpwuid_r(getuid(), &pwd, buf, NSS_BUFLEN_PASSWD, &pwdbuf);
    if (rc != 0 || pwdbuf == NULL ) {
        szPath = getenv("HOME");
        if (szPath == NULL) {
            return NULL;
        }
        snprintf(buf, sizeof(buf), "%s", szPath);

        return strdup(buf);
    }

    szPath = strdup(pwd.pw_dir);

    return szPath;
}

/* we have read access on file */
int ssh_file_readaccess_ok(const char *file)
{
    if (access(file, R_OK) < 0) {
        return 0;
    }

    return 1;
}

/**
 * @brief Check if the given path is an existing directory and that is
 * accessible for writing.
 *
 * @param[in] path Path to the directory to be checked
 *
 * @return Return 1 if the directory exists and is accessible; 0 otherwise
 * */
int ssh_dir_writeable(const char *path)
{
    struct stat buffer;
    int rc;

    rc = stat(path, &buffer);
    if (rc < 0) {
        return 0;
    }

    if (S_ISDIR(buffer.st_mode) && (buffer.st_mode & S_IWRITE)) {
        return 1;
    }

    return 0;
}

char *ssh_get_local_username(void)
{
    struct passwd pwd;
    struct passwd *pwdbuf = NULL;
    char buf[NSS_BUFLEN_PASSWD];
    char *name = NULL;
    int rc;

    rc = getpwuid_r(getuid(), &pwd, buf, NSS_BUFLEN_PASSWD, &pwdbuf);
    if (rc != 0 || pwdbuf == NULL) {
        return NULL;
    }

    name = strdup(pwd.pw_name);
    rc = ssh_check_username_syntax(name);

    if (rc != SSH_OK) {
        free(name);
        return NULL;
    }

    return name;
}

int ssh_is_ipaddr_v4(const char *str)
{
    int rc = -1;
    struct in_addr dest;

    rc = inet_pton(AF_INET, str, &dest);
    if (rc > 0) {
        return 1;
    }

    return 0;
}

int ssh_is_ipaddr(const char *str)
{
    int rc = -1;
    char *s = strdup(str);

    if (s == NULL) {
        return -1;
    }
    if (strchr(s, ':')) {
        struct in6_addr dest6;
        char *network_interface = strchr(s, '%');

        /* link-local (IP:v6:addr%ifname). */
        if (network_interface != NULL) {
            rc = if_nametoindex(network_interface + 1);
            if (rc == 0) {
                free(s);
                return 0;
            }
            *network_interface = '\0';
        }
        rc = inet_pton(AF_INET6, s, &dest6);
        if (rc > 0) {
            free(s);
            return 1;
        }
    }

    free(s);
    return ssh_is_ipaddr_v4(str);
}

#endif /* _WIN32 */

char *ssh_lowercase(const char* str)
{
  char *new, *p;

  if (str == NULL) {
    return NULL;
  }

  new = strdup(str);
  if (new == NULL) {
    return NULL;
  }

  for (p = new; *p; p++) {
    *p = tolower(*p);
  }

  return new;
}

char *ssh_hostport(const char *host, int port)
{
    char *dest = NULL;
    size_t len;

    if (host == NULL) {
        return NULL;
    }

    /* 3 for []:, 5 for 65536 and 1 for nul */
    len = strlen(host) + 3 + 5 + 1;
    dest = malloc(len);
    if (dest == NULL) {
        return NULL;
    }
    snprintf(dest, len, "[%s]:%d", host, port);

    return dest;
}

/**
 * @brief Convert a buffer into a colon separated hex string.
 * The caller has to free the memory.
 *
 * @param[in]  what         What should be converted to a hex string.
 *
 * @param[in]  len          Length of the buffer to convert.
 *
 * @return                  The hex string or NULL on error. The memory needs
 *                          to be freed using ssh_string_free_char().
 *
 * @see ssh_string_free_char()
 */
char *ssh_get_hexa(const unsigned char *what, size_t len)
{
    const char h[] = "0123456789abcdef";
    char *hexa;
    size_t i;
    size_t hlen = len * 3;

    if (len > (UINT_MAX - 1) / 3) {
        return NULL;
    }

    hexa = malloc(hlen + 1);
    if (hexa == NULL) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        hexa[i * 3] = h[(what[i] >> 4) & 0xF];
        hexa[i * 3 + 1] = h[what[i] & 0xF];
        hexa[i * 3 + 2] = ':';
    }
    hexa[hlen - 1] = '\0';

    return hexa;
}

/**
 * @deprecated          Please use ssh_print_hash() instead
 */
void ssh_print_hexa(const char *descr, const unsigned char *what, size_t len)
{
    char *hexa = ssh_get_hexa(what, len);

    if (hexa == NULL) {
      return;
    }
    fprintf(stderr, "%s: %s\n", descr, hexa);

    free(hexa);
}

/**
 * @brief Log the content of a buffer in hexadecimal format, similar to the
 * output of 'hexdump -C' command.
 *
 * The first logged line is the given description followed by the length.
 * Then the content of the buffer is logged 16 bytes per line in the following
 * format:
 *
 * (offset) (first 8 bytes) (last 8 bytes) (the 16 bytes as ASCII char values)
 *
 * The output for a 16 bytes array containing values from 0x00 to 0x0f would be:
 *
 * "Example (16 bytes):"
 * "  00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................"
 *
 * The value for each byte as corresponding ASCII character is printed at the
 * end if the value is printable. Otherwise, it is replaced with '.'.
 *
 * @param[in] descr A description for the content to be logged
 * @param[in] what  The buffer to be logged
 * @param[in] len   The length of the buffer given in what
 *
 * @note If a too long description is provided (which would result in a first
 * line longer than 80 bytes), the function will fail.
 */
void ssh_log_hexdump(const char *descr, const unsigned char *what, size_t len)
{
    size_t i;
    char ascii[17];
    const unsigned char *pc = NULL;
    size_t count = 0;
    ssize_t printed = 0;

    /* The required buffer size is calculated from:
     *
     *  2 bytes for spaces at the beginning
     *  8 bytes for the offset
     *  2 bytes for spaces
     * 24 bytes to print the first 8 bytes + spaces
     *  1 byte for an extra space
     * 24 bytes to print next 8 bytes + spaces
     *  2 bytes for extra spaces
     * 16 bytes for the content as ASCII characters at the end
     *  1 byte for the ending '\0'
     *
     * Resulting in 80 bytes.
     *
     * Except for the first line (description + size), all lines have fixed
     * length. If a too long description is used, the function will fail.
     * */
    char buffer[80];

    /* Print description */
    if (descr != NULL) {
        printed = snprintf(buffer, sizeof(buffer), "%s ", descr);
        if (printed < 0) {
            goto error;
        }
        count += printed;
    } else {
        printed = snprintf(buffer, sizeof(buffer), "(NULL description) ");
        if (printed < 0) {
            goto error;
        }
        count += printed;
    }

    if (len == 0) {
        printed = snprintf(buffer + count, sizeof(buffer) - count,
                           "(zero length):");
        if (printed < 0) {
            goto error;
        }
        SSH_LOG(SSH_LOG_DEBUG, "%s", buffer);
        return;
    } else {
        printed = snprintf(buffer + count, sizeof(buffer) - count,
                           "(%zu bytes):", len);
        if (printed < 0) {
            goto error;
        }
        count += printed;
    }

    if (what == NULL) {
        printed = snprintf(buffer + count, sizeof(buffer) - count,
                           "(NULL)");
        if (printed < 0) {
            goto error;
        }
        SSH_LOG(SSH_LOG_DEBUG, "%s", buffer);
        return;
    }

    SSH_LOG(SSH_LOG_DEBUG, "%s", buffer);

    /* Reset state */
    count = 0;
    pc = what;

    for (i = 0; i < len; i++) {
        /* Add one space after printing 8 bytes */
        if ((i % 8) == 0) {
            if (i != 0) {
                printed = snprintf(buffer + count, sizeof(buffer) - count, " ");
                if (printed < 0) {
                    goto error;
                }
                count += printed;
            }
        }

        /* Log previous line and reset state for new line */
        if ((i % 16) == 0) {
            if (i != 0) {
                printed = snprintf(buffer + count, sizeof(buffer) - count,
                                   "  %s", ascii);
                if (printed < 0) {
                    goto error;
                }
                SSH_LOG(SSH_LOG_DEBUG, "%s", buffer);
                count = 0;
            }

            /* Start a new line with the offset */
            printed = snprintf(buffer, sizeof(buffer),
                               "  %08zx ", i);
            if (printed < 0) {
                goto error;
            }
            count += printed;
        }

        /* Print the current byte hexadecimal representation */
        printed = snprintf(buffer + count, sizeof(buffer) - count,
                           " %02x", pc[i]);
        if (printed < 0) {
            goto error;
        }
        count += printed;

        /* If printable, store the ASCII character */
        if (isprint(pc[i])) {
            ascii[i % 16] = pc[i];
        } else {
            ascii[i % 16] = '.';
        }
        ascii[(i % 16) + 1] = '\0';
    }

    /* Add padding if not exactly 16 characters */
    while ((i % 16) != 0) {
        /* Add one space after printing 8 bytes */
        if ((i % 8) == 0) {
            if (i != 0) {
                printed = snprintf(buffer + count, sizeof(buffer) - count, " ");
                if (printed < 0) {
                    goto error;
                }
                count += printed;
            }
        }

        printed = snprintf(buffer + count, sizeof(buffer) - count, "   ");
        if (printed < 0) {
            goto error;
        }
        count += printed;
        i++;
    }

    /* Print the last printable part */
    printed = snprintf(buffer + count, sizeof(buffer) - count,
                       "   %s", ascii);
    if (printed < 0) {
        goto error;
    }

    SSH_LOG(SSH_LOG_DEBUG, "%s", buffer);

    return;

error:
    SSH_LOG(SSH_LOG_DEBUG, "Could not print to buffer");
    return;
}

/**
 * @brief Check if libssh is the required version or get the version
 * string.
 *
 * @param[in]  req_version The version required.
 *
 * @return              If the version of libssh is newer than the version
 *                      required it will return a version string.
 *                      NULL if the version is older.
 *
 * Example:
 *
 * @code
 *  if (ssh_version(SSH_VERSION_INT(0,2,1)) == NULL) {
 *    fprintf(stderr, "libssh version is too old!\n");
 *    exit(1);
 *  }
 *
 *  if (debug) {
 *    printf("libssh %s\n", ssh_version(0));
 *  }
 * @endcode
 */
const char *ssh_version(int req_version)
{
    if (req_version <= LIBSSH_VERSION_INT) {
        return SSH_STRINGIFY(LIBSSH_VERSION) GCRYPT_STRING CRYPTO_STRING
               MBED_STRING ZLIB_STRING;
    }

    return NULL;
}

struct ssh_list *ssh_list_new(void)
{
    struct ssh_list *ret = malloc(sizeof(struct ssh_list));
    if (ret == NULL) {
        return NULL;
    }
    ret->root = ret->end = NULL;
    return ret;
}

void ssh_list_free(struct ssh_list *list)
{
    struct ssh_iterator *ptr, *next;
    if (!list)
        return;
    ptr = list->root;
    while (ptr) {
        next = ptr->next;
        SAFE_FREE(ptr);
        ptr = next;
    }
    SAFE_FREE(list);
}

struct ssh_iterator *ssh_list_get_iterator(const struct ssh_list *list)
{
    if (!list)
        return NULL;
    return list->root;
}

struct ssh_iterator *ssh_list_find(const struct ssh_list *list, void *value)
{
    struct ssh_iterator *it;

    for (it = ssh_list_get_iterator(list); it != NULL ; it = it->next)
        if (it->data == value)
            return it;
    return NULL;
}

/**
 * @brief Get the number of elements in the list
 *
 * @param[in]  list     The list to count.
 *
 * @return The number of elements in the list.
 */
size_t ssh_list_count(const struct ssh_list *list)
{
  struct ssh_iterator *it = NULL;
  size_t count = 0;

  for (it = ssh_list_get_iterator(list); it != NULL ; it = it->next) {
      count++;
  }

  return count;
}

static struct ssh_iterator *ssh_iterator_new(const void *data)
{
    struct ssh_iterator *iterator = malloc(sizeof(struct ssh_iterator));

    if (iterator == NULL) {
        return NULL;
    }
    iterator->next = NULL;
    iterator->data = data;
    return iterator;
}

int ssh_list_append(struct ssh_list *list,const void *data)
{
  struct ssh_iterator *iterator = NULL;

  if (list == NULL) {
      return SSH_ERROR;
  }

  iterator = ssh_iterator_new(data);
  if (iterator == NULL) {
      return SSH_ERROR;
  }

  if(!list->end){
    /* list is empty */
    list->root=list->end=iterator;
  } else {
    /* put it on end of list */
    list->end->next=iterator;
    list->end=iterator;
  }
  return SSH_OK;
}

int ssh_list_prepend(struct ssh_list *list, const void *data)
{
  struct ssh_iterator *it = NULL;

  if (list == NULL) {
      return SSH_ERROR;
  }

  it = ssh_iterator_new(data);
  if (it == NULL) {
    return SSH_ERROR;
  }

  if (list->end == NULL) {
    /* list is empty */
    list->root = list->end = it;
  } else {
    /* set as new root */
    it->next = list->root;
    list->root = it;
  }

  return SSH_OK;
}

void ssh_list_remove(struct ssh_list *list, struct ssh_iterator *iterator)
{
  struct ssh_iterator *ptr, *prev;

  if (list == NULL) {
      return;
  }

  prev=NULL;
  ptr=list->root;
  while(ptr && ptr != iterator){
    prev=ptr;
    ptr=ptr->next;
  }
  if(!ptr){
    /* we did not find the element */
    return;
  }
  /* unlink it */
  if(prev)
    prev->next=ptr->next;
  /* if iterator was the head */
  if(list->root == iterator)
    list->root=iterator->next;
  /* if iterator was the tail */
  if(list->end == iterator)
    list->end = prev;
  SAFE_FREE(iterator);
}

/**
 * @internal
 *
 * @brief Removes the top element of the list and returns the data value
 * attached to it.
 *
 * @param[in]  list     The ssh_list to remove the element.
 *
 * @returns             A pointer to the element being stored in head, or NULL
 *                      if the list is empty.
 */
const void *_ssh_list_pop_head(struct ssh_list *list)
{
  struct ssh_iterator *iterator = NULL;
  const void *data = NULL;

  if (list == NULL) {
      return NULL;
  }

  iterator = list->root;
  if (iterator == NULL) {
      return NULL;
  }
  data=iterator->data;
  list->root=iterator->next;
  if(list->end==iterator)
    list->end=NULL;
  SAFE_FREE(iterator);
  return data;
}

/**
 * @brief Parse directory component.
 *
 * dirname breaks a null-terminated pathname string into a directory component.
 * In the usual case, ssh_dirname() returns the string up to, but not including,
 * the final '/'. Trailing '/' characters are  not  counted as part of the
 * pathname. The caller must free the memory using ssh_string_free_char().
 *
 * @param[in]  path     The path to parse.
 *
 * @return              The dirname of path or NULL if we can't allocate memory.
 *                      If path does not contain a slash, c_dirname() returns
 *                      the string ".".  If path is a string "/", it returns
 *                      the string "/". If path is NULL or an empty string,
 *                      "." is returned. The memory needs to be freed using
 *                      ssh_string_free_char().
 *
 * @see ssh_string_free_char()
 */
char *ssh_dirname (const char *path)
{
  char *new = NULL;
  size_t len;

  if (path == NULL || *path == '\0') {
    return strdup(".");
  }

  len = strlen(path);

  /* Remove trailing slashes */
  while(len > 0 && path[len - 1] == '/') --len;

  /* We have only slashes */
  if (len == 0) {
    return strdup("/");
  }

  /* goto next slash */
  while(len > 0 && path[len - 1] != '/') --len;

  if (len == 0) {
    return strdup(".");
  } else if (len == 1) {
    return strdup("/");
  }

  /* Remove slashes again */
  while(len > 0 && path[len - 1] == '/') --len;

  new = malloc(len + 1);
  if (new == NULL) {
    return NULL;
  }

  strncpy(new, path, len);
  new[len] = '\0';

  return new;
}

/**
 * @brief basename - parse filename component.
 *
 * basename breaks a null-terminated pathname string into a filename component.
 * ssh_basename() returns the component following the final '/'.  Trailing '/'
 * characters are not counted as part of the pathname.
 *
 * @param[in]  path     The path to parse.
 *
 * @return              The filename of path or NULL if we can't allocate
 *                      memory. If path is the string "/", basename returns
 *                      the string "/". If path is NULL or an empty string,
 *                      "." is returned. The caller needs to free this memory
 *                      ssh_string_free_char().
 *
 * @see ssh_string_free_char()
 */
char *ssh_basename (const char *path)
{
  char *new = NULL;
  const char *s;
  size_t len;

  if (path == NULL || *path == '\0') {
    return strdup(".");
  }

  len = strlen(path);
  /* Remove trailing slashes */
  while(len > 0 && path[len - 1] == '/') --len;

  /* We have only slashes */
  if (len == 0) {
    return strdup("/");
  }

  while(len > 0 && path[len - 1] != '/') --len;

  if (len > 0) {
    s = path + len;
    len = strlen(s);

    while(len > 0 && s[len - 1] == '/') --len;
  } else {
    return strdup(path);
  }

  new = malloc(len + 1);
  if (new == NULL) {
    return NULL;
  }

  strncpy(new, s, len);
  new[len] = '\0';

  return new;
}

/**
 * @brief Attempts to create a directory with the given pathname.
 *
 * This is the portable version of mkdir, mode is ignored on Windows systems.
 *
 * @param[in]  pathname The path name to create the directory.
 *
 * @param[in]  mode     The permissions to use.
 *
 * @return              0 on success, < 0 on error with errno set.
 */
int ssh_mkdir(const char *pathname, mode_t mode)
{
    int r;
#ifdef _WIN32
    r = _mkdir(pathname);
#else
    r = mkdir(pathname, mode);
#endif

    return r;
}

/**
 * @brief Attempts to create a directory with the given pathname. The missing
 * directories in the given pathname are created recursively.
 *
 * @param[in]  pathname The path name to create the directory.
 *
 * @param[in]  mode     The permissions to use.
 *
 * @return              0 on success, < 0 on error with errno set.
 *
 * @note mode is ignored on Windows systems.
 */
int ssh_mkdirs(const char *pathname, mode_t mode)
{
    int rc = 0;
    char *parent = NULL;

    if (pathname == NULL ||
        pathname[0] == '\0' ||
        !strcmp(pathname, "/") ||
        !strcmp(pathname, "."))
    {
        errno = EINVAL;
        return -1;
    }

    errno = 0;

#ifdef _WIN32
    rc = _mkdir(pathname);
#else
    rc = mkdir(pathname, mode);
#endif

    if (rc < 0) {
        /* If a directory was missing, try to create the parent */
        if (errno == ENOENT) {
            parent = ssh_dirname(pathname);
            if (parent == NULL) {
                errno = ENOMEM;
                return -1;
            }

            rc = ssh_mkdirs(parent, mode);
            if (rc < 0) {
                /* We could not create the parent */
                SAFE_FREE(parent);
                return -1;
            }

            SAFE_FREE(parent);

            /* Try again */
            errno = 0;
#ifdef _WIN32
            rc = _mkdir(pathname);
#else
            rc = mkdir(pathname, mode);
#endif
        }
    }

    return rc;
}

/**
 * @brief Expand a directory starting with a tilde '~'
 *
 * @param[in]  d        The directory to expand.
 *
 * @return              The expanded directory, NULL on error. The caller
 *                      needs to free the memory using ssh_string_free_char().
 *
 * @see ssh_string_free_char()
 */
char *ssh_path_expand_tilde(const char *d)
{
    char *h = NULL, *r;
    const char *p;
    size_t ld;
    size_t lh = 0;

    if (d[0] != '~') {
        return strdup(d);
    }
    d++;

    /* handle ~user/path */
    p = strchr(d, '/');
    if (p != NULL && p > d) {
#ifdef _WIN32
        return strdup(d);
#else
        struct passwd *pw;
        size_t s = p - d;
        char u[128];

        if (s >= sizeof(u)) {
            return NULL;
        }
        memcpy(u, d, s);
        u[s] = '\0';
        pw = getpwnam(u);
        if (pw == NULL) {
            return NULL;
        }
        ld = strlen(p);
        h = strdup(pw->pw_dir);
#endif
    } else {
        ld = strlen(d);
        p = (char *) d;
        h = ssh_get_user_home_dir();
    }
    if (h == NULL) {
        return NULL;
    }
    lh = strlen(h);

    r = malloc(ld + lh + 1);
    if (r == NULL) {
        SAFE_FREE(h);
        return NULL;
    }

    if (lh > 0) {
        memcpy(r, h, lh);
    }
    SAFE_FREE(h);
    memcpy(r + lh, p, ld + 1);

    return r;
}

/** @internal
 * @brief expands a string in function of session options
 * @param[in] s Format string to expand. Known parameters:
 *              %d SSH configuration directory (~/.ssh)
 *              %h target host name
 *              %u local username
 *              %l local hostname
 *              %r remote username
 *              %p remote port
 * @returns Expanded string. The caller needs to free the memory using
 *          ssh_string_free_char().
 *
 * @see ssh_string_free_char()
 */
char *ssh_path_expand_escape(ssh_session session, const char *s)
{
    char host[NI_MAXHOST] = {0};
    char *buf = NULL;
    char *r = NULL;
    char *x = NULL;
    const char *p;
    size_t i, l;

    r = ssh_path_expand_tilde(s);
    if (r == NULL) {
        ssh_set_error_oom(session);
        return NULL;
    }

    if (strlen(r) > MAX_BUF_SIZE) {
        ssh_set_error(session, SSH_FATAL, "string to expand too long");
        free(r);
        return NULL;
    }

    buf = malloc(MAX_BUF_SIZE);
    if (buf == NULL) {
        ssh_set_error_oom(session);
        free(r);
        return NULL;
    }

    p = r;
    buf[0] = '\0';

    for (i = 0; *p != '\0'; p++) {
        if (*p != '%') {
        escape:
            buf[i] = *p;
            i++;
            if (i >= MAX_BUF_SIZE) {
                free(buf);
                free(r);
                return NULL;
            }
            buf[i] = '\0';
            continue;
        }

        p++;
        if (*p == '\0') {
            break;
        }

        switch (*p) {
            case '%':
                goto escape;
            case 'd':
                if (session->opts.sshdir) {
                    x = strdup(session->opts.sshdir);
                } else {
                    ssh_set_error(session, SSH_FATAL,
                            "Cannot expand sshdir");
                    free(buf);
                    free(r);
                    return NULL;
                }
                break;
            case 'u':
                x = ssh_get_local_username();
                break;
            case 'l':
                if (gethostname(host, sizeof(host) == 0)) {
                    x = strdup(host);
                }
                break;
            case 'h':
                if (session->opts.host) {
                    x = strdup(session->opts.host);
                } else {
                    ssh_set_error(session, SSH_FATAL,
                            "Cannot expand host");
                    free(buf);
                    free(r);
                    return NULL;
                }
                break;
            case 'r':
                if (session->opts.username) {
                    x = strdup(session->opts.username);
                } else {
                    ssh_set_error(session, SSH_FATAL,
                            "Cannot expand username");
                    free(buf);
                    free(r);
                    return NULL;
                }
                break;
            case 'p':
                {
                  char tmp[6];

                  snprintf(tmp, sizeof(tmp), "%hu",
                           (uint16_t)(session->opts.port > 0 ? session->opts.port
                                                             : 22));
                  x = strdup(tmp);
                }
                break;
            default:
                ssh_set_error(session, SSH_FATAL,
                        "Wrong escape sequence detected");
                free(buf);
                free(r);
                return NULL;
        }

        if (x == NULL) {
            ssh_set_error_oom(session);
            free(buf);
            free(r);
            return NULL;
        }

        i += strlen(x);
        if (i >= MAX_BUF_SIZE) {
            ssh_set_error(session, SSH_FATAL,
                    "String too long");
            free(buf);
            free(x);
            free(r);
            return NULL;
        }
        l = strlen(buf);
        strncpy(buf + l, x, MAX_BUF_SIZE - l - 1);
        buf[i] = '\0';
        SAFE_FREE(x);
    }

    free(r);

    /* strip the unused space by realloc */
    x = realloc(buf, strlen(buf) + 1);
    if (x == NULL) {
        ssh_set_error_oom(session);
        free(buf);
    }
    return x;
}

/**
 * @internal
 *
 * @brief Analyze the SSH banner to extract version information.
 *
 * @param  session      The session to analyze the banner from.
 * @param  server       0 means we are a client, 1 a server.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see ssh_get_issue_banner()
 */
int ssh_analyze_banner(ssh_session session, int server)
{
    const char *banner;
    const char *openssh;

    if (server) {
        banner = session->clientbanner;
    } else {
        banner = session->serverbanner;
    }

    if (banner == NULL) {
        ssh_set_error(session, SSH_FATAL, "Invalid banner");
        return -1;
    }

    /*
     * Typical banners e.g. are:
     *
     * SSH-1.5-openSSH_5.4
     * SSH-1.99-openSSH_3.0
     *
     * SSH-2.0-something
     * 012345678901234567890
     */
    if (strlen(banner) < 6 ||
        strncmp(banner, "SSH-", 4) != 0) {
          ssh_set_error(session, SSH_FATAL, "Protocol mismatch: %s", banner);
          return -1;
    }

    SSH_LOG(SSH_LOG_DEBUG, "Analyzing banner: %s", banner);

    switch (banner[4]) {
        case '2':
            break;
        case '1':
            if (strlen(banner) > 6) {
                if (banner[6] == '9') {
                    break;
                }
            }
            FALL_THROUGH;
        default:
            ssh_set_error(session, SSH_FATAL, "Protocol mismatch: %s", banner);
            return -1;
    }

    /* Make a best-effort to extract OpenSSH version numbers. */
    openssh = strstr(banner, "OpenSSH");
    if (openssh != NULL) {
        char *tmp = NULL;
        unsigned long int major = 0UL;
        unsigned long int minor = 0UL;

        /*
         * The banner is typical:
         * OpenSSH_5.4
         * 012345678901234567890
         */
        if (strlen(openssh) > 9) {
            errno = 0;
            major = strtoul(openssh + 8, &tmp, 10);
            if ((tmp == (openssh + 8)) ||
                ((errno == ERANGE) && (major == ULONG_MAX)) ||
                ((errno != 0) && (major == 0)) ||
                ((major < 1) || (major > 100))) {
                /* invalid major */
                errno = 0;
                goto done;
            }

            errno = 0;
            minor = strtoul(openssh + 10, &tmp, 10);
            if ((tmp == (openssh + 10)) ||
                ((errno == ERANGE) && (major == ULONG_MAX)) ||
                ((errno != 0) && (major == 0)) ||
                (minor > 100)) {
                /* invalid minor */
                errno = 0;
                goto done;
            }

            session->openssh = SSH_VERSION_INT(((int) major), ((int) minor), 0);

            SSH_LOG(SSH_LOG_DEBUG,
                    "We are talking to an OpenSSH %s version: %lu.%lu (%x)",
                    server ? "client" : "server",
                    major, minor, session->openssh);
        }
    }

done:
    return 0;
}

/* try the Monotonic clock if possible for perfs reasons */
#ifdef _POSIX_MONOTONIC_CLOCK
#define CLOCK CLOCK_MONOTONIC
#else
#define CLOCK CLOCK_REALTIME
#endif

/**
 * @internal
 * @brief initializes a timestamp to the current time
 * @param[out] ts pointer to an allocated ssh_timestamp structure
 */
void ssh_timestamp_init(struct ssh_timestamp *ts)
{
#ifdef HAVE_CLOCK_GETTIME
  struct timespec tp;
  clock_gettime(CLOCK, &tp);
  ts->useconds = tp.tv_nsec / 1000;
#else
  struct timeval tp;
  gettimeofday(&tp, NULL);
  ts->useconds = tp.tv_usec;
#endif
  ts->seconds = tp.tv_sec;
}

#undef CLOCK

/**
 * @internal
 * @brief gets the time difference between two timestamps in ms
 * @param[in] old older value
 * @param[in] new newer value
 * @returns difference in milliseconds
 */

static int
ssh_timestamp_difference(struct ssh_timestamp *old, struct ssh_timestamp *new)
{
    long seconds, usecs, msecs;
    seconds = new->seconds - old->seconds;
    usecs = new->useconds - old->useconds;
    if (usecs < 0){
        seconds--;
        usecs += 1000000;
    }
    msecs = seconds * 1000 + usecs/1000;
    return msecs;
}

/**
 * @internal
 * @brief turn seconds and microseconds pair (as provided by user-set options)
 * into millisecond value
 * @param[in] sec number of seconds
 * @param[in] usec number of microseconds
 * @returns milliseconds, or 10000 if user supplied values are equal to zero
 */
int ssh_make_milliseconds(unsigned long sec, unsigned long usec)
{
	unsigned long res = usec ? (usec / 1000) : 0;
	res += (sec * 1000);
	if (res == 0) {
		res = 10 * 1000; /* use a reasonable default value in case
				* SSH_OPTIONS_TIMEOUT is not set in options. */
	}

    if (res > INT_MAX) {
        return SSH_TIMEOUT_INFINITE;
    } else {
        return (int)res;
    }
}

/**
 * @internal
 * @brief Checks if a timeout is elapsed, in function of a previous
 * timestamp and an assigned timeout
 * @param[in] ts pointer to an existing timestamp
 * @param[in] timeout timeout in milliseconds. Negative values mean infinite
 *                   timeout
 * @returns 1 if timeout is elapsed
 *          0 otherwise
 */
int ssh_timeout_elapsed(struct ssh_timestamp *ts, int timeout)
{
    struct ssh_timestamp now;

    switch(timeout) {
        case -2: /*
                  * -2 means user-defined timeout as available in
                  * session->timeout, session->timeout_usec.
                  */
            SSH_LOG(SSH_LOG_DEBUG, "ssh_timeout_elapsed called with -2. this needs to "
                            "be fixed. please set a breakpoint on misc.c:%d and "
                            "fix the caller\n", __LINE__);
            return 0;
        case -1: /* -1 means infinite timeout */
            return 0;
        case 0: /* 0 means no timeout */
            return 1;
        default:
            break;
    }

    ssh_timestamp_init(&now);

    return (ssh_timestamp_difference(ts,&now) >= timeout);
}

/**
 * @brief updates a timeout value so it reflects the remaining time
 * @param[in] ts pointer to an existing timestamp
 * @param[in] timeout timeout in milliseconds. Negative values mean infinite
 *             timeout
 * @returns   remaining time in milliseconds, 0 if elapsed, -1 if never.
 */
int ssh_timeout_update(struct ssh_timestamp *ts, int timeout)
{
  struct ssh_timestamp now;
  int ms, ret;
  if (timeout <= 0) {
      return timeout;
  }
  ssh_timestamp_init(&now);
  ms = ssh_timestamp_difference(ts,&now);
  if(ms < 0)
    ms = 0;
  ret = timeout - ms;
  return ret >= 0 ? ret: 0;
}

#if !defined(HAVE_EXPLICIT_BZERO)
void explicit_bzero(void *s, size_t n)
{
#if defined(HAVE_MEMSET_S)
    memset_s(s, n, '\0', n);
#elif defined(HAVE_SECURE_ZERO_MEMORY)
    SecureZeroMemory(s, n);
#else
    memset(s, '\0', n);
#if defined(HAVE_GCC_VOLATILE_MEMORY_PROTECTION)
    /* See http://llvm.org/bugs/show_bug.cgi?id=15495 */
    __asm__ volatile("" : : "g"(s) : "memory");
#endif /* HAVE_GCC_VOLATILE_MEMORY_PROTECTION */
#endif
}
#endif /* !HAVE_EXPLICIT_BZERO */

#if !defined(HAVE_STRNDUP)
char *strndup(const char *s, size_t n)
{
    char *x = NULL;

    if (n + 1 < n) {
        return NULL;
    }

    x = malloc(n + 1);
    if (x == NULL) {
        return NULL;
    }

    memcpy(x, s, n);
    x[n] = '\0';

    return x;
}
#endif /* ! HAVE_STRNDUP */

/* Increment 64b integer in network byte order */
void
uint64_inc(unsigned char *counter)
{
    int i;

    for (i = 7; i >= 0; i--) {
        counter[i]++;
        if (counter[i])
          return;
    }
}

/**
 * @internal
 *
 * @brief Quote file name to be used on shell.
 *
 * Try to put the given file name between single quotes. There are special
 * cases:
 *
 * - When the '\'' char is found in the file name, it is double quoted
 *   - example:
 *     input: a'b
 *     output: 'a'"'"'b'
 * - When the '!' char is found in the file name, it is replaced by an unquoted
 *   verbatim char "\!"
 *   - example:
 *     input: a!b
 *     output 'a'\!'b'
 *
 * @param[in]   file_name  File name string to be quoted before used on shell
 * @param[out]  buf       Buffer to receive the final quoted file name.  Must
 *                        have room for the final quoted string.  The maximum
 *                        output length would be (3 * strlen(file_name) + 1)
 *                        since in the worst case each character would be
 *                        replaced by 3 characters, plus the terminating '\0'.
 * @param[in]   buf_len   The size of the provided output buffer
 *
 * @returns SSH_ERROR on error; length of the resulting string not counting the
 * string terminator '\0'
 * */
int ssh_quote_file_name(const char *file_name, char *buf, size_t buf_len)
{
    const char *src = NULL;
    char *dst = NULL;
    size_t required_buf_len;

    enum ssh_quote_state_e state = NO_QUOTE;

    if (file_name == NULL || buf == NULL || buf_len == 0) {
        SSH_LOG(SSH_LOG_TRACE, "Invalid parameter");
        return SSH_ERROR;
    }

    /* Only allow file names smaller than 32kb. */
    if (strlen(file_name) > 32 * 1024) {
        SSH_LOG(SSH_LOG_TRACE, "File name too long");
        return SSH_ERROR;
    }

    /* Paranoia check */
    required_buf_len = (size_t)3 * strlen(file_name) + 1;
    if (required_buf_len > buf_len) {
        SSH_LOG(SSH_LOG_TRACE, "Buffer too small");
        return SSH_ERROR;
    }

    src = file_name;
    dst = buf;

    while ((*src != '\0')) {
        switch (*src) {

        /* The '\'' char is double quoted */

        case '\'':
            switch (state) {
            case NO_QUOTE:
                /* Start a new double quoted string. The '\'' char will be
                 * copied to the beginning of it at the end of the loop. */
                *dst++ = '"';
                break;
            case SINGLE_QUOTE:
                /* Close the current single quoted string and start a new double
                 * quoted string. The '\'' char will be copied to the beginning
                 * of it at the end of the loop. */
                *dst++ = '\'';
                *dst++ = '"';
                break;
            case DOUBLE_QUOTE:
                /* If already in the double quoted string, keep copying the
                 * sequence of chars. */
                break;
            default:
                /* Should never be reached */
                goto error;
            }

            /* When the '\'' char is found, the resulting state will be
             * DOUBLE_QUOTE in any case*/
            state = DOUBLE_QUOTE;
            break;

        /* The '!' char is replaced by unquoted "\!" */

        case '!':
            switch (state) {
            case NO_QUOTE:
                /* The '!' char is interpreted in some shells (e.g. CSH) even
                 * when is quoted with single quotes.  Replace it with unquoted
                 * "\!" which is correctly interpreted as the '!' character. */
                *dst++ = '\\';
                break;
            case SINGLE_QUOTE:
                /* Close the currently quoted string and replace '!' for unquoted
                 * "\!" */
                *dst++ = '\'';
                *dst++ = '\\';
                break;
            case DOUBLE_QUOTE:
                /* Close currently quoted string and replace  "!" for unquoted
                 * "\!" */
                *dst++ = '"';
                *dst++ = '\\';
                break;
            default:
                /* Should never be reached */
                goto error;
            }

            /* When the '!' char is found, the resulting state will be NO_QUOTE
             * in any case*/
            state = NO_QUOTE;
            break;

        /* Ordinary chars are single quoted */

        default:
            switch (state) {
            case NO_QUOTE:
                /* Start a new single quoted string */
                *dst++ = '\'';
                break;
            case SINGLE_QUOTE:
                /* If already in the single quoted string, keep copying the
                 * sequence of chars. */
                break;
            case DOUBLE_QUOTE:
                /* Close current double quoted string and start a new single
                 * quoted string. */
                *dst++ = '"';
                *dst++ = '\'';
                break;
            default:
                /* Should never be reached */
                goto error;
            }

            /* When an ordinary char is found, the resulting state will be
             * SINGLE_QUOTE in any case*/
            state = SINGLE_QUOTE;
            break;
        }

        /* Copy the current char to output */
        *dst++ = *src++;
    }

    /* Close the quoted string when necessary */

    switch (state) {
    case NO_QUOTE:
        /* No open string */
        break;
    case SINGLE_QUOTE:
        /* Close current single quoted string */
        *dst++ = '\'';
        break;
    case DOUBLE_QUOTE:
        /* Close current double quoted string */
        *dst++ = '"';
        break;
    default:
        /* Should never be reached */
        goto error;
    }

    /* Put the string terminator */
    *dst = '\0';

    return (int)(dst - buf);

error:
    return SSH_ERROR;
}

/**
 * @internal
 *
 * @brief Given a string, encode existing newlines as the string "\\n"
 *
 * @param[in]  string   Input string
 * @param[out] buf      Output buffer. This buffer must be at least (2 *
 *                      strlen(string)) + 1 long.  In the worst case,
 *                      each character can be encoded as 2 characters plus the
 *                      terminating '\0'.
 * @param[in]  buf_len  Size of the provided output buffer
 *
 * @returns SSH_ERROR on error; length of the resulting string not counting the
 * terminating '\0' otherwise
 */
int ssh_newline_vis(const char *string, char *buf, size_t buf_len)
{
    const char *in = NULL;
    char *out = NULL;

    if (string == NULL || buf == NULL || buf_len == 0) {
        return SSH_ERROR;
    }

    if ((2 * strlen(string) + 1) > buf_len) {
        SSH_LOG(SSH_LOG_TRACE, "Buffer too small");
        return SSH_ERROR;
    }

    out = buf;
    for (in = string; *in != '\0'; in++) {
        if (*in == '\n') {
            *out++ = '\\';
            *out++ = 'n';
        } else {
            *out++ = *in;
        }
    }
    *out = '\0';

    return (int)(out - buf);
}

/**
 * @internal
 *
 * @brief Replaces the last 6 characters of a string from 'X' to 6 random hexdigits.
 *
 * @param[in,out]  name   Any input string with last 6 characters as 'X'.
 * @returns -1 as error when the last 6 characters of the input to be replaced are not 'X'
 * 0 otherwise.
 */
int ssh_tmpname(char *name)
{
    char *tmp = NULL;
    size_t i = 0;
    int rc = 0;
    uint8_t random[6];

    if (name == NULL) {
        goto err;
    }

    tmp = name + strlen(name) - 6;
    if (tmp < name) {
        goto err;
    }

    for (i = 0; i < 6; i++) {
        if (tmp[i] != 'X') {
            SSH_LOG(SSH_LOG_WARNING,
                    "Invalid input. Last six characters of the input must be \'X\'");
            goto err;
        }
    }

    rc = ssh_get_random(random, 6, 0);
    if (!rc) {
        SSH_LOG(SSH_LOG_WARNING,
                "Could not generate random data\n");
        goto err;
    }

    for (i = 0; i < 6; i++) {
        /* Limit the random[i] < 32 */
        random[i] &= 0x1f;
        /* For values from 0 to 9 use numbers, otherwise use letters */
        tmp[i] = random[i] > 9 ? random[i] + 'a' - 10 : random[i] + '0';
    }

    return 0;

err:
    errno = EINVAL;
    return -1;
}

/**
 * @internal
 *
 * @brief Finds the first occurrence of a pattern in a string and replaces it.
 *
 * @param[in]  src          Source string containing the pattern to be replaced.
 * @param[in]  pattern      Pattern to be replaced in the source string.
 *                          Note: this function replaces the first occurrence of
 *                          pattern only.
 * @param[in]  replace      String to be replaced is stored in replace.
 *
 * @returns  src_replaced a pointer that points to the replaced string.
 * NULL if allocation fails or if src is NULL. The returned memory needs to be
 * freed using ssh_string_free_char().
 *
 * @see ssh_string_free_char()
 */
char *ssh_strreplace(const char *src, const char *pattern, const char *replace)
{
    char *p = NULL;
    char *src_replaced = NULL;

    if (src == NULL) {
        return NULL;
    }

    if (pattern == NULL || replace == NULL) {
        return strdup(src);
    }

    p = strstr(src, pattern);

    if (p != NULL) {
        size_t offset = p - src;
        size_t pattern_len = strlen(pattern);
        size_t replace_len = strlen(replace);
        size_t len  = strlen(src);
        size_t len_replaced = len + replace_len - pattern_len + 1;

        src_replaced = (char *)malloc(len_replaced);

        if (src_replaced == NULL) {
            return NULL;
        }

        memset(src_replaced, 0, len_replaced);
        memcpy(src_replaced, src, offset);
        memcpy(src_replaced + offset, replace, replace_len);
        memcpy(src_replaced + offset + replace_len, src + offset + pattern_len, len - offset - pattern_len);
        return src_replaced; /* free in the caller */
    } else {
        return strdup(src);
    }
}

/**
 * @internal
 *
 * @brief Processes errno into error string
 *
 * @param[in] err_num The errno value
 * @param[out] buf Pointer to a place where the string could be saved
 * @param[in] buflen The allocated size of buf
 *
 * @return error string
 */
char *ssh_strerror(int err_num, char *buf, size_t buflen)
{
#if ((defined(__linux__) && defined(__GLIBC__)) || defined(__CYGWIN__)) && defined(_GNU_SOURCE)
    /* GNU extension on Linux */
    return strerror_r(err_num, buf, buflen);
#else
    int rv;

#if defined(_WIN32)
    rv = strerror_s(buf, buflen, err_num);
#else
    /* POSIX version available for example on FreeBSD or in musl libc */
    rv = strerror_r(err_num, buf, buflen);
#endif /* _WIN32 */

    /* make sure the buffer is initialized and terminated with NULL */
    if (-rv == ERANGE) {
        buf[0] = '\0';
    }
    return buf;
#endif /* ((defined(__linux__) && defined(__GLIBC__)) || defined(__CYGWIN__)) && defined(_GNU_SOURCE) */
}

/**
 * @brief Read the requested number of bytes from a local file.
 *
 * A call to read() may perform a short read even when sufficient data is
 * present in the file. This function can be used to avoid such short reads.
 *
 * This function tries to read the requested number of bytes from the file
 * until one of the following occurs :
 *     - Requested number of bytes are read.
 *     - EOF is encountered before reading the requested number of bytes.
 *     - An error occurs.
 *
 * On encountering an error due to an interrupt, this function ignores that
 * error and continues trying to read the data.
 *
 * @param[in] fd          The file descriptor of the local file to read from.
 *
 * @param[out] buf        Pointer to a buffer in which read data will be
 *                        stored.
 *
 * @param[in] nbytes      Number of bytes to read.
 *
 * @returns               Number of bytes read on success,
 *                        SSH_ERROR on error with errno set to indicate the
 *                        error.
 */
ssize_t ssh_readn(int fd, void *buf, size_t nbytes)
{
    size_t total_bytes_read = 0;
    ssize_t bytes_read;

    if (fd < 0 || buf == NULL || nbytes == 0) {
        errno = EINVAL;
        return SSH_ERROR;
    }

    do {
        bytes_read = read(fd,
                          ((char *)buf) + total_bytes_read,
                          nbytes - total_bytes_read);
        if (bytes_read == -1) {
            if (errno == EINTR) {
                /* Ignoring errors due to signal interrupts */
                continue;
            }

            return SSH_ERROR;
        }

        if (bytes_read == 0) {
            /* EOF encountered on the local file before reading nbytes */
            break;
        }

        total_bytes_read += (size_t)bytes_read;
    } while (total_bytes_read < nbytes);

    return total_bytes_read;
}

/**
 * @brief Write the requested number of bytes to a local file.
 *
 * A call to write() may perform a short write on a local file. This function
 * can be used to avoid short writes.
 *
 * This function tries to write the requested number of bytes until those many
 * bytes are written or some error occurs.
 *
 * On encountering an error due to an interrupt, this function ignores that
 * error and continues trying to write the data.
 *
 * @param[in] fd          The file descriptor of the local file to write to.
 *
 * @param[in] buf         Pointer to a buffer in which data to write is stored.
 *
 * @param[in] nbytes      Number of bytes to write.
 *
 * @returns               Number of bytes written on success,
 *                        SSH_ERROR on error with errno set to indicate the
 *                        error.
 */
ssize_t ssh_writen(int fd, const void *buf, size_t nbytes)
{
    size_t total_bytes_written = 0;
    ssize_t bytes_written;

    if (fd < 0 || buf == NULL || nbytes == 0) {
        errno = EINVAL;
        return SSH_ERROR;
    }

    do {
        bytes_written = write(fd,
                              ((const char *)buf) + total_bytes_written,
                              nbytes - total_bytes_written);
        if (bytes_written == -1) {
            if (errno == EINTR) {
                /* Ignoring errors due to signal interrupts */
                continue;
            }

            return SSH_ERROR;
        }

        total_bytes_written += (size_t)bytes_written;
    } while (total_bytes_written < nbytes);

    return total_bytes_written;
}

/**
 * @brief Checks syntax of a domain name
 *
 * The check is made based on the RFC1035 section 2.3.1
 * Allowed characters are: hyphen, period, digits (0-9) and letters (a-zA-Z)
 *
 * The label should be no longer than 63 characters
 * The label should start with a letter and end with a letter or number
 * The label in this implementation can start with a number to allow virtual
 * URLs to pass. Note that this will make IPv4 addresses to pass
 * this check too.
 *
 * @param hostname The domain name to be checked, has to be null terminated
 *
 * @return SSH_OK if the hostname passes syntax check
 *         SSH_ERROR otherwise or if hostname is NULL or empty string
 */
int ssh_check_hostname_syntax(const char *hostname)
{
    char *it = NULL, *s = NULL, *buf = NULL;
    size_t it_len;
    char c;

    if (hostname == NULL || strlen(hostname) == 0) {
        return SSH_ERROR;
    }

    /* strtok_r writes into the string, keep the input clean */
    s = strdup(hostname);
    if (s == NULL) {
        return SSH_ERROR;
    }

    it = strtok_r(s, ".", &buf);
    /* if the token has 0 length */
    if (it == NULL) {
        free(s);
        return SSH_ERROR;
    }
    do {
        it_len = strlen(it);
        if (it_len > ARPA_DOMAIN_MAX_LEN ||
            /* the first char must be a letter, but some virtual urls start
             * with a number */
            isalnum(it[0]) == 0 ||
            isalnum(it[it_len - 1]) == 0) {
            free(s);
            return SSH_ERROR;
        }
        while (*it != '\0') {
            c = *it;
            /* the "." is allowed too, but tokenization removes it from the
             * string */
            if (isalnum(c) == 0 && c != '-') {
                free(s);
                return SSH_ERROR;
            }
            it++;
        }
    } while ((it = strtok_r(NULL, ".", &buf)) != NULL);

    free(s);

    return SSH_OK;
}

/**
 * @brief Checks syntax of a username
 *
 * This check disallows metacharacters in the username
 *
 * @param username The username to be checked, has to be null terminated
 *
 * @return SSH_OK if the username passes syntax check
 *         SSH_ERROR otherwise or if username is NULL or empty string
 */
int ssh_check_username_syntax(const char *username)
{
    size_t username_len;

    if (username == NULL || *username == '-') {
        return SSH_ERROR;
    }

    username_len = strlen(username);
    if (username_len == 0 || username[username_len - 1] == '\\' ||
        strpbrk(username, "'`\";&<>|(){}") != NULL) {
        return SSH_ERROR;
    }
    for (size_t i = 0; i < username_len; i++) {
        if (isspace(username[i]) != 0 && username[i + 1] == '-') {
            return SSH_ERROR;
        }
    }

    return SSH_OK;
}

/**
 * @brief Free proxy jump list
 *
 * Frees everything in a proxy jump list, but doesn't free the ssh_list
 *
 * @param proxy_jump_list
 *
 */
void
ssh_proxyjumps_free(struct ssh_list *proxy_jump_list)
{
    struct ssh_jump_info_struct *jump = NULL;

    for (jump =
             ssh_list_pop_head(struct ssh_jump_info_struct *, proxy_jump_list);
         jump != NULL;
         jump = ssh_list_pop_head(struct ssh_jump_info_struct *,
                                  proxy_jump_list)) {
        SAFE_FREE(jump->hostname);
        SAFE_FREE(jump->username);
        SAFE_FREE(jump);
    }
}

/**
 * @brief Check if libssh proxy jumps is enabled
 *
 * If env variable OPENSSH_PROXYJUMP is set to 1 then proxyjump will be
 * through the OpenSSH binary.
 *
 * @return false if OPENSSH_PROXYJUMP=1
 *         true otherwise
 */
bool
ssh_libssh_proxy_jumps(void)
{
    const char *t = getenv("OPENSSH_PROXYJUMP");

    return !(t != NULL && t[0] == '1');
}

/**
 * @brief Converts an absolute time value to a formatted string.
 *
 * This function takes a `uint64_t` absolute time value (representing time
 * in seconds since the Unix epoch) and converts it to a human-readable string
 * in the format "YYYY-MM-DD HH:MM:SS".
 *
 * @param[in] timestamp      The timestamp value to be converted.
 *
 * @param[out] buf           A pointer to a buffer where the formatted time
 *                           string will be stored. The buffer should be large
 *                           enough to hold the formatted string.
 *
 * @return The number of characters placed in the buffer.
 * @returns 0 if the conversion fails and the buffer is undefined.
 */
size_t
ssh_format_time_to_string(uint64_t timestamp, char *buf, size_t buf_size)
{
    struct tm *tm_info = NULL;
    size_t rc;

    time_t time = (time_t)timestamp;
    tm_info = localtime(&time);

    rc = strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", tm_info);
    return rc;
}

/**
 * @brief Removes the outermost square brackets from a C string.
 *
 * If both brackets are present, the brackets are removed, and the string
 * is adjusted accordingly.
 *
 * @param str  The C string to process.\n
 *             If NULL, the function returns immediately.
 */
void
ssh_remove_square_brackets(char *str)
{
    size_t content_len, len;

    if (str == NULL) {
        return;
    }

    len = strlen(str);
    if (len < 2) {
        return;
    }

    if (str[0] == '[' && str[len - 1] == ']') {
        content_len = len - 2;
        memmove(str, str + 1, content_len);
        str[content_len] = '\0';
    }
}

/**
 * @brief Removes surrounding quotes ("") from a C string if present.
 *
 * @param[in] str  The C string to process.\n
 *                 If NULL or empty, the function returns NULL.
 *
 * @returns A newly allocated string without the surrounding quotes if both
 *          opening and closing quotes are found.\n
 *          If the string has no quotes then a copy of the input string
 *          is returned.
 * @returns NULL on error.
 *
 * @note The caller is responsible for freeing the returned string.
 */
char *
ssh_dequote(const char *str)
{
    size_t len;
    char *ret = NULL;

    if (str == NULL || *str == '\0') {
        return NULL;
    }

    len = strlen(str);
    if (len > 1 && str[0] == '"' && str[len - 1] == '"') {
        if (len == 2) {
            SSH_LOG(SSH_LOG_DEBUG,
                    "Nothing to de-quote. Empty value between quotes");
            return NULL;
        }

        ret = strndup(str + 1, len - 2);
        if (ret == NULL) {
            SSH_LOG(SSH_LOG_DEBUG,
                    "Memory allocation error while de-quoting %s",
                    str);
            return NULL;
        }
    } else if (len > 1 && str[0] == '"' && str[len - 1] != '"') {
        SSH_LOG(SSH_LOG_DEBUG, "Missing closing quote");
        return NULL;
    } else if (len > 1 && str[0] != '"' && str[len - 1] == '"') {
        SSH_LOG(SSH_LOG_DEBUG, "Missing opening quote");
        return NULL;
    } else {
        /* If there are no quotes then return a copy of the input string */
        ret = strdup(str);
        if (ret == NULL) {
            SSH_LOG(SSH_LOG_DEBUG,
                    "Memory allocation error while duplicating %s",
                    str);
            return NULL;
        }
    }

    return ret;
}

/**
 * @brief Calculates the number of days from year 0 up to a given year. The year
 * is not inclusive.
 *
 * This function computes the total number of days from the start of year 0 up
 * to the beginning of the specified year, accounting for leap years \n
 *
 * The leap years (1 day more for each leap year) is calculated as follows:
 * - Add the number of leap years by dividing the number of years by 4.\n
 * - Subtract the years divisible by 100 to exclude non-leap centuries.\n
 * - Add back the years divisible by 400 to include leap centuries.\n
 *
 * @param[in] year  The year up to which days are counted. The year is not
 *                  inclusive.
 *
 * @returns The total number of days from year 0 up to but not including the
 * specified year.
 */
static int
days_from_0(int year)
{
    year -= 1;
    return 365 * year + (year / 4) - (year / 100) + (year / 400);
}

/**
 * @brief Calculates the number of days from the Epoch (January 1, 1970) to the
 * beginning of a given year.
 *
 * This function calculates the number of days from year 0 to the beginning of
 * the given year and subtracts the number of days from year 0 to the beginning
 * of 1970. All the calculations account for leap years.
 *
 * @param[in] year  The year to which days are counted. The year is not
 *                  inclusive.
 *
 * @return the total number of days from the Epoch (January 1, 1970)
 * to the beginning of the specified year.
 */
static int
days_from_epoch_to_year(int year)
{
    return days_from_0(year) - days_from_0(1970);
}

/**
 * @brief Determines if a given year is a leap year.
 *
 * This function checks whether a specified year is a leap year based on the
 * following rules:
 * - A year is a leap year if it is divisible by 4.
 * - However, years divisible by 100 are not leap years, unless they are also
 * divisible by 400.
 *
 * @note When working with broken-down time structure, always adjust the
 * `tm_year` field (years expressed since 1900) to a full year.
 * @see `tm`
 *
 * @param[in] year  The year to check. The year MUST be validated (not a
 *                  negative value).
 *
 * @returns true if the year is a leap year.
 * @returns false otherwise.
 */
static bool
is_leap_year(int year)
{
    return (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0));
}

/**
 * @brief Gets the number of days in a given month (expressed using zero-based
 * indexing).
 *
 * This function returns the number of days in the specified month, taking into
 * account whether the year is a leap year.
 * This is needed because with February (month 1) the function will return 29
 * days if it's a leap year, otherwise 28.
 * For other months, it returns the standard number of days.
 *
 * @param[in] month  The month for which to get the number of days
 *                   (0 = January, ..., 11 = December).
 *
 * @param[in] year   The year to check for leap year status.
 *
 * @return the number of days in the given month.
 * @returns -1 if the month or year is invalid.
 */
static int
days_from_month(int month, int year)
{
    static const int month_days[] = {31, 28, 31, 30, 31,
                                     30, 31, 31, 30, 31,
                                     30, 31};
    if (month < 0 || month > 11 || year < 0) {
        return -1;
    }

    if (month == 1 && is_leap_year(year)) {
        return 29;
    }
    return month_days[month];
}

/**
 * @brief Validates a broken-down time structure.
 *
 * This function ensures that each field of the `tm` struct is within
 * the standard datetime range and that the day is valid for the given month
 * and year, considering leap years for February.
 *
 * @note The `tm` struct fields are validated as follows:\n
 *       - Year (`tm_year`): Must be non-negative.\n
 *       - Month (`tm_mon`): Must be between 0 and 11
 *                           (0 = January, 11 = December).\n
 *       - Day (`tm_mday`): Must be between 1 and 31.\n
 *       - Hour (`tm_hour`): Must be between 0 and 23.\n
 *       - Minute (`tm_min`): Must be between 0 and 59.\n
 *       - Second (`tm_sec`): Must be between 0 and 59.\n
 *
 *     Additionally, the function checks the day is valid for the given month:\n
 *     - Months with 31 days\n
 *     - Months with 30 days\n
 *     - February: 28 or 29 days depending on whether the year is a leap year
 *
 *
 * @param[in] tm Pointer to a `tm` struct containing the date and time
 *               to be validated.
 *
 * @returns true if the `tm` is valid.
 * @returns false if the `tm` is not valid.
 *
 * @see `tm`
 */
static bool
is_valid_tm(const struct tm *tm)
{
    int month_days, year;

    if (tm == NULL) {
        return false;
    }

    /*
     * Although month and day are validated later, immediately return if they
     * do not satisfy standard datetime syntax.
     */
    if (tm->tm_year < 0 ||
        tm->tm_mon < 0 || tm->tm_mon > 11 ||
        tm->tm_mday < 1 || tm->tm_mday > 31 ||
        tm->tm_hour < 0 || tm->tm_hour > 23 ||
        tm->tm_min < 0 || tm->tm_min > 59 ||
        tm->tm_sec < 0 || tm->tm_sec > 59) {
        return false;
    }

    year = tm->tm_year + 1900;
    month_days = days_from_month(tm->tm_mon, year);

    if (month_days == -1) {
        /* Should never reach here */
        return false;
    }

    /* Validate day of the month */
    if (tm->tm_mday > month_days) {
        return false;
    }

    return true;
}

/**
 * @brief Converts a broken-down time structure to seconds since the Epoch time
 * (1970-01-01 00:00:00 UTC). The input is assumed to be expressed in UTC.
 *
 * @note This function is a portable implementation of the `timegm` function
 * from <time.h>. The `timegm` function is not part of the POSIX standard and
 * may not be available on all systems. By providing a custom implementation,
 * `portable_timegm` ensures consistent behavior across different environments
 * where `timegm` might not be implemented or may differ in its implementation.
 *
 * @param[in] tm  Pointer to a `tm` struct containing the broken-down time
 *                to be converted.
 *
 * @returns time since Epoch in seconds.
 * @returns (time_t)-1 on error, with errno set.
 */
time_t
portable_timegm(struct tm *tm)
{
    int i, year, days_since_epoch = 0;
    time_t ret;

    if (tm == NULL) {
        errno = EINVAL;
        return (time_t)-1;
    }

    /* Always validate tm structure */
    if (!is_valid_tm(tm)) {
        errno = EINVAL;
        return (time_t)-1;
    }

    /* Adjust years (since 1900) to a full year */
    year = tm->tm_year + 1900;

    /* Calculate total days since epoch, accounting also for leap years */
    days_since_epoch += days_from_epoch_to_year(year);

    /* Add days for each month up to the given month */
    for (i = 0; i < tm->tm_mon; i++) {
        days_since_epoch += days_from_month(i, year);
    }

    /*
     * Add days of the given month. We need to subtract 1 because tm_mday counts
     * days starting from 1, but for calculating days since the epoch, we need
     * a zero-based count.
     * E.g., if tm_mday is 4, we want to add 3 full days to days_since_epoch
     * and then account for the 4th day separately by counting its hours, time
     * and seconds (if any).
     */
    days_since_epoch += (tm->tm_mday - 1);

    ret = (days_since_epoch * (24 * 3600)) +
          (tm->tm_hour * 3600) +
          (tm->tm_min * 60) +
          tm->tm_sec;

    return ret;
}

/**
 * @brief Parse a human-readable datetime string and convert it to seconds since
 * the Epoch time.
 *
 * This function parses a datetime string in various formats and converts it
 * into the corresponding number of seconds since the Unix epoch
 * (1970-01-01 00:00:00 UTC).\n
 * It supports datetime strings with the following formats:\n
 * - YYYYMMDD[Z]\n
 * - YYYYMMDDHHMM[Z]\n
 * - YYYYMMDDHHMMSS[Z]\n
 *
 * @note If the datetime string ends with a 'Z', it is interpreted as being
 * in UTC time, and the timestamp will be adjusted accordingly to reflect the
 * correct Epoch time. If the 'Z' is not present, the datetime is assumed to be
 * in the local time zone, and the returned timestamp will reflect this local
 * time.
 *
 * @param[in] datetime    A null-terminated string representing the datetime to
 *                        be parsed.
 *
 * @param[out] timestamp  A pointer to a uint64_t where the resulting epoch time
 *                        (in seconds) will be stored.
 *
 * @returns 0 on success, with the converted epoch time stored in *timestamp.
 * @returns -1 on failure (e.g. error while parsing the input string or
 * converting it to epoch time)
 */
int
ssh_convert_datetime_format_to_timestamp(const char *datetime,
                                         uint64_t *timestamp)
{
    struct tm tm;
    time_t time;
    char *datetime_copy = NULL;
    bool utc_tz = false;
    int n_parsed;
    size_t len;

    if (datetime == NULL || timestamp == NULL) {
        SSH_LOG(SSH_LOG_DEBUG, "Bad argument");
        return -1;
    }

    len = strlen(datetime);
    if (datetime[len - 1] == 'Z') {
        utc_tz = true;
        datetime_copy = strdup(datetime);
        if (datetime_copy == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "Error while duplicating datetime");
            return -1;
        }
        datetime_copy[len - 1] = '\0';
        len -= 1;
    } else {
        datetime_copy = strdup(datetime);
        if (datetime_copy == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "Error while duplicating datetime");
            return -1;
        }
    }

    /*
     * Zero tm struct since there could be fields like hours, minutes and
     * seconds not set by sscanf (reason: missing hours,minutes and seconds
     * format or only missing seconds format).
     */
    ZERO_STRUCT(tm);

    if (len != 8 && len != 12 && len != 14) {
        SSH_LOG(SSH_LOG_DEBUG,
                "Invalid datetime format: %s",
                datetime);
        return -1;
    }

    n_parsed = sscanf(datetime_copy,
                          "%4d%2d%2d",
                          &tm.tm_year,
                          &tm.tm_mon,
                          &tm.tm_mday);
    if (n_parsed < 3) {
        SSH_LOG(SSH_LOG_TRACE, "Invalid datetime format: %s", datetime);
        return -1;
    }

    if (len >= 12) {
        n_parsed = sscanf(datetime_copy + 8,
                          "%2d%2d",
                          &tm.tm_hour,
                          &tm.tm_min);
        if (n_parsed < 2) {
            SSH_LOG(SSH_LOG_TRACE, "Invalid datetime format: %s", datetime);
            return -1;
        }
    }

    if (len == 14) {
        n_parsed = sscanf(datetime_copy + 12,
                          "%2d",
                          &tm.tm_sec);
        if (n_parsed < 1) {
            SSH_LOG(SSH_LOG_TRACE, "Invalid datetime format: %s", datetime);
            return -1;
        }
    }
    SAFE_FREE(datetime_copy);

    /*
     * Adjust year and month values for tm struct to be interpreted correctly.
     * https://man7.org/linux/man-pages/man3/tm.3type.html
     */

    /* Year since 1900 */
    tm.tm_year -= 1900;
    /* Months are 0-based in tm struct */
    tm.tm_mon -= 1;

    /* Validate tm struct fields */
    if (!is_valid_tm(&tm)) {
        SSH_LOG(SSH_LOG_DEBUG,
                "Invalid tm fields: invalid syntax for %s datetime",
                datetime);
        return -1;
    }

    errno = 0;
    if (utc_tz) {
        time = timegm(&tm);
    } else {
        time = mktime(&tm);
    }

    if (time == (time_t)-1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Error while converting tm struct: %s",
                strerror(errno));
        return -1;
    }

    *timestamp = (uint64_t)time;
    return 0;
}

/** @} */
