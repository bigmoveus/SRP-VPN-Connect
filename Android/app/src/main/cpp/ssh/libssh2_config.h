/* libssh2 on Android (ssh_jni.c, CMakeLists.txt): the iOS build's hand-written config (iOS/SSH/build_libssh2.sh) for
 * Bionic. Without HAVE_MEMSET_S, libssh2 wipes secrets with its own volatile loop. */
#ifndef LIBSSH2_CONFIG_H
#define LIBSSH2_CONFIG_H

#define LIBSSH2_OPENSSL 1

#define HAVE_UNISTD_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_UIO_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_UN_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_IN_H 1

#define HAVE_GETTIMEOFDAY 1
#define HAVE_STRTOLL 1
#define HAVE_SNPRINTF 1
#define HAVE_POLL 1
#define HAVE_SELECT 1

#define HAVE_O_NONBLOCK 1
#define HAVE_FIONBIO 1

#endif
