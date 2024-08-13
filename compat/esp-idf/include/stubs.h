#include <net/if.h>
#include <pwd.h>
#include <glob.h>

// #if !defined(GLOB_NOMATCH)
// #define GLOB_NOMATCH -3
// #endif

// #define gai_strerror(ecode) "unknown error"
// #define getuid() getuid_stub() (uid_t)0

// static inline int getpwuid_r_stub(struct passwd **result) { errno = ENOENT; *result = NULL; return 1; }
// #define getpwuid_r(uid,passwd,buffer,buflen,result) getpwuid_r_stub(result)

static inline struct passwd *getpwnam_stub() { errno = ENOENT; return NULL; }
#define getpwnam(name) getpwnam_stub()

static inline int gethostname_stub(char *name, size_t namelen) {strlcpy(name, "esp32", namelen); return 0; }
#define gethostname(name, namelen) gethostname_stub(name, namelen)

static inline pid_t waitpid_stub() { errno = ENOSYS; return (pid_t)-1; }
#define waitpid(pid,status,options) waitpid_stub()

// static inline int glob_stub() { errno = ENOENT; return GLOB_NOMATCH; }
// #define glob(pattern, flags, errfunc, pglob) glob_stub()

// #define globfree(pglob) do { } while(0)

/*
static inline int socketpair_stub() { errno = ENOSYS; return -1; }
#define socketpair(d, type, protocol, sv) socketpair_stub()
*/

/* for ttyopts.c: */
/* c_cc characters */
// #define VINTR            0
// #define VQUIT            1
// #define VERASE           2
// #define VKILL            3
// #define VEOF             4
// #define VTIME            5
// #define VMIN             6
// #define VSWTC            7
// #define VSTART           8
// #define VSTOP            9
// #define VSUSP           10
// #define VEOL            11
#define VREPRINT        12
#define VDISCARD        13
#define VWERASE         14
#define VLNEXT          15
#define VEOL2           16
/* c_iflag bits */
// #define IUCLC   0x0200
// #define IXON    0x0400
// #define IXOFF   0x1000
#define IMAXBEL 0x2000
// #define IUTF8   0x4000
/* c_lflag bits */
// #define ISIG    0x00001
// #define ICANON  0x00002
// #define XCASE   0x00004
// #define ECHO    0x00008
// #define ECHOE   0x00010
// #define ECHOK   0x00020
// #define ECHONL  0x00040
// #define NOFLSH  0x00080
// #define TOSTOP  0x00100
#define ECHOCTL 0x00200
// #define ECHOPRT 0x00400
#define ECHOKE  0x00800
// #define FLUSHO  0x01000
#define PENDIN  0x04000
// #define IEXTEN  0x08000
// #define EXTPROC 0x10000
/* copied from linux-headers-6.9/include/asm-generic/termbits.h */
