/*
 * hshield.c - Hephaestus Organ 2: Supply-Chain Auditor & Landlock Containment
 *
 * Portable C11 implementation:
 *   - Cross-platform repository trap auditor (`hshield audit [path] [--json]`):
 *     * Active .git/hooks and suspicious .git/config execution hooks
 *     * Build/lifecycle script traps (package.json, setup.py, pyproject.toml, Makefile)
 *     * Symlink escapes outside canonical repository root (via lstat + lexical check)
 *     * Untrusted repo-local agent/MCP configs (.mcp.json, .claude/settings*, .codex, .gemini)
 *     * Trojan Source bidirectional/tag Unicode & prompt-injection overrides
 *     * Zero-import Pickle VM bytecode opcode analyzer (Protocols 0..5 + PyTorch .pt/.pth ZIP)
 *   - Posture & telemetry (`hshield status [--json]`)
 *   - Zero-daemon Linux Landlock LSM containment (`hshield sandbox ... -- <cmd...>`)
 *     supporting ABI v1..v6 (filesystem, TCP network isolation unless --net, IPC scoping)
 *     with clean POSIX fallback (--strict fail-closed on non-Linux).
 *   - Linux mechanistic VMA / FFI trampoline inspector (`hshield eval-pid <pid> [--json]`)
 */

#if defined(__linux__)
#define _GNU_SOURCE
#elif defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifdef __linux__
#include <elf.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>

#if defined(__has_include)
#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#endif
#endif

#ifndef __NR_landlock_create_ruleset
#if defined(__x86_64__) || defined(__aarch64__) || defined(__riscv)
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule       445
#define __NR_landlock_restrict_self  446
#endif
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif
#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
#endif
#ifndef LANDLOCK_RULE_NET_PORT
#define LANDLOCK_RULE_NET_PORT 2
#endif

#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#define LANDLOCK_ACCESS_FS_EXECUTE     (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE  (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE   (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR    (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR  (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR   (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR    (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG    (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK   (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO   (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK  (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM    (1ULL << 12)
#endif
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER       (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE    (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV   (1ULL << 15)
#endif

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP    (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#endif
#ifndef LANDLOCK_SCOPE_SIGNAL
#define LANDLOCK_SCOPE_SIGNAL               (1ULL << 1)
#endif

struct hs_ll_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
    uint64_t scoped;
};

struct hs_ll_path_beneath_attr {
    uint64_t allowed_access;
    int32_t  parent_fd;
} __attribute__((packed));
#endif /* __linux__ */

#define HSHIELD_VERSION "0.1.0"
#define MAX_FINDINGS    512
#define MAX_ALLOW_WRITE 32
#define MAX_AUDIT_DEPTH 32
#define MAX_FILE_READ   (8U * 1024U * 1024U)

typedef struct {
    char kind[48];
    char severity[16];
    char path[512];
    char detail[256];
} AuditFinding;

typedef struct {
    char         canon_root[PATH_MAX];
    size_t       canon_root_len;
    uint64_t     scanned_files;
    size_t       finding_count;
    AuditFinding findings[MAX_FINDINGS];
} AuditCtx;

/* -------------------------------------------------------------------------
 * Portable Path, Clock & JSON Helpers
 * ------------------------------------------------------------------------- */

static uint64_t mono_ns(void) {
    struct timespec ts;
#ifdef CLOCK_MONOTONIC
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
#endif
    return 0;
}

static void resolve_home_dir(char *out, size_t cap) {
    const char *h = getenv("HOME");
    if (h && h[0]) {
        snprintf(out, cap, "%.*s", (int)(cap - 1), h);
        return;
    }
    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_dir && pw->pw_dir[0]) {
        snprintf(out, cap, "%.*s", (int)(cap - 1), pw->pw_dir);
        return;
    }
    snprintf(out, cap, "/tmp");
}

static void resolve_hephaestus_home(char *out, size_t cap) {
    const char *eh = getenv("HEPHAESTUS_HOME");
    if (eh && eh[0]) {
        snprintf(out, cap, "%.*s", (int)(cap - 1), eh);
        return;
    }
    char home[PATH_MAX];
    resolve_home_dir(home, sizeof(home));
    snprintf(out, cap, "%.*s/.hephaestus", (int)(cap - 16), home);
}

static void resolve_cache_dir(char *out, size_t cap) {
    const char *ec = getenv("HEPHAESTUS_CACHE_DIR");
    if (ec && ec[0]) {
        snprintf(out, cap, "%.*s", (int)(cap - 1), ec);
        return;
    }
    struct stat st;
    if (stat("/dev/shm", &st) == 0 && S_ISDIR(st.st_mode) &&
        access("/dev/shm", W_OK | X_OK) == 0) {
        snprintf(out, cap, "/dev/shm/hephaestus-%u", (unsigned)getuid());
        return;
    }
    const char *xdg = getenv("XDG_CACHE_HOME");
    if (xdg && xdg[0]) {
        snprintf(out, cap, "%.*s/hephaestus", (int)(cap - 16), xdg);
        return;
    }
    char home[PATH_MAX];
    resolve_home_dir(home, sizeof(home));
    if (strcmp(home, "/tmp") != 0) {
        snprintf(out, cap, "%.*s/.cache/hephaestus", (int)(cap - 24), home);
        return;
    }
    snprintf(out, cap, "/tmp/hephaestus-%u", (unsigned)getuid());
}

static void json_print_escaped(FILE *fp, const char *s) {
    fputc('"', fp);
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            unsigned char c = *p;
            if (c == '"') fputs("\\\"", fp);
            else if (c == '\\') fputs("\\\\", fp);
            else if (c == '\n') fputs("\\n", fp);
            else if (c == '\r') fputs("\\r", fp);
            else if (c == '\t') fputs("\\t", fp);
            else if (c < 0x20) fprintf(fp, "\\u%04x", (unsigned)c);
            else fputc((int)c, fp);
        }
    }
    fputc('"', fp);
}

static const char *platform_name(void) {
#if defined(__linux__)
    return "linux";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    return "bsd";
#else
    return "posix";
#endif
}

static const char *arch_name(void) {
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__aarch64__) || defined(__arm64__)
    return "aarch64";
#elif defined(__riscv)
    return "riscv64";
#else
    return "generic";
#endif
}

static int detect_landlock_abi(void) {
#if defined(__linux__) && defined(__NR_landlock_create_ruleset)
    long abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi >= 1) return (int)abi;
    return 0;
#else
    return -1;
#endif
}

/* Case-insensitive substring search without non-standard strcasestr */
static const char *ci_strstr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    if (!needle[0]) return haystack;
    size_t nlen = strlen(needle);
    char n0 = (char)tolower((unsigned char)needle[0]);
    for (const char *p = haystack; *p; p++) {
        if ((char)tolower((unsigned char)*p) == n0) {
            if (strncasecmp(p, needle, nlen) == 0) return p;
        }
    }
    return NULL;
}

static bool str_ends_with_ci(const char *s, const char *suffix) {
    if (!s || !suffix) return false;
    size_t sl = strlen(s);
    size_t xl = strlen(suffix);
    if (xl > sl) return false;
    return strcasecmp(s + sl - xl, suffix) == 0;
}

static void record_finding(AuditCtx *ctx, const char *kind, const char *severity,
                           const char *full_path, const char *detail) {
    if (!ctx || ctx->finding_count >= MAX_FINDINGS) return;
    const char *rel = full_path ? full_path : "";
    if (ctx->canon_root_len > 0 &&
        strncmp(rel, ctx->canon_root, ctx->canon_root_len) == 0) {
        if (rel[ctx->canon_root_len] == '/') {
            rel = rel + ctx->canon_root_len + 1;
        } else if (rel[ctx->canon_root_len] == '\0') {
            const char *slash = strrchr(full_path, '/');
            rel = slash ? (slash + 1) : full_path;
        }
    }
    AuditFinding *f = &ctx->findings[ctx->finding_count++];
    snprintf(f->kind, sizeof(f->kind), "%.*s", (int)sizeof(f->kind) - 1, kind ? kind : "issue");
    snprintf(f->severity, sizeof(f->severity), "%.*s", (int)sizeof(f->severity) - 1, severity ? severity : "high");
    snprintf(f->path, sizeof(f->path), "%.*s", (int)sizeof(f->path) - 1, rel[0] ? rel : ".");
    snprintf(f->detail, sizeof(f->detail), "%.*s", (int)sizeof(f->detail) - 1, detail ? detail : "");
}

/* Lexical path normalizer resolving '.' and '..' without requiring target existence */
static void normalize_lexical_path(const char *in_path, char *out, size_t cap) {
    if (!in_path || !in_path[0] || cap < 2) {
        if (cap > 0) out[0] = '\0';
        return;
    }
    const char *segs[128];
    size_t lens[128];
    int depth = 0;
    bool is_abs = (in_path[0] == '/');

    const char *p = in_path;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - start);
        if (len == 1 && start[0] == '.') {
            continue;
        }
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (depth > 0 && !(lens[depth - 1] == 2 && segs[depth - 1][0] == '.' && segs[depth - 1][1] == '.')) {
                depth--;
            } else if (!is_abs && depth < 128) {
                segs[depth] = start;
                lens[depth] = len;
                depth++;
            }
            continue;
        }
        if (depth < 128) {
            segs[depth] = start;
            lens[depth] = len;
            depth++;
        }
    }

    size_t pos = 0;
    if (is_abs) {
        out[pos++] = '/';
    }
    for (int i = 0; i < depth; i++) {
        if (i > 0 && pos + 1 < cap) out[pos++] = '/';
        size_t copy_n = lens[i];
        if (pos + copy_n >= cap) copy_n = cap - 1 - pos;
        if (copy_n > 0) {
            memcpy(out + pos, segs[i], copy_n);
            pos += copy_n;
        }
    }
    if (pos == 0 && cap >= 2) {
        out[pos++] = is_abs ? '/' : '.';
    }
    out[pos] = '\0';
}

static bool path_within_root(const char *candidate, const char *root) {
    if (!candidate || !root || !root[0]) return false;
    if (strcmp(root, "/") == 0) return candidate[0] == '/';
    size_t rlen = strlen(root);
    if (strncmp(candidate, root, rlen) != 0) return false;
    return (candidate[rlen] == '\0' || candidate[rlen] == '/');
}

static uint8_t *slurp_file_bounded(const char *path, size_t max_bytes, size_t *len_out) {
    *len_out = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return NULL;
    }
    size_t target = (size_t)st.st_size;
    if (target > max_bytes) target = max_bytes;

    uint8_t *buf = (uint8_t *)malloc(target + 1);
    if (!buf) {
        close(fd);
        return NULL;
    }
    size_t got = 0;
    while (got < target) {
        ssize_t n = read(fd, buf + got, target - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    buf[got] = '\0';
    *len_out = got;
    return buf;
}

/* -------------------------------------------------------------------------
 * Zero-Import Pickle VM Bytecode Opcode Scanner (Protocols 0..5 + ZIP .pt)
 * ------------------------------------------------------------------------- */

#define PKL_STACK_MAX 128
#define PKL_MEMO_MAX  128

typedef enum {
    PKL_VAL_OTHER = 0,
    PKL_VAL_MARK,
    PKL_VAL_STR,
    PKL_VAL_GLOBAL
} PklValKind;

typedef struct {
    PklValKind kind;
    char       s1[96];
    char       s2[96];
} PklVal;

static bool is_safe_pickle_global(const char *mod, const char *name) {
    if (!mod || !name) return false;

    /* Explicit high-risk RCE modules */
    static const char *const bad_mods[] = {
        "os", "posix", "nt", "subprocess", "pty", "commands", "popen2",
        "sys", "importlib", "runpy", "marshal", "ctypes", "cffi",
        "socket", "ssl", "http", "urllib", "requests", "ftplib", "smtplib",
        "telnetlib", "xmlrpc", "webbrowser", "pip", "setuptools", "distutils",
        "venv", "shutil", "tempfile", "code", "codeop", "bdb", "pdb",
        "timeit", "pickle", "_pickle", "types", NULL
    };
    for (int i = 0; bad_mods[i]; i++) {
        size_t bl = strlen(bad_mods[i]);
        if (strcmp(mod, bad_mods[i]) == 0 ||
            (strncmp(mod, bad_mods[i], bl) == 0 && mod[bl] == '.')) {
            return false;
        }
    }

    if (strcmp(mod, "builtins") == 0 || strcmp(mod, "__builtin__") == 0) {
        static const char *const safe_builtins[] = {
            "slice", "complex", "set", "frozenset", "bytearray", "bytes",
            "range", "dict", "list", "tuple", "int", "float", "str", "bool",
            "object", NULL
        };
        for (int i = 0; safe_builtins[i]; i++) {
            if (strcmp(name, safe_builtins[i]) == 0) return true;
        }
        return false;
    }

    /* Strict allowlist for tensor/array/collection data serialization */
    if (strcmp(mod, "collections") == 0) {
        return (strcmp(name, "OrderedDict") == 0 ||
                strcmp(name, "defaultdict") == 0 ||
                strcmp(name, "Counter") == 0 ||
                strcmp(name, "deque") == 0);
    }
    if (strcmp(mod, "copy_reg") == 0 || strcmp(mod, "copyreg") == 0) {
        return strcmp(name, "_reconstructor") == 0;
    }
    if (strcmp(mod, "_codecs") == 0) {
        return strcmp(name, "encode") == 0;
    }
    if (strcmp(mod, "datetime") == 0) {
        return (strcmp(name, "datetime") == 0 || strcmp(name, "date") == 0 ||
                strcmp(name, "time") == 0 || strcmp(name, "timedelta") == 0 ||
                strcmp(name, "timezone") == 0);
    }
    if (strncmp(mod, "torch", 5) == 0 && (mod[5] == '\0' || mod[5] == '.')) {
        if (strstr(mod, "jit") || strstr(mod, "hub") || strstr(mod, "package")) {
            return false;
        }
        return (strncmp(name, "_rebuild_", 9) == 0 ||
                strstr(name, "Storage") != NULL ||
                strcmp(name, "Size") == 0 ||
                strcmp(name, "device") == 0 ||
                strcmp(name, "dtype") == 0 ||
                strcmp(name, "Tensor") == 0);
    }
    if (strncmp(mod, "numpy", 5) == 0 && (mod[5] == '\0' || mod[5] == '.')) {
        if (strstr(mod, "f2py") || strstr(mod, "distutils") || strstr(mod, "testing")) {
            return false;
        }
        return (strcmp(name, "_reconstruct") == 0 ||
                strcmp(name, "scalar") == 0 ||
                strcmp(name, "ndarray") == 0 ||
                strcmp(name, "dtype") == 0 ||
                strcmp(name, "_frombuffer") == 0);
    }
    return false;
}

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_u64_le(const uint8_t *p) {
    return (uint64_t)read_u32_le(p) | ((uint64_t)read_u32_le(p + 4) << 32);
}

static bool read_nl_token(const uint8_t *buf, size_t len, size_t *pos, char *out, size_t cap) {
    size_t start = *pos;
    size_t i = start;
    while (i < len && buf[i] != '\n') i++;
    if (i >= len) return false;
    size_t slen = i - start;
    if (slen > 0 && buf[start + slen - 1] == '\r') slen--;
    /* Strip optional Protocol 0 string quotes */
    if (slen >= 2 && ((buf[start] == '\'' && buf[start + slen - 1] == '\'') ||
                      (buf[start] == '"' && buf[start + slen - 1] == '"'))) {
        start++;
        slen -= 2;
    }
    if (slen >= cap) slen = cap - 1;
    if (slen > 0) memcpy(out, buf + start, slen);
    out[slen] = '\0';
    *pos = i + 1;
    return true;
}

static void pkl_push(PklVal *stack, int *sp, PklVal v) {
    if (*sp < PKL_STACK_MAX) {
        stack[(*sp)++] = v;
    } else {
        memmove(stack, stack + 1, (PKL_STACK_MAX - 1) * sizeof(PklVal));
        stack[PKL_STACK_MAX - 1] = v;
    }
}

static PklVal pkl_pop(PklVal *stack, int *sp) {
    PklVal empty;
    memset(&empty, 0, sizeof(empty));
    if (*sp <= 0) return empty;
    return stack[--(*sp)];
}

static void pkl_pop_to_mark(PklVal *stack, int *sp) {
    while (*sp > 0) {
        (*sp)--;
        if (stack[*sp].kind == PKL_VAL_MARK) break;
    }
}

static bool scan_pickle_stream(const uint8_t *buf, size_t len, char *detail_out, size_t dcap) {
    if (!buf || len == 0) return false;

    PklVal stack[PKL_STACK_MAX];
    PklVal memo[PKL_MEMO_MAX];
    memset(stack, 0, sizeof(stack));
    memset(memo, 0, sizeof(memo));
    int sp = 0;
    int next_memo = 0;

    size_t pos = 0;
    size_t ops = 0;
    while (pos < len && ops < 2000000U) {
        uint8_t op = buf[pos++];
        ops++;
        PklVal v;
        memset(&v, 0, sizeof(v));

        switch (op) {
        case 0x80: /* PROTO */
            if (pos >= len) {
                snprintf(detail_out, dcap, "truncated pickle PROTO header");
                return true;
            }
            pos += 1;
            break;

        case 0x95: /* FRAME (8-byte prefetch frame length; opcodes follow inline) */
            if (pos + 8 > len) {
                snprintf(detail_out, dcap, "truncated pickle FRAME header");
                return true;
            }
            pos += 8;
            break;

        case '.': /* STOP */
            return false;

        case '(': /* MARK */
            v.kind = PKL_VAL_MARK;
            pkl_push(stack, &sp, v);
            break;

        case '0': /* POP */
            (void)pkl_pop(stack, &sp);
            break;

        case '1': /* POP_MARK */
            pkl_pop_to_mark(stack, &sp);
            break;

        case '2': /* DUP */
            if (sp > 0) pkl_push(stack, &sp, stack[sp - 1]);
            break;

        case 'N': /* NONE */
        case 0x88: /* NEWTRUE */
        case 0x89: /* NEWFALSE */
        case ')': /* EMPTY_TUPLE */
        case ']': /* EMPTY_LIST */
        case '}': /* EMPTY_DICT */
        case 0x8f: /* EMPTY_SET */
        case 0x97: /* NEXT_BUFFER */
            pkl_push(stack, &sp, v);
            break;

        case 0x98: /* READONLY_BUFFER */
        case 0x85: /* TUPLE1 */
            break;

        case 0x86: /* TUPLE2 */
            (void)pkl_pop(stack, &sp);
            (void)pkl_pop(stack, &sp);
            pkl_push(stack, &sp, v);
            break;

        case 0x87: /* TUPLE3 */
            (void)pkl_pop(stack, &sp);
            (void)pkl_pop(stack, &sp);
            (void)pkl_pop(stack, &sp);
            pkl_push(stack, &sp, v);
            break;

        case 't': /* TUPLE */
        case 'l': /* LIST */
        case 'd': /* DICT */
        case 0x91: /* FROZENSET */
            pkl_pop_to_mark(stack, &sp);
            pkl_push(stack, &sp, v);
            break;

        case 'a': /* APPEND */
        case 'b': /* BUILD */
        case 'Q': /* BINPERSID */
            (void)pkl_pop(stack, &sp);
            break;

        case 's': /* SETITEM */
            (void)pkl_pop(stack, &sp);
            (void)pkl_pop(stack, &sp);
            break;

        case 'e': /* APPENDS */
        case 'u': /* SETITEMS */
        case 0x90: /* ADDITEMS */
            pkl_pop_to_mark(stack, &sp);
            break;

        case 'K': /* BININT1 */
            if (pos + 1 > len) return false;
            pos += 1;
            pkl_push(stack, &sp, v);
            break;

        case 'M': /* BININT2 */
            if (pos + 2 > len) return false;
            pos += 2;
            pkl_push(stack, &sp, v);
            break;

        case 'J': /* BININT */
            if (pos + 4 > len) return false;
            pos += 4;
            pkl_push(stack, &sp, v);
            break;

        case 'G': /* BINFLOAT */
            if (pos + 8 > len) return false;
            pos += 8;
            pkl_push(stack, &sp, v);
            break;

        case 0x8a: { /* LONG1 */
            if (pos + 1 > len) return false;
            size_t n = buf[pos++];
            if (pos + n > len) return false;
            pos += n;
            pkl_push(stack, &sp, v);
            break;
        }

        case 0x8b: { /* LONG4 */
            if (pos + 4 > len) return false;
            uint32_t n = read_u32_le(buf + pos);
            pos += 4;
            if (n > len - pos) return false;
            pos += n;
            pkl_push(stack, &sp, v);
            break;
        }

        case 'I': /* INT */
        case 'L': /* LONG */
        case 'F': /* FLOAT */
        case 'P': { /* PERSID */
            char tmp[64];
            if (!read_nl_token(buf, len, &pos, tmp, sizeof(tmp))) return false;
            pkl_push(stack, &sp, v);
            break;
        }

        case 'S': /* STRING */
        case 'V': { /* UNICODE */
            v.kind = PKL_VAL_STR;
            if (!read_nl_token(buf, len, &pos, v.s1, sizeof(v.s1))) return false;
            pkl_push(stack, &sp, v);
            break;
        }

        case 0x8c: /* SHORT_BINUNICODE */
        case 'U': { /* SHORT_BINSTRING */
            if (pos + 1 > len) return false;
            size_t n = buf[pos++];
            if (pos + n > len) return false;
            v.kind = PKL_VAL_STR;
            size_t cp = n < sizeof(v.s1) - 1 ? n : sizeof(v.s1) - 1;
            if (cp > 0) memcpy(v.s1, buf + pos, cp);
            v.s1[cp] = '\0';
            pos += n;
            pkl_push(stack, &sp, v);
            break;
        }

        case 'X': /* BINUNICODE */
        case 'T': { /* BINSTRING */
            if (pos + 4 > len) return false;
            uint32_t n = read_u32_le(buf + pos);
            pos += 4;
            if (n > len - pos) return false;
            v.kind = PKL_VAL_STR;
            size_t cp = n < sizeof(v.s1) - 1 ? (size_t)n : sizeof(v.s1) - 1;
            if (cp > 0) memcpy(v.s1, buf + pos, cp);
            v.s1[cp] = '\0';
            pos += n;
            pkl_push(stack, &sp, v);
            break;
        }

        case 0x8d: { /* BINUNICODE8 */
            if (pos + 8 > len) return false;
            uint64_t n = read_u64_le(buf + pos);
            pos += 8;
            if (n > (uint64_t)(len - pos)) return false;
            v.kind = PKL_VAL_STR;
            size_t cp = n < sizeof(v.s1) - 1 ? (size_t)n : sizeof(v.s1) - 1;
            if (cp > 0) memcpy(v.s1, buf + pos, cp);
            v.s1[cp] = '\0';
            pos += (size_t)n;
            pkl_push(stack, &sp, v);
            break;
        }

        case 'C': { /* SHORT_BINBYTES */
            if (pos + 1 > len) return false;
            size_t n = buf[pos++];
            if (pos + n > len) return false;
            pos += n;
            pkl_push(stack, &sp, v);
            break;
        }

        case 'B': { /* BINBYTES */
            if (pos + 4 > len) return false;
            uint32_t n = read_u32_le(buf + pos);
            pos += 4;
            if (n > len - pos) return false;
            pos += n;
            pkl_push(stack, &sp, v);
            break;
        }

        case 0x8e: /* BINBYTES8 */
        case 0x96: { /* BYTEARRAY8 */
            if (pos + 8 > len) return false;
            uint64_t n = read_u64_le(buf + pos);
            pos += 8;
            if (n > (uint64_t)(len - pos)) return false;
            pos += (size_t)n;
            pkl_push(stack, &sp, v);
            break;
        }

        case 0x94: /* MEMOIZE */
            if (sp > 0 && next_memo < PKL_MEMO_MAX) {
                memo[next_memo++] = stack[sp - 1];
            }
            break;

        case 'q': { /* BINPUT */
            if (pos + 1 > len) return false;
            uint8_t idx = buf[pos++];
            if (sp > 0 && idx < PKL_MEMO_MAX) memo[idx] = stack[sp - 1];
            break;
        }

        case 'r': { /* LONG_BINPUT */
            if (pos + 4 > len) return false;
            uint32_t idx = read_u32_le(buf + pos);
            pos += 4;
            if (sp > 0 && idx < PKL_MEMO_MAX) memo[idx] = stack[sp - 1];
            break;
        }

        case 'p': { /* PUT */
            char idx_s[32];
            if (!read_nl_token(buf, len, &pos, idx_s, sizeof(idx_s))) return false;
            int idx = atoi(idx_s);
            if (sp > 0 && idx >= 0 && idx < PKL_MEMO_MAX) memo[idx] = stack[sp - 1];
            break;
        }

        case 'h': { /* BINGET */
            if (pos + 1 > len) return false;
            uint8_t idx = buf[pos++];
            if (idx < PKL_MEMO_MAX) pkl_push(stack, &sp, memo[idx]);
            else pkl_push(stack, &sp, v);
            break;
        }

        case 'j': { /* LONG_BINGET */
            if (pos + 4 > len) return false;
            uint32_t idx = read_u32_le(buf + pos);
            pos += 4;
            if (idx < PKL_MEMO_MAX) pkl_push(stack, &sp, memo[idx]);
            else pkl_push(stack, &sp, v);
            break;
        }

        case 'g': { /* GET */
            char idx_s[32];
            if (!read_nl_token(buf, len, &pos, idx_s, sizeof(idx_s))) return false;
            int idx = atoi(idx_s);
            if (idx >= 0 && idx < PKL_MEMO_MAX) pkl_push(stack, &sp, memo[idx]);
            else pkl_push(stack, &sp, v);
            break;
        }

        case 'c': /* GLOBAL */
        case 'i': { /* INST */
            v.kind = PKL_VAL_GLOBAL;
            if (!read_nl_token(buf, len, &pos, v.s1, sizeof(v.s1)) ||
                !read_nl_token(buf, len, &pos, v.s2, sizeof(v.s2))) {
                snprintf(detail_out, dcap, "malformed pickle GLOBAL/INST opcode");
                return true;
            }
            if (!is_safe_pickle_global(v.s1, v.s2)) {
                snprintf(detail_out, dcap, "dangerous pickle %s target: %.64s.%.64s",
                         (op == 'i') ? "INST" : "GLOBAL", v.s1, v.s2);
                return true;
            }
            if (op == 'i') {
                pkl_pop_to_mark(stack, &sp);
                v.kind = PKL_VAL_OTHER;
            }
            pkl_push(stack, &sp, v);
            break;
        }

        case 0x93: { /* STACK_GLOBAL */
            PklVal name_v = pkl_pop(stack, &sp);
            PklVal mod_v  = pkl_pop(stack, &sp);
            if (mod_v.kind != PKL_VAL_STR || name_v.kind != PKL_VAL_STR) {
                snprintf(detail_out, dcap, "non-literal pickle STACK_GLOBAL resolution");
                return true;
            }
            if (!is_safe_pickle_global(mod_v.s1, name_v.s1)) {
                snprintf(detail_out, dcap, "dangerous pickle STACK_GLOBAL target: %.64s.%.64s",
                         mod_v.s1, name_v.s1);
                return true;
            }
            v.kind = PKL_VAL_GLOBAL;
            snprintf(v.s1, sizeof(v.s1), "%s", mod_v.s1);
            snprintf(v.s2, sizeof(v.s2), "%s", name_v.s1);
            pkl_push(stack, &sp, v);
            break;
        }

        case 0x82: /* EXT1 */
        case 0x83: /* EXT2 */
        case 0x84: /* EXT4 */
            snprintf(detail_out, dcap, "disallowed pickle copyreg EXT opcode (0x%02x)", (unsigned)op);
            return true;

        case 'R': { /* REDUCE */
            (void)pkl_pop(stack, &sp); /* args tuple */
            PklVal fn = pkl_pop(stack, &sp);
            if (fn.kind == PKL_VAL_GLOBAL && !is_safe_pickle_global(fn.s1, fn.s2)) {
                snprintf(detail_out, dcap, "dangerous pickle REDUCE invocation: %.64s.%.64s", fn.s1, fn.s2);
                return true;
            }
            pkl_push(stack, &sp, v);
            break;
        }

        case 0x81: { /* NEWOBJ */
            (void)pkl_pop(stack, &sp); /* args */
            PklVal cls = pkl_pop(stack, &sp);
            if (cls.kind == PKL_VAL_GLOBAL && !is_safe_pickle_global(cls.s1, cls.s2)) {
                snprintf(detail_out, dcap, "dangerous pickle NEWOBJ instantiation: %.64s.%.64s", cls.s1, cls.s2);
                return true;
            }
            pkl_push(stack, &sp, v);
            break;
        }

        case 0x92: { /* NEWOBJ_EX */
            (void)pkl_pop(stack, &sp); /* kwargs */
            (void)pkl_pop(stack, &sp); /* args */
            PklVal cls = pkl_pop(stack, &sp);
            if (cls.kind == PKL_VAL_GLOBAL && !is_safe_pickle_global(cls.s1, cls.s2)) {
                snprintf(detail_out, dcap, "dangerous pickle NEWOBJ_EX instantiation: %.64s.%.64s", cls.s1, cls.s2);
                return true;
            }
            pkl_push(stack, &sp, v);
            break;
        }

        case 'o': /* OBJ */
            pkl_pop_to_mark(stack, &sp);
            pkl_push(stack, &sp, v);
            break;

        default:
            snprintf(detail_out, dcap, "unknown/untrusted pickle opcode 0x%02x at offset %zu",
                     (unsigned)op, pos - 1);
            return true;
        }
    }
    return false;
}

/* Scan PyTorch .pt/.pth/.ckpt ZIP container for embedded *.pkl entries */
static void audit_zip_pickle_archive(AuditCtx *ctx, const char *full_path,
                                     const uint8_t *buf, size_t len) {
    size_t pos = 0;
    while (pos + 30 <= len) {
        if (!(buf[pos] == 'P' && buf[pos + 1] == 'K')) {
            pos++;
            continue;
        }
        if (buf[pos + 2] == 0x01 && buf[pos + 3] == 0x02) break; /* Central directory */
        if (buf[pos + 2] != 0x03 || buf[pos + 3] != 0x04) {
            pos += 4;
            continue;
        }

        uint16_t flags  = (uint16_t)(buf[pos + 6] | (buf[pos + 7] << 8));
        uint16_t method = (uint16_t)(buf[pos + 8] | (buf[pos + 9] << 8));
        uint32_t csize  = read_u32_le(buf + pos + 18);
        uint16_t fnlen  = (uint16_t)(buf[pos + 26] | (buf[pos + 27] << 8));
        uint16_t exlen  = (uint16_t)(buf[pos + 28] | (buf[pos + 29] << 8));

        size_t hdr_end = pos + 30 + (size_t)fnlen + (size_t)exlen;
        if (hdr_end > len) break;

        char entry_name[256];
        size_t ncp = fnlen < sizeof(entry_name) - 1 ? fnlen : sizeof(entry_name) - 1;
        memcpy(entry_name, buf + pos + 30, ncp);
        entry_name[ncp] = '\0';

        /* Check Zip-Slip path traversal inside archive entry name */
        if (entry_name[0] == '/' || strstr(entry_name, "../") != NULL) {
            char msg[256];
            snprintf(msg, sizeof(msg), "zip-slip path traversal in archive entry: %.160s", entry_name);
            record_finding(ctx, "archive_traversal", "high", full_path, msg);
        }

        size_t data_len = csize;
        if (hdr_end + data_len > len) {
            /* If streaming data descriptor (bit 3) was used without csize, scan for next PK header */
            if ((flags & 0x08U) != 0 && csize == 0) {
                size_t scan = hdr_end;
                while (scan + 4 <= len &&
                       !(buf[scan] == 'P' && buf[scan + 1] == 'K' &&
                         (buf[scan + 2] == 0x03 || buf[scan + 2] == 0x01 || buf[scan + 2] == 0x07))) {
                    scan++;
                }
                data_len = scan - hdr_end;
            } else {
                data_len = len - hdr_end;
            }
        }

        if (str_ends_with_ci(entry_name, ".pkl") || str_ends_with_ci(entry_name, ".pickle")) {
            if (method == 0 && data_len > 0) {
                char pdetail[200];
                if (scan_pickle_stream(buf + hdr_end, data_len, pdetail, sizeof(pdetail))) {
                    char msg[256];
                    snprintf(msg, sizeof(msg), "%.72s: %.170s", entry_name, pdetail);
                    record_finding(ctx, "pickle_rce", "high", full_path, msg);
                }
            } else if (method != 0) {
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "compressed pickle entry %.120s (method=%u) obscures static bytecode inspection",
                         entry_name, (unsigned)method);
                record_finding(ctx, "pickle_compressed", "high", full_path, msg);
            }
        }

        pos = hdr_end + data_len;
    }
}

static bool has_pickle_extension(const char *base) {
    return (str_ends_with_ci(base, ".pkl") ||
            str_ends_with_ci(base, ".pickle") ||
            str_ends_with_ci(base, ".dill") ||
            str_ends_with_ci(base, ".joblib") ||
            str_ends_with_ci(base, ".pt") ||
            str_ends_with_ci(base, ".pth") ||
            str_ends_with_ci(base, ".ckpt") ||
            str_ends_with_ci(base, ".mar"));
}

/* -------------------------------------------------------------------------
 * Repository Trap Detectors (Hooks, Build Scripts, Configs, Unicode, Prompts)
 * ------------------------------------------------------------------------- */

static void inspect_text_for_trojan_unicode(AuditCtx *ctx, const char *full_path,
                                            const uint8_t *buf, size_t len) {
    /* Skip binary blobs containing NUL bytes in prefix */
    size_t probe = len < 4096 ? len : 4096;
    for (size_t i = 0; i < probe; i++) {
        if (buf[i] == 0x00) return;
    }

    size_t line = 1;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\n') {
            line++;
            continue;
        }
        /* UTF-8 E2 80 [AA..AE] (LRE..RLO) or E2 80 [8B..8F] (ZWSP/ZWNJ/ZWJ/LRM/RLM) */
        if (i + 2 < len && buf[i] == 0xE2 && buf[i + 1] == 0x80) {
            uint8_t b2 = buf[i + 2];
            if (b2 >= 0xAA && b2 <= 0xAE) {
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "Trojan Source bidirectional override U+20%02X at line %zu",
                         (unsigned)b2, line);
                record_finding(ctx, "trojan_unicode", "high", full_path, msg);
                return;
            }
            if (b2 == 0x8B || b2 == 0x8E || b2 == 0x8F) {
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "hidden zero-width/directional control U+20%02X at line %zu",
                         (unsigned)b2, line);
                record_finding(ctx, "trojan_unicode", "medium", full_path, msg);
                return;
            }
        }
        /* UTF-8 E2 81 [A6..A9] (LRI, RLI, FSI, PDI) */
        if (i + 2 < len && buf[i] == 0xE2 && buf[i + 1] == 0x81) {
            uint8_t b2 = buf[i + 2];
            if (b2 >= 0xA6 && b2 <= 0xA9) {
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "Trojan Source bidirectional isolate U+20%02X at line %zu",
                         (unsigned)(b2 - 0x40), line);
                record_finding(ctx, "trojan_unicode", "high", full_path, msg);
                return;
            }
        }
        /* Unicode Tag smuggling U+E0001..U+E007F: F3 A0 80 [81..BF] or F3 A0 81 [80..BF] */
        if (i + 3 < len && buf[i] == 0xF3 && buf[i + 1] == 0xA0 &&
            (buf[i + 2] == 0x80 || buf[i + 2] == 0x81)) {
            char msg[256];
            snprintf(msg, sizeof(msg), "hidden Unicode Tag ASCII-smuggling sequence at line %zu", line);
            record_finding(ctx, "trojan_unicode", "high", full_path, msg);
            return;
        }
    }
}

static bool is_doc_or_agent_instruction_file(const char *base) {
    if (!base) return false;
    if (strcasecmp(base, "CLAUDE.md") == 0 ||
        strcasecmp(base, "AGENTS.md") == 0 ||
        strcasecmp(base, "GEMINI.md") == 0 ||
        strcasecmp(base, ".cursorrules") == 0 ||
        strcasecmp(base, ".windsurfrules") == 0 ||
        strcasecmp(base, "copilot-instructions.md") == 0) {
        return true;
    }
    return (str_ends_with_ci(base, ".md") ||
            str_ends_with_ci(base, ".mdc") ||
            str_ends_with_ci(base, ".txt") ||
            str_ends_with_ci(base, ".rst"));
}

static void inspect_prompt_injection(AuditCtx *ctx, const char *full_path, const char *text) {
    static const char *const directives[] = {
        "ignore previous instructions",
        "ignore all previous instructions",
        "disregard all previous instructions",
        "disregard prior instructions",
        "forget all previous instructions",
        "new system instructions:",
        "system prompt override",
        "you are now in developer mode",
        NULL
    };
    for (int i = 0; directives[i]; i++) {
        if (ci_strstr(text, directives[i]) != NULL) {
            char msg[256];
            snprintf(msg, sizeof(msg), "prompt-injection override phrase detected: '%s'", directives[i]);
            record_finding(ctx, "prompt_injection", "high", full_path, msg);
            return;
        }
    }
    /* Hidden HTML comment carrying shell/exfiltration instruction */
    const char *cstart = strstr(text, "<!--");
    while (cstart) {
        const char *cend = strstr(cstart + 4, "-->");
        if (!cend) break;
        size_t clen = (size_t)(cend - (cstart + 4));
        if (clen > 0 && clen < 4096) {
            char snippet[4096];
            memcpy(snippet, cstart + 4, clen);
            snippet[clen] = '\0';
            if ((ci_strstr(snippet, "curl ") || ci_strstr(snippet, "wget ") ||
                 ci_strstr(snippet, ".ssh") || ci_strstr(snippet, "exfiltrate")) &&
                (ci_strstr(snippet, "assistant") || ci_strstr(snippet, "agent") ||
                 ci_strstr(snippet, "do not tell") || ci_strstr(snippet, "silently") ||
                 ci_strstr(snippet, "run "))) {
                record_finding(ctx, "prompt_injection", "high", full_path,
                               "hidden HTML comment contains covert agent execution/exfiltration directive");
                return;
            }
        }
        cstart = strstr(cend + 3, "<!--");
    }
}

static bool json_lifecycle_value_suspicious(const char *val) {
    static const char *const indicators[] = {
        "curl ", "curl\t", "wget ", "nc ", "ncat ", "socat ", "/dev/tcp/",
        "bash -c", "sh -c", "zsh -c", "eval ", "base64", "chmod +x",
        "child_process", "urllib", "subprocess", "os.system", "pty.spawn",
        ".ssh", ".aws", ".gnupg", ".netrc", "http://", "https://", "powershell",
        NULL
    };
    for (int i = 0; indicators[i]; i++) {
        if (ci_strstr(val, indicators[i]) != NULL) {
            /* Allow benign https:// registry/docs links only if no shell exec token */
            if (strcmp(indicators[i], "https://") == 0 || strcmp(indicators[i], "http://") == 0) {
                if (ci_strstr(val, "curl") || ci_strstr(val, "wget") ||
                    ci_strstr(val, "fetch(") || ci_strstr(val, "node -e") ||
                    ci_strstr(val, "python")) {
                    return true;
                }
                continue;
            }
            return true;
        }
    }
    return false;
}

static void inspect_package_json(AuditCtx *ctx, const char *full_path, const char *text) {
    static const char *const hooks[] = {
        "\"preinstall\"", "\"install\"", "\"postinstall\"",
        "\"preuninstall\"", "\"postuninstall\"", "\"prepare\"", NULL
    };
    for (int i = 0; hooks[i]; i++) {
        const char *p = strstr(text, hooks[i]);
        while (p) {
            const char *colon = strchr(p + strlen(hooks[i]), ':');
            if (!colon) break;
            const char *q = colon + 1;
            while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
            if (*q == '"') {
                q++;
                char val[1024];
                size_t vi = 0;
                while (*q && *q != '"' && vi + 1 < sizeof(val)) {
                    if (*q == '\\' && q[1]) {
                        val[vi++] = q[1];
                        q += 2;
                    } else {
                        val[vi++] = *q++;
                    }
                }
                val[vi] = '\0';
                if (json_lifecycle_value_suspicious(val)) {
                    char msg[256];
                    snprintf(msg, sizeof(msg), "suspicious npm %s hook: %.160s", hooks[i], val);
                    record_finding(ctx, "build_script_trap", "high", full_path, msg);
                    return;
                }
            }
            p = strstr(colon + 1, hooks[i]);
        }
    }
}

static void inspect_python_build_file(AuditCtx *ctx, const char *full_path,
                                      const char *base, const char *text) {
    if (strcasecmp(base, "setup.py") == 0) {
        bool has_exec = (strstr(text, "os.system(") != NULL ||
                         strstr(text, "subprocess.") != NULL ||
                         strstr(text, "pty.spawn") != NULL ||
                         strstr(text, "base64.b64decode") != NULL);
        bool has_net_or_shell = (strstr(text, "urllib") != NULL ||
                                 strstr(text, "requests.") != NULL ||
                                 strstr(text, "socket.") != NULL ||
                                 strstr(text, "curl ") != NULL ||
                                 strstr(text, "wget ") != NULL ||
                                 strstr(text, "/dev/tcp/") != NULL ||
                                 strstr(text, "exec(") != NULL ||
                                 strstr(text, "eval(") != NULL ||
                                 strstr(text, ".ssh") != NULL);
        if ((has_exec && has_net_or_shell) || strstr(text, "/dev/tcp/") != NULL ||
            (strstr(text, "base64.b64decode") != NULL &&
             (strstr(text, "exec(") != NULL || strstr(text, "subprocess") != NULL))) {
            record_finding(ctx, "build_script_trap", "high", full_path,
                           "setup.py contains install-time code execution / network payload");
        }
    } else if (strcasecmp(base, "pyproject.toml") == 0) {
        if (strstr(text, "/dev/tcp/") != NULL ||
            (ci_strstr(text, "curl ") && (strstr(text, "| sh") || strstr(text, "| bash"))) ||
            (ci_strstr(text, "wget ") && (strstr(text, "| sh") || strstr(text, "| bash"))) ||
            strstr(text, "base64 -d") != NULL) {
            record_finding(ctx, "build_script_trap", "high", full_path,
                           "pyproject.toml contains shell execution trap");
        }
    }
}

static void inspect_makefile(AuditCtx *ctx, const char *full_path, const char *text) {
    if (strstr(text, "/dev/tcp/") != NULL ||
        (ci_strstr(text, "curl ") && (strstr(text, "| sh") || strstr(text, "| bash") || strstr(text, "|sh") || strstr(text, "|bash"))) ||
        (ci_strstr(text, "wget ") && (strstr(text, "| sh") || strstr(text, "| bash") || strstr(text, "|sh") || strstr(text, "|bash"))) ||
        (strstr(text, "base64 -d") && (strstr(text, "| sh") || strstr(text, "| bash") || strstr(text, "eval "))) ||
        strstr(text, "nc -e /bin/") != NULL ||
        strstr(text, "bash -i >&") != NULL) {
        record_finding(ctx, "build_script_trap", "high", full_path,
                       "Makefile contains remote pipe-to-shell or reverse-shell recipe");
    }
}

static void inspect_agent_config(AuditCtx *ctx, const char *full_path,
                                 const char *rel_or_base, const char *text) {
    bool is_mcp = (strcasecmp(rel_or_base, ".mcp.json") == 0 ||
                   str_ends_with_ci(full_path, "/.mcp.json") ||
                   str_ends_with_ci(full_path, "/.cursor/mcp.json") ||
                   str_ends_with_ci(full_path, "/.vscode/mcp.json") ||
                   str_ends_with_ci(full_path, "/.claude/mcp.json"));
    if (is_mcp) {
        if (strstr(text, "\"mcpServers\"") != NULL || strstr(text, "\"servers\"") != NULL) {
            if (ci_strstr(text, "bash") || ci_strstr(text, "\"sh\"") || ci_strstr(text, "/bin/sh") ||
                ci_strstr(text, "curl") || ci_strstr(text, "wget") || ci_strstr(text, "nc ") ||
                ci_strstr(text, "socat") || ci_strstr(text, "eval") || ci_strstr(text, "base64") ||
                ci_strstr(text, "LD_PRELOAD") || ci_strstr(text, "DYLD_INSERT_LIBRARIES") ||
                ci_strstr(text, "NODE_OPTIONS") || ci_strstr(text, "PYTHONSTARTUP") ||
                ci_strstr(text, "/tmp/") || ci_strstr(text, "npx") || ci_strstr(text, "uvx") ||
                ci_strstr(text, "python -c") || ci_strstr(text, "python3 -c") ||
                ci_strstr(text, "node -e")) {
                record_finding(ctx, "agent_config_trap", "high", full_path,
                               "untrusted repo-local MCP config invokes shell/dynamic command");
                return;
            }
            record_finding(ctx, "agent_config_trap", "medium", full_path,
                           "repo-local MCP server definition requires review before enabling");
        }
        return;
    }

    /* .claude/settings.json, .codex/config, .gemini/settings, .cursor/hooks.json */
    if (strstr(text, "\"hooks\"") != NULL ||
        strstr(text, "\"apiKeyHelper\"") != NULL ||
        strstr(text, "\"awsAuthRefresh\"") != NULL ||
        strstr(text, "\"gcpAuthRefresh\"") != NULL ||
        strstr(text, "\"otelHeadersHelper\"") != NULL ||
        strstr(text, "Bash(*)") != NULL ||
        strstr(text, "dangerously-skip-permissions") != NULL ||
        strstr(text, "approval_policy = \"never\"") != NULL ||
        strstr(text, "sandbox_mode = \"danger-full-access\"") != NULL) {
        record_finding(ctx, "agent_config_trap", "high", full_path,
                       "repo-local agent config overrides hooks, auth helpers, or sandbox permissions");
    }
}

static void inspect_git_dir(AuditCtx *ctx, const char *git_dir) {
    /* 1. Check .git/config for core.fsmonitor / core.sshCommand / core.hooksPath traps */
    char cfg_path[PATH_MAX];
    snprintf(cfg_path, sizeof(cfg_path), "%.*s/config", (int)sizeof(cfg_path) - 16, git_dir);
    size_t cfg_len = 0;
    uint8_t *cfg_buf = slurp_file_bounded(cfg_path, 262144, &cfg_len);
    if (cfg_buf) {
        ctx->scanned_files++;
        const char *text = (const char *)cfg_buf;
        if (ci_strstr(text, "fsmonitor") || ci_strstr(text, "sshCommand") ||
            ci_strstr(text, "hooksPath") || ci_strstr(text, "ProxyCommand")) {
            record_finding(ctx, "git_config_trap", "high", cfg_path,
                           ".git/config defines custom execution hook (fsmonitor/sshCommand/hooksPath)");
        }
        free(cfg_buf);
    }

    /* 2. Check .git/hooks directory for active non-.sample hooks */
    char hooks_dir[PATH_MAX];
    snprintf(hooks_dir, sizeof(hooks_dir), "%.*s/hooks", (int)sizeof(hooks_dir) - 16, git_dir);
    DIR *d = opendir(hooks_dir);
    if (!d) return;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if (str_ends_with_ci(name, ".sample") || strncasecmp(name, "README", 6) == 0) continue;

        char hp[PATH_MAX];
        snprintf(hp, sizeof(hp), "%.*s/%.*s",
                 (int)(sizeof(hp) - 260), hooks_dir, 250, name);
        struct stat st;
        if (lstat(hp, &st) != 0) continue;
        ctx->scanned_files++;

        if (S_ISLNK(st.st_mode)) {
            record_finding(ctx, "git_hook_trap", "high", hp,
                           "symlinked git hook inside .git/hooks");
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;

        size_t hlen = 0;
        uint8_t *hbuf = slurp_file_bounded(hp, 262144, &hlen);
        bool exec_bit = ((st.st_mode & 0111) != 0);
        bool has_susp = false;
        if (hbuf) {
            const char *ht = (const char *)hbuf;
            if (ci_strstr(ht, "curl ") || ci_strstr(ht, "wget ") || ci_strstr(ht, "/dev/tcp/") ||
                ci_strstr(ht, "nc ") || ci_strstr(ht, "socat ") || ci_strstr(ht, "base64") ||
                ci_strstr(ht, "python") || ci_strstr(ht, "nohup") || ci_strstr(ht, ".ssh")) {
                has_susp = true;
            }
            free(hbuf);
        }
        if (exec_bit || has_susp) {
            char msg[256];
            snprintf(msg, sizeof(msg), "active git hook '%.160s' (%s)",
                     name, has_susp ? "contains network/exec primitives" : "executable non-sample hook");
            record_finding(ctx, "git_hook_trap", "high", hp, msg);
        }
    }
    closedir(d);
}

static void inspect_symlink(AuditCtx *ctx, const char *parent_dir, const char *full_path) {
    char link_target[PATH_MAX];
    ssize_t rl = readlink(full_path, link_target, sizeof(link_target) - 1);
    if (rl < 0) return;
    link_target[rl] = '\0';

    /* 1. Try canonical realpath resolution if target exists */
    char resolved[PATH_MAX];
    if (realpath(full_path, resolved) != NULL) {
        if (!path_within_root(resolved, ctx->canon_root)) {
            char msg[256];
            snprintf(msg, sizeof(msg), "symlink escapes repository root -> %.160s", link_target);
            record_finding(ctx, "symlink_escape", "high", full_path, msg);
        }
        return;
    }

    /* 2. Dangling symlink: resolve lexically relative to canonical parent directory */
    char real_parent[PATH_MAX];
    if (realpath(parent_dir, real_parent) == NULL) {
        snprintf(real_parent, sizeof(real_parent), "%.*s", (int)sizeof(real_parent) - 1, parent_dir);
    }
    char joined[PATH_MAX * 2];
    if (link_target[0] == '/') {
        snprintf(joined, sizeof(joined), "%s", link_target);
    } else {
        snprintf(joined, sizeof(joined), "%s/%s", real_parent, link_target);
    }
    char norm[PATH_MAX];
    normalize_lexical_path(joined, norm, sizeof(norm));
    if (!path_within_root(norm, ctx->canon_root)) {
        char msg[256];
        snprintf(msg, sizeof(msg), "dangling symlink escapes repository root -> %.160s", link_target);
        record_finding(ctx, "symlink_escape", "high", full_path, msg);
    }
}

static void inspect_regular_file(AuditCtx *ctx, const char *full_path, const char *base) {
    size_t len = 0;
    uint8_t *buf = slurp_file_bounded(full_path, MAX_FILE_READ, &len);
    if (!buf) return;

    /* 1. Binary Pickle / PyTorch ZIP inspection */
    bool is_zip_magic = (len >= 4 && buf[0] == 'P' && buf[1] == 'K' &&
                         buf[2] == 0x03 && buf[3] == 0x04);
    bool is_pkl_magic = (len >= 2 && buf[0] == 0x80 && buf[1] >= 2 && buf[1] <= 5);
    bool pkl_ext      = has_pickle_extension(base);

    if (is_zip_magic && (pkl_ext || str_ends_with_ci(base, ".bin"))) {
        audit_zip_pickle_archive(ctx, full_path, buf, len);
        free(buf);
        return;
    }
    if (is_pkl_magic || str_ends_with_ci(base, ".pkl") ||
        str_ends_with_ci(base, ".pickle") || str_ends_with_ci(base, ".dill")) {
        char pdetail[200];
        if (scan_pickle_stream(buf, len, pdetail, sizeof(pdetail))) {
            record_finding(ctx, "pickle_rce", "high", full_path, pdetail);
        }
        free(buf);
        return;
    }

    /* 2. Trojan Source Unicode check across all text/source/config files */
    inspect_text_for_trojan_unicode(ctx, full_path, buf, len);

    const char *text = (const char *)buf;

    /* 3. Lifecycle / build script traps */
    if (strcasecmp(base, "package.json") == 0) {
        inspect_package_json(ctx, full_path, text);
    } else if (strcasecmp(base, "setup.py") == 0 || strcasecmp(base, "pyproject.toml") == 0) {
        inspect_python_build_file(ctx, full_path, base, text);
    } else if (strcasecmp(base, "Makefile") == 0 || strcasecmp(base, "GNUmakefile") == 0) {
        inspect_makefile(ctx, full_path, text);
    }

    /* 4. Repo-local agent / MCP config traps */
    if (strcasecmp(base, ".mcp.json") == 0 ||
        str_ends_with_ci(full_path, "/.cursor/mcp.json") ||
        str_ends_with_ci(full_path, "/.vscode/mcp.json") ||
        str_ends_with_ci(full_path, "/.claude/mcp.json") ||
        str_ends_with_ci(full_path, "/.claude/settings.json") ||
        str_ends_with_ci(full_path, "/.claude/settings.local.json") ||
        str_ends_with_ci(full_path, "/.codex/config.toml") ||
        str_ends_with_ci(full_path, "/.codex/config.json") ||
        str_ends_with_ci(full_path, "/.gemini/settings.json") ||
        str_ends_with_ci(full_path, "/.cursor/hooks.json")) {
        inspect_agent_config(ctx, full_path, base, text);
    }

    /* 5. Prompt injection directives in docs & agent rule files */
    if (is_doc_or_agent_instruction_file(base)) {
        inspect_prompt_injection(ctx, full_path, text);
    }

    free(buf);
}

static bool should_skip_dir_name(const char *name) {
    return (strcmp(name, "__pycache__") == 0 ||
            strcmp(name, ".pytest_cache") == 0 ||
            strcmp(name, ".mypy_cache") == 0 ||
            strcmp(name, ".ruff_cache") == 0 ||
            strcmp(name, "build") == 0 ||
            strcmp(name, "dist") == 0);
}

static void audit_walk_dir(AuditCtx *ctx, const char *dir_path, int depth) {
    if (depth > MAX_AUDIT_DEPTH) return;
    DIR *d = opendir(dir_path);
    if (!d) return;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;

        char full[PATH_MAX];
        int n = snprintf(full, sizeof(full), "%s/%s", dir_path, name);
        if (n < 0 || (size_t)n >= sizeof(full)) continue;

        struct stat st;
        if (lstat(full, &st) != 0) continue;

        if (S_ISLNK(st.st_mode)) {
            ctx->scanned_files++;
            inspect_symlink(ctx, dir_path, full);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (strcmp(name, ".git") == 0) {
                inspect_git_dir(ctx, full);
                continue;
            }
            if (should_skip_dir_name(name)) continue;
            audit_walk_dir(ctx, full, depth + 1);
            continue;
        }
        if (S_ISREG(st.st_mode)) {
            ctx->scanned_files++;
            inspect_regular_file(ctx, full, name);
        }
    }
    closedir(d);
}

static int cmd_audit(int argc, char **argv) {
    bool json_mode = false;
    const char *target = ".";

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) {
            json_mode = true;
        } else if (argv[i][0] != '-') {
            target = argv[i];
        } else {
            fprintf(stderr, "hshield audit: unknown option '%s'\n", argv[i]);
            return 2;
        }
    }

    struct stat st;
    if (lstat(target, &st) != 0) {
        if (json_mode) {
            printf("{\"ok\":false,\"clean\":false,\"error\":\"path not found\",\"target\":");
            json_print_escaped(stdout, target);
            printf("}\n");
        } else {
            fprintf(stderr, "hshield audit: cannot access '%s': %s\n", target, strerror(errno));
        }
        return 2;
    }

    AuditCtx *ctx = (AuditCtx *)calloc(1, sizeof(AuditCtx));
    if (!ctx) return 2;

    uint64_t t0 = mono_ns();
    if (S_ISDIR(st.st_mode)) {
        if (realpath(target, ctx->canon_root) == NULL) {
            normalize_lexical_path(target, ctx->canon_root, sizeof(ctx->canon_root));
        }
        ctx->canon_root_len = strlen(ctx->canon_root);
        audit_walk_dir(ctx, ctx->canon_root, 0);
    } else if (S_ISLNK(st.st_mode)) {
        char parent[PATH_MAX];
        snprintf(parent, sizeof(parent), "%.*s", (int)sizeof(parent) - 1, target);
        char *slash = strrchr(parent, '/');
        if (slash) *slash = '\0';
        else snprintf(parent, sizeof(parent), ".");
        if (realpath(parent, ctx->canon_root) == NULL) {
            normalize_lexical_path(parent, ctx->canon_root, sizeof(ctx->canon_root));
        }
        ctx->canon_root_len = strlen(ctx->canon_root);
        ctx->scanned_files = 1;
        inspect_symlink(ctx, parent, target);
    } else if (S_ISREG(st.st_mode)) {
        const char *slash = strrchr(target, '/');
        const char *base = slash ? (slash + 1) : target;
        ctx->scanned_files = 1;
        inspect_regular_file(ctx, target, base);
    }

    double elapsed_ms = (double)(mono_ns() - t0) / 1e6;
    bool clean = (ctx->finding_count == 0);

    if (json_mode) {
        printf("{\"ok\":true,\"clean\":%s,\"target\":", clean ? "true" : "false");
        json_print_escaped(stdout, ctx->canon_root[0] ? ctx->canon_root : target);
        printf(",\"scanned_files\":%" PRIu64 ",\"finding_count\":%zu,\"elapsed_ms\":%.2f,\"findings\":[",
               ctx->scanned_files, ctx->finding_count, elapsed_ms);
        for (size_t i = 0; i < ctx->finding_count; i++) {
            const AuditFinding *f = &ctx->findings[i];
            if (i > 0) fputc(',', stdout);
            printf("{\"kind\":");
            json_print_escaped(stdout, f->kind);
            printf(",\"severity\":");
            json_print_escaped(stdout, f->severity);
            printf(",\"path\":");
            json_print_escaped(stdout, f->path);
            printf(",\"detail\":");
            json_print_escaped(stdout, f->detail);
            fputc('}', stdout);
        }
        printf("]}\n");
    } else {
        printf("hshield audit  %s\n", ctx->canon_root[0] ? ctx->canon_root : target);
        printf("scanned_files: %" PRIu64 "  findings: %zu  elapsed: %.2f ms\n",
               ctx->scanned_files, ctx->finding_count, elapsed_ms);
        if (clean) {
            printf("status: CLEAN (0 supply-chain or containment traps detected)\n");
        } else {
            for (size_t i = 0; i < ctx->finding_count; i++) {
                const AuditFinding *f = &ctx->findings[i];
                printf("  [%s] %s (%s): %s\n", f->severity, f->path, f->kind, f->detail);
            }
        }
    }

    int rc = clean ? 0 : 1;
    free(ctx);
    return rc;
}

/* -------------------------------------------------------------------------
 * Posture & Telemetry (`hshield status [--json]`)
 * ------------------------------------------------------------------------- */

static size_t count_dir_entries(const char *dir_path) {
    DIR *d = opendir(dir_path);
    if (!d) return 0;
    size_t cnt = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        cnt++;
    }
    closedir(d);
    return cnt;
}

static size_t count_file_lines(const char *file_path) {
    size_t len = 0;
    uint8_t *buf = slurp_file_bounded(file_path, 262144, &len);
    if (!buf) return 0;
    size_t lines = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\n') lines++;
    }
    free(buf);
    return lines;
}

static int cmd_status(int argc, char **argv) {
    bool json_mode = false;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) {
            json_mode = true;
        }
    }

    int abi = detect_landlock_abi();
    bool sandbox_avail = (abi >= 1);
    bool net_iso_avail = (abi >= 4);

    char posture[96];
    if (abi >= 1) {
        snprintf(posture, sizeof(posture), "Landlock ABI v%d%s%s",
                 abi,
                 abi >= 4 ? " + tcp-net" : "",
                 abi >= 6 ? " + ipc-scope" : "");
    } else if (abi == 0) {
        snprintf(posture, sizeof(posture), "Linux POSIX (Landlock disabled)");
    } else {
        snprintf(posture, sizeof(posture), "POSIX audit-only");
    }

    char heph_home[PATH_MAX];
    char cache_dir[PATH_MAX];
    resolve_hephaestus_home(heph_home, sizeof(heph_home));
    resolve_cache_dir(cache_dir, sizeof(cache_dir));

    struct stat hst;
    bool home_initialized = (stat(heph_home, &hst) == 0 && S_ISDIR(hst.st_mode));

    char qdir[PATH_MAX + 64];
    char rfile[PATH_MAX + 64];
    snprintf(qdir, sizeof(qdir), "%s/shield/quarantine", heph_home);
    snprintf(rfile, sizeof(rfile), "%s/shield/rules.conf", heph_home);
    size_t quarantine_cnt = count_dir_entries(qdir);
    size_t rules_cnt      = count_file_lines(rfile);

    const char *daemon_state = "standby";
    char sfile[PATH_MAX + 64];
    snprintf(sfile, sizeof(sfile), "%s/hshield.pid", cache_dir);
    size_t plen = 0;
    uint8_t *pbuf = slurp_file_bounded(sfile, 64, &plen);
    if (pbuf) {
        int dpid = atoi((const char *)pbuf);
        if (dpid > 1 && kill((pid_t)dpid, 0) == 0) daemon_state = "active";
        free(pbuf);
    }

    if (json_mode) {
        printf("{\"ok\":true,\"version\":");
        json_print_escaped(stdout, HSHIELD_VERSION);
        printf(",\"platform\":");
        json_print_escaped(stdout, platform_name());
        printf(",\"arch\":");
        json_print_escaped(stdout, arch_name());
        printf(",\"sandbox_available\":%s,\"landlock_abi\":%d,\"net_isolation_available\":%s,\"posture\":",
               sandbox_avail ? "true" : "false", abi, net_iso_avail ? "true" : "false");
        json_print_escaped(stdout, posture);
        printf(",\"hephaestus_home\":");
        json_print_escaped(stdout, heph_home);
        printf(",\"hephaestus_home_exists\":%s,\"cache_dir\":", home_initialized ? "true" : "false");
        json_print_escaped(stdout, cache_dir);
        printf(",\"rules_count\":%zu,\"quarantine_count\":%zu,\"daemon\":",
               rules_cnt, quarantine_cnt);
        json_print_escaped(stdout, daemon_state);
        printf("}\n");
    } else {
        printf("hshield %s (%s/%s)\n", HSHIELD_VERSION, platform_name(), arch_name());
        printf("  posture:          %s\n", posture);
        printf("  sandbox:          %s\n", sandbox_avail ? "enforced (kernel LSM)" : "degraded (POSIX)");
        printf("  tcp_isolation:    %s\n", net_iso_avail ? "available (ABI >= 4)" : "unavailable");
        printf("  hephaestus_home:  %s (%s)\n", heph_home, home_initialized ? "present" : "uninitialized");
        printf("  cache_dir:        %s\n", cache_dir);
        printf("  rules_count:      %zu\n", rules_cnt);
        printf("  quarantine_count: %zu\n", quarantine_cnt);
        printf("  daemon:           %s\n", daemon_state);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Zero-Daemon Landlock LSM Sandbox (`hshield sandbox ... -- <cmd...>`)
 * ------------------------------------------------------------------------- */

#ifdef __linux__
static bool is_sensitive_home_subpath(const char *cand, const char *home) {
    if (!cand || !home || !home[0] || strcmp(home, "/") == 0) return false;
    size_t hlen = strlen(home);
    if (strcmp(cand, home) == 0) return true;
    if (strncmp(cand, home, hlen) != 0 || cand[hlen] != '/') return false;

    const char *sub = cand + hlen + 1;
    static const char *const sensitive[] = {
        ".ssh", ".gnupg", ".aws", ".kube", ".docker", ".netrc",
        ".claude", ".codex", ".gemini", ".hephaestus",
        ".config/gh", ".config/gcloud", ".config/google-chrome",
        ".config/chromium", ".config/BraveSoftware", ".mozilla",
        ".npmrc", ".pypirc", ".git-credentials", NULL
    };
    for (int i = 0; sensitive[i]; i++) {
        size_t sl = strlen(sensitive[i]);
        if (strncmp(sub, sensitive[i], sl) == 0 &&
            (sub[sl] == '\0' || sub[sl] == '/')) {
            return true;
        }
    }
    return false;
}

static void ll_allow_path(int ruleset_fd, const char *path, uint64_t access_mask) {
    if (!path || !path[0] || access_mask == 0) return;
#ifdef O_PATH
    int open_flags = O_PATH | O_CLOEXEC;
#else
    int open_flags = O_RDONLY | O_CLOEXEC;
#endif
    int fd = open(path, open_flags);
    if (fd < 0) return;

    struct stat st;
    if (fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode)) {
        /* Regular/device file descriptors cannot receive directory-only access bits */
        uint64_t file_bits = LANDLOCK_ACCESS_FS_EXECUTE |
                             LANDLOCK_ACCESS_FS_WRITE_FILE |
                             LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_TRUNCATE |
                             LANDLOCK_ACCESS_FS_IOCTL_DEV;
        access_mask &= file_bits;
    }
    if (access_mask != 0) {
        struct hs_ll_path_beneath_attr pb;
        memset(&pb, 0, sizeof(pb));
        pb.allowed_access = access_mask;
        pb.parent_fd      = fd;
        (void)syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    }
    close(fd);
}
#endif /* __linux__ */

static int cmd_sandbox(int argc, char **argv) {
    bool allow_net = false;
    bool strict_mode = false;
    const char *allow_writes[MAX_ALLOW_WRITE];
    int allow_write_cnt = 0;
    int cmd_idx = -1;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            cmd_idx = i + 1;
            break;
        }
        if (strcmp(argv[i], "--net") == 0) {
            allow_net = true;
        } else if (strcmp(argv[i], "--strict") == 0) {
            strict_mode = true;
        } else if (strcmp(argv[i], "--allow-write") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "hshield sandbox: --allow-write requires a directory argument\n");
                return 2;
            }
            if (allow_write_cnt < MAX_ALLOW_WRITE) {
                allow_writes[allow_write_cnt++] = argv[++i];
            } else {
                i++;
            }
        } else if (strncmp(argv[i], "--allow-write=", 14) == 0) {
            if (allow_write_cnt < MAX_ALLOW_WRITE) {
                allow_writes[allow_write_cnt++] = argv[i] + 14;
            }
        } else if (argv[i][0] != '-') {
            cmd_idx = i;
            break;
        } else {
            fprintf(stderr, "hshield sandbox: unknown option '%s'\n", argv[i]);
            return 2;
        }
    }

    if (cmd_idx < 0 || cmd_idx >= argc) {
        fprintf(stderr, "Usage: hshield sandbox [--net] [--strict] [--allow-write <dir>] -- <cmd> [args...]\n");
        return 2;
    }

#ifndef __linux__
    (void)allow_net;
    (void)allow_writes;
    (void)allow_write_cnt;
    if (strict_mode) {
        fprintf(stderr,
                "hshield sandbox: kernel Landlock LSM unavailable on %s (--strict fail-closed)\n",
                platform_name());
        return 1;
    }
    fprintf(stderr,
            "hshield sandbox: note: Landlock LSM unavailable on %s; running in degraded POSIX mode\n",
            platform_name());
    execvp(argv[cmd_idx], &argv[cmd_idx]);
    fprintf(stderr, "hshield sandbox: execvp('%s') failed: %s\n", argv[cmd_idx], strerror(errno));
    return (errno == ENOENT) ? 127 : 126;
#else
    int abi = detect_landlock_abi();
    if (abi < 1) {
        if (strict_mode) {
            fprintf(stderr,
                    "hshield sandbox: kernel Landlock LSM disabled (ABI=%d) and --strict set\n",
                    abi);
            return 1;
        }
        fprintf(stderr,
                "hshield sandbox: note: kernel Landlock disabled; running in degraded POSIX mode\n");
        execvp(argv[cmd_idx], &argv[cmd_idx]);
        fprintf(stderr, "hshield sandbox: execvp('%s') failed: %s\n", argv[cmd_idx], strerror(errno));
        return (errno == ENOENT) ? 127 : 126;
    }

    uint64_t fs_handled =
        LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR |
        LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SOCK |
        LANDLOCK_ACCESS_FS_MAKE_FIFO |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        LANDLOCK_ACCESS_FS_MAKE_SYM;

    if (abi >= 2) fs_handled |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) fs_handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) fs_handled |= LANDLOCK_ACCESS_FS_IOCTL_DEV;

    struct hs_ll_ruleset_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.handled_access_fs = fs_handled;

    if (abi >= 4 && !allow_net) {
        attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
    }
    if (abi >= 6) {
        attr.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;
    }

    size_t attr_size = sizeof(uint64_t);
    if (abi >= 6) attr_size = 3 * sizeof(uint64_t);
    else if (abi >= 4) attr_size = 2 * sizeof(uint64_t);

    int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset, &attr, attr_size, 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "hshield sandbox: landlock_create_ruleset failed: %s\n", strerror(errno));
        return 1;
    }

    uint64_t ro_mask = (LANDLOCK_ACCESS_FS_EXECUTE |
                        LANDLOCK_ACCESS_FS_READ_FILE |
                        LANDLOCK_ACCESS_FS_READ_DIR) & fs_handled;
    uint64_t rw_mask = fs_handled;
    uint64_t dev_rw  = (LANDLOCK_ACCESS_FS_READ_FILE |
                        LANDLOCK_ACCESS_FS_WRITE_FILE |
                        LANDLOCK_ACCESS_FS_TRUNCATE |
                        LANDLOCK_ACCESS_FS_IOCTL_DEV) & fs_handled;

    /* 1. System read-only + execute trees (excludes $HOME and /tmp) */
    static const char *const sys_ro[] = {
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32",
        "/etc", "/opt", "/nix", "/proc", "/sys", "/run", NULL
    };
    for (int i = 0; sys_ro[i]; i++) {
        ll_allow_path(ruleset_fd, sys_ro[i], ro_mask);
    }

    /* 2. Safe character devices only (never expose raw block devices like /dev/sda) */
    static const char *const safe_devs[] = {
        "/dev/null", "/dev/zero", "/dev/full", "/dev/urandom", "/dev/random", "/dev/tty", NULL
    };
    for (int i = 0; safe_devs[i]; i++) {
        ll_allow_path(ruleset_fd, safe_devs[i], dev_rw);
    }
    ll_allow_path(ruleset_fd, "/dev/fd", ro_mask);

    /* 3. Resolve $HOME and current working directory */
    char raw_home[PATH_MAX];
    char canon_home[PATH_MAX];
    resolve_home_dir(raw_home, sizeof(raw_home));
    if (realpath(raw_home, canon_home) == NULL) {
        normalize_lexical_path(raw_home, canon_home, sizeof(canon_home));
    }

    /* Safe user toolchain prefixes (read-only) */
    static const char *const user_toolchains[] = {
        ".local/bin", ".local/lib", ".cargo/bin", ".rustup", ".pyenv", NULL
    };
    for (int i = 0; user_toolchains[i]; i++) {
        char tc[PATH_MAX + 64];
        snprintf(tc, sizeof(tc), "%s/%s", canon_home, user_toolchains[i]);
        ll_allow_path(ruleset_fd, tc, ro_mask);
    }

    /* Allow read-only access to current workspace if it does NOT enclose $HOME or credential dirs */
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        char canon_cwd[PATH_MAX];
        if (realpath(cwd, canon_cwd) == NULL) {
            normalize_lexical_path(cwd, canon_cwd, sizeof(canon_cwd));
        }
        bool cwd_encloses_home = path_within_root(canon_home, canon_cwd);
        if (!cwd_encloses_home && !is_sensitive_home_subpath(canon_cwd, canon_home)) {
            ll_allow_path(ruleset_fd, canon_cwd, ro_mask);
        }
    }

    /* 4. Explicit --allow-write directories */
    for (int i = 0; i < allow_write_cnt; i++) {
        char canon_w[PATH_MAX];
        if (realpath(allow_writes[i], canon_w) == NULL) {
            normalize_lexical_path(allow_writes[i], canon_w, sizeof(canon_w));
        }
        if (is_sensitive_home_subpath(canon_w, canon_home)) {
            fprintf(stderr, "hshield sandbox: refusing --allow-write on sensitive credential path '%s'\n",
                    allow_writes[i]);
            close(ruleset_fd);
            return 1;
        }
        ll_allow_path(ruleset_fd, canon_w, rw_mask);
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "hshield sandbox: prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n", strerror(errno));
        close(ruleset_fd);
        return 1;
    }

    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
        fprintf(stderr, "hshield sandbox: landlock_restrict_self failed: %s\n", strerror(errno));
        close(ruleset_fd);
        return 1;
    }
    close(ruleset_fd);

    execvp(argv[cmd_idx], &argv[cmd_idx]);
    fprintf(stderr, "hshield sandbox: execvp('%s') failed: %s\n", argv[cmd_idx], strerror(errno));
    return (errno == ENOENT) ? 127 : 126;
#endif
}

/* -------------------------------------------------------------------------
 * Linux Mechanistic VMA & FFI Trampoline Inspector (`hshield eval-pid <pid>`)
 * ------------------------------------------------------------------------- */

#ifdef __linux__
typedef struct {
    uint64_t start;
    uint64_t end;
} VmaSpan;

static bool addr_in_spans(uint64_t addr, const VmaSpan *spans, int count) {
    for (int i = 0; i < count; i++) {
        if (addr >= spans[i].start && addr < spans[i].end) return true;
    }
    return false;
}

/*
 * Mechanistic FFI closure trampoline verifier:
 * Distinguishes benign libffi/cffi closure trampolines jumping into persistent
 * file-backed r-xp shared libraries from raw anonymous W+X shellcode pages.
 */
static bool is_mechanistic_ffi_trampoline(const uint8_t *buf, size_t len,
                                          bool is_rwx, const VmaSpan *file_x, int file_x_cnt) {
    if (len == 0 || len > 65536) return false;

    uint64_t first_qword = 0;
    if (len >= 8) memcpy(&first_qword, buf, 8);

    size_t nonzero = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) nonzero++;
    }
    if (first_qword == 0 && nonzero <= 16) return true;

#if defined(__x86_64__)
    bool entry_is_thunk = (len >= 16 &&
        ((buf[0] == 0xf3 && buf[1] == 0x0f && buf[2] == 0x1e && buf[3] == 0xfa) ||
         (buf[0] == 0xff && buf[1] == 0x25) ||
         (buf[0] == 0x49 && (buf[1] == 0xba || buf[1] == 0xbb))));
    if (is_rwx && first_qword != 0 && !entry_is_thunk) return false;

    int valid_trampolines = 0;
    for (size_t i = 0; i + 16 <= len; i++) {
        if (buf[i] == 0xff && buf[i + 1] == 0x25) {
            int32_t disp = 0;
            memcpy(&disp, buf + i + 2, 4);
            int64_t target_off = (int64_t)(i + 6) + (int64_t)disp;
            if (target_off >= 0 && (size_t)(target_off + 8) <= len) {
                uint64_t jmp_dst = 0;
                memcpy(&jmp_dst, buf + (size_t)target_off, 8);
                if (addr_in_spans(jmp_dst, file_x, file_x_cnt)) valid_trampolines++;
            }
        }
        if (i + 13 <= len && buf[i] == 0x49 && (buf[i + 1] == 0xba || buf[i + 1] == 0xbb)) {
            uint64_t imm = 0;
            memcpy(&imm, buf + i + 2, 8);
            if (addr_in_spans(imm, file_x, file_x_cnt)) {
                for (size_t k = i + 10; k + 3 <= len && k <= i + 24; k++) {
                    if (buf[k] == 0x41 && buf[k + 1] == 0xff && (buf[k + 2] == 0xe2 || buf[k + 2] == 0xe3)) {
                        valid_trampolines++;
                        break;
                    }
                }
            }
        }
    }
    return valid_trampolines > 0;
#elif defined(__aarch64__)
    (void)is_rwx;
    int valid_trampolines = 0;
    for (size_t i = 0; i + 16 <= len; i += 4) {
        uint32_t insn0 = read_u32_le(buf + i);
        uint32_t insn1 = read_u32_le(buf + i + 4);
        /* LDR X16/X17, #imm ; BR X16/X17 (libffi aarch64 closure) */
        if (((insn0 & 0xff00001fU) == 0x58000010U || (insn0 & 0xff00001fU) == 0x58000011U) &&
            (insn1 == 0xd61f0200U || insn1 == 0xd61f0220U)) {
            int32_t imm19 = (int32_t)((insn0 >> 5) & 0x7ffffU);
            if (imm19 & 0x40000) imm19 |= ~0x7ffff;
            int64_t lit_off = (int64_t)i + ((int64_t)imm19 * 4);
            if (lit_off >= 0 && (size_t)(lit_off + 8) <= len) {
                uint64_t jmp_dst = read_u64_le(buf + (size_t)lit_off);
                if (addr_in_spans(jmp_dst, file_x, file_x_cnt)) valid_trampolines++;
            }
        }
    }
    return valid_trampolines > 0;
#else
    (void)is_rwx;
    (void)file_x;
    (void)file_x_cnt;
    return false;
#endif
}
#endif /* __linux__ */

static int cmd_eval_pid(int argc, char **argv) {
    bool json_mode = false;
    int target_pid = -1;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) {
            json_mode = true;
        } else if (isdigit((unsigned char)argv[i][0])) {
            target_pid = atoi(argv[i]);
        }
    }
    if (target_pid <= 0) {
        fprintf(stderr, "Usage: hshield eval-pid <pid> [--json]\n");
        return 2;
    }
#ifndef __linux__
    if (json_mode) {
        printf("{\"ok\":false,\"supported\":false,\"pid\":%d,\"detail\":\"/proc VMA inspection requires Linux\"}\n",
               target_pid);
    } else {
        fprintf(stderr, "hshield eval-pid: /proc VMA inspection is Linux-only\n");
    }
    return 1;
#else
    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/maps", target_pid);
    int mfd = open(mpath, O_RDONLY | O_CLOEXEC);
    if (mfd < 0) {
        if (json_mode) {
            printf("{\"ok\":false,\"pid\":%d,\"error\":\"cannot open /proc/%d/maps\"}\n", target_pid, target_pid);
        } else {
            fprintf(stderr, "hshield eval-pid: cannot open %s: %s\n", mpath, strerror(errno));
        }
        return 1;
    }

    char *maps = (char *)malloc(131072);
    if (!maps) {
        close(mfd);
        return 2;
    }
    size_t total = 0;
    while (total + 1 < 131072) {
        ssize_t n = read(mfd, maps + total, 131071 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    close(mfd);
    maps[total] = '\0';

    VmaSpan file_x[256];
    int file_x_cnt = 0;
    VmaSpan anon_x[64];
    bool anon_rwx[64];
    bool anon_memfd[64];
    int anon_cnt = 0;

    char *savep = NULL;
    for (char *ln = strtok_r(maps, "\n", &savep); ln; ln = strtok_r(NULL, "\n", &savep)) {
        unsigned long long s = 0, e = 0, off = 0, ino = 0;
        char perms[8] = {0}, dev[16] = {0}, path[256] = {0};
        int n = sscanf(ln, "%llx-%llx %7s %llx %15s %llu %255[^\n]",
                       &s, &e, perms, &off, dev, &ino, path);
        if (n < 6 || e <= s) continue;
        char *pt = path;
        while (*pt == ' ' || *pt == '\t') pt++;
        if (strcmp(pt, "[vdso]") == 0 || strcmp(pt, "[vsyscall]") == 0 || strncmp(pt, "[vvar", 5) == 0) {
            continue;
        }
        bool has_w = (perms[1] == 'w');
        bool has_x = (perms[2] == 'x');
        bool is_mfd = (strstr(pt, "/memfd:") != NULL);
        if (ino != 0 && has_x && !is_mfd && file_x_cnt < 256) {
            file_x[file_x_cnt].start = (uint64_t)s;
            file_x[file_x_cnt].end   = (uint64_t)e;
            file_x_cnt++;
        } else if (has_x && (ino == 0 || is_mfd) && anon_cnt < 64) {
            anon_x[anon_cnt].start = (uint64_t)s;
            anon_x[anon_cnt].end   = (uint64_t)e;
            anon_rwx[anon_cnt]     = has_w && has_x;
            anon_memfd[anon_cnt]   = is_mfd;
            anon_cnt++;
        }
    }
    free(maps);

    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", target_pid);
    int mem_fd = open(mem_path, O_RDONLY | O_CLOEXEC);

    int suspicious_vmas = 0;
    int benign_ffi_vmas = 0;
    uint8_t page[4096];
    for (int i = 0; i < anon_cnt; i++) {
        size_t vlen = (size_t)(anon_x[i].end - anon_x[i].start);
        size_t rlen = vlen < sizeof(page) ? vlen : sizeof(page);
        ssize_t got = (mem_fd >= 0) ? pread(mem_fd, page, rlen, (off_t)anon_x[i].start) : -1;
        if (got > 0 && !anon_memfd[i] &&
            is_mechanistic_ffi_trampoline(page, (size_t)got, anon_rwx[i], file_x, file_x_cnt)) {
            benign_ffi_vmas++;
            continue;
        }
        if (anon_memfd[i] || anon_rwx[i]) suspicious_vmas++;
    }
    if (mem_fd >= 0) close(mem_fd);

    bool clean = (suspicious_vmas == 0);
    if (json_mode) {
        printf("{\"ok\":true,\"pid\":%d,\"clean\":%s,\"anon_exec_vmas\":%d,\"benign_ffi_vmas\":%d,\"suspicious_wx_vmas\":%d}\n",
               target_pid, clean ? "true" : "false", anon_cnt, benign_ffi_vmas, suspicious_vmas);
    } else {
        printf("hshield eval-pid %d: %s (anon_exec=%d, benign_ffi=%d, suspicious_wx=%d)\n",
               target_pid, clean ? "CLEAN" : "SUSPICIOUS", anon_cnt, benign_ffi_vmas, suspicious_vmas);
    }
    return clean ? 0 : 1;
#endif
}

/* -------------------------------------------------------------------------
 * CLI Entrypoint
 * ------------------------------------------------------------------------- */

static void print_usage(FILE *fp) {
    fprintf(fp,
        "hshield %s - Hephaestus Organ 2: Supply-Chain Auditor & Landlock Sandbox\n"
        "\n"
        "Usage:\n"
        "  hshield audit [path] [--json]\n"
        "  hshield status [--json]\n"
        "  hshield sandbox [--net] [--strict] [--allow-write <dir>] -- <cmd> [args...]\n"
        "  hshield eval-pid <pid> [--json]\n"
        "  hshield --help | --version\n"
        "\n"
        "Commands:\n"
        "  audit     Scan repository or artifact for git hook traps, lifecycle scripts,\n"
        "            symlink escapes, untrusted agent/MCP configs, Trojan Source Unicode,\n"
        "            prompt injection, and zero-import Pickle VM RCE opcodes (.pkl/.pt).\n"
        "  status    Report platform posture, Landlock ABI, and shield telemetry.\n"
        "  sandbox   Execute <cmd> inside a zero-daemon Linux Landlock LSM containment\n"
        "            blocking sensitive $HOME credentials and TCP network (unless --net).\n"
        "  eval-pid  Inspect Linux process VMAs for raw W+X / memfd vs FFI trampolines.\n",
        HSHIELD_VERSION);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(stderr);
        return 2;
    }
    const char *sub = argv[1];
    if (strcmp(sub, "--help") == 0 || strcmp(sub, "-h") == 0 || strcmp(sub, "help") == 0) {
        print_usage(stdout);
        return 0;
    }
    if (strcmp(sub, "--version") == 0 || strcmp(sub, "-v") == 0 || strcmp(sub, "version") == 0) {
        printf("hshield %s\n", HSHIELD_VERSION);
        return 0;
    }
    if (strcmp(sub, "audit") == 0) {
        return cmd_audit(argc, argv);
    }
    if (strcmp(sub, "status") == 0) {
        return cmd_status(argc, argv);
    }
    if (strcmp(sub, "sandbox") == 0) {
        return cmd_sandbox(argc, argv);
    }
    if (strcmp(sub, "eval-pid") == 0) {
        return cmd_eval_pid(argc, argv);
    }

    fprintf(stderr, "hshield: unknown subcommand '%s' (see 'hshield --help')\n", sub);
    return 2;
}
