/*
 * hslice_common.h - Portable C11 shared index layout, cache resolution, and root discovery
 *                   for Hephaestus Organ 1 (`hslice`, `hfind`, `hsearch`).
 *
 * Cross-platform: Linux & macOS (POSIX.1-2008), zero hardcoded host paths.
 */
#ifndef HSLICE_COMMON_H
#define HSLICE_COMMON_H

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#elif defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#elif !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define HSLICE_VERSION "0.3.0"

#define HFIND_MAGIC   0x37444E46U /* "FND7" */
#define HSYM_MAGIC    0x4D595348U /* "HSYM" */
#define IDX_VERSION   2U
#define TRIGRAM_SLOTS 16384U
#define MAX_ROOTS     16

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t built_ns;
    uint32_t n_dirs;
    uint32_t n_files;
    uint32_t pool_size;
    uint32_t dirs_off;
    uint32_t files_off;
    uint32_t pool_off;
    uint32_t dir_tri_off;
    uint32_t dir_post_off;
    uint32_t base_tri_off;
    uint32_t base_post_off;
} HFindHeader;

typedef struct {
    int32_t  parent_idx;
    uint32_t name_off;
    uint64_t mtime_ns;
    uint16_t name_len;
    uint8_t  tier;
    uint8_t  depth;
    uint16_t watch_id;
    uint16_t pad;
} PathDirRec;

typedef struct {
    uint32_t dir_idx;
    uint32_t name_off;
    uint16_t name_len;
    uint8_t  flags;
    uint8_t  tier;
} PathFileRec;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t built_ns;
    uint32_t n_dirs;
    uint32_t n_files;
    uint32_t n_syms;
    uint32_t pool_size;
    uint32_t dirs_off;
    uint32_t files_off;
    uint32_t syms_off;
    uint32_t pool_off;
    uint32_t trigrams_off;
    uint32_t postings_off;
} HSymHeader;

typedef struct {
    int32_t  parent_idx;
    uint32_t name_off;
    uint64_t mtime_ns;
    uint16_t name_len;
    uint8_t  tier;
    uint8_t  depth;
    uint16_t watch_id;
    uint16_t pad;
} SymDirRec;

typedef struct {
    uint32_t dir_idx;
    uint32_t name_off;
    uint64_t mtime_ns;
    uint32_t size_lo;
    uint32_t file_hash;
    uint32_t first_sym;
    uint32_t sym_count;
    uint16_t name_len;
    uint8_t  tier;
    uint8_t  lang;
} SymFileRec;

typedef struct {
    uint32_t name_off;
    uint32_t sig_off;
    uint32_t file_id;
    uint32_t start_line;
    uint32_t end_line;
    uint16_t name_len;
    uint16_t sig_len;
    uint8_t  kind;
    uint8_t  flags;
    uint16_t pad;
} SymRec;

typedef struct {
    uint32_t offset;
    uint32_t count;
} TriBucket;

enum {
    SK_FN     = 1,
    SK_CLASS  = 2,
    SK_STRUCT = 3,
    SK_METHOD = 4,
    SK_TYPE   = 5,
    SK_MACRO  = 6,
    SK_CONST  = 7
};

static inline const char *hslice_kind_label(uint8_t k) {
    switch (k) {
        case SK_FN:     return "fn";
        case SK_CLASS:  return "class";
        case SK_STRUCT: return "struct";
        case SK_METHOD: return "method";
        case SK_TYPE:   return "type";
        case SK_MACRO:  return "macro";
        case SK_CONST:  return "const";
        default:        return "sym";
    }
}

static inline uint64_t hslice_stat_mtime_ns(const struct stat *st) {
#if defined(__APPLE__)
    return (uint64_t)st->st_mtimespec.tv_sec * 1000000000ULL +
           (uint64_t)st->st_mtimespec.tv_nsec;
#else
    return (uint64_t)st->st_mtim.tv_sec * 1000000000ULL +
           (uint64_t)st->st_mtim.tv_nsec;
#endif
}

static inline uint64_t hslice_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline uint64_t hslice_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline uint32_t hslice_pack_tri(unsigned char a, unsigned char b, unsigned char c) {
    uint32_t la = (uint32_t)tolower(a);
    uint32_t lb = (uint32_t)tolower(b);
    uint32_t lc = (uint32_t)tolower(c);
    uint32_t h = (la * 31337U) ^ (lb * 1013U) ^ (lc * 37U);
    return h & (TRIGRAM_SLOTS - 1U);
}

static inline uint32_t hslice_fnv1a32_bytes(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = 2166136261U;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619U;
    }
    return h ? h : 1U;
}

static inline uint64_t hslice_fnv1a64_update(uint64_t h, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static inline const char *hslice_ci_strstr(const char *hay, size_t hlen, const char *nd, size_t nlen) {
    if (nlen == 0) return hay;
    if (hlen < nlen) return NULL;
    unsigned char first = (unsigned char)tolower((unsigned char)nd[0]);
    size_t lim = hlen - nlen;
    for (size_t i = 0; i <= lim; i++) {
        if ((unsigned char)tolower((unsigned char)hay[i]) != first) continue;
        size_t k = 1;
        while (k < nlen &&
               tolower((unsigned char)hay[i + k]) == tolower((unsigned char)nd[k])) {
            k++;
        }
        if (k == nlen) return hay + i;
    }
    return NULL;
}

static inline void hslice_copy_str(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    if (n > 0) memcpy(dst, src, n);
    dst[n] = '\0';
}

static inline void hslice_json_escape(const char *in, char *out, size_t cap) {
    if (cap == 0) return;
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 6 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"') { out[j++] = '\\'; out[j++] = '"'; }
        else if (c == '\\') { out[j++] = '\\'; out[j++] = '\\'; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { out[j++] = '\\'; out[j++] = 'r'; }
        else if (c == '\t') { out[j++] = '\\'; out[j++] = 't'; }
        else if (c < 0x20) {
            j += (size_t)snprintf(out + j, cap - j, "\\u%04x", (unsigned)c);
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
}

static inline bool hslice_mkdir_p(const char *dir, mode_t mode) {
    if (!dir || !dir[0]) return false;
    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s", dir);
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return false;
    size_t len = (size_t)n;
    while (len > 1 && tmp[len - 1] == '/') tmp[--len] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(tmp, mode);
            *p = '/';
        }
    }
    (void)mkdir(tmp, mode);
    struct stat st;
    return (stat(tmp, &st) == 0 && S_ISDIR(st.st_mode) && access(tmp, W_OK | X_OK) == 0);
}

/*
 * Portable 5-tier cache directory resolution (Linux & macOS):
 *   1. $HEPHAESTUS_CACHE_DIR (or $HSLICE_CACHE_DIR compatibility alias)
 *   2. /dev/shm/hephaestus-$UID ONLY if /dev/shm exists and is writable
 *   3. $XDG_CACHE_HOME/hephaestus
 *   4. $HOME/.cache/hephaestus
 *   5. /tmp/hephaestus-$UID
 */
static inline void hslice_resolve_cache_dir(char *out, size_t cap) {
    const char *ov = getenv("HEPHAESTUS_CACHE_DIR");
    if (!ov || !ov[0]) ov = getenv("HSLICE_CACHE_DIR");
    if (ov && ov[0]) {
        if (hslice_mkdir_p(ov, 0700)) {
            snprintf(out, cap, "%s", ov);
            return;
        }
    }

    unsigned uid = (unsigned)getuid();
    struct stat shm_st;
    if (stat("/dev/shm", &shm_st) == 0 && S_ISDIR(shm_st.st_mode) &&
        access("/dev/shm", W_OK | X_OK) == 0) {
        char cand[PATH_MAX];
        snprintf(cand, sizeof(cand), "/dev/shm/hephaestus-%u", uid);
        if (hslice_mkdir_p(cand, 0700)) {
            snprintf(out, cap, "%s", cand);
            return;
        }
    }

    const char *xdg_cache = getenv("XDG_CACHE_HOME");
    if (xdg_cache && xdg_cache[0]) {
        char cand[PATH_MAX];
        int cn = snprintf(cand, sizeof(cand), "%s/hephaestus", xdg_cache);
        if (cn > 0 && (size_t)cn < sizeof(cand) && hslice_mkdir_p(cand, 0700)) {
            snprintf(out, cap, "%s", cand);
            return;
        }
    }

    const char *home = getenv("HOME");
    if (home && home[0]) {
        char cand[PATH_MAX];
        int cn = snprintf(cand, sizeof(cand), "%s/.cache/hephaestus", home);
        if (cn > 0 && (size_t)cn < sizeof(cand) && hslice_mkdir_p(cand, 0700)) {
            snprintf(out, cap, "%s", cand);
            return;
        }
    }

    char fallback[PATH_MAX];
    snprintf(fallback, sizeof(fallback), "/tmp/hephaestus-%u", uid);
    (void)hslice_mkdir_p(fallback, 0700);
    snprintf(out, cap, "%s", fallback);
}

static inline uint64_t hslice_roots_hash(char *const *roots, int n_roots) {
    uint64_t h = 14695981039346656037ULL;
    for (int i = 0; i < n_roots; i++) {
        h = hslice_fnv1a64_update(h, roots[i], strlen(roots[i]));
        h = hslice_fnv1a64_update(h, "\n", 1);
    }
    return h;
}

static inline void hslice_idx_path_for_roots(
    char *out, size_t cap, const char *prefix, char *const *roots, int n_roots
) {
    char cdir[PATH_MAX];
    hslice_resolve_cache_dir(cdir, sizeof(cdir));
    uint64_t rh = hslice_roots_hash(roots, n_roots);
    int n = snprintf(out, cap, "%s/%s-%016" PRIx64 ".idx", cdir, prefix, rh);
    if (n <= 0 || (size_t)n >= cap) {
        snprintf(out, cap, "/tmp/%s-%016" PRIx64 ".idx", prefix, rh);
    }
}

/* Walk upward from `start_dir` to find nearest `.git` directory or worktree file. */
static inline bool hslice_find_git_root(const char *start_dir, char *out, size_t cap) {
    char cur[PATH_MAX];
    if (!realpath(start_dir, cur)) {
        int n = snprintf(cur, sizeof(cur), "%s", start_dir);
        if (n <= 0 || (size_t)n >= sizeof(cur)) return false;
    }
    for (;;) {
        char git_marker[PATH_MAX + 16];
        snprintf(git_marker, sizeof(git_marker), "%s/.git", cur);
        struct stat st;
        if (stat(git_marker, &st) == 0 && (S_ISDIR(st.st_mode) || S_ISREG(st.st_mode))) {
            snprintf(out, cap, "%s", cur);
            return true;
        }
        char *slash = strrchr(cur, '/');
        if (!slash || slash == cur) break;
        *slash = '\0';
    }
    return false;
}

/*
 * Universal root discovery:
 *   1. Explicit CLI `--root <dir>` entries (`cli_roots`)
 *   2. `$HEPHAESTUS_ROOTS` (`:`-separated directory list)
 *   3. `$HSLICE_ROOTS` (`:`-separated directory list)
 *   4. Nearest `.git` repository root from `getcwd()`
 *   5. `getcwd()`
 */
static inline int hslice_discover_roots(
    const char **cli_roots, int n_cli_roots,
    char rbufs[MAX_ROOTS][PATH_MAX], char *roots[MAX_ROOTS]
) {
    int n_roots = 0;

    for (int i = 0; i < n_cli_roots && n_roots < MAX_ROOTS; i++) {
        if (!cli_roots[i] || !cli_roots[i][0]) continue;
        char rp[PATH_MAX];
        const char *resolved = realpath(cli_roots[i], rp) ? rp : cli_roots[i];
        struct stat st;
        if (stat(resolved, &st) == 0 && S_ISDIR(st.st_mode)) {
            snprintf(rbufs[n_roots], PATH_MAX, "%s", resolved);
            roots[n_roots] = rbufs[n_roots];
            n_roots++;
        }
    }
    if (n_roots > 0) return n_roots;

    const char *env_roots = getenv("HEPHAESTUS_ROOTS");
    if (!env_roots || !env_roots[0]) env_roots = getenv("HSLICE_ROOTS");
    if (env_roots && env_roots[0]) {
        const char *p = env_roots;
        while (*p && n_roots < MAX_ROOTS) {
            const char *sep = strchr(p, ':');
            size_t len = sep ? (size_t)(sep - p) : strlen(p);
            if (len > 0 && len < PATH_MAX) {
                char tmp[PATH_MAX], rp[PATH_MAX];
                memcpy(tmp, p, len);
                tmp[len] = '\0';
                const char *resolved = realpath(tmp, rp) ? rp : tmp;
                struct stat st;
                if (stat(resolved, &st) == 0 && S_ISDIR(st.st_mode)) {
                    snprintf(rbufs[n_roots], PATH_MAX, "%s", resolved);
                    roots[n_roots] = rbufs[n_roots];
                    n_roots++;
                }
            }
            if (!sep) break;
            p = sep + 1;
        }
        if (n_roots > 0) return n_roots;
    }

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        snprintf(cwd, sizeof(cwd), ".");
    }
    if (hslice_find_git_root(cwd, rbufs[0], PATH_MAX)) {
        roots[0] = rbufs[0];
        return 1;
    }

    char rp[PATH_MAX];
    snprintf(rbufs[0], PATH_MAX, "%s", realpath(cwd, rp) ? rp : cwd);
    roots[0] = rbufs[0];
    return 1;
}

/* Resolve sibling binary path (`hfind` or `hsearch`) next to the current executable. */
static inline void hslice_resolve_self_exe(const char *argv0, char *out, size_t cap) {
#if defined(__linux__)
    ssize_t rl = readlink("/proc/self/exe", out, cap - 1);
    if (rl > 0) {
        out[rl] = '\0';
        return;
    }
#elif defined(__APPLE__)
    char raw[PATH_MAX];
    uint32_t sz = (uint32_t)sizeof(raw);
    if (_NSGetExecutablePath(raw, &sz) == 0) {
        char rp[PATH_MAX];
        snprintf(out, cap, "%s", realpath(raw, rp) ? rp : raw);
        return;
    }
#endif
    if (argv0 && strchr(argv0, '/') != NULL) {
        char rp[PATH_MAX];
        snprintf(out, cap, "%s", realpath(argv0, rp) ? rp : argv0);
        return;
    }
    out[0] = '\0';
}

static inline void hslice_resolve_sibling_bin(
    const char *argv0, const char *sibling_name, char *out, size_t cap
) {
    char self_exe[PATH_MAX];
    hslice_resolve_self_exe(argv0, self_exe, sizeof(self_exe));
    char *slash = strrchr(self_exe, '/');
    if (slash) {
        *slash = '\0';
        char cand[PATH_MAX + 64];
        int n = snprintf(cand, sizeof(cand), "%s/%s", self_exe, sibling_name);
        if (n > 0 && (size_t)n < sizeof(cand) && access(cand, X_OK) == 0) {
            hslice_copy_str(out, cap, cand);
            return;
        }
    }
    hslice_copy_str(out, cap, sibling_name);
}

#endif /* HSLICE_COMMON_H */
