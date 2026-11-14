/*
 * hfind.c - Hephaestus Organ 1 Sub-Millisecond Path, Symbol & Grep Engine (`hfind` / `hsearch`)
 *
 * Architectural Core:
 *   1. Compact DirRec + FileRec + Interned String Pool mmap binary index (~75% smaller footprint).
 *   2. Split Directory + Basename 3-Gram Inverted Postings:
 *      - Basename tokens intersect tiny posting lists directly.
 *      - Directory tokens match compact DirRecs and expand via binary search.
 *   3. Incremental Symbol Indexer:
 *      - Reuses unchanged directory & file symbol slices in O(changed_files).
 *   4. Zero-Staleness Live Dirty-Directory Overlay + Detached Compactor:
 *      - Tracks directory mtime_ns up to depth 6; scans modified directories live on query
 *        and compacts asynchronously in the background.
 *   5. Global-Limit `hsearch -g` Wrapper:
 *      - Streams `rg` (or portable `grep -rnE` fallback) with strict global line cap.
 *
 * Build: cc -std=c11 -O3 -Wall -Wextra -Werror -o hfind src/hfind.c
 */
#include "hslice_common.h"
#include <sys/file.h>

#define MAX_TOKENS      16
#define MAX_RESULTS     512
#define MAX_RG_ARGS     64
#define MAX_WATCH_DIRS  512
#define MAX_DIRTY_DIRS  64

enum {
    LANG_NONE = 0,
    LANG_PY   = 1,
    LANG_TS   = 2,
    LANG_RUST = 3,
    LANG_GO   = 4,
    LANG_C    = 5,
    LANG_SH   = 6,
    LANG_JAVA = 7
};

/* =========================================================================
 * Dynamic Arena Builders
 * ========================================================================= */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} ByteBuf;

static void bb_init(ByteBuf *b, size_t cap) {
    b->cap = cap ? cap : 4096;
    b->data = (char *)malloc(b->cap);
    if (!b->data) { perror("malloc"); exit(1); }
    b->len = 0;
}

static uint32_t bb_push(ByteBuf *b, const char *s, size_t n) {
    if (b->len + n + 1 > b->cap) {
        while (b->len + n + 1 > b->cap) b->cap *= 2;
        b->data = (char *)realloc(b->data, b->cap);
        if (!b->data) { perror("realloc"); exit(1); }
    }
    uint32_t off = (uint32_t)b->len;
    if (n > 0) memcpy(b->data + b->len, s, n);
    b->data[b->len + n] = '\0';
    b->len += n + 1;
    return off;
}

static void bb_free(ByteBuf *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

typedef struct {
    uint32_t *data;
    size_t    len;
    size_t    cap;
} U32Vec;

static void u32v_push(U32Vec *v, uint32_t x) {
    if (v->len == v->cap) {
        v->cap = v->cap ? (v->cap * 2) : 8;
        v->data = (uint32_t *)realloc(v->data, v->cap * sizeof(uint32_t));
        if (!v->data) { perror("realloc"); exit(1); }
    }
    v->data[v->len++] = x;
}

static void u32v_push_unique_last(U32Vec *v, uint32_t x) {
    if (v->len > 0 && v->data[v->len - 1] == x) return;
    u32v_push(v, x);
}

static void add_str_trigrams(U32Vec *buckets, const char *s, size_t len, uint32_t doc_id) {
    if (len < 3) return;
    uint32_t seen[64];
    size_t n_seen = 0;
    for (size_t i = 0; i + 2 < len; i++) {
        uint32_t slot = hslice_pack_tri((unsigned char)s[i],
                                        (unsigned char)s[i + 1],
                                        (unsigned char)s[i + 2]);
        if (n_seen < 64) {
            bool dup = false;
            for (size_t k = 0; k < n_seen; k++) {
                if (seen[k] == slot) { dup = true; break; }
            }
            if (dup) continue;
            seen[n_seen++] = slot;
        }
        u32v_push_unique_last(&buckets[slot], doc_id);
    }
}

/* =========================================================================
 * Ignore Filter & Language Classifier
 * ========================================================================= */
static bool is_ignored_dir(const char *name) {
    if (name[0] == '\0') return true;
    if (name[0] == '.') {
        if (strcmp(name, ".config") == 0 ||
            strcmp(name, ".github") == 0 ||
            strcmp(name, ".claude") == 0 ||
            strcmp(name, ".claude-plugin") == 0) {
            return false;
        }
        return true;
    }
    static const char *const skips[] = {
        "node_modules", "__pycache__", "venv", "env", "target", "dist", "build",
        "out", "coverage", "htmlcov", "site-packages", "vendor", "Pods",
        "DerivedData", "CMakeFiles", "zig-cache", "zig-out", "artifacts",
        "checkpoints", "logs", "wandb", "mlruns", "bazel-bin", "bazel-out", NULL
    };
    for (int i = 0; skips[i]; i++) {
        if (strcmp(name, skips[i]) == 0) return true;
    }
    return false;
}

static bool is_ignored_file(const char *name, size_t len) {
    if (len == 0) return true;
    if (name[len - 1] == '~') return true;
    const char *dot = strrchr(name, '.');
    if (!dot) return false;
    static const char *const bad_ext[] = {
        ".pyc", ".pyo", ".o", ".ko", ".obj", ".so", ".dylib", ".dll", ".a", ".rlib", ".rmeta",
        ".Lock", ".lock", ".idx", ".pack", ".rev", ".tmp", ".bak", ".swp", ".swo",
        ".class", ".jar", ".wasm", ".min.js", ".min.css", ".map",
        ".safetensors", ".gguf", ".pt", ".pth", ".onnx", ".bin", ".npy", ".npz", NULL
    };
    for (int i = 0; bad_ext[i]; i++) {
        if (strcasecmp(dot, bad_ext[i]) == 0) return true;
    }
    return false;
}

static uint8_t detect_code_lang(const char *name, size_t len) {
    const char *dot = strrchr(name, '.');
    if (!dot || dot == name) return LANG_NONE;
    size_t elen = len - (size_t)(dot - name);
    if (elen == 3 && memcmp(dot, ".py", 3) == 0) return LANG_PY;
    if (elen == 4 && memcmp(dot, ".pyi", 4) == 0) return LANG_PY;
    if ((elen == 3 && (memcmp(dot, ".ts", 3) == 0 || memcmp(dot, ".js", 3) == 0)) ||
        (elen == 4 && (memcmp(dot, ".tsx", 4) == 0 || memcmp(dot, ".jsx", 4) == 0 ||
                       memcmp(dot, ".mjs", 4) == 0 || memcmp(dot, ".cjs", 4) == 0)))
        return LANG_TS;
    if (elen == 3 && memcmp(dot, ".rs", 3) == 0) return LANG_RUST;
    if (elen == 3 && memcmp(dot, ".go", 3) == 0) return LANG_GO;
    if ((elen == 2 && (memcmp(dot, ".c", 2) == 0 || memcmp(dot, ".h", 2) == 0)) ||
        (elen == 3 && (memcmp(dot, ".cc", 3) == 0 || memcmp(dot, ".hh", 3) == 0)) ||
        (elen == 4 && (memcmp(dot, ".cpp", 4) == 0 || memcmp(dot, ".hpp", 4) == 0 ||
                       memcmp(dot, ".cxx", 4) == 0 || memcmp(dot, ".hxx", 4) == 0 ||
                       memcmp(dot, ".cuh", 4) == 0)) ||
        (elen == 3 && memcmp(dot, ".cu", 3) == 0))
        return LANG_C;
    if ((elen == 3 && memcmp(dot, ".sh", 3) == 0) ||
        (elen == 5 && memcmp(dot, ".bash", 5) == 0) ||
        (elen == 4 && memcmp(dot, ".zsh", 4) == 0))
        return LANG_SH;
    if (elen == 5 && memcmp(dot, ".java", 5) == 0) return LANG_JAVA;
    return LANG_NONE;
}

static inline uint8_t compute_recency_tier(uint64_t mtime_ns, uint64_t now_ns) {
    if (now_ns > mtime_ns) {
        uint64_t age_sec = (now_ns - mtime_ns) / 1000000000ULL;
        if (age_sec <= 7ULL * 86400ULL) return 3;
        if (age_sec <= 30ULL * 86400ULL) return 2;
    } else {
        return 3;
    }
    return 1;
}

/* =========================================================================
 * Directory Chain Path Materializer
 * ========================================================================= */
static size_t materialize_path_dir(
    const PathDirRec *dirs, uint32_t n_dirs, const char *pool,
    uint32_t dir_idx, char *out, size_t cap
) {
    uint32_t chain[64];
    int depth = 0;
    int32_t cur = (int32_t)dir_idx;
    while (cur >= 0 && (uint32_t)cur < n_dirs && depth < 64) {
        chain[depth++] = (uint32_t)cur;
        cur = dirs[cur].parent_idx;
    }
    size_t pos = 0;
    for (int i = depth - 1; i >= 0; i--) {
        const PathDirRec *d = &dirs[chain[i]];
        const char *seg = pool + d->name_off;
        size_t slen = d->name_len;
        if (i < depth - 1 && pos > 0 && out[pos - 1] != '/' && pos + 1 < cap) {
            out[pos++] = '/';
        }
        if (pos + slen >= cap) slen = (cap > pos + 1) ? (cap - pos - 1) : 0;
        if (slen > 0) {
            memcpy(out + pos, seg, slen);
            pos += slen;
        }
    }
    out[pos] = '\0';
    return pos;
}

static size_t materialize_sym_dir(
    const SymDirRec *dirs, uint32_t n_dirs, const char *pool,
    uint32_t dir_idx, char *out, size_t cap
) {
    uint32_t chain[64];
    int depth = 0;
    int32_t cur = (int32_t)dir_idx;
    while (cur >= 0 && (uint32_t)cur < n_dirs && depth < 64) {
        chain[depth++] = (uint32_t)cur;
        cur = dirs[cur].parent_idx;
    }
    size_t pos = 0;
    for (int i = depth - 1; i >= 0; i--) {
        const SymDirRec *d = &dirs[chain[i]];
        const char *seg = pool + d->name_off;
        size_t slen = d->name_len;
        if (i < depth - 1 && pos > 0 && out[pos - 1] != '/' && pos + 1 < cap) {
            out[pos++] = '/';
        }
        if (pos + slen >= cap) slen = (cap > pos + 1) ? (cap - pos - 1) : 0;
        if (slen > 0) {
            memcpy(out + pos, seg, slen);
            pos += slen;
        }
    }
    out[pos] = '\0';
    return pos;
}

static size_t materialize_sym_file(
    const SymDirRec *dirs, uint32_t n_dirs, const SymFileRec *f,
    const char *pool, char *out, size_t cap
) {
    size_t pos = materialize_sym_dir(dirs, n_dirs, pool, f->dir_idx, out, cap);
    if (pos + 1 < cap && (pos == 0 || out[pos - 1] != '/')) out[pos++] = '/';
    const char *fn = pool + f->name_off;
    size_t flen = f->name_len;
    if (pos + flen >= cap) flen = (cap > pos + 1) ? (cap - pos - 1) : 0;
    if (flen > 0) {
        memcpy(out + pos, fn, flen);
        pos += flen;
    }
    out[pos] = '\0';
    return pos;
}

/* =========================================================================
 * PART 1: Path Index Builder (`hfind-<hash>.idx`)
 * ========================================================================= */
typedef struct {
    PathDirRec  *dirs;
    size_t       n_dirs, cap_dirs;
    PathFileRec *files;
    size_t       n_files, cap_files;
    ByteBuf      pool;
    U32Vec       dir_tri[TRIGRAM_SLOTS];
    U32Vec       base_tri[TRIGRAM_SLOTS];
    uint16_t     next_watch_id;
    uint64_t     now_ns;
} PathBuilder;

static uint32_t pb_add_dir(
    PathBuilder *pb, int32_t parent_idx, const char *name, size_t nlen,
    uint64_t mtime_ns, uint8_t tier, uint8_t depth, bool watch
) {
    if (pb->n_dirs == pb->cap_dirs) {
        pb->cap_dirs = pb->cap_dirs ? (pb->cap_dirs * 2) : 2048;
        pb->dirs = (PathDirRec *)realloc(pb->dirs, pb->cap_dirs * sizeof(PathDirRec));
        if (!pb->dirs) { perror("realloc"); exit(1); }
    }
    uint32_t idx = (uint32_t)pb->n_dirs++;
    PathDirRec *d = &pb->dirs[idx];
    d->parent_idx = parent_idx;
    d->name_off = bb_push(&pb->pool, name, nlen);
    d->mtime_ns = mtime_ns;
    d->name_len = (uint16_t)(nlen > 65535 ? 65535 : nlen);
    d->tier = tier;
    d->depth = depth;
    if (watch && pb->next_watch_id < MAX_WATCH_DIRS) {
        d->watch_id = pb->next_watch_id++;
    } else {
        d->watch_id = 0xFFFFU;
    }
    d->pad = 0;

    if (parent_idx < 0) {
        const char *base = strrchr(name, '/');
        const char *seg = base ? (base + 1) : name;
        add_str_trigrams(pb->dir_tri, seg, strlen(seg), idx);
    } else {
        add_str_trigrams(pb->dir_tri, name, nlen, idx);
    }
    return idx;
}

static void pb_add_file(
    PathBuilder *pb, uint32_t dir_idx, const char *name, size_t nlen,
    uint8_t flags, uint8_t tier
) {
    if (pb->n_files == pb->cap_files) {
        pb->cap_files = pb->cap_files ? (pb->cap_files * 2) : 16384;
        pb->files = (PathFileRec *)realloc(pb->files, pb->cap_files * sizeof(PathFileRec));
        if (!pb->files) { perror("realloc"); exit(1); }
    }
    uint32_t fid = (uint32_t)pb->n_files++;
    PathFileRec *f = &pb->files[fid];
    f->dir_idx = dir_idx;
    f->name_off = bb_push(&pb->pool, name, nlen);
    f->name_len = (uint16_t)(nlen > 65535 ? 65535 : nlen);
    f->flags = flags;
    f->tier = tier;
    add_str_trigrams(pb->base_tri, name, nlen, fid);
}

typedef struct {
    char   name[256];
    size_t nlen;
} ChildDirEnt;

static int cmp_child_dir(const void *a, const void *b) {
    return strcmp(((const ChildDirEnt *)a)->name, ((const ChildDirEnt *)b)->name);
}

static void walk_path_dir(
    PathBuilder *pb, const char *full_path, size_t plen, uint32_t dir_idx, uint8_t depth
) {
    if (depth > 24 || pb->n_files >= 500000) return;
    DIR *d = opendir(full_path);
    if (!d) return;
    int dfd = dirfd(d);

    ChildDirEnt *subdirs = NULL;
    size_t n_sub = 0, cap_sub = 0;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *nm = de->d_name;
        if (nm[0] == '.' && (nm[1] == '\0' || (nm[1] == '.' && nm[2] == '\0'))) continue;
        size_t nl = strlen(nm);
        if (nl == 0 || nl >= 255 || plen + 1 + nl >= PATH_MAX) continue;

        bool is_dir = false, is_reg = false, is_lnk = false;
#ifdef DT_DIR
        if (de->d_type == DT_DIR) is_dir = true;
        else if (de->d_type == DT_REG) is_reg = true;
        else if (de->d_type == DT_LNK) is_lnk = true;
        else if (de->d_type == DT_UNKNOWN)
#endif
        {
            struct stat st;
            if (fstatat(dfd, nm, &st, AT_SYMLINK_NOFOLLOW) == 0) {
                is_dir = S_ISDIR(st.st_mode);
                is_reg = S_ISREG(st.st_mode);
                is_lnk = S_ISLNK(st.st_mode);
            }
        }
        if (is_lnk) continue;

        if (is_dir) {
            if (is_ignored_dir(nm)) continue;
            if (n_sub == cap_sub) {
                cap_sub = cap_sub ? (cap_sub * 2) : 16;
                subdirs = (ChildDirEnt *)realloc(subdirs, cap_sub * sizeof(ChildDirEnt));
                if (!subdirs) { perror("realloc"); exit(1); }
            }
            memcpy(subdirs[n_sub].name, nm, nl + 1);
            subdirs[n_sub].nlen = nl;
            n_sub++;
        } else if (is_reg) {
            if (is_ignored_file(nm, nl)) continue;
            uint8_t tier = pb->dirs[dir_idx].tier;
            pb_add_file(pb, dir_idx, nm, nl, 0, tier);
        }
    }

    if (n_sub > 1) qsort(subdirs, n_sub, sizeof(ChildDirEnt), cmp_child_dir);

    ChildDirEnt *sub_nodes = NULL;
    uint32_t *sub_ids = NULL;
    size_t n_valid_sub = 0;
    if (n_sub > 0) {
        sub_nodes = (ChildDirEnt *)malloc(n_sub * sizeof(ChildDirEnt));
        sub_ids = (uint32_t *)malloc(n_sub * sizeof(uint32_t));
        for (size_t i = 0; i < n_sub; i++) {
            struct stat st;
            if (fstatat(dfd, subdirs[i].name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(st.st_mode))
                continue;
            uint64_t mns = hslice_stat_mtime_ns(&st);
            uint8_t dtier = compute_recency_tier(mns, pb->now_ns);
            if (pb->dirs[dir_idx].tier > dtier) dtier = pb->dirs[dir_idx].tier;
            bool watch = (depth + 1 <= 6);
            uint32_t cid = pb_add_dir(pb, (int32_t)dir_idx, subdirs[i].name, subdirs[i].nlen,
                                      mns, dtier, (uint8_t)(depth + 1), watch);
            pb_add_file(pb, dir_idx, subdirs[i].name, subdirs[i].nlen, 1, dtier);
            sub_nodes[n_valid_sub] = subdirs[i];
            sub_ids[n_valid_sub] = cid;
            n_valid_sub++;
        }
    }

    free(subdirs);
    closedir(d);

    char child_path[PATH_MAX];
    memcpy(child_path, full_path, plen);
    for (size_t i = 0; i < n_valid_sub; i++) {
        size_t pos = plen;
        if (pos > 0 && child_path[pos - 1] != '/') child_path[pos++] = '/';
        memcpy(child_path + pos, sub_nodes[i].name, sub_nodes[i].nlen);
        pos += sub_nodes[i].nlen;
        child_path[pos] = '\0';
        walk_path_dir(pb, child_path, pos, sub_ids[i], (uint8_t)(depth + 1));
    }
    free(sub_nodes);
    free(sub_ids);
}

static bool write_all_fd(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += (size_t)w;
        len -= (size_t)w;
    }
    return true;
}

static bool write_zeros_fd(int fd, size_t count) {
    static const char zeros[64] = {0};
    while (count > 0) {
        size_t chunk = count > sizeof(zeros) ? sizeof(zeros) : count;
        if (!write_all_fd(fd, zeros, chunk)) return false;
        count -= chunk;
    }
    return true;
}

static int build_path_index(const char *idx_path, char **roots, int n_roots, bool verbose) {
    uint64_t t0 = hslice_mono_ns();

    char lock_path[PATH_MAX + 16];
    snprintf(lock_path, sizeof(lock_path), "%s.lock", idx_path);
    int lfd = open(lock_path, O_CREAT | O_RDWR, 0600);
    if (lfd >= 0) {
        if (flock(lfd, LOCK_EX | LOCK_NB) != 0) {
            struct stat ist;
            if (stat(idx_path, &ist) == 0 && ist.st_size > (off_t)sizeof(HFindHeader)) {
                close(lfd);
                return 0;
            }
            (void)flock(lfd, LOCK_EX);
        }
    }

    PathBuilder pb;
    memset(&pb, 0, sizeof(pb));
    bb_init(&pb.pool, 1 << 18);
    pb.now_ns = hslice_now_ns();

    for (int i = 0; i < n_roots; i++) {
        struct stat st;
        if (stat(roots[i], &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        size_t rlen = strlen(roots[i]);
        while (rlen > 1 && roots[i][rlen - 1] == '/') rlen--;
        char clean_root[PATH_MAX];
        if (rlen >= sizeof(clean_root)) continue;
        memcpy(clean_root, roots[i], rlen);
        clean_root[rlen] = '\0';

        uint64_t mns = hslice_stat_mtime_ns(&st);
        uint32_t rid = pb_add_dir(&pb, -1, clean_root, rlen, mns, 3, 0, true);
        walk_path_dir(&pb, clean_root, rlen, rid, 0);
    }

    TriBucket *dir_tab = (TriBucket *)calloc(TRIGRAM_SLOTS, sizeof(TriBucket));
    TriBucket *base_tab = (TriBucket *)calloc(TRIGRAM_SLOTS, sizeof(TriBucket));
    if (!dir_tab || !base_tab) { perror("calloc"); exit(1); }

    uint32_t dir_post_cnt = 0, base_post_cnt = 0;
    for (uint32_t s = 0; s < TRIGRAM_SLOTS; s++) {
        dir_tab[s].offset = dir_post_cnt;
        dir_tab[s].count = (uint32_t)pb.dir_tri[s].len;
        dir_post_cnt += (uint32_t)pb.dir_tri[s].len;

        base_tab[s].offset = base_post_cnt;
        base_tab[s].count = (uint32_t)pb.base_tri[s].len;
        base_post_cnt += (uint32_t)pb.base_tri[s].len;
    }

    HFindHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = HFIND_MAGIC;
    hdr.version = IDX_VERSION;
    hdr.built_ns = pb.now_ns;
    hdr.n_dirs = (uint32_t)pb.n_dirs;
    hdr.n_files = (uint32_t)pb.n_files;
    hdr.pool_size = (uint32_t)pb.pool.len;

    uint32_t off = (uint32_t)sizeof(HFindHeader);
    hdr.dirs_off = off;
    off += (uint32_t)(pb.n_dirs * sizeof(PathDirRec));
    hdr.files_off = off;
    off += (uint32_t)(pb.n_files * sizeof(PathFileRec));
    hdr.pool_off = off;
    off += (uint32_t)pb.pool.len;
    off = (off + 7U) & ~7U;
    hdr.dir_tri_off = off;
    off += (uint32_t)(TRIGRAM_SLOTS * sizeof(TriBucket));
    hdr.dir_post_off = off;
    off += (uint32_t)(dir_post_cnt * sizeof(uint32_t));
    hdr.base_tri_off = off;
    off += (uint32_t)(TRIGRAM_SLOTS * sizeof(TriBucket));
    hdr.base_post_off = off;
    uint32_t total_bytes = off + (uint32_t)(base_post_cnt * sizeof(uint32_t));

    char tmp_path[PATH_MAX + 32];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", idx_path, (int)getpid());
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    bool ok = (fd >= 0);
    if (ok) ok = write_all_fd(fd, &hdr, sizeof(hdr));
    if (ok && pb.n_dirs) ok = write_all_fd(fd, pb.dirs, pb.n_dirs * sizeof(PathDirRec));
    if (ok && pb.n_files) ok = write_all_fd(fd, pb.files, pb.n_files * sizeof(PathFileRec));
    if (ok && pb.pool.len) ok = write_all_fd(fd, pb.pool.data, pb.pool.len);
    size_t pad = (size_t)hdr.dir_tri_off -
                 (sizeof(HFindHeader) + pb.n_dirs * sizeof(PathDirRec) +
                  pb.n_files * sizeof(PathFileRec) + pb.pool.len);
    if (ok && pad) ok = write_zeros_fd(fd, pad);
    if (ok) ok = write_all_fd(fd, dir_tab, TRIGRAM_SLOTS * sizeof(TriBucket));
    for (uint32_t s = 0; ok && s < TRIGRAM_SLOTS; s++) {
        if (pb.dir_tri[s].len)
            ok = write_all_fd(fd, pb.dir_tri[s].data, pb.dir_tri[s].len * sizeof(uint32_t));
        free(pb.dir_tri[s].data);
    }
    if (ok) ok = write_all_fd(fd, base_tab, TRIGRAM_SLOTS * sizeof(TriBucket));
    for (uint32_t s = 0; ok && s < TRIGRAM_SLOTS; s++) {
        if (pb.base_tri[s].len)
            ok = write_all_fd(fd, pb.base_tri[s].data, pb.base_tri[s].len * sizeof(uint32_t));
        free(pb.base_tri[s].data);
    }

    if (fd >= 0) close(fd);
    if (ok && rename(tmp_path, idx_path) != 0) ok = false;
    if (!ok) unlink(tmp_path);

    if (lfd >= 0) {
        (void)flock(lfd, LOCK_UN);
        close(lfd);
    }

    free(dir_tab);
    free(base_tab);
    free(pb.dirs);
    free(pb.files);
    bb_free(&pb.pool);

    if (ok && verbose) {
        double ms = (double)(hslice_mono_ns() - t0) / 1e6;
        fprintf(stderr,
                "[hfind] indexed %u files across %u dirs (%.2f MiB mmap) in %.1f ms\n",
                hdr.n_files, hdr.n_dirs, (double)total_bytes / (1024.0 * 1024.0), ms);
    }
    return ok ? 0 : -1;
}

/* =========================================================================
 * PART 2: Stateful Deep Symbol Scanner & Incremental `hsym-<hash>.idx` Builder
 * ========================================================================= */
typedef struct {
    SymDirRec  *dirs;
    size_t      n_dirs, cap_dirs;
    SymFileRec *files;
    size_t      n_files, cap_files;
    SymRec     *syms;
    size_t      n_syms, cap_syms;
    ByteBuf     pool;
    U32Vec      tri[TRIGRAM_SLOTS];
    uint16_t    next_watch_id;
    uint64_t    now_ns;
    uint32_t    reused_files;
    uint32_t    parsed_files;
} SymBuilder;

typedef struct {
    void             *map;
    size_t            map_len;
    const HSymHeader *hdr;
    const SymDirRec  *dirs;
    const SymFileRec *files;
    const SymRec     *syms;
    const char       *pool;
    char            **dir_paths;
} OldSymIdx;

typedef struct {
    const char *path;
    uint32_t    old_dir_idx;
} DirPathPair;

static int cmp_dir_pair(const void *a, const void *b) {
    return strcmp(((const DirPathPair *)a)->path, ((const DirPathPair *)b)->path);
}

static bool open_old_sym_idx(const char *idx_path, OldSymIdx *old, DirPathPair **sorted_out, size_t *n_out) {
    memset(old, 0, sizeof(*old));
    *sorted_out = NULL;
    *n_out = 0;

    int fd = open(idx_path, O_RDONLY);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || (size_t)st.st_size < sizeof(HSymHeader)) {
        close(fd);
        return false;
    }
    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return false;

    const HSymHeader *h = (const HSymHeader *)map;
    if (h->magic != HSYM_MAGIC || h->version != IDX_VERSION ||
        h->pool_off + h->pool_size > (size_t)st.st_size) {
        munmap(map, (size_t)st.st_size);
        return false;
    }

    old->map = map;
    old->map_len = (size_t)st.st_size;
    old->hdr = h;
    old->dirs = (const SymDirRec *)((const char *)map + h->dirs_off);
    old->files = (const SymFileRec *)((const char *)map + h->files_off);
    old->syms = (const SymRec *)((const char *)map + h->syms_off);
    old->pool = (const char *)map + h->pool_off;

    old->dir_paths = (char **)calloc(h->n_dirs, sizeof(char *));
    DirPathPair *pairs = (DirPathPair *)malloc(h->n_dirs * sizeof(DirPathPair));
    if (!old->dir_paths || !pairs) {
        free(old->dir_paths);
        free(pairs);
        munmap(map, (size_t)st.st_size);
        memset(old, 0, sizeof(*old));
        return false;
    }
    char tmp[PATH_MAX];
    for (uint32_t i = 0; i < h->n_dirs; i++) {
        size_t pl = materialize_sym_dir(old->dirs, h->n_dirs, old->pool, i, tmp, sizeof(tmp));
        old->dir_paths[i] = (char *)malloc(pl + 1);
        memcpy(old->dir_paths[i], tmp, pl + 1);
        pairs[i].path = old->dir_paths[i];
        pairs[i].old_dir_idx = i;
    }
    qsort(pairs, h->n_dirs, sizeof(DirPathPair), cmp_dir_pair);
    *sorted_out = pairs;
    *n_out = h->n_dirs;
    return true;
}

static void close_old_sym_idx(OldSymIdx *old, DirPathPair *pairs) {
    if (!old->map) return;
    for (uint32_t i = 0; i < old->hdr->n_dirs; i++) free(old->dir_paths[i]);
    free(old->dir_paths);
    free(pairs);
    munmap(old->map, old->map_len);
    memset(old, 0, sizeof(*old));
}

static int32_t find_old_dir(const DirPathPair *pairs, size_t n, const char *path) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(pairs[mid].path, path);
        if (c == 0) return (int32_t)pairs[mid].old_dir_idx;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return -1;
}

static uint32_t sb_add_dir(
    SymBuilder *sb, int32_t parent_idx, const char *name, size_t nlen,
    uint64_t mtime_ns, uint8_t tier, uint8_t depth, bool watch
) {
    if (sb->n_dirs == sb->cap_dirs) {
        sb->cap_dirs = sb->cap_dirs ? (sb->cap_dirs * 2) : 1024;
        sb->dirs = (SymDirRec *)realloc(sb->dirs, sb->cap_dirs * sizeof(SymDirRec));
        if (!sb->dirs) { perror("realloc"); exit(1); }
    }
    uint32_t idx = (uint32_t)sb->n_dirs++;
    SymDirRec *d = &sb->dirs[idx];
    d->parent_idx = parent_idx;
    d->name_off = bb_push(&sb->pool, name, nlen);
    d->mtime_ns = mtime_ns;
    d->name_len = (uint16_t)(nlen > 65535 ? 65535 : nlen);
    d->tier = tier;
    d->depth = depth;
    d->watch_id = (watch && sb->next_watch_id < MAX_WATCH_DIRS) ? sb->next_watch_id++ : 0xFFFFU;
    d->pad = 0;
    return idx;
}

static uint32_t sb_add_file(
    SymBuilder *sb, uint32_t dir_idx, const char *name, size_t nlen,
    uint64_t mtime_ns, uint32_t size_lo, uint32_t file_hash, uint8_t tier, uint8_t lang
) {
    if (sb->n_files == sb->cap_files) {
        sb->cap_files = sb->cap_files ? (sb->cap_files * 2) : 8192;
        sb->files = (SymFileRec *)realloc(sb->files, sb->cap_files * sizeof(SymFileRec));
        if (!sb->files) { perror("realloc"); exit(1); }
    }
    uint32_t fid = (uint32_t)sb->n_files++;
    SymFileRec *f = &sb->files[fid];
    f->dir_idx = dir_idx;
    f->name_off = bb_push(&sb->pool, name, nlen);
    f->mtime_ns = mtime_ns;
    f->size_lo = size_lo;
    f->file_hash = file_hash;
    f->first_sym = (uint32_t)sb->n_syms;
    f->sym_count = 0;
    f->name_len = (uint16_t)(nlen > 65535 ? 65535 : nlen);
    f->tier = tier;
    f->lang = lang;
    return fid;
}

static uint32_t sb_add_sym(
    SymBuilder *sb, uint32_t file_id, const char *name, size_t nlen,
    const char *sig, size_t slen, uint32_t start_line, uint32_t end_line,
    uint8_t kind, uint8_t flags
) {
    if (nlen < 2) return UINT32_MAX;
    if (nlen > 160) nlen = 160;
    if (slen > 220) slen = 220;

    if (sb->n_syms == sb->cap_syms) {
        sb->cap_syms = sb->cap_syms ? (sb->cap_syms * 2) : 32768;
        sb->syms = (SymRec *)realloc(sb->syms, sb->cap_syms * sizeof(SymRec));
        if (!sb->syms) { perror("realloc"); exit(1); }
    }
    uint32_t sid = (uint32_t)sb->n_syms++;
    SymRec *s = &sb->syms[sid];
    s->name_off = bb_push(&sb->pool, name, nlen);
    s->sig_off = bb_push(&sb->pool, sig, slen);
    s->file_id = file_id;
    s->start_line = start_line;
    s->end_line = end_line >= start_line ? end_line : start_line;
    s->name_len = (uint16_t)nlen;
    s->sig_len = (uint16_t)slen;
    s->kind = kind;
    s->flags = flags;
    s->pad = 0;

    sb->files[file_id].sym_count++;
    add_str_trigrams(sb->tri, name, nlen, sid);
    return sid;
}

static inline bool is_ident0(unsigned char c) {
    return isalpha(c) || c == '_' || c == '$';
}

static inline bool is_ident(unsigned char c) {
    return isalnum(c) || c == '_' || c == '$';
}

static size_t read_ident(const char *p, char *out, size_t cap) {
    if (!is_ident0((unsigned char)*p)) return 0;
    size_t k = 0;
    while (is_ident((unsigned char)p[k]) && k + 1 < cap) {
        out[k] = p[k];
        k++;
    }
    out[k] = '\0';
    return k;
}

static bool is_ctrl_kw(const char *w) {
    static const char *const kw[] = {
        "if", "else", "for", "while", "switch", "case", "return", "sizeof",
        "catch", "typeof", "delete", "new", "throw", "await", "yield",
        "match", "loop", "where", "import", "from", "export", "default", NULL
    };
    for (int i = 0; kw[i]; i++) {
        if (strcmp(w, kw[i]) == 0) return true;
    }
    return false;
}

static void clean_signature(const char *line, size_t len, char *out, size_t cap) {
    while (len > 0 && (*line == ' ' || *line == '\t')) { line++; len--; }
    size_t j = 0;
    bool prev_sp = false;
    for (size_t i = 0; i < len && j + 1 < cap; i++) {
        unsigned char c = (unsigned char)line[i];
        if (c == '\r' || c == '\n') break;
        if (c == ' ' || c == '\t') {
            if (!prev_sp) { out[j++] = ' '; prev_sp = true; }
        } else {
            out[j++] = (char)c;
            prev_sp = false;
        }
    }
    while (j > 0 && out[j - 1] == ' ') j--;
    out[j] = '\0';
}

typedef void (*EmitSymFn)(
    void *ctx, const char *name, size_t nlen, const char *sig, size_t slen,
    uint32_t start_line, uint32_t end_line, uint8_t kind, uint8_t flags
);

typedef struct {
    uint32_t sym_idx;
    int      indent;
    int      brace_depth;
} OpenScope;

typedef struct {
    SymBuilder *sb;
    uint32_t    fid;
} SbEmitCtx;

static void sb_emit_cb(
    void *ctx, const char *name, size_t nlen, const char *sig, size_t slen,
    uint32_t start_line, uint32_t end_line, uint8_t kind, uint8_t flags
) {
    SbEmitCtx *ec = (SbEmitCtx *)ctx;
    (void)sb_add_sym(ec->sb, ec->fid, name, nlen, sig, slen, start_line, end_line, kind, flags);
}

static void scan_source_buffer(
    const char *buf, size_t sz, uint8_t lang, SymBuilder *sb, uint32_t fid,
    EmitSymFn custom_emit, void *custom_ctx
) {
    SbEmitCtx sb_ctx = {sb, fid};
    EmitSymFn emit = custom_emit ? custom_emit : sb_emit_cb;
    void *ectx = custom_emit ? custom_ctx : (void *)&sb_ctx;

    OpenScope py_stack[16];
    int n_py = 0;
    char py_cls[96] = {0};
    int py_cls_indent = -1;

    OpenScope br_stack[24];
    int n_br = 0;
    int brace_depth = 0;
    bool in_block_comment = false;
    uint8_t py_triple_quote = 0;

    char impl_type[96] = {0};
    int impl_brace_depth = -1;

    char pend_c_name[128] = {0};
    char pend_c_sig[220] = {0};
    uint32_t pend_c_line = 0;
    uint8_t pend_c_kind = SK_FN;
    int pend_paren_bal = 0;

    uint32_t pend_typedef_line = 0;
    int pend_typedef_depth = -1;
    char pend_typedef_sig[220] = {0};

    char prev_ret_line[160] = {0};
    uint32_t prev_ret_lineno = 0;
    uint32_t decorator_start_line = 0;

    uint32_t lineno = 0;
    const char *cur = buf;
    const char *end = buf + sz;

    while (cur < end) {
        const char *nl = (const char *)memchr(cur, '\n', (size_t)(end - cur));
        size_t llen = nl ? (size_t)(nl - cur) : (size_t)(end - cur);
        if (llen > 0 && cur[llen - 1] == '\r') llen--;
        lineno++;

        int indent = 0;
        size_t i = 0;
        while (i < llen && (cur[i] == ' ' || cur[i] == '\t')) {
            indent += (cur[i] == '\t') ? 4 : 1;
            i++;
        }
        const char *p = cur + i;
        size_t rem = llen - i;

        /* ==================== PYTHON ==================== */
        if (lang == LANG_PY) {
            if (py_triple_quote != 0) {
                char q = (py_triple_quote == 1) ? '\'' : '"';
                for (size_t k = 0; k + 2 < rem; k++) {
                    if (p[k] == '\\') { k++; continue; }
                    if (p[k] == q && p[k + 1] == q && p[k + 2] == q) {
                        py_triple_quote = 0;
                        break;
                    }
                }
                cur = nl ? (nl + 1) : end;
                continue;
            }

            if (rem > 0 && p[0] != '#') {
                while (n_py > 0 && indent <= py_stack[n_py - 1].indent && p[0] != '@' &&
                       !(rem >= 4 && memcmp(p, "elif", 4) == 0) &&
                       !(rem >= 4 && memcmp(p, "else", 4) == 0) &&
                       !(rem >= 6 && memcmp(p, "except", 6) == 0) &&
                       !(rem >= 7 && memcmp(p, "finally", 7) == 0)) {
                    if (sb && py_stack[n_py - 1].sym_idx < sb->n_syms) {
                        sb->syms[py_stack[n_py - 1].sym_idx].end_line = lineno - 1;
                    }
                    n_py--;
                }
                if (py_cls_indent >= 0 && indent <= py_cls_indent && p[0] != '@') {
                    py_cls[0] = '\0';
                    py_cls_indent = -1;
                }
            }

            for (size_t k = 0; k + 2 < rem; k++) {
                if (p[k] == '#') break;
                if (p[k] == '\\') { k++; continue; }
                if ((p[k] == '\'' && p[k + 1] == '\'' && p[k + 2] == '\'') ||
                    (p[k] == '"' && p[k + 1] == '"' && p[k + 2] == '"')) {
                    char q = p[k];
                    bool closed = false;
                    for (size_t m = k + 3; m + 2 < rem; m++) {
                        if (p[m] == '\\') { m++; continue; }
                        if (p[m] == q && p[m + 1] == q && p[m + 2] == q) {
                            closed = true;
                            k = m + 2;
                            break;
                        }
                    }
                    if (!closed) {
                        py_triple_quote = (q == '\'') ? 1 : 2;
                        break;
                    }
                }
            }

            if (rem > 1 && p[0] == '@') {
                if (decorator_start_line == 0) decorator_start_line = lineno;
                cur = nl ? (nl + 1) : end;
                continue;
            }

            const char *kw = p;
            if (rem > 6 && memcmp(kw, "async ", 6) == 0) {
                kw += 6;
                while (*kw == ' ') kw++;
            }

            char name[128], sym[160], sig[220];
            uint32_t s_start = decorator_start_line ? decorator_start_line : lineno;

            if (strncmp(kw, "def ", 4) == 0 && is_ident0((unsigned char)kw[4])) {
                decorator_start_line = 0;
                size_t nl_id = read_ident(kw + 4, name, sizeof(name));
                if (nl_id > 0) {
                    uint8_t kind = SK_FN;
                    if (py_cls[0] && indent > py_cls_indent) {
                        snprintf(sym, sizeof(sym), "%s.%s", py_cls, name);
                        kind = SK_METHOD;
                    } else {
                        snprintf(sym, sizeof(sym), "%s", name);
                    }
                    clean_signature(p, rem, sig, sizeof(sig));
                    uint32_t sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                    emit(ectx, sym, strlen(sym), sig, strlen(sig), s_start, lineno, kind, 1);
                    if (sb && sid < sb->n_syms && n_py < 16) {
                        py_stack[n_py].sym_idx = sid;
                        py_stack[n_py].indent = indent;
                        n_py++;
                    }
                }
            } else if (strncmp(kw, "class ", 6) == 0 && is_ident0((unsigned char)kw[6])) {
                decorator_start_line = 0;
                size_t nl_id = read_ident(kw + 6, name, sizeof(name));
                if (nl_id > 0) {
                    clean_signature(p, rem, sig, sizeof(sig));
                    uint32_t sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                    emit(ectx, name, nl_id, sig, strlen(sig), s_start, lineno, SK_CLASS, 1);
                    snprintf(py_cls, sizeof(py_cls), "%.95s", name);
                    py_cls_indent = indent;
                    if (sb && sid < sb->n_syms && n_py < 16) {
                        py_stack[n_py].sym_idx = sid;
                        py_stack[n_py].indent = indent;
                        n_py++;
                    }
                }
            } else if (rem > 0 && p[0] != '#') {
                decorator_start_line = 0;
                if (indent == 0 && isupper((unsigned char)p[0])) {
                    size_t nl_id = read_ident(p, name, sizeof(name));
                    if (nl_id >= 3) {
                        const char *q = p + nl_id;
                        while (*q == ' ' || *q == '\t') q++;
                        if (*q == '=' && q[1] != '=') {
                            clean_signature(p, rem, sig, sizeof(sig));
                            emit(ectx, name, nl_id, sig, strlen(sig), lineno, lineno, SK_CONST, 0);
                        }
                    }
                }
            }
            cur = nl ? (nl + 1) : end;
            continue;
        }

        /* ==================== BRACE LANGUAGES ==================== */
        int line_open_braces = 0, line_close_braces = 0;
        int line_paren_delta = 0;
        bool started_in_comment = in_block_comment;

        for (size_t k = 0; k < rem; k++) {
            char c = p[k];
            char nx = (k + 1 < rem) ? p[k + 1] : '\0';
            if (in_block_comment) {
                if (c == '*' && nx == '/') { in_block_comment = false; k++; }
                continue;
            }
            if (lang != LANG_SH && c == '/' && nx == '/') break;
            if (lang == LANG_SH && c == '#') break;
            if (lang != LANG_SH && c == '/' && nx == '*') { in_block_comment = true; k++; continue; }
            if (c == '"' || c == '\'' || (lang == LANG_TS && c == '`') || (lang == LANG_GO && c == '`')) {
                char q = c;
                if (lang == LANG_RUST && q == '\'') {
                    if (!(k + 2 < rem && (p[k + 2] == '\'' || (p[k + 1] == '\\' && k + 3 < rem && p[k + 3] == '\''))))
                        continue;
                }
                k++;
                while (k < rem) {
                    if (p[k] == '\\') { k += 2; continue; }
                    if (p[k] == q) break;
                    k++;
                }
                continue;
            }
            if (c == '{') line_open_braces++;
            else if (c == '}') line_close_braces++;
            else if (c == '(') line_paren_delta++;
            else if (c == ')') line_paren_delta--;
        }

        int depth_before = brace_depth;
        int depth_after = brace_depth + line_open_braces - line_close_braces;
        if (depth_after < 0) depth_after = 0;

        if (pend_c_name[0] != '\0') {
            pend_paren_bal += line_paren_delta;
            bool saw_semi = (memchr(p, ';', rem) != NULL);
            if (pend_paren_bal <= 0 && line_open_braces > 0 && !saw_semi) {
                uint32_t sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                emit(ectx, pend_c_name, strlen(pend_c_name), pend_c_sig, strlen(pend_c_sig),
                     pend_c_line, lineno, pend_c_kind, 1);
                if (sb && sid < sb->n_syms && n_br < 24 && depth_after > depth_before) {
                    br_stack[n_br].sym_idx = sid;
                    br_stack[n_br].brace_depth = depth_before;
                    n_br++;
                }
                pend_c_name[0] = '\0';
            } else if (saw_semi || (lineno - pend_c_line) > 8) {
                pend_c_name[0] = '\0';
            }
        }

        if (!started_in_comment && rem > 0) {
            char name[128], sym[160], sig[220];
            uint32_t matched_sid = UINT32_MAX;
            bool matched = false;
            char opened_class[160] = {0};

            if (lang == LANG_RUST) {
                const char *s = p;
                if (strncmp(s, "#[", 2) == 0) {
                    if (decorator_start_line == 0) decorator_start_line = lineno;
                } else {
                    uint32_t s_start = decorator_start_line ? decorator_start_line : lineno;
                    decorator_start_line = 0;

                    if (strncmp(s, "pub", 3) == 0 && (s[3] == ' ' || s[3] == '(')) {
                        s += 3;
                        if (*s == '(') { while (*s && *s != ')') s++; if (*s == ')') s++; }
                        while (*s == ' ') s++;
                    }
                    while (strncmp(s, "async ", 6) == 0 || strncmp(s, "unsafe ", 7) == 0 ||
                           strncmp(s, "const ", 6) == 0 || strncmp(s, "extern ", 7) == 0) {
                        if (strncmp(s, "extern ", 7) == 0) {
                            s += 7; while (*s == ' ') s++;
                            if (*s == '"') { s++; while (*s && *s != '"') s++; if (*s == '"') s++; }
                        } else {
                            while (*s && *s != ' ') s++;
                        }
                        while (*s == ' ') s++;
                    }

                    uint8_t kind = 0;
                    if (strncmp(s, "fn ", 3) == 0) { s += 3; kind = SK_FN; }
                    else if (strncmp(s, "struct ", 7) == 0) { s += 7; kind = SK_STRUCT; }
                    else if (strncmp(s, "enum ", 5) == 0) { s += 5; kind = SK_TYPE; }
                    else if (strncmp(s, "trait ", 6) == 0) { s += 6; kind = SK_CLASS; }
                    else if (strncmp(s, "type ", 5) == 0) { s += 5; kind = SK_TYPE; }
                    else if (strncmp(s, "mod ", 4) == 0) { s += 4; kind = SK_TYPE; }
                    else if (strncmp(s, "macro_rules!", 12) == 0) { s += 12; kind = SK_MACRO; }
                    else if (strncmp(s, "impl", 4) == 0 && (s[4] == ' ' || s[4] == '<')) {
                        const char *for_kw = strstr(s, " for ");
                        const char *tpos = for_kw ? (for_kw + 5) : (s + 4);
                        if (!for_kw && *tpos == '<') {
                            int gd = 1; tpos++;
                            while (*tpos && gd > 0) {
                                if (*tpos == '<') gd++;
                                else if (*tpos == '>') gd--;
                                tpos++;
                            }
                        }
                        while (*tpos == ' ' || *tpos == '&' || *tpos == '\t') tpos++;
                        if (read_ident(tpos, impl_type, sizeof(impl_type)) > 0 && line_open_braces > 0) {
                            impl_brace_depth = depth_before;
                        }
                    }

                    if (kind != 0) {
                        while (*s == ' ') s++;
                        size_t nl_id = read_ident(s, name, sizeof(name));
                        if (nl_id > 0) {
                            if (kind == SK_FN && impl_type[0] && depth_before > impl_brace_depth) {
                                snprintf(sym, sizeof(sym), "%s::%s", impl_type, name);
                                kind = SK_METHOD;
                            } else {
                                snprintf(sym, sizeof(sym), "%s", name);
                            }
                            clean_signature(p, rem, sig, sizeof(sig));
                            matched_sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                            emit(ectx, sym, strlen(sym), sig, strlen(sig), s_start, lineno, kind, 1);
                            matched = true;
                        }
                    }
                }
            } else if (lang == LANG_GO) {
                if (strncmp(p, "func ", 5) == 0) {
                    const char *s = p + 5;
                    while (*s == ' ') s++;
                    char recv[96] = {0};
                    if (*s == '(') {
                        s++;
                        const char *rp = strchr(s, ')');
                        if (rp) {
                            const char *t = rp - 1;
                            while (t > s && (*t == ' ' || *t == ']')) {
                                if (*t == ']') { while (t > s && *t != '[') t--; }
                                if (t > s) t--;
                            }
                            while (t > s && is_ident((unsigned char)t[-1])) t--;
                            read_ident(t, recv, sizeof(recv));
                            s = rp + 1;
                            while (*s == ' ') s++;
                        }
                    }
                    size_t nl_id = read_ident(s, name, sizeof(name));
                    if (nl_id > 0) {
                        uint8_t kind = SK_FN;
                        if (recv[0]) {
                            snprintf(sym, sizeof(sym), "%s.%s", recv, name);
                            kind = SK_METHOD;
                        } else {
                            snprintf(sym, sizeof(sym), "%s", name);
                        }
                        clean_signature(p, rem, sig, sizeof(sig));
                        matched_sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                        emit(ectx, sym, strlen(sym), sig, strlen(sig), lineno, lineno, kind, 1);
                        matched = true;
                    }
                } else if (strncmp(p, "type ", 5) == 0) {
                    const char *s = p + 5;
                    while (*s == ' ') s++;
                    size_t nl_id = read_ident(s, name, sizeof(name));
                    if (nl_id > 0) {
                        const char *after = s + nl_id;
                        while (*after == ' ' || *after == '\t') after++;
                        uint8_t kind = (strncmp(after, "struct", 6) == 0) ? SK_STRUCT :
                                       (strncmp(after, "interface", 9) == 0 ? SK_CLASS : SK_TYPE);
                        clean_signature(p, rem, sig, sizeof(sig));
                        matched_sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                        emit(ectx, name, nl_id, sig, strlen(sig), lineno, lineno, kind, 1);
                        matched = true;
                    }
                }
            } else if (lang == LANG_TS) {
                const char *s = p;
                if (strncmp(s, "export ", 7) == 0) { s += 7; while (*s == ' ') s++; }
                if (strncmp(s, "default ", 8) == 0) { s += 8; while (*s == ' ') s++; }
                if (strncmp(s, "declare ", 8) == 0) { s += 8; while (*s == ' ') s++; }
                if (strncmp(s, "abstract ", 9) == 0) { s += 9; while (*s == ' ') s++; }
                if (strncmp(s, "async ", 6) == 0) { s += 6; while (*s == ' ') s++; }

                uint8_t kind = 0;
                if (strncmp(s, "function ", 9) == 0 || strncmp(s, "function*", 9) == 0) {
                    s += 9; kind = SK_FN;
                } else if (strncmp(s, "class ", 6) == 0) { s += 6; kind = SK_CLASS; }
                else if (strncmp(s, "interface ", 10) == 0) { s += 10; kind = SK_TYPE; }
                else if (strncmp(s, "type ", 5) == 0) { s += 5; kind = SK_TYPE; }
                else if (strncmp(s, "enum ", 5) == 0) { s += 5; kind = SK_TYPE; }
                else if ((strncmp(s, "const ", 6) == 0 || strncmp(s, "let ", 4) == 0) && depth_before == 0) {
                    s += (s[0] == 'c') ? 6 : 4;
                    while (*s == ' ') s++;
                    size_t nl_id = read_ident(s, name, sizeof(name));
                    if (nl_id > 0 && (strstr(s + nl_id, "=>") || strstr(s + nl_id, "function"))) {
                        clean_signature(p, rem, sig, sizeof(sig));
                        matched_sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                        emit(ectx, name, nl_id, sig, strlen(sig), lineno, lineno, SK_FN, 1);
                        matched = true;
                    }
                }

                if (!matched && kind != 0) {
                    while (*s == ' ') s++;
                    size_t nl_id = read_ident(s, name, sizeof(name));
                    if (nl_id > 0) {
                        clean_signature(p, rem, sig, sizeof(sig));
                        matched_sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                        emit(ectx, name, nl_id, sig, strlen(sig), lineno, lineno, kind, 1);
                        matched = true;
                        if (kind == SK_CLASS && line_open_braces > 0) {
                            snprintf(opened_class, sizeof(opened_class), "%s", name);
                        }
                    }
                } else if (!matched && impl_type[0] && depth_before == impl_brace_depth + 1 && line_open_braces > 0) {
                    const char *ms = p;
                    while (strncmp(ms, "public ", 7) == 0 || strncmp(ms, "private ", 8) == 0 ||
                           strncmp(ms, "protected ", 10) == 0 || strncmp(ms, "static ", 7) == 0 ||
                           strncmp(ms, "async ", 6) == 0 || strncmp(ms, "get ", 4) == 0 ||
                           strncmp(ms, "set ", 4) == 0 || strncmp(ms, "readonly ", 9) == 0) {
                        while (*ms && *ms != ' ') ms++;
                        while (*ms == ' ') ms++;
                    }
                    size_t nl_id = read_ident(ms, name, sizeof(name));
                    if (nl_id > 0 && !is_ctrl_kw(name)) {
                        const char *ap = ms + nl_id;
                        if (*ap == '<') {
                            int gd = 1; ap++;
                            while (*ap && gd > 0) { if (*ap == '<') gd++; else if (*ap == '>') gd--; ap++; }
                        }
                        while (*ap == ' ') ap++;
                        if (*ap == '(') {
                            snprintf(sym, sizeof(sym), "%s.%s", impl_type, name);
                            clean_signature(p, rem, sig, sizeof(sig));
                            matched_sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                            emit(ectx, sym, strlen(sym), sig, strlen(sig), lineno, lineno, SK_METHOD, 1);
                            matched = true;
                        }
                    }
                }
            } else if (lang == LANG_SH) {
                const char *s = p;
                if (strncmp(s, "function ", 9) == 0) {
                    s += 9;
                    while (*s == ' ') s++;
                    size_t nl_id = read_ident(s, name, sizeof(name));
                    if (nl_id > 0) {
                        clean_signature(p, rem, sig, sizeof(sig));
                        matched_sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                        emit(ectx, name, nl_id, sig, strlen(sig), lineno, lineno, SK_FN, 1);
                        matched = true;
                    }
                } else if (is_ident0((unsigned char)*s)) {
                    size_t nl_id = read_ident(s, name, sizeof(name));
                    if (nl_id > 0 && !is_ctrl_kw(name)) {
                        const char *q = s + nl_id;
                        while (*q == ' ' || *q == '\t') q++;
                        if (q[0] == '(' && q[1] == ')') {
                            clean_signature(p, rem, sig, sizeof(sig));
                            matched_sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                            emit(ectx, name, nl_id, sig, strlen(sig), lineno, lineno, SK_FN, 1);
                            matched = true;
                        }
                    }
                }
            } else if (lang == LANG_C || lang == LANG_JAVA) {
                if (p[0] == '#') {
                    const char *s = p + 1;
                    while (*s == ' ' || *s == '\t') s++;
                    if (strncmp(s, "define ", 7) == 0) {
                        s += 7;
                        while (*s == ' ' || *s == '\t') s++;
                        size_t nl_id = read_ident(s, name, sizeof(name));
                        if (nl_id >= 3 && !(nl_id > 2 && strcmp(name + nl_id - 2, "_H") == 0)) {
                            uint32_t end_ln = lineno;
                            clean_signature(p, rem, sig, sizeof(sig));
                            emit(ectx, name, nl_id, sig, strlen(sig), lineno, end_ln, SK_MACRO, 0);
                        }
                    }
                } else if (depth_before <= 2) {
                    const char *s = p;
                    if (strncmp(s, "template", 8) == 0 && (s[8] == '<' || s[8] == ' ')) {
                        const char *gt = NULL;
                        for (const char * scan = p + rem; scan > s; scan--) {
                            if (scan[-1] == '>') { gt = scan - 1; break; }
                        }
                        if (gt && gt < p + rem) {
                            s = gt + 1;
                            while (s < p + rem && *s == ' ') s++;
                        }
                    }
                    bool is_typedef = false;
                    if (strncmp(s, "typedef ", 8) == 0) {
                        is_typedef = true;
                        s += 8;
                        while (*s == ' ') s++;
                    }
                    if (is_typedef &&
                        ((strncmp(s, "struct", 6) == 0 && (s[6] == ' ' || s[6] == '\t' || s[6] == '{' || s[6] == '\0')) ||
                         (strncmp(s, "enum", 4) == 0 && (s[4] == ' ' || s[4] == '\t' || s[4] == '{' || s[4] == '\0')) ||
                         (strncmp(s, "union", 5) == 0 && (s[5] == ' ' || s[5] == '\t' || s[5] == '{' || s[5] == '\0')))) {
                        if (pend_typedef_depth < 0 && !memchr(p, ';', rem)) {
                            pend_typedef_line = lineno;
                            pend_typedef_depth = depth_before;
                            clean_signature(p, rem, pend_typedef_sig, sizeof(pend_typedef_sig));
                        }
                    }
                    if (strncmp(s, "struct ", 7) == 0 || strncmp(s, "class ", 6) == 0 ||
                        strncmp(s, "enum ", 5) == 0 || strncmp(s, "namespace ", 10) == 0 ||
                        (lang == LANG_JAVA && strncmp(s, "interface ", 10) == 0)) {
                        uint8_t tk = (s[0] == 's') ? SK_STRUCT : ((s[0] == 'c' || s[0] == 'i') ? SK_CLASS : SK_TYPE);
                        bool is_cls_like = (s[0] == 's' || s[0] == 'c' || s[0] == 'i');
                        while (*s && *s != ' ') s++;
                        while (*s == ' ') s++;
                        if (strncmp(s, "class ", 6) == 0) { s += 6; while (*s == ' ') s++; }
                        size_t nl_id = read_ident(s, name, sizeof(name));
                        if (nl_id > 0 && (line_open_braces > 0 || !memchr(p, ';', rem))) {
                            clean_signature(p, rem, sig, sizeof(sig));
                            matched_sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                            emit(ectx, name, nl_id, sig, strlen(sig), lineno, lineno, tk, 1);
                            matched = true;
                            if (is_cls_like && line_open_braces > 0) {
                                snprintf(opened_class, sizeof(opened_class), "%s", name);
                            }
                        }
                    } else if (is_typedef && memchr(p, ';', rem) != NULL && line_open_braces == 0) {
                        const char *sc = (const char *)memchr(p, ';', rem);
                        const char * end_id = sc;
                        while (end_id > s && (end_id[-1] == ' ' || end_id[-1] == '\t')) end_id--;
                        const char *st_id = end_id;
                        while (st_id > s && is_ident((unsigned char)st_id[-1])) st_id--;
                        if (st_id < end_id && is_ident0((unsigned char)*st_id)) {
                            size_t nl_id = (size_t)(end_id - st_id);
                            if (nl_id < sizeof(name)) {
                                memcpy(name, st_id, nl_id);
                                name[nl_id] = '\0';
                                clean_signature(p, rem, sig, sizeof(sig));
                                emit(ectx, name, nl_id, sig, strlen(sig), lineno, lineno, SK_TYPE, 0);
                            }
                        }
                    } else if (indent <= 8) {
                        const char *lp = (const char *)memchr(p, '(', rem);
                        if (lp && lp > p && !memchr(p, '=', (size_t)(lp - p))) {
                            const char *id_end = lp;
                            while (id_end > p && (id_end[-1] == ' ' || id_end[-1] == '\t')) id_end--;
                            const char *id_start = id_end;
                            while (id_start > p && (is_ident((unsigned char)id_start[-1]) || id_start[-1] == ':' || id_start[-1] == '~'))
                                id_start--;
                            size_t fn_len = (size_t)(id_end - id_start);
                            if (fn_len >= 2 && fn_len < sizeof(sym)) {
                                memcpy(sym, id_start, fn_len);
                                sym[fn_len] = '\0';
                                const char *base_fn = strrchr(sym, ':');
                                base_fn = base_fn ? (base_fn + 1) : sym;
                                if (!is_ctrl_kw(base_fn) && (is_ident0((unsigned char)base_fn[0]) || base_fn[0] == '~')) {
                                    bool has_ret_prefix = false;
                                    const char *pre = p;
                                    while (pre < id_start && (*pre == ' ' || *pre == '*' || *pre == '&')) pre++;
                                    if (pre < id_start) has_ret_prefix = true;
                                    else if (prev_ret_lineno == lineno - 1 && prev_ret_line[0]) has_ret_prefix = true;
                                    else if (lang == LANG_C && impl_type[0] && strcmp(base_fn, impl_type) == 0) has_ret_prefix = true;

                                    if (has_ret_prefix) {
                                        uint8_t fk = (strchr(sym, ':') != NULL) ? SK_METHOD : SK_FN;
                                        if (fk == SK_FN && impl_type[0] && depth_before == impl_brace_depth + 1) {
                                            char qsym[160];
                                            snprintf(qsym, sizeof(qsym),
                                                     (lang == LANG_JAVA) ? "%.70s.%.80s" : "%.70s::%.80s",
                                                     impl_type, sym);
                                            snprintf(sym, sizeof(sym), "%s", qsym);
                                            fk = SK_METHOD;
                                        }
                                        uint32_t s_line = (pre == id_start && prev_ret_lineno == lineno - 1) ? prev_ret_lineno : lineno;
                                        if (s_line < lineno && prev_ret_line[0]) {
                                            char sig_buf[680];
                                            char cur_clean[480];
                                            clean_signature(p, rem, cur_clean, sizeof(cur_clean));
                                            snprintf(sig_buf, sizeof(sig_buf), "%.160s %.479s", prev_ret_line, cur_clean);
                                            clean_signature(sig_buf, strlen(sig_buf), sig, sizeof(sig));
                                        } else {
                                            clean_signature(p, rem, sig, sizeof(sig));
                                        }

                                        bool saw_semi = (memchr(lp, ';', (size_t)((p + rem) - lp)) != NULL);
                                        if (line_open_braces > 0 && !saw_semi) {
                                            matched_sid = sb ? (uint32_t)sb->n_syms : UINT32_MAX;
                                            emit(ectx, sym, strlen(sym), sig, strlen(sig), s_line, lineno, fk, 1);
                                            matched = true;
                                        } else if (!saw_semi) {
                                            snprintf(pend_c_name, sizeof(pend_c_name), "%.127s", sym);
                                            snprintf(pend_c_sig, sizeof(pend_c_sig), "%.219s", sig);
                                            pend_c_line = s_line;
                                            pend_c_kind = fk;
                                            pend_paren_bal = line_paren_delta;
                                        }
                                    }
                                }
                            }
                        } else if (indent == 0 && line_open_braces == 0 && !memchr(p, ';', rem) &&
                                   !memchr(p, '(', rem) && is_ident0((unsigned char)p[0])) {
                            clean_signature(p, rem, prev_ret_line, sizeof(prev_ret_line));
                            prev_ret_lineno = lineno;
                        }
                    }
                }
            }

            if (matched && sb && matched_sid < sb->n_syms && line_open_braces > 0 &&
                depth_after > depth_before && n_br < 24) {
                br_stack[n_br].sym_idx = matched_sid;
                br_stack[n_br].brace_depth = depth_before;
                n_br++;
            }
            if (opened_class[0]) {
                snprintf(impl_type, sizeof(impl_type), "%.95s", opened_class);
                impl_brace_depth = depth_before;
            }
        }

        while (n_br > 0 && depth_after <= br_stack[n_br - 1].brace_depth && line_close_braces > 0) {
            if (sb && br_stack[n_br - 1].sym_idx < sb->n_syms) {
                sb->syms[br_stack[n_br - 1].sym_idx].end_line = lineno;
            }
            n_br--;
        }
        if (pend_typedef_depth >= 0 && depth_after <= pend_typedef_depth && line_close_braces > 0) {
            const char *rb = NULL;
            for (size_t k = rem; k > 0; k--) {
                if (p[k - 1] == '}') { rb = p + (k - 1); break; }
            }
            if (rb) {
                const char *q = rb + 1;
                while (q < p + rem && (*q == ' ' || *q == '\t')) q++;
                size_t tdn = 0;
                while (q + tdn < p + rem &&
                       (tdn == 0 ? is_ident0((unsigned char)q[tdn]) : is_ident((unsigned char)q[tdn]))) {
                    tdn++;
                }
                if (tdn > 0 && tdn < 128) {
                    char td_name[128];
                    memcpy(td_name, q, tdn);
                    td_name[tdn] = '\0';
                    emit(ectx, td_name, tdn, pend_typedef_sig, strlen(pend_typedef_sig),
                         pend_typedef_line, lineno, SK_TYPE, 0);
                }
            }
            pend_typedef_depth = -1;
            pend_typedef_line = 0;
        }
        if (impl_brace_depth >= 0 && depth_after <= impl_brace_depth && line_close_braces > 0) {
            impl_type[0] = '\0';
            impl_brace_depth = -1;
        }
        brace_depth = depth_after;

        cur = nl ? (nl + 1) : end;
    }

    while (n_py > 0) {
        if (sb && py_stack[n_py - 1].sym_idx < sb->n_syms)
            sb->syms[py_stack[n_py - 1].sym_idx].end_line = lineno;
        n_py--;
    }
    while (n_br > 0) {
        if (sb && br_stack[n_br - 1].sym_idx < sb->n_syms)
            sb->syms[br_stack[n_br - 1].sym_idx].end_line = lineno;
        n_br--;
    }
}

static void parse_file_into_sb(SymBuilder *sb, int dfd, const char *fname, uint8_t lang, uint32_t fid, size_t fsize) {
    if (fsize == 0 || fsize > 4 * 1024 * 1024) return;
    int open_flags = O_RDONLY;
#ifdef O_NOATIME
    int fd = openat(dfd, fname, open_flags | O_NOATIME);
    if (fd < 0) fd = openat(dfd, fname, open_flags);
#else
    int fd = openat(dfd, fname, open_flags);
#endif
    if (fd < 0) return;

    char stack_buf[65536];
    if (fsize <= sizeof(stack_buf)) {
        ssize_t r = read(fd, stack_buf, fsize);
        close(fd);
        if (r > 0) {
            sb->files[fid].file_hash = hslice_fnv1a32_bytes(stack_buf, (size_t)r);
            scan_source_buffer(stack_buf, (size_t)r, lang, sb, fid, NULL, NULL);
        }
        return;
    }
    void *map = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return;
    sb->files[fid].file_hash = hslice_fnv1a32_bytes(map, fsize);
    scan_source_buffer((const char *)map, fsize, lang, sb, fid, NULL, NULL);
    munmap(map, fsize);
}

static void reuse_old_dir_subtree(
    SymBuilder *sb, const OldSymIdx *old, uint32_t old_did, uint32_t new_did
) {
    uint32_t lo = 0, hi = old->hdr->n_files;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (old->files[mid].dir_idx < old_did) lo = mid + 1;
        else hi = mid;
    }
    for (uint32_t fi = lo; fi < old->hdr->n_files && old->files[fi].dir_idx == old_did; fi++) {
        const SymFileRec *of = &old->files[fi];
        const char *fn = old->pool + of->name_off;
        uint32_t nfid = sb_add_file(sb, new_did, fn, of->name_len,
                                    of->mtime_ns, of->size_lo, of->file_hash, of->tier, of->lang);
        for (uint32_t k = 0; k < of->sym_count; k++) {
            const SymRec *os = &old->syms[of->first_sym + k];
            (void)sb_add_sym(sb, nfid, old->pool + os->name_off, os->name_len,
                             old->pool + os->sig_off, os->sig_len,
                             os->start_line, os->end_line, os->kind, os->flags);
        }
        sb->reused_files++;
    }
}

static const SymFileRec *find_old_file_in_dir(
    const OldSymIdx *old, uint32_t old_did, const char *fname, size_t fnlen
) {
    uint32_t lo = 0, hi = old->hdr->n_files;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (old->files[mid].dir_idx < old_did) lo = mid + 1;
        else hi = mid;
    }
    for (uint32_t fi = lo; fi < old->hdr->n_files && old->files[fi].dir_idx == old_did; fi++) {
        const SymFileRec *of = &old->files[fi];
        if (of->name_len == fnlen && memcmp(old->pool + of->name_off, fname, fnlen) == 0) {
            return of;
        }
    }
    return NULL;
}

static bool old_dir_files_unchanged(
    const OldSymIdx *old, uint32_t old_did, const char *full_path, size_t plen
) {
    uint32_t lo = 0, hi = old->hdr->n_files;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (old->files[mid].dir_idx < old_did) lo = mid + 1;
        else hi = mid;
    }
    char fpath[PATH_MAX];
    for (uint32_t fi = lo; fi < old->hdr->n_files && old->files[fi].dir_idx == old_did; fi++) {
        const SymFileRec *of = &old->files[fi];
        if (plen + 1 + of->name_len >= sizeof(fpath)) return false;
        memcpy(fpath, full_path, plen);
        size_t pos = plen;
        if (pos > 0 && fpath[pos - 1] != '/') fpath[pos++] = '/';
        memcpy(fpath + pos, old->pool + of->name_off, of->name_len);
        fpath[pos + of->name_len] = '\0';
        struct stat st;
        if (lstat(fpath, &st) != 0 || !S_ISREG(st.st_mode)) return false;
        if (hslice_stat_mtime_ns(&st) != of->mtime_ns || (uint32_t)st.st_size != of->size_lo) {
            return false;
        }
    }
    return true;
}

static void walk_sym_dir(
    SymBuilder *sb, const OldSymIdx *old, const DirPathPair *old_pairs, size_t n_old_pairs,
    const char *full_path, size_t plen, uint32_t dir_idx, uint64_t dir_mtime_ns, uint8_t depth
) {
    if (depth > 22 || sb->n_syms >= 800000) return;

    int32_t old_did = -1;
    if (old && old->map) {
        old_did = find_old_dir(old_pairs, n_old_pairs, full_path);
        if (old_did >= 0 && old->dirs[old_did].mtime_ns == dir_mtime_ns &&
            old_dir_files_unchanged(old, (uint32_t)old_did, full_path, plen)) {
            reuse_old_dir_subtree(sb, old, (uint32_t)old_did, dir_idx);
            for (uint32_t ci = (uint32_t)old_did + 1; ci < old->hdr->n_dirs; ci++) {
                if (old->dirs[ci].parent_idx == old_did) {
                    const char *cn = old->pool + old->dirs[ci].name_off;
                    size_t cnl = old->dirs[ci].name_len;
                    if (plen + 1 + cnl >= PATH_MAX) continue;
                    char cpath[PATH_MAX];
                    memcpy(cpath, full_path, plen);
                    size_t pos = plen;
                    if (pos > 0 && cpath[pos - 1] != '/') cpath[pos++] = '/';
                    memcpy(cpath + pos, cn, cnl);
                    pos += cnl;
                    cpath[pos] = '\0';

                    struct stat cst;
                    if (lstat(cpath, &cst) != 0 || !S_ISDIR(cst.st_mode)) continue;
                    uint64_t cmns = hslice_stat_mtime_ns(&cst);
                    uint8_t dtier = compute_recency_tier(cmns, sb->now_ns);
                    if (sb->dirs[dir_idx].tier > dtier) dtier = sb->dirs[dir_idx].tier;
                    uint32_t ncid = sb_add_dir(sb, (int32_t)dir_idx, cn, cnl, cmns, dtier,
                                               (uint8_t)(depth + 1), depth + 1 <= 6);
                    walk_sym_dir(sb, old, old_pairs, n_old_pairs, cpath, pos, ncid, cmns, (uint8_t)(depth + 1));
                }
            }
            return;
        }
    }

    DIR *d = opendir(full_path);
    if (!d) return;
    int dfd = dirfd(d);

    ChildDirEnt *subdirs = NULL;
    size_t n_sub = 0, cap_sub = 0;
    ChildDirEnt *codefiles = NULL;
    size_t n_cf = 0, cap_cf = 0;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *nm = de->d_name;
        if (nm[0] == '.' && (nm[1] == '\0' || (nm[1] == '.' && nm[2] == '\0'))) continue;
        size_t nl = strlen(nm);
        if (nl == 0 || nl >= 255 || plen + 1 + nl >= PATH_MAX) continue;

        bool is_dir = false, is_reg = false, is_lnk = false;
#ifdef DT_DIR
        if (de->d_type == DT_DIR) is_dir = true;
        else if (de->d_type == DT_REG) is_reg = true;
        else if (de->d_type == DT_LNK) is_lnk = true;
        else if (de->d_type == DT_UNKNOWN)
#endif
        {
            struct stat st;
            if (fstatat(dfd, nm, &st, AT_SYMLINK_NOFOLLOW) == 0) {
                is_dir = S_ISDIR(st.st_mode);
                is_reg = S_ISREG(st.st_mode);
                is_lnk = S_ISLNK(st.st_mode);
            }
        }
        if (is_lnk) continue;

        if (is_dir) {
            if (is_ignored_dir(nm)) continue;
            if (n_sub == cap_sub) {
                cap_sub = cap_sub ? (cap_sub * 2) : 16;
                subdirs = (ChildDirEnt *)realloc(subdirs, cap_sub * sizeof(ChildDirEnt));
                if (!subdirs) { perror("realloc"); exit(1); }
            }
            memcpy(subdirs[n_sub].name, nm, nl + 1);
            subdirs[n_sub].nlen = nl;
            n_sub++;
        } else if (is_reg) {
            if (detect_code_lang(nm, nl) == LANG_NONE) continue;
            if (is_ignored_file(nm, nl)) continue;
            if (n_cf == cap_cf) {
                cap_cf = cap_cf ? (cap_cf * 2) : 32;
                codefiles = (ChildDirEnt *)realloc(codefiles, cap_cf * sizeof(ChildDirEnt));
                if (!codefiles) { perror("realloc"); exit(1); }
            }
            memcpy(codefiles[n_cf].name, nm, nl + 1);
            codefiles[n_cf].nlen = nl;
            n_cf++;
        }
    }

    if (n_cf > 1) qsort(codefiles, n_cf, sizeof(ChildDirEnt), cmp_child_dir);
    if (n_sub > 1) qsort(subdirs, n_sub, sizeof(ChildDirEnt), cmp_child_dir);

    for (size_t i = 0; i < n_cf; i++) {
        struct stat st;
        if (fstatat(dfd, codefiles[i].name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode))
            continue;
        uint64_t fmns = hslice_stat_mtime_ns(&st);
        uint32_t fsz = (uint32_t)st.st_size;
        uint8_t lang = detect_code_lang(codefiles[i].name, codefiles[i].nlen);
        uint8_t ftier = compute_recency_tier(fmns, sb->now_ns);
        if (sb->dirs[dir_idx].tier > ftier) ftier = sb->dirs[dir_idx].tier;

        if (old_did >= 0) {
            const SymFileRec *of = find_old_file_in_dir(old, (uint32_t)old_did, codefiles[i].name, codefiles[i].nlen);
            if (of && of->mtime_ns == fmns && of->size_lo == fsz) {
                uint32_t fid = sb_add_file(sb, dir_idx, codefiles[i].name, codefiles[i].nlen,
                                           fmns, fsz, of->file_hash, ftier, lang);
                for (uint32_t k = 0; k < of->sym_count; k++) {
                    const SymRec *os = &old->syms[of->first_sym + k];
                    (void)sb_add_sym(sb, fid, old->pool + os->name_off, os->name_len,
                                     old->pool + os->sig_off, os->sig_len,
                                     os->start_line, os->end_line, os->kind, os->flags);
                }
                sb->reused_files++;
                continue;
            }
        }

        uint32_t fid = sb_add_file(sb, dir_idx, codefiles[i].name, codefiles[i].nlen, fmns, fsz, 0, ftier, lang);
        parse_file_into_sb(sb, dfd, codefiles[i].name, lang, fid, (size_t)st.st_size);
        sb->parsed_files++;
    }
    free(codefiles);

    ChildDirEnt *sub_nodes = NULL;
    uint32_t *sub_ids = NULL;
    uint64_t *sub_mns = NULL;
    size_t n_valid_sub = 0;
    if (n_sub > 0) {
        sub_nodes = (ChildDirEnt *)malloc(n_sub * sizeof(ChildDirEnt));
        sub_ids = (uint32_t *)malloc(n_sub * sizeof(uint32_t));
        sub_mns = (uint64_t *)malloc(n_sub * sizeof(uint64_t));
        for (size_t i = 0; i < n_sub; i++) {
            struct stat st;
            if (fstatat(dfd, subdirs[i].name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(st.st_mode))
                continue;
            uint64_t cmns = hslice_stat_mtime_ns(&st);
            uint8_t dtier = compute_recency_tier(cmns, sb->now_ns);
            if (sb->dirs[dir_idx].tier > dtier) dtier = sb->dirs[dir_idx].tier;
            uint32_t cid = sb_add_dir(sb, (int32_t)dir_idx, subdirs[i].name, subdirs[i].nlen,
                                      cmns, dtier, (uint8_t)(depth + 1), depth + 1 <= 6);
            sub_nodes[n_valid_sub] = subdirs[i];
            sub_ids[n_valid_sub] = cid;
            sub_mns[n_valid_sub] = cmns;
            n_valid_sub++;
        }
    }
    free(subdirs);
    closedir(d);

    char cpath[PATH_MAX];
    memcpy(cpath, full_path, plen);
    for (size_t i = 0; i < n_valid_sub; i++) {
        size_t pos = plen;
        if (pos > 0 && cpath[pos - 1] != '/') cpath[pos++] = '/';
        memcpy(cpath + pos, sub_nodes[i].name, sub_nodes[i].nlen);
        pos += sub_nodes[i].nlen;
        cpath[pos] = '\0';
        walk_sym_dir(sb, old, old_pairs, n_old_pairs, cpath, pos, sub_ids[i], sub_mns[i], (uint8_t)(depth + 1));
    }
    free(sub_nodes);
    free(sub_ids);
    free(sub_mns);
}

static int build_sym_index(const char *idx_path, char **roots, int n_roots, bool incremental, bool verbose) {
    uint64_t t0 = hslice_mono_ns();

    char lock_path[PATH_MAX + 16];
    snprintf(lock_path, sizeof(lock_path), "%s.lock", idx_path);
    int lfd = open(lock_path, O_CREAT | O_RDWR, 0600);
    if (lfd >= 0) {
        if (flock(lfd, LOCK_EX | LOCK_NB) != 0) {
            struct stat ist;
            if (stat(idx_path, &ist) == 0 && ist.st_size > (off_t)sizeof(HSymHeader)) {
                close(lfd);
                return 0;
            }
            (void)flock(lfd, LOCK_EX);
        }
    }

    OldSymIdx old;
    DirPathPair *old_pairs = NULL;
    size_t n_old_pairs = 0;
    if (incremental) {
        (void)open_old_sym_idx(idx_path, &old, &old_pairs, &n_old_pairs);
    } else {
        memset(&old, 0, sizeof(old));
    }

    SymBuilder sb;
    memset(&sb, 0, sizeof(sb));
    bb_init(&sb.pool, 1 << 19);
    sb.now_ns = hslice_now_ns();

    for (int i = 0; i < n_roots; i++) {
        struct stat st;
        if (stat(roots[i], &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        size_t rlen = strlen(roots[i]);
        while (rlen > 1 && roots[i][rlen - 1] == '/') rlen--;
        char clean_root[PATH_MAX];
        if (rlen >= sizeof(clean_root)) continue;
        memcpy(clean_root, roots[i], rlen);
        clean_root[rlen] = '\0';

        uint64_t mns = hslice_stat_mtime_ns(&st);
        uint32_t rid = sb_add_dir(&sb, -1, clean_root, rlen, mns, 3, 0, true);
        walk_sym_dir(&sb, &old, old_pairs, n_old_pairs, clean_root, rlen, rid, mns, 0);
    }

    close_old_sym_idx(&old, old_pairs);

    TriBucket *tri_tab = (TriBucket *)calloc(TRIGRAM_SLOTS, sizeof(TriBucket));
    if (!tri_tab) { perror("calloc"); exit(1); }
    uint32_t post_cnt = 0;
    for (uint32_t s = 0; s < TRIGRAM_SLOTS; s++) {
        tri_tab[s].offset = post_cnt;
        tri_tab[s].count = (uint32_t)sb.tri[s].len;
        post_cnt += (uint32_t)sb.tri[s].len;
    }

    HSymHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = HSYM_MAGIC;
    hdr.version = IDX_VERSION;
    hdr.built_ns = sb.now_ns;
    hdr.n_dirs = (uint32_t)sb.n_dirs;
    hdr.n_files = (uint32_t)sb.n_files;
    hdr.n_syms = (uint32_t)sb.n_syms;
    hdr.pool_size = (uint32_t)sb.pool.len;

    uint32_t off = (uint32_t)sizeof(HSymHeader);
    hdr.dirs_off = off;
    off += (uint32_t)(sb.n_dirs * sizeof(SymDirRec));
    hdr.files_off = off;
    off += (uint32_t)(sb.n_files * sizeof(SymFileRec));
    hdr.syms_off = off;
    off += (uint32_t)(sb.n_syms * sizeof(SymRec));
    hdr.pool_off = off;
    off += (uint32_t)sb.pool.len;
    off = (off + 7U) & ~7U;
    hdr.trigrams_off = off;
    off += (uint32_t)(TRIGRAM_SLOTS * sizeof(TriBucket));
    hdr.postings_off = off;
    uint32_t total_bytes = off + (uint32_t)(post_cnt * sizeof(uint32_t));

    char tmp_path[PATH_MAX + 32];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", idx_path, (int)getpid());
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    bool ok = (fd >= 0);
    if (ok) ok = write_all_fd(fd, &hdr, sizeof(hdr));
    if (ok && sb.n_dirs) ok = write_all_fd(fd, sb.dirs, sb.n_dirs * sizeof(SymDirRec));
    if (ok && sb.n_files) ok = write_all_fd(fd, sb.files, sb.n_files * sizeof(SymFileRec));
    if (ok && sb.n_syms) ok = write_all_fd(fd, sb.syms, sb.n_syms * sizeof(SymRec));
    if (ok && sb.pool.len) ok = write_all_fd(fd, sb.pool.data, sb.pool.len);
    size_t pad = (size_t)hdr.trigrams_off -
                 (sizeof(HSymHeader) + sb.n_dirs * sizeof(SymDirRec) +
                  sb.n_files * sizeof(SymFileRec) + sb.n_syms * sizeof(SymRec) + sb.pool.len);
    if (ok && pad) ok = write_zeros_fd(fd, pad);
    if (ok) ok = write_all_fd(fd, tri_tab, TRIGRAM_SLOTS * sizeof(TriBucket));
    for (uint32_t s = 0; ok && s < TRIGRAM_SLOTS; s++) {
        if (sb.tri[s].len)
            ok = write_all_fd(fd, sb.tri[s].data, sb.tri[s].len * sizeof(uint32_t));
        free(sb.tri[s].data);
    }

    if (fd >= 0) close(fd);
    if (ok && rename(tmp_path, idx_path) != 0) ok = false;
    if (!ok) unlink(tmp_path);

    if (lfd >= 0) {
        (void)flock(lfd, LOCK_UN);
        close(lfd);
    }

    free(tri_tab);
    free(sb.dirs);
    free(sb.files);
    free(sb.syms);
    bb_free(&sb.pool);

    if (ok && verbose) {
        double ms = (double)(hslice_mono_ns() - t0) / 1e6;
        fprintf(stderr,
                "[hsearch] indexed %u symbols across %u files (reused=%u, parsed=%u, %.2f MiB mmap) in %.1f ms\n",
                hdr.n_syms, hdr.n_files, sb.reused_files, sb.parsed_files,
                (double)total_bytes / (1024.0 * 1024.0), ms);
    }
    return ok ? 0 : -1;
}

/* =========================================================================
 * PART 3: Zero-Staleness Watch Radar & Async Background Compactor
 * ========================================================================= */
static void spawn_async_compactor(const char *argv0, bool sym_mode, char *const *roots, int n_roots) {
    char self_exe[PATH_MAX];
    hslice_resolve_self_exe(argv0, self_exe, sizeof(self_exe));
    const char *bin = self_exe[0] ? self_exe : argv0;

    pid_t pid = fork();
    if (pid != 0) {
        if (pid > 0) (void)waitpid(pid, NULL, WNOHANG);
        return;
    }
    if (setsid() < 0) _exit(0);
    pid_t p2 = fork();
    if (p2 != 0) _exit(0);

    int dn = open("/dev/null", O_RDWR);
    if (dn >= 0) {
        dup2(dn, STDIN_FILENO);
        dup2(dn, STDOUT_FILENO);
        dup2(dn, STDERR_FILENO);
        if (dn > 2) close(dn);
    }

    char *cargv[MAX_ROOTS * 2 + 8];
    int k = 0;
    cargv[k++] = (char *)bin;
    cargv[k++] = sym_mode ? "--sym" : "--path";
    cargv[k++] = "--rebuild";
    for (int i = 0; i < n_roots && k + 2 < (int)(sizeof(cargv) / sizeof(cargv[0])); i++) {
        cargv[k++] = "--root";
        cargv[k++] = roots[i];
    }
    cargv[k] = NULL;
    execvp(cargv[0], cargv);
    _exit(0);
}

static size_t collect_dirty_dirs(
    const PathDirRec *dirs, uint32_t n_dirs, const char *pool,
    uint32_t *dirty_ids, char dirty_paths[][PATH_MAX], size_t max_dirty
) {
    size_t n_dirty = 0;
    for (uint32_t i = 0; i < n_dirs && n_dirty < max_dirty; i++) {
        if (dirs[i].watch_id == 0xFFFFU) continue;
        char dpath[PATH_MAX];
        materialize_path_dir(dirs, n_dirs, pool, i, dpath, sizeof(dpath));
        struct stat st;
        if (stat(dpath, &st) != 0) {
            dirty_ids[n_dirty] = i;
            snprintf(dirty_paths[n_dirty], PATH_MAX, "%s", dpath);
            n_dirty++;
            continue;
        }
        if (hslice_stat_mtime_ns(&st) != dirs[i].mtime_ns) {
            dirty_ids[n_dirty] = i;
            snprintf(dirty_paths[n_dirty], PATH_MAX, "%s", dpath);
            n_dirty++;
        }
    }
    return n_dirty;
}

static size_t collect_dirty_sym_dirs(
    const SymDirRec *dirs, uint32_t n_dirs,
    const SymFileRec *files, uint32_t n_files, const char *pool,
    uint32_t *dirty_ids, char dirty_paths[][PATH_MAX], size_t max_dirty
) {
    size_t n_dirty = 0;
    for (uint32_t i = 0; i < n_dirs && n_dirty < max_dirty; i++) {
        if (dirs[i].watch_id == 0xFFFFU) continue;
        char dpath[PATH_MAX];
        materialize_sym_dir(dirs, n_dirs, pool, i, dpath, sizeof(dpath));
        struct stat st;
        if (stat(dpath, &st) != 0 || hslice_stat_mtime_ns(&st) != dirs[i].mtime_ns) {
            dirty_ids[n_dirty] = i;
            hslice_copy_str(dirty_paths[n_dirty], PATH_MAX, dpath);
            n_dirty++;
        }
    }
    if (n_files <= 2048) {
        uint32_t cached_did = UINT32_MAX;
        char dpath[PATH_MAX];
        size_t dlen = 0;
        for (uint32_t fi = 0; fi < n_files && n_dirty < max_dirty; fi++) {
            const SymFileRec *f = &files[fi];
            bool already = false;
            for (size_t k = 0; k < n_dirty; k++) {
                if (dirty_ids[k] == f->dir_idx) { already = true; break; }
            }
            if (already) continue;
            if (f->dir_idx != cached_did) {
                cached_did = f->dir_idx;
                dlen = materialize_sym_dir(dirs, n_dirs, pool, cached_did, dpath, sizeof(dpath));
            }
            if (dlen + 1 + f->name_len >= PATH_MAX) continue;
            char fpath[PATH_MAX];
            memcpy(fpath, dpath, dlen);
            size_t pos = dlen;
            if (pos > 0 && fpath[pos - 1] != '/') fpath[pos++] = '/';
            memcpy(fpath + pos, pool + f->name_off, f->name_len);
            fpath[pos + f->name_len] = '\0';
            struct stat st;
            if (stat(fpath, &st) != 0 ||
                hslice_stat_mtime_ns(&st) != f->mtime_ns ||
                (uint32_t)st.st_size != f->size_lo) {
                dirty_ids[n_dirty] = f->dir_idx;
                hslice_copy_str(dirty_paths[n_dirty], PATH_MAX, dpath);
                n_dirty++;
            }
        }
    }
    return n_dirty;
}

/* =========================================================================
 * PART 4: Query Engine (`hfind` & `hsearch`)
 * ========================================================================= */
typedef struct {
    int32_t score;
    char    path[PATH_MAX];
    char    name[160];
    char    sig[220];
    uint32_t start_line;
    uint32_t end_line;
    uint8_t  kind;
    uint8_t  is_dir;
} ScoredHit;

typedef struct {
    ScoredHit *hits;
    size_t     count;
    size_t     cap;
} HitHeap;

static void heap_push(HitHeap *h, const ScoredHit *cand) {
    for (size_t i = 0; i < h->count; i++) {
        if (h->hits[i].start_line == cand->start_line &&
            strcmp(h->hits[i].path, cand->path) == 0 &&
            strcmp(h->hits[i].name, cand->name) == 0) {
            if (cand->score > h->hits[i].score) h->hits[i] = *cand;
            return;
        }
    }
    if (h->count < h->cap) {
        h->hits[h->count++] = *cand;
        return;
    }
    size_t min_i = 0;
    for (size_t i = 1; i < h->count; i++) {
        if (h->hits[i].score < h->hits[min_i].score) min_i = i;
    }
    if (cand->score > h->hits[min_i].score) {
        h->hits[min_i] = *cand;
    }
}

static int cmp_hits_desc(const void *a, const void *b) {
    const ScoredHit *ha = (const ScoredHit *)a;
    const ScoredHit *hb = (const ScoredHit *)b;
    if (ha->score != hb->score) return (hb->score > ha->score) ? 1 : -1;
    int pc = strcmp(ha->path, hb->path);
    if (pc != 0) return pc;
    return (int)ha->start_line - (int)hb->start_line;
}

static size_t intersect_sorted_u32(
    const uint32_t *a, size_t na, const uint32_t *b, size_t nb, uint32_t *out
) {
    size_t ia = 0, ib = 0, k = 0;
    while (ia < na && ib < nb) {
        uint32_t va = a[ia], vb = b[ib];
        if (va == vb) { out[k++] = va; ia++; ib++; }
        else if (va < vb) ia++;
        else ib++;
    }
    return k;
}

static uint32_t *trigram_candidates_for_token(
    const TriBucket *tab, const uint32_t *postings, const char *tok, size_t tlen,
    size_t *out_n, bool *used_index
) {
    *used_index = false;
    *out_n = 0;
    if (tlen < 3) return NULL;

    uint32_t slots[64];
    size_t ns = 0;
    for (size_t i = 0; i + 2 < tlen && ns < 64; i++) {
        if (tok[i] == '/' || tok[i + 1] == '/' || tok[i + 2] == '/') continue;
        uint32_t sl = hslice_pack_tri((unsigned char)tok[i],
                                      (unsigned char)tok[i + 1],
                                      (unsigned char)tok[i + 2]);
        bool dup = false;
        for (size_t j = 0; j < ns; j++) {
            if (slots[j] == sl) { dup = true; break; }
        }
        if (!dup) slots[ns++] = sl;
    }
    if (ns == 0) return NULL;
    *used_index = true;

    for (size_t i = 1; i < ns; i++) {
        uint32_t key = slots[i];
        uint32_t kc = tab[key].count;
        size_t j = i;
        while (j > 0 && tab[slots[j - 1]].count > kc) {
            slots[j] = slots[j - 1];
            j--;
        }
        slots[j] = key;
    }

    uint32_t s0 = slots[0];
    uint32_t c0 = tab[s0].count;
    if (c0 == 0) return NULL;

    uint32_t *cur = (uint32_t *)malloc(c0 * sizeof(uint32_t));
    if (!cur) return NULL;
    memcpy(cur, postings + tab[s0].offset, c0 * sizeof(uint32_t));
    size_t cur_n = c0;

    for (size_t i = 1; i < ns && cur_n > 0; i++) {
        uint32_t si = slots[i];
        cur_n = intersect_sorted_u32(cur, cur_n, postings + tab[si].offset, tab[si].count, cur);
    }
    *out_n = cur_n;
    return cur;
}

static int32_t score_path_candidate(
    const char *full_path, size_t full_len, const char *base, size_t blen,
    uint8_t tier, bool is_dir, char **tokens, size_t *tlens, int n_toks
) {
    int32_t score = (int32_t)tier * 90;
    if (!is_dir) score += 15;
    for (int t = 0; t < n_toks; t++) {
        const char *m_base = hslice_ci_strstr(base, blen, tokens[t], tlens[t]);
        if (m_base) {
            if (blen == tlens[t]) score += 450;
            else if (m_base == base) score += 260;
            else score += 150;
            if (memmem(base, blen, tokens[t], tlens[t]) != NULL) score += 30;
        } else {
            const char *m_full = hslice_ci_strstr(full_path, full_len, tokens[t], tlens[t]);
            if (!m_full) return -1;
            score += 65;
        }
    }
    score -= (int32_t)(full_len / 5);
    return score;
}

static int32_t score_sym_candidate(
    const char *sym_name, size_t nlen, const char *fpath, size_t flen,
    uint8_t kind, uint8_t tier, char **tokens, size_t *tlens, int n_toks,
    const char *file_filter
) {
    if (file_filter && file_filter[0]) {
        if (!hslice_ci_strstr(fpath, flen, file_filter, strlen(file_filter))) return -1;
    }

    const char *short_sym = strrchr(sym_name, '.');
    const char *c_sep = strrchr(sym_name, ':');
    if (c_sep && (!short_sym || c_sep > short_sym)) short_sym = c_sep;
    short_sym = short_sym ? (short_sym + 1) : sym_name;
    size_t short_len = nlen - (size_t)(short_sym - sym_name);

    int32_t score = (int32_t)tier * 70;
    if (kind == SK_CLASS || kind == SK_STRUCT) score += 25;
    else if (kind == SK_FN || kind == SK_METHOD) score += 20;

    bool any_sym_hit = false;
    for (int t = 0; t < n_toks; t++) {
        const char *ms = hslice_ci_strstr(short_sym, short_len, tokens[t], tlens[t]);
        const char *mf = ms ? ms : hslice_ci_strstr(sym_name, nlen, tokens[t], tlens[t]);
        if (mf) {
            any_sym_hit = true;
            if (short_len == tlens[t] && ms) {
                score += 600;
                if (memcmp(short_sym, tokens[t], tlens[t]) == 0) score += 120;
            } else if (nlen == tlens[t]) {
                score += 550;
            } else if (ms == short_sym) {
                score += 310;
            } else if (mf == sym_name) {
                score += 250;
            } else {
                score += 140;
            }
        } else {
            if (!hslice_ci_strstr(fpath, flen, tokens[t], tlens[t])) return -1;
            score += 45;
        }
    }
    if (!any_sym_hit) return -1;

    const char *fbase = strrchr(fpath, '/');
    fbase = fbase ? (fbase + 1) : fpath;
    if (strncmp(fbase, "test_", 5) == 0 || strstr(fpath, "/tests/") != NULL) {
        score -= 40;
    }
    score -= (int32_t)(nlen / 3);
    return score;
}

static void scan_live_overlay_paths(
    const char *dir_path, int depth,
    char **tokens, size_t *tlens, int n_toks, HitHeap *heap
) {
    if (depth > 3) return;
    DIR *d = opendir(dir_path);
    if (!d) return;
    int dfd = dirfd(d);
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *nm = de->d_name;
        if (nm[0] == '.' && (nm[1] == '\0' || (nm[1] == '.' && nm[2] == '\0'))) continue;
        size_t nl = strlen(nm);
        char full[PATH_MAX];
        int fn = snprintf(full, sizeof(full), "%s/%s", dir_path, nm);
        if (fn <= 0 || (size_t)fn >= sizeof(full)) continue;

        struct stat st;
        if (fstatat(dfd, nm, &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;

        if (S_ISDIR(st.st_mode)) {
            if (is_ignored_dir(nm)) continue;
            int32_t sc = score_path_candidate(full, (size_t)fn, nm, nl, 3, true, tokens, tlens, n_toks);
            if (sc >= 0) {
                ScoredHit hit;
                memset(&hit, 0, sizeof(hit));
                hit.score = sc + 15;
                hit.is_dir = 1;
                memcpy(hit.path, full, (size_t)fn + 1);
                heap_push(heap, &hit);
            }
            if (depth == 0) {
                scan_live_overlay_paths(full, depth + 1, tokens, tlens, n_toks, heap);
            }
        } else if (S_ISREG(st.st_mode)) {
            if (is_ignored_file(nm, nl)) continue;
            int32_t sc = score_path_candidate(full, (size_t)fn, nm, nl, 3, false, tokens, tlens, n_toks);
            if (sc >= 0) {
                ScoredHit hit;
                memset(&hit, 0, sizeof(hit));
                hit.score = sc + 15;
                memcpy(hit.path, full, (size_t)fn + 1);
                heap_push(heap, &hit);
            }
        }
    }
    closedir(d);
}

typedef struct {
    const char *fpath;
    size_t      flen;
    char      **tokens;
    size_t     *tlens;
    int         n_toks;
    const char *file_filter;
    HitHeap    *heap;
} LiveSymCtx;

static void live_sym_emit_cb(
    void *ctx, const char *name, size_t nlen, const char *sig, size_t slen,
    uint32_t start_line, uint32_t end_line, uint8_t kind, uint8_t flags
) {
    (void)flags;
    LiveSymCtx *lc = (LiveSymCtx *)ctx;
    int32_t sc = score_sym_candidate(name, nlen, lc->fpath, lc->flen, kind, 3,
                                     lc->tokens, lc->tlens, lc->n_toks, lc->file_filter);
    if (sc >= 0) {
        ScoredHit hit;
        memset(&hit, 0, sizeof(hit));
        hit.score = sc + 20;
        snprintf(hit.path, sizeof(hit.path), "%s", lc->fpath);
        snprintf(hit.name, sizeof(hit.name), "%.*s", (int)(nlen > 159 ? 159 : nlen), name);
        snprintf(hit.sig, sizeof(hit.sig), "%.*s", (int)(slen > 219 ? 219 : slen), sig);
        hit.start_line = start_line;
        hit.end_line = end_line;
        hit.kind = kind;
        heap_push(lc->heap, &hit);
    }
}

static void scan_live_overlay_syms(
    const char *dir_path, int depth, char **tokens, size_t *tlens, int n_toks,
    const char *file_filter, HitHeap *heap
) {
    if (depth > 3) return;
    DIR *d = opendir(dir_path);
    if (!d) return;
    int dfd = dirfd(d);
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *nm = de->d_name;
        if (nm[0] == '.' && (nm[1] == '\0' || (nm[1] == '.' && nm[2] == '\0'))) continue;
        size_t nl = strlen(nm);
        char full[PATH_MAX];
        int fn = snprintf(full, sizeof(full), "%s/%s", dir_path, nm);
        if (fn <= 0 || (size_t)fn >= sizeof(full)) continue;

        struct stat st;
        if (fstatat(dfd, nm, &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;

        if (S_ISDIR(st.st_mode)) {
            if (!is_ignored_dir(nm) && depth == 0) {
                scan_live_overlay_syms(full, depth + 1, tokens, tlens, n_toks, file_filter, heap);
            }
        } else if (S_ISREG(st.st_mode) && st.st_size > 0 && st.st_size <= 2 * 1024 * 1024) {
            uint8_t lang = detect_code_lang(nm, nl);
            if (lang == LANG_NONE || is_ignored_file(nm, nl)) continue;
            int fd = openat(dfd, nm, O_RDONLY);
            if (fd < 0) continue;
            void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            close(fd);
            if (map == MAP_FAILED) continue;
            LiveSymCtx lc = {full, (size_t)fn, tokens, tlens, n_toks, file_filter, heap};
            scan_source_buffer((const char *)map, (size_t)st.st_size, lang, NULL, 0, live_sym_emit_cb, &lc);
            munmap(map, (size_t)st.st_size);
        }
    }
    closedir(d);
}

static bool is_dir_in_list(uint32_t did, const uint32_t *list, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (list[i] == did) return true;
    }
    return false;
}

static int execute_hfind_query(
    const char *argv0, const char *idx_path, char **roots, int n_roots,
    char **tokens, size_t *tlens, int n_toks, int limit, bool active_only,
    bool show_stats, bool json_out
) {
    int fd = open(idx_path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || (size_t)st.st_size < sizeof(HFindHeader)) {
        close(fd);
        return -1;
    }
    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return -1;

    const HFindHeader *h = (const HFindHeader *)map;
    if (h->magic != HFIND_MAGIC || h->version != IDX_VERSION ||
        h->pool_off + h->pool_size > (size_t)st.st_size) {
        munmap(map, (size_t)st.st_size);
        return -1;
    }

    const PathDirRec  *dirs = (const PathDirRec *)((const char *)map + h->dirs_off);
    const PathFileRec *files = (const PathFileRec *)((const char *)map + h->files_off);
    const char        *pool = (const char *)map + h->pool_off;
    const TriBucket   *dir_tri = (const TriBucket *)((const char *)map + h->dir_tri_off);
    const uint32_t    *dir_post = (const uint32_t *)((const char *)map + h->dir_post_off);
    const TriBucket   *base_tri = (const TriBucket *)((const char *)map + h->base_tri_off);
    const uint32_t    *base_post = (const uint32_t *)((const char *)map + h->base_post_off);

    uint32_t dirty_ids[MAX_DIRTY_DIRS];
    char dirty_paths[MAX_DIRTY_DIRS][PATH_MAX];
    size_t n_dirty = collect_dirty_dirs(dirs, h->n_dirs, pool, dirty_ids, dirty_paths, MAX_DIRTY_DIRS);
    if (n_dirty > 0) {
        spawn_async_compactor(argv0, false, roots, n_roots);
    }

    if (show_stats) {
        if (json_out) {
            printf("{\"ok\":true,\"kind\":\"path\",\"files\":%u,\"dirs\":%u,\"size_mib\":%.2f,\"dirty_dirs\":%zu}\n",
                   h->n_files, h->n_dirs, (double)st.st_size / (1024.0 * 1024.0), n_dirty);
        } else {
            printf("hfind index: %u files | %u dirs | %.2f MiB mmap | dirty_watched_dirs=%zu\n",
                   h->n_files, h->n_dirs, (double)st.st_size / (1024.0 * 1024.0), n_dirty);
        }
        if (n_toks == 0) {
            munmap(map, (size_t)st.st_size);
            return 0;
        }
    }
    if (n_toks == 0) {
        munmap(map, (size_t)st.st_size);
        return 0;
    }

    ScoredHit *hit_buf = (ScoredHit *)calloc((size_t)limit, sizeof(ScoredHit));
    HitHeap heap = {hit_buf, 0, (size_t)limit};

    int best_tok = -1;
    size_t best_cost = SIZE_MAX;
    uint32_t *best_base_cands = NULL;
    size_t best_base_n = 0;
    uint32_t *best_dir_cands = NULL;
    size_t best_dir_n = 0;

    for (int t = 0; t < n_toks; t++) {
        if (tlens[t] < 3 || memchr(tokens[t], '/', tlens[t]) != NULL) continue;
        size_t bn = 0, dn = 0;
        bool bu = false, du = false;
        uint32_t *bc = trigram_candidates_for_token(base_tri, base_post, tokens[t], tlens[t], &bn, &bu);
        uint32_t *dc = trigram_candidates_for_token(dir_tri, dir_post, tokens[t], tlens[t], &dn, &du);
        if (!bu && !du) { free(bc); free(dc); continue; }
        size_t cost = bn + dn * 24;
        if (cost < best_cost) {
            free(best_base_cands);
            free(best_dir_cands);
            best_cost = cost;
            best_tok = t;
            best_base_cands = bc;
            best_base_n = bn;
            best_dir_cands = dc;
            best_dir_n = dn;
        } else {
            free(bc);
            free(dc);
        }
    }

    uint32_t cached_did = UINT32_MAX;
    char cached_dpath[PATH_MAX];
    size_t cached_dlen = 0;

    if (best_tok >= 0) {
        for (size_t i = 0; i < best_base_n; i++) {
            uint32_t fid = best_base_cands[i];
            if (fid >= h->n_files) continue;
            const PathFileRec *f = &files[fid];
            if (active_only && f->tier < 2) continue;
            bool dirty_parent = (n_dirty > 0 && is_dir_in_list(f->dir_idx, dirty_ids, n_dirty));

            if (f->dir_idx != cached_did) {
                cached_did = f->dir_idx;
                cached_dlen = materialize_path_dir(dirs, h->n_dirs, pool, cached_did, cached_dpath, sizeof(cached_dpath));
            }
            const char *fn = pool + f->name_off;
            char full[PATH_MAX];
            size_t pos = (cached_dlen < sizeof(full) - 1) ? cached_dlen : (sizeof(full) - 1);
            if (pos > 0) memcpy(full, cached_dpath, pos);
            if (pos + 1 < sizeof(full) && (pos == 0 || full[pos - 1] != '/')) full[pos++] = '/';
            size_t cl = f->name_len;
            size_t avail = (pos < sizeof(full) - 1) ? (sizeof(full) - 1 - pos) : 0;
            if (cl > avail) cl = avail;
            if (cl > 0) memcpy(full + pos, fn, cl);
            pos += cl;
            full[pos] = '\0';

            int32_t sc = score_path_candidate(full, pos, fn, f->name_len, f->tier, f->flags & 1,
                                              tokens, tlens, n_toks);
            if (sc >= 0) {
                if (dirty_parent && access(full, F_OK) != 0) continue;
                ScoredHit hit;
                memset(&hit, 0, sizeof(hit));
                hit.score = sc;
                hit.is_dir = f->flags & 1;
                memcpy(hit.path, full, pos + 1);
                heap_push(&heap, &hit);
            }
        }

        if (best_dir_n > 0) {
            bool *desc_dir = (bool *)calloc(h->n_dirs, sizeof(bool));
            for (size_t i = 0; i < best_dir_n; i++) {
                if (best_dir_cands[i] < h->n_dirs) desc_dir[best_dir_cands[i]] = true;
            }
            for (uint32_t d = 0; d < h->n_dirs; d++) {
                if (!desc_dir[d] && dirs[d].parent_idx >= 0 && desc_dir[dirs[d].parent_idx]) {
                    desc_dir[d] = true;
                }
            }
            for (uint32_t d = 0; d < h->n_dirs; d++) {
                if (!desc_dir[d]) continue;
                if (active_only && dirs[d].tier < 2) continue;
                bool dirty_d = (n_dirty > 0 && is_dir_in_list(d, dirty_ids, n_dirty));
                size_t dlen = materialize_path_dir(dirs, h->n_dirs, pool, d, cached_dpath, sizeof(cached_dpath));

                uint32_t lo = 0, hi = h->n_files;
                while (lo < hi) {
                    uint32_t mid = lo + (hi - lo) / 2;
                    if (files[mid].dir_idx < d) lo = mid + 1;
                    else hi = mid;
                }
                for (uint32_t fi = lo; fi < h->n_files && files[fi].dir_idx == d; fi++) {
                    const PathFileRec *f = &files[fi];
                    const char *fn = pool + f->name_off;
                    char full[PATH_MAX];
                    size_t pos = (dlen < sizeof(full) - 1) ? dlen : (sizeof(full) - 1);
                    if (pos > 0) memcpy(full, cached_dpath, pos);
                    if (pos + 1 < sizeof(full) && (pos == 0 || full[pos - 1] != '/')) full[pos++] = '/';
                    size_t cl = f->name_len;
                    size_t avail = (pos < sizeof(full) - 1) ? (sizeof(full) - 1 - pos) : 0;
                    if (cl > avail) cl = avail;
                    if (cl > 0) memcpy(full + pos, fn, cl);
                    pos += cl;
                    full[pos] = '\0';

                    int32_t sc = score_path_candidate(full, pos, fn, f->name_len, f->tier, f->flags & 1,
                                                      tokens, tlens, n_toks);
                    if (sc >= 0) {
                        if (dirty_d && access(full, F_OK) != 0) continue;
                        ScoredHit hit;
                        memset(&hit, 0, sizeof(hit));
                        hit.score = sc;
                        hit.is_dir = f->flags & 1;
                        memcpy(hit.path, full, pos + 1);
                        heap_push(&heap, &hit);
                    }
                }
            }
            free(desc_dir);
        }
    } else {
        for (uint32_t fi = 0; fi < h->n_files; fi++) {
            const PathFileRec *f = &files[fi];
            if (active_only && f->tier < 2) continue;
            if (f->dir_idx != cached_did) {
                cached_did = f->dir_idx;
                cached_dlen = materialize_path_dir(dirs, h->n_dirs, pool, cached_did, cached_dpath, sizeof(cached_dpath));
            }
            const char *fn = pool + f->name_off;
            char full[PATH_MAX];
            size_t pos = (cached_dlen < sizeof(full) - 1) ? cached_dlen : (sizeof(full) - 1);
            if (pos > 0) memcpy(full, cached_dpath, pos);
            if (pos + 1 < sizeof(full) && (pos == 0 || full[pos - 1] != '/')) full[pos++] = '/';
            size_t cl = f->name_len;
            size_t avail = (pos < sizeof(full) - 1) ? (sizeof(full) - 1 - pos) : 0;
            if (cl > avail) cl = avail;
            if (cl > 0) memcpy(full + pos, fn, cl);
            pos += cl;
            full[pos] = '\0';

            int32_t sc = score_path_candidate(full, pos, fn, f->name_len, f->tier, f->flags & 1,
                                              tokens, tlens, n_toks);
            if (sc >= 0) {
                if (n_dirty > 0 && is_dir_in_list(f->dir_idx, dirty_ids, n_dirty) && access(full, F_OK) != 0)
                    continue;
                ScoredHit hit;
                memset(&hit, 0, sizeof(hit));
                hit.score = sc;
                hit.is_dir = f->flags & 1;
                memcpy(hit.path, full, pos + 1);
                heap_push(&heap, &hit);
            }
        }
    }

    for (size_t i = 0; i < n_dirty; i++) {
        scan_live_overlay_paths(dirty_paths[i], 0, tokens, tlens, n_toks, &heap);
    }

    free(best_base_cands);
    free(best_dir_cands);
    munmap(map, (size_t)st.st_size);

    qsort(heap.hits, heap.count, sizeof(ScoredHit), cmp_hits_desc);
    if (json_out) {
        printf("{\"ok\":true,\"count\":%zu,\"hits\":[", heap.count);
        for (size_t i = 0; i < heap.count; i++) {
            char pe[PATH_MAX * 2];
            hslice_json_escape(heap.hits[i].path, pe, sizeof(pe));
            printf("%s{\"path\":\"%s\",\"is_dir\":%s,\"score\":%d}",
                   i > 0 ? "," : "", pe, heap.hits[i].is_dir ? "true" : "false",
                   (int)heap.hits[i].score);
        }
        printf("]}\n");
    } else {
        for (size_t i = 0; i < heap.count; i++) {
            puts(heap.hits[i].path);
        }
    }
    bool any = (heap.count > 0);
    free(hit_buf);
    return any ? 0 : 2;
}

static int execute_hsearch_query(
    const char *argv0, const char *idx_path, char **roots, int n_roots,
    char **tokens, size_t *tlens, int n_toks, const char *file_filter,
    int limit, bool active_only, bool show_stats, bool json_out
) {
    int fd = open(idx_path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || (size_t)st.st_size < sizeof(HSymHeader)) {
        close(fd);
        return -1;
    }
    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return -1;

    const HSymHeader *h = (const HSymHeader *)map;
    if (h->magic != HSYM_MAGIC || h->version != IDX_VERSION ||
        h->pool_off + h->pool_size > (size_t)st.st_size) {
        munmap(map, (size_t)st.st_size);
        return -1;
    }

    const SymDirRec  *dirs = (const SymDirRec *)((const char *)map + h->dirs_off);
    const SymFileRec *files = (const SymFileRec *)((const char *)map + h->files_off);
    const SymRec     *syms = (const SymRec *)((const char *)map + h->syms_off);
    const char       *pool = (const char *)map + h->pool_off;
    const TriBucket  *tri = (const TriBucket *)((const char *)map + h->trigrams_off);
    const uint32_t   *post = (const uint32_t *)((const char *)map + h->postings_off);

    uint32_t dirty_ids[MAX_DIRTY_DIRS];
    char dirty_paths[MAX_DIRTY_DIRS][PATH_MAX];
    size_t n_dirty = collect_dirty_sym_dirs(dirs, h->n_dirs, files, h->n_files, pool, dirty_ids, dirty_paths, MAX_DIRTY_DIRS);
    if (n_dirty > 0) {
        spawn_async_compactor(argv0, true, roots, n_roots);
    }

    if (show_stats) {
        if (json_out) {
            printf("{\"ok\":true,\"kind\":\"symbol\",\"symbols\":%u,\"files\":%u,\"dirs\":%u,\"size_mib\":%.2f,\"dirty_dirs\":%zu}\n",
                   h->n_syms, h->n_files, h->n_dirs, (double)st.st_size / (1024.0 * 1024.0), n_dirty);
        } else {
            printf("hsearch index: %u symbols | %u files | %u dirs | %.2f MiB mmap | dirty_watched_dirs=%zu\n",
                   h->n_syms, h->n_files, h->n_dirs, (double)st.st_size / (1024.0 * 1024.0), n_dirty);
        }
        if (n_toks == 0) {
            munmap(map, (size_t)st.st_size);
            return 0;
        }
    }
    if (n_toks == 0) {
        munmap(map, (size_t)st.st_size);
        return 0;
    }

    ScoredHit *hit_buf = (ScoredHit *)calloc((size_t)limit, sizeof(ScoredHit));
    HitHeap heap = {hit_buf, 0, (size_t)limit};

    int best_tok = -1;
    uint32_t *best_cands = NULL;
    size_t best_n = SIZE_MAX;

    for (int t = 0; t < n_toks; t++) {
        if (tlens[t] < 3 || memchr(tokens[t], '/', tlens[t]) != NULL) continue;
        size_t cn = 0;
        bool used = false;
        uint32_t *cc = trigram_candidates_for_token(tri, post, tokens[t], tlens[t], &cn, &used);
        if (!used) { free(cc); continue; }
        if (cn < best_n) {
            free(best_cands);
            best_cands = cc;
            best_n = cn;
            best_tok = t;
        } else {
            free(cc);
        }
    }

    uint32_t cached_fid = UINT32_MAX;
    char cached_fpath[PATH_MAX];
    size_t cached_flen = 0;

    size_t iter_n = (best_tok >= 0) ? best_n : h->n_syms;
    for (size_t i = 0; i < iter_n; i++) {
        uint32_t sid = (best_tok >= 0) ? best_cands[i] : (uint32_t)i;
        if (sid >= h->n_syms) continue;
        const SymRec *s = &syms[sid];
        const SymFileRec *f = &files[s->file_id];
        if (active_only && f->tier < 2) continue;
        if (n_dirty > 0 && is_dir_in_list(f->dir_idx, dirty_ids, n_dirty)) {
            continue;
        }
        if (s->file_id != cached_fid) {
            cached_fid = s->file_id;
            cached_flen = materialize_sym_file(dirs, h->n_dirs, f, pool, cached_fpath, sizeof(cached_fpath));
        }
        const char *sname = pool + s->name_off;
        int32_t sc = score_sym_candidate(sname, s->name_len, cached_fpath, cached_flen,
                                         s->kind, f->tier, tokens, tlens, n_toks, file_filter);
        if (sc >= 0) {
            ScoredHit hit;
            memset(&hit, 0, sizeof(hit));
            hit.score = sc;
            memcpy(hit.path, cached_fpath, cached_flen + 1);
            snprintf(hit.name, sizeof(hit.name), "%s", sname);
            snprintf(hit.sig, sizeof(hit.sig), "%s", pool + s->sig_off);
            hit.start_line = s->start_line;
            hit.end_line = s->end_line;
            hit.kind = s->kind;
            heap_push(&heap, &hit);
        }
    }

    if (best_tok >= 0 && heap.count == 0 && n_toks >= 2) {
        for (uint32_t sid = 0; sid < h->n_syms; sid++) {
            const SymRec *s = &syms[sid];
            const SymFileRec *f = &files[s->file_id];
            if (active_only && f->tier < 2) continue;
            if (n_dirty > 0 && is_dir_in_list(f->dir_idx, dirty_ids, n_dirty)) continue;
            if (s->file_id != cached_fid) {
                cached_fid = s->file_id;
                cached_flen = materialize_sym_file(dirs, h->n_dirs, f, pool, cached_fpath, sizeof(cached_fpath));
            }
            const char *sname = pool + s->name_off;
            int32_t sc = score_sym_candidate(sname, s->name_len, cached_fpath, cached_flen,
                                             s->kind, f->tier, tokens, tlens, n_toks, file_filter);
            if (sc >= 0) {
                ScoredHit hit;
                memset(&hit, 0, sizeof(hit));
                hit.score = sc;
                memcpy(hit.path, cached_fpath, cached_flen + 1);
                snprintf(hit.name, sizeof(hit.name), "%s", sname);
                snprintf(hit.sig, sizeof(hit.sig), "%s", pool + s->sig_off);
                hit.start_line = s->start_line;
                hit.end_line = s->end_line;
                hit.kind = s->kind;
                heap_push(&heap, &hit);
            }
        }
    }

    for (size_t i = 0; i < n_dirty; i++) {
        scan_live_overlay_syms(dirty_paths[i], 0, tokens, tlens, n_toks, file_filter, &heap);
    }

    free(best_cands);
    munmap(map, (size_t)st.st_size);

    qsort(heap.hits, heap.count, sizeof(ScoredHit), cmp_hits_desc);
    if (json_out) {
        printf("{\"ok\":true,\"count\":%zu,\"hits\":[", heap.count);
        for (size_t i = 0; i < heap.count; i++) {
            const ScoredHit *sh = &heap.hits[i];
            char pe[PATH_MAX * 2], ne[384], se[512];
            hslice_json_escape(sh->path, pe, sizeof(pe));
            hslice_json_escape(sh->name, ne, sizeof(ne));
            hslice_json_escape(sh->sig, se, sizeof(se));
            printf("%s{\"path\":\"%s\",\"start_line\":%u,\"end_line\":%u,\"kind\":\"%s\",\"symbol\":\"%s\",\"signature\":\"%s\",\"score\":%d}",
                   i > 0 ? "," : "", pe, sh->start_line, sh->end_line,
                   hslice_kind_label(sh->kind), ne, se, (int)sh->score);
        }
        printf("]}\n");
    } else {
        for (size_t i = 0; i < heap.count; i++) {
            const ScoredHit *sh = &heap.hits[i];
            if (sh->end_line > sh->start_line) {
                printf("%s:%u-%u  [%s] %s  | %s\n",
                       sh->path, sh->start_line, sh->end_line,
                       hslice_kind_label(sh->kind), sh->name, sh->sig);
            } else {
                printf("%s:%u  [%s] %s  | %s\n",
                       sh->path, sh->start_line,
                       hslice_kind_label(sh->kind), sh->name, sh->sig);
            }
        }
    }
    bool any = (heap.count > 0);
    free(hit_buf);
    return any ? 0 : 2;
}

/* =========================================================================
 * PART 5: Global-Limit `hsearch -g` Wrapper (`rg` + Portable `grep` Fallback)
 * ========================================================================= */
static bool is_rg_zero_arg_flag(const char *a, bool *has_ctx) {
    static const char *const zf[] = {
        "-i", "--ignore-case", "-S", "--smart-case", "-s", "--case-sensitive",
        "-w", "--word-regexp", "-F", "--fixed-strings", "-v", "--invert-match",
        "-l", "--files-with-matches", "-c", "--count", "-u", "-uu", "-uuu",
        "--hidden", "--no-ignore", "-P", "--pcre2", "-U", "--multiline", NULL
    };
    for (int i = 0; zf[i]; i++) {
        if (strcmp(a, zf[i]) == 0) return true;
    }
    if (a[0] == '-' && (a[1] == 'C' || a[1] == 'A' || a[1] == 'B') && isdigit((unsigned char)a[2])) {
        *has_ctx = true;
        return true;
    }
    return false;
}

static bool is_rg_one_arg_flag(const char *a, bool *has_ctx) {
    if (strcmp(a, "-C") == 0 || strcmp(a, "-A") == 0 || strcmp(a, "-B") == 0 ||
        strcmp(a, "--context") == 0 || strcmp(a, "--after-context") == 0 || strcmp(a, "--before-context") == 0) {
        *has_ctx = true;
        return true;
    }
    static const char *const of[] = {
        "-t", "--type", "-T", "--type-not", "-g", "--glob", "--iglob",
        "-M", "--max-columns", "-d", "--max-depth", NULL
    };
    for (int i = 0; of[i]; i++) {
        if (strcmp(a, of[i]) == 0) return true;
    }
    return false;
}

static bool has_bin_in_path(const char *bin) {
    const char *path_env = getenv("PATH");
    if (!path_env || !path_env[0]) return false;
    const char *p = path_env;
    while (*p) {
        const char *sep = strchr(p, ':');
        size_t dl = sep ? (size_t)(sep - p) : strlen(p);
        if (dl > 0 && dl + strlen(bin) + 2 < PATH_MAX) {
            char cand[PATH_MAX];
            memcpy(cand, p, dl);
            cand[dl] = '/';
            strcpy(cand + dl + 1, bin);
            if (access(cand, X_OK) == 0) return true;
        }
        if (!sep) break;
        p = sep + 1;
    }
    return false;
}

static int run_ripgrep_bounded(
    char **rg_flags, int n_rg_flags, char **pos_args, int n_pos, int limit, bool has_ctx
) {
    if (n_pos < 1) {
        fprintf(stderr, "Usage: hsearch -g [rg-flags] [-n LIMIT] <pattern> [path...]\n");
        return 2;
    }

    bool use_rg = has_bin_in_path("rg");
    char *argv_exec[128];
    int k = 0;

    if (use_rg) {
        argv_exec[k++] = "rg";
        argv_exec[k++] = "--no-heading";
        argv_exec[k++] = "--with-filename";
        argv_exec[k++] = "--line-number";
        argv_exec[k++] = "--color=never";
        argv_exec[k++] = "--max-columns=240";
        argv_exec[k++] = "--max-columns-preview";
        for (int i = 0; i < n_rg_flags && k < 100; i++) argv_exec[k++] = rg_flags[i];
        argv_exec[k++] = "--";
        argv_exec[k++] = pos_args[0];
        if (n_pos == 1) {
            argv_exec[k++] = ".";
        } else {
            for (int i = 1; i < n_pos && k < 124; i++) argv_exec[k++] = pos_args[i];
        }
    } else {
        argv_exec[k++] = "grep";
        argv_exec[k++] = "-rnI";
        argv_exec[k++] = "-H";
        bool fixed = false;
        for (int i = 0; i < n_rg_flags; i++) {
            if (strcmp(rg_flags[i], "-i") == 0 || strcmp(rg_flags[i], "--ignore-case") == 0) {
                argv_exec[k++] = "-i";
            } else if (strcmp(rg_flags[i], "-w") == 0 || strcmp(rg_flags[i], "--word-regexp") == 0) {
                argv_exec[k++] = "-w";
            } else if (strcmp(rg_flags[i], "-F") == 0 || strcmp(rg_flags[i], "--fixed-strings") == 0) {
                fixed = true;
            }
        }
        argv_exec[k++] = fixed ? "-F" : "-E";
        argv_exec[k++] = "--exclude-dir=.git";
        argv_exec[k++] = "--exclude-dir=node_modules";
        argv_exec[k++] = "--exclude-dir=.venv";
        argv_exec[k++] = "--exclude-dir=target";
        argv_exec[k++] = "--exclude-dir=__pycache__";
        argv_exec[k++] = "--";
        argv_exec[k++] = pos_args[0];
        if (n_pos == 1) {
            argv_exec[k++] = ".";
        } else {
            for (int i = 1; i < n_pos && k < 124; i++) argv_exec[k++] = pos_args[i];
        }
    }
    argv_exec[k] = NULL;

    int pfd[2];
    if (pipe(pfd) != 0) { perror("pipe"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); close(pfd[0]); close(pfd[1]); return 1; }
    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        close(pfd[1]);
        execvp(argv_exec[0], argv_exec);
        _exit(127);
    }
    close(pfd[1]);

    int max_lines = has_ctx ? (limit * 4) : limit;
    int emitted = 0;
    bool truncated = false;
    FILE *fp = fdopen(pfd[0], "r");
    char line[4096];
    if (fp) {
        while (fgets(line, sizeof(line), fp) != NULL) {
            if (emitted < max_lines) {
                fputs(line, stdout);
                emitted++;
            } else {
                truncated = true;
                kill(pid, SIGPIPE);
                break;
            }
        }
        fclose(fp);
    } else {
        close(pfd[0]);
    }

    int status = 0;
    (void)waitpid(pid, &status, 0);
    if (truncated) {
        printf("... [hsearch -g capped at %d lines; pass -n <N> or narrow path]\n", max_lines);
        return 0;
    }
    return (emitted > 0) ? 0 : 1;
}

/* =========================================================================
 * Main Entrypoint (`hfind` & `hsearch` symlink dispatch)
 * ========================================================================= */
static void print_help(const char *prog) {
    printf("%s v%s - Hephaestus Organ 1 Sub-Millisecond Path, Symbol & Grep Engine\n\n"
           "Usage:\n"
           "  hfind   [--root DIR] [--active] [--rebuild] [--stats] [--json] [-n LIMIT] <path tokens...>\n"
           "  hsearch [--root DIR] [--active] [--rebuild] [--stats] [--json] [-f FILE] [-n LIMIT] <symbol tokens...>\n"
           "  hsearch -g [-i] [-w] [-F] [-t TYPE] [-n LIMIT] <pattern> [dir...]\n\n"
           "Environment:\n"
           "  HEPHAESTUS_ROOTS      Colon-separated workspace roots (default: nearest .git root or cwd)\n"
           "  HEPHAESTUS_CACHE_DIR  Index cache dir (/dev/shm/hephaestus-$UID -> ~/.cache/hephaestus -> /tmp)\n",
           prog, HSLICE_VERSION);
}

int main(int argc, char **argv) {
    const char *prog = strrchr(argv[0], '/');
    prog = prog ? (prog + 1) : argv[0];

    bool sym_mode = (strcmp(prog, "hsearch") == 0);
    bool grep_mode = false;
    bool active_only = false;
    bool force_rebuild = false;
    bool full_rebuild = false;
    bool show_stats = false;
    bool json_out = false;
    const char *file_filter = NULL;
    int limit = 25;

    const char *cli_roots[MAX_ROOTS];
    int n_cli_roots = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) break;
        if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--grep") == 0) {
            grep_mode = true;
            break;
        }
    }

    char *tokens[MAX_TOKENS];
    size_t tlens[MAX_TOKENS];
    char clean_bufs[MAX_TOKENS][256];
    int n_toks = 0;

    char *rg_flags[MAX_RG_ARGS];
    int n_rg_flags = 0;
    bool rg_has_ctx = false;
    bool saw_grep_flag = false;
    bool after_ddash = false;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (!after_ddash && strcmp(arg, "--") == 0) {
            after_ddash = true;
            continue;
        }
        if (!after_ddash) {
            if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
                print_help(prog);
                return 0;
            }
            if (strcmp(arg, "--version") == 0 || strcmp(arg, "-V") == 0) {
                printf("%s %s\n", prog, HSLICE_VERSION);
                return 0;
            }
            if ((strcmp(arg, "-n") == 0 || strcmp(arg, "--limit") == 0) && i + 1 < argc) {
                limit = atoi(argv[++i]);
                if (limit < 1) limit = 1;
                if (limit > MAX_RESULTS) limit = MAX_RESULTS;
                continue;
            }
            if (strncmp(arg, "-n", 2) == 0 && isdigit((unsigned char)arg[2])) {
                limit = atoi(arg + 2);
                if (limit < 1) limit = 1;
                if (limit > MAX_RESULTS) limit = MAX_RESULTS;
                continue;
            }
            if (!grep_mode && strcmp(arg, "--root") == 0 && i + 1 < argc) {
                if (n_cli_roots < MAX_ROOTS) cli_roots[n_cli_roots++] = argv[++i];
                else i++;
                continue;
            }
            if (grep_mode) {
                if (!saw_grep_flag && (strcmp(arg, "-g") == 0 || strcmp(arg, "--grep") == 0)) {
                    saw_grep_flag = true;
                    continue;
                }
                if (saw_grep_flag && strcmp(arg, "-g") == 0 && i + 1 < argc) {
                    if (n_rg_flags + 2 <= MAX_RG_ARGS) {
                        rg_flags[n_rg_flags++] = "--glob";
                        rg_flags[n_rg_flags++] = argv[++i];
                    }
                    continue;
                }
                if ((strcmp(arg, "-e") == 0 || strcmp(arg, "--regexp") == 0) && i + 1 < argc) {
                    if (n_toks < MAX_TOKENS) {
                        tokens[n_toks] = argv[++i];
                        tlens[n_toks] = strlen(tokens[n_toks]);
                        n_toks++;
                    }
                    continue;
                }
                if (is_rg_zero_arg_flag(arg, &rg_has_ctx)) {
                    if (n_rg_flags < MAX_RG_ARGS) rg_flags[n_rg_flags++] = (char *)arg;
                    continue;
                }
                if (is_rg_one_arg_flag(arg, &rg_has_ctx) && i + 1 < argc) {
                    if (n_rg_flags + 2 <= MAX_RG_ARGS) {
                        rg_flags[n_rg_flags++] = (char *)arg;
                        rg_flags[n_rg_flags++] = argv[++i];
                    }
                    continue;
                }
                if (strncmp(arg, "--glob=", 7) == 0 || strncmp(arg, "--type=", 7) == 0 ||
                    (arg[0] == '-' && (arg[1] == 't' || arg[1] == 'T') && arg[2] != '\0')) {
                    if (n_rg_flags < MAX_RG_ARGS) rg_flags[n_rg_flags++] = (char *)arg;
                    continue;
                }
            } else {
                if (strcmp(arg, "--sym") == 0 || strcmp(arg, "-s") == 0) { sym_mode = true; continue; }
                if (strcmp(arg, "--path") == 0 || strcmp(arg, "-p") == 0) { sym_mode = false; continue; }
                if ((strcmp(arg, "--file") == 0 || strcmp(arg, "-f") == 0) && i + 1 < argc) { file_filter = argv[++i]; continue; }
                if (strcmp(arg, "--active") == 0 || strcmp(arg, "-a") == 0) { active_only = true; continue; }
                if (strcmp(arg, "--rebuild") == 0 || strcmp(arg, "-r") == 0) { force_rebuild = true; continue; }
                if (strcmp(arg, "--full") == 0) { force_rebuild = true; full_rebuild = true; continue; }
                if (strcmp(arg, "--stats") == 0) { show_stats = true; continue; }
                if (strcmp(arg, "--json") == 0 || strcmp(arg, "-j") == 0) { json_out = true; continue; }
                if (arg[0] == '-') {
                    fprintf(stderr, "%s: unknown option '%s' (try --help)\n", prog, arg);
                    return 2;
                }
            }
        }

        if (n_toks < MAX_TOKENS) {
            if (grep_mode) {
                tokens[n_toks] = (char *)arg;
                tlens[n_toks] = strlen(arg);
                n_toks++;
            } else {
                const char *src = arg;
                if (src[0] == '.' && src[1] == '/') src += 2;
                size_t j = 0;
                for (size_t k = 0; src[k] && j + 1 < sizeof(clean_bufs[0]); k++) {
                    if (src[k] == '*' || src[k] == '?') continue;
                    if (src[k] == ':' && isdigit((unsigned char)src[k + 1])) break;
                    clean_bufs[n_toks][j++] = src[k];
                }
                clean_bufs[n_toks][j] = '\0';
                if (j > 0) {
                    tokens[n_toks] = clean_bufs[n_toks];
                    tlens[n_toks] = j;
                    n_toks++;
                }
            }
        }
    }

    if (grep_mode) {
        return run_ripgrep_bounded(rg_flags, n_rg_flags, tokens, n_toks, limit, rg_has_ctx);
    }

    if (n_toks == 0 && !force_rebuild && !show_stats) {
        print_help(prog);
        return 2;
    }

    char rbufs[MAX_ROOTS][PATH_MAX];
    char *roots[MAX_ROOTS];
    int n_roots = hslice_discover_roots(cli_roots, n_cli_roots, rbufs, roots);

    char idx_path[PATH_MAX];
    hslice_idx_path_for_roots(idx_path, sizeof(idx_path), sym_mode ? "hsym" : "hfind", roots, n_roots);

    struct stat st;
    bool need_build = force_rebuild || (stat(idx_path, &st) != 0);
    if (!need_build) {
        int qrc = sym_mode
            ? execute_hsearch_query(argv[0], idx_path, roots, n_roots, tokens, tlens, n_toks,
                                    file_filter, limit, active_only, show_stats, json_out)
            : execute_hfind_query(argv[0], idx_path, roots, n_roots, tokens, tlens, n_toks,
                                  limit, active_only, show_stats, json_out);
        if (qrc == 0) return 0;
        if (qrc == 2) return 1;
        need_build = true;
    }

    if (need_build) {
        int rc = sym_mode
            ? build_sym_index(idx_path, roots, n_roots, !full_rebuild, force_rebuild || show_stats)
            : build_path_index(idx_path, roots, n_roots, force_rebuild || show_stats);
        if (rc != 0) {
            fprintf(stderr, "%s: failed to build index at %s\n", prog, idx_path);
            return 1;
        }
        if (force_rebuild && n_toks == 0 && !show_stats) return 0;
    }

    int qrc = sym_mode
        ? execute_hsearch_query(argv[0], idx_path, roots, n_roots, tokens, tlens, n_toks,
                                file_filter, limit, active_only, show_stats, json_out)
        : execute_hfind_query(argv[0], idx_path, roots, n_roots, tokens, tlens, n_toks,
                              limit, active_only, show_stats, json_out);
    return (qrc == 0) ? 0 : 1;
}
