#ifndef HMEMORY_CORE_H
#define HMEMORY_CORE_H

#include "hmemory_stem.h"
#include <errno.h>
#include <math.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define HMEMORY_VERSION "0.1.0"

/* Safe dynamic RFC 8259 JSON string builder */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
    bool   oom;
} hm_json_t;

static inline void hm_j_init(hm_json_t *j, size_t init_cap) {
    if (init_cap < 256U) init_cap = 256U;
    j->buf = (char *)malloc(init_cap);
    j->len = 0U;
    j->cap = j->buf ? init_cap : 0U;
    j->oom = (j->buf == NULL);
    if (j->buf) j->buf[0] = '\0';
}

static inline void hm_j_free(hm_json_t *j) {
    free(j->buf);
    j->buf = NULL;
    j->len = 0U;
    j->cap = 0U;
}

static inline bool hm_j_grow(hm_json_t *j, size_t extra) {
    if (j->oom) return false;
    if (j->len + extra + 1U <= j->cap) return true;
    size_t ncap = j->cap ? j->cap * 2U : 256U;
    while (ncap < j->len + extra + 1U) ncap *= 2U;
    char *nb = (char *)realloc(j->buf, ncap);
    if (!nb) {
        j->oom = true;
        return false;
    }
    j->buf = nb;
    j->cap = ncap;
    return true;
}

static inline void hm_j_raw_n(hm_json_t *j, const char *s, size_t n) {
    if (!s || n == 0U || !hm_j_grow(j, n)) return;
    memcpy(j->buf + j->len, s, n);
    j->len += n;
    j->buf[j->len] = '\0';
}

static inline void hm_j_raw(hm_json_t *j, const char *s) {
    if (s) hm_j_raw_n(j, s, strlen(s));
}

static inline void hm_j_ch(hm_json_t *j, char c) {
    if (!hm_j_grow(j, 1U)) return;
    j->buf[j->len++] = c;
    j->buf[j->len] = '\0';
}

static inline void hm_j_str_n(hm_json_t *j, const char *s, size_t n) {
    if (!s) {
        hm_j_raw_n(j, "null", 4U);
        return;
    }
    hm_j_ch(j, '"');
    static const char HEX[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  hm_j_raw_n(j, "\\\"", 2U); break;
            case '\\': hm_j_raw_n(j, "\\\\", 2U); break;
            case '\b': hm_j_raw_n(j, "\\b", 2U);  break;
            case '\f': hm_j_raw_n(j, "\\f", 2U);  break;
            case '\n': hm_j_raw_n(j, "\\n", 2U);  break;
            case '\r': hm_j_raw_n(j, "\\r", 2U);  break;
            case '\t': hm_j_raw_n(j, "\\t", 2U);  break;
            default:
                if (c < 0x20U) {
                    char esc[6] = { '\\', 'u', '0', '0', HEX[(c >> 4) & 0x0FU], HEX[c & 0x0FU] };
                    hm_j_raw_n(j, esc, 6U);
                } else {
                    hm_j_ch(j, (char)c);
                }
                break;
        }
    }
    hm_j_ch(j, '"');
}

static inline void hm_j_str(hm_json_t *j, const char *s) {
    if (!s) hm_j_raw_n(j, "null", 4U);
    else hm_j_str_n(j, s, strlen(s));
}

static inline void hm_j_i64(hm_json_t *j, int64_t v) {
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
    if (n > 0) hm_j_raw_n(j, tmp, (size_t)n);
}

static inline void hm_j_dbl(hm_json_t *j, double v) {
    if (!isfinite(v)) v = 0.0;
    char tmp[48];
    int n = snprintf(tmp, sizeof(tmp), "%.4f", v);
    if (n > 0) hm_j_raw_n(j, tmp, (size_t)n);
}

static inline void hm_j_tags_arr(hm_json_t *j, const char *csv) {
    hm_j_ch(j, '[');
    if (csv && csv[0]) {
        const char *p = csv;
        bool first = true;
        while (*p) {
            while (*p == ' ' || *p == ',' || *p == '\t') p++;
            if (!*p) break;
            const char *start = p;
            while (*p && *p != ',') p++;
            const char *end = p;
            while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
            if (end > start) {
                if (!first) hm_j_ch(j, ',');
                first = false;
                hm_j_str_n(j, start, (size_t)(end - start));
            }
        }
    }
    hm_j_ch(j, ']');
}

static inline int64_t hm_now_sec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        return (int64_t)ts.tv_sec;
    }
    return (int64_t)time(NULL);
}

static inline void hm_expand_tilde(const char *raw, char *out, size_t cap) {
    if (!raw || !raw[0]) {
        out[0] = '\0';
        return;
    }
    if (raw[0] == '~' && (raw[1] == '/' || raw[1] == '\0')) {
        const char *home = getenv("HOME");
        if (home && home[0]) {
            snprintf(out, cap, "%s%s", home, raw + 1);
            return;
        }
    }
    snprintf(out, cap, "%s", raw);
}

/* Portable DB path resolution matching bin/hephaestus & mcp/hephaestus_mcp.py */
static inline void hm_resolve_db_path(const char *cli_override, char *out, size_t cap) {
    if (cli_override && cli_override[0]) {
        hm_expand_tilde(cli_override, out, cap);
        return;
    }
    const char *env_db = getenv("HEPHAESTUS_MEMORY_DB");
    if (env_db && env_db[0]) {
        hm_expand_tilde(env_db, out, cap);
        return;
    }
    const char *xdg = getenv("XDG_DATA_HOME");
    if (xdg && xdg[0]) {
        char base[768];
        hm_expand_tilde(xdg, base, sizeof(base));
        snprintf(out, cap, "%s/hephaestus/memory.db", base);
        return;
    }
    const char *hhome = getenv("HEPHAESTUS_HOME");
    if (hhome && hhome[0]) {
        char base[768];
        hm_expand_tilde(hhome, base, sizeof(base));
        snprintf(out, cap, "%s/memory/memory.db", base);
        return;
    }
    const char *home = getenv("HOME");
    if (home && home[0]) {
        snprintf(out, cap, "%s/.hephaestus/memory/memory.db", home);
        return;
    }
    snprintf(out, cap, "/tmp/hephaestus-memory.db");
}

static inline int hm_mkdir_parents(const char *filepath) {
    char tmp[1024];
    int n = snprintf(tmp, sizeof(tmp), "%s", filepath);
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return -1;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
                /* Allow read-only root ancestors like /tmp or /Users */
            }
            *p = '/';
        }
    }
    return 0;
}

static const char HM_SCHEMA_DDL[] =
    "PRAGMA journal_mode=WAL;\n"
    "PRAGMA synchronous=NORMAL;\n"
    "PRAGMA foreign_keys=ON;\n"
    "CREATE TABLE IF NOT EXISTS beliefs (\n"
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
    "    uid TEXT UNIQUE NOT NULL,\n"
    "    kind TEXT NOT NULL DEFAULT 'fact',\n"
    "    title TEXT NOT NULL,\n"
    "    body TEXT NOT NULL,\n"
    "    tags TEXT NOT NULL DEFAULT '',\n"
    "    status TEXT NOT NULL DEFAULT 'IN' CHECK (status IN ('IN','RETRACTED')),\n"
    "    retired INTEGER NOT NULL DEFAULT 0,\n"
    "    retracted_reason TEXT NOT NULL DEFAULT '',\n"
    "    retracted_by INTEGER,\n"
    "    entrenchment REAL NOT NULL DEFAULT 1.4,\n"
    "    access_count INTEGER NOT NULL DEFAULT 1,\n"
    "    created_at INTEGER NOT NULL,\n"
    "    updated_at INTEGER NOT NULL,\n"
    "    last_accessed_at INTEGER NOT NULL\n"
    ");\n"
    "CREATE INDEX IF NOT EXISTS idx_beliefs_status ON beliefs(status, kind);\n"
    "CREATE TABLE IF NOT EXISTS edges (\n"
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
    "    src_id INTEGER NOT NULL REFERENCES beliefs(id) ON DELETE CASCADE,\n"
    "    relation TEXT NOT NULL CHECK (relation IN ('supports','contradicts','supersedes')),\n"
    "    dst_id INTEGER NOT NULL REFERENCES beliefs(id) ON DELETE CASCADE,\n"
    "    created_at INTEGER NOT NULL,\n"
    "    UNIQUE(src_id, relation, dst_id)\n"
    ");\n"
    "CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src_id, relation);\n"
    "CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst_id, relation);\n"
    "CREATE VIRTUAL TABLE IF NOT EXISTS beliefs_fts USING fts5(\n"
    "    belief_id UNINDEXED,\n"
    "    title_raw,\n"
    "    body_raw,\n"
    "    tags_raw,\n"
    "    stem_bag,\n"
    "    tokenize='unicode61 remove_diacritics 2'\n"
    ");\n";

static inline int hm_open_db(const char *path, bool create_if_missing, sqlite3 **out_db, char *err, size_t err_cap) {
    *out_db = NULL;
    if (err && err_cap > 0U) err[0] = '\0';
    if (!create_if_missing && access(path, F_OK) != 0) {
        return 0; /* Uninitialized DB on read path */
    }
    (void)hm_mkdir_parents(path);

    sqlite3 *db = NULL;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX;
    if (sqlite3_open_v2(path, &db, flags, NULL) != SQLITE_OK || !db) {
        if (err && err_cap > 0U) {
            snprintf(err, err_cap, "sqlite open failed: %s", db ? sqlite3_errmsg(db) : "out of memory");
        }
        if (db) sqlite3_close(db);
        return -1;
    }

    (void)sqlite3_busy_timeout(db, 5000);
#ifdef SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION
    (void)sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, (int *)0);
#endif
#ifdef SQLITE_DBCONFIG_TRUSTED_SCHEMA
    (void)sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, (int *)0);
#endif

    char *zerr = NULL;
    if (sqlite3_exec(db, HM_SCHEMA_DDL, NULL, NULL, &zerr) != SQLITE_OK) {
        if (err && err_cap > 0U) {
            snprintf(err, err_cap, "schema init failed: %s", zerr ? zerr : "unknown");
        }
        if (zerr) sqlite3_free(zerr);
        sqlite3_close(db);
        return -1;
    }

#ifdef SQLITE_DBCONFIG_DEFENSIVE
    (void)sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, (int *)0);
#endif

    *out_db = db;
    return 0;
}

static inline double hm_kind_entrenchment(const char *kind) {
    if (!kind) return 1.4;
    if (strcmp(kind, "constraint") == 0) return 2.4;
    if (strcmp(kind, "decision") == 0)   return 2.2;
    if (strcmp(kind, "bugfix") == 0)     return 1.9;
    if (strcmp(kind, "fact") == 0)       return 1.4;
    return 1.2;
}

/* ACT-R base-level activation B_i = ln(1 + access_count) - 0.5 * ln(1 + age_hours) */
static inline double hm_actr_activation(int64_t access_count, int64_t last_accessed_at, int64_t now_sec) {
    if (access_count < 1) access_count = 1;
    double age_h = (now_sec > last_accessed_at && last_accessed_at > 0)
                 ? ((double)(now_sec - last_accessed_at) / 3600.0)
                 : 0.0;
    double raw = log(1.0 + (double)access_count) - 0.5 * log(1.0 + age_h);
    return 1.0 / (1.0 + exp(-raw)); /* Sigmoid normalized to (0, 1) */
}

/* Resolve numeric id ("12") or string uid ("m_...") to integer belief id */
static inline int64_t hm_resolve_belief_id(sqlite3 *db, const char *spec, char *out_uid, size_t uid_cap) {
    if (out_uid && uid_cap > 0U) out_uid[0] = '\0';
    if (!db || !spec || !spec[0]) return -1;

    char *endp = NULL;
    long long parsed = strtoll(spec, &endp, 10);
    sqlite3_stmt *st = NULL;

    if (endp && *endp == '\0' && parsed > 0) {
        if (sqlite3_prepare_v2(db, "SELECT id, uid FROM beliefs WHERE id = ? LIMIT 1", -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(st, 1, (int64_t)parsed);
            if (sqlite3_step(st) == SQLITE_ROW) {
                int64_t id = sqlite3_column_int64(st, 0);
                const char *u = (const char *)sqlite3_column_text(st, 1);
                if (out_uid && uid_cap > 0U && u) snprintf(out_uid, uid_cap, "%s", u);
                sqlite3_finalize(st);
                return id;
            }
            sqlite3_finalize(st);
        }
    }

    if (sqlite3_prepare_v2(db, "SELECT id, uid FROM beliefs WHERE uid = ? LIMIT 1", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, spec, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW) {
            int64_t id = sqlite3_column_int64(st, 0);
            const char *u = (const char *)sqlite3_column_text(st, 1);
            if (out_uid && uid_cap > 0U && u) snprintf(out_uid, uid_cap, "%s", u);
            sqlite3_finalize(st);
            return id;
        }
        sqlite3_finalize(st);
    }

    if (strlen(spec) >= 6U) {
        char pat[128];
        snprintf(pat, sizeof(pat), "%s%%", spec);
        if (sqlite3_prepare_v2(db, "SELECT id, uid FROM beliefs WHERE uid LIKE ? LIMIT 2", -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, pat, -1, SQLITE_STATIC);
            if (sqlite3_step(st) == SQLITE_ROW) {
                int64_t id = sqlite3_column_int64(st, 0);
                const char *u = (const char *)sqlite3_column_text(st, 1);
                char u_copy[64] = {0};
                if (u) snprintf(u_copy, sizeof(u_copy), "%s", u);
                bool unique = (sqlite3_step(st) != SQLITE_ROW);
                sqlite3_finalize(st);
                if (unique) {
                    if (out_uid && uid_cap > 0U) snprintf(out_uid, uid_cap, "%s", u_copy);
                    return id;
                }
            } else {
                sqlite3_finalize(st);
            }
        }
    }
    return -1;
}

typedef struct {
    int64_t ids[128];
    size_t  count;
} hm_idlist_t;

typedef struct {
    int64_t id;
    int     retired;
    bool    was_in;
    bool    cur_in;
    int64_t blocker_id;
    char    reason[24];
} hm_jnode_t;

typedef struct {
    int64_t src_id;
    int64_t dst_id;
    int     rel; /* 1=supports, 2=contradicts, 3=supersedes */
} hm_jedge_t;

static inline int hm_find_jnode_idx(const hm_jnode_t *nodes, size_t n, int64_t id) {
    size_t lo = 0U, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2U;
        if (nodes[mid].id == id) return (int)mid;
        if (nodes[mid].id < id) lo = mid + 1U;
        else hi = mid;
    }
    return -1;
}

/* Guard against cycles in supports/supersedes graph */
static inline bool hm_would_cycle(sqlite3 *db, int64_t src_id, int64_t dst_id) {
    if (src_id == dst_id) return true;
    int64_t queue[256];
    size_t head = 0U, tail = 0U;
    queue[tail++] = dst_id;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db,
            "SELECT dst_id FROM edges WHERE src_id = ? AND relation IN ('supports','supersedes')",
            -1, &st, NULL) != SQLITE_OK) {
        return false;
    }
    bool cycle = false;
    while (head < tail && !cycle) {
        int64_t cur = queue[head++];
        sqlite3_reset(st);
        sqlite3_bind_int64(st, 1, cur);
        while (sqlite3_step(st) == SQLITE_ROW) {
            int64_t nxt = sqlite3_column_int64(st, 0);
            if (nxt == src_id) {
                cycle = true;
                break;
            }
            bool seen = false;
            for (size_t i = 0; i < tail; i++) {
                if (queue[i] == nxt) { seen = true; break; }
            }
            if (!seen && tail < 256U) queue[tail++] = nxt;
        }
    }
    sqlite3_finalize(st);
    return cycle;
}

/* Stratified Doyle JTMS Fixed-Point Solver */
static inline int hm_recompute_jtms(sqlite3 *db, hm_idlist_t *out_retracted, hm_idlist_t *out_restored) {
    if (out_retracted) out_retracted->count = 0U;
    if (out_restored) out_restored->count = 0U;

    size_t n_cap = 256U, n_len = 0U;
    hm_jnode_t *nodes = (hm_jnode_t *)calloc(n_cap, sizeof(hm_jnode_t));
    if (!nodes) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT id, retired, status FROM beliefs ORDER BY id ASC", -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (n_len >= n_cap) {
                n_cap *= 2U;
                hm_jnode_t * tmp = (hm_jnode_t *)realloc(nodes, n_cap * sizeof(hm_jnode_t));
                if (!tmp) { sqlite3_finalize(st); free(nodes); return -1; }
                nodes = tmp;
            }
            int64_t id = sqlite3_column_int64(st, 0);
            int ret = sqlite3_column_int(st, 1);
            const char *s = (const char *)sqlite3_column_text(st, 2);
            bool is_in = (s && strcmp(s, "IN") == 0);
            nodes[n_len].id = id;
            nodes[n_len].retired = ret;
            nodes[n_len].was_in = is_in;
            nodes[n_len].cur_in = (ret == 0);
            nodes[n_len].blocker_id = 0;
            nodes[n_len].reason[0] = '\0';
            n_len++;
        }
        sqlite3_finalize(st);
    }
    if (n_len == 0U) {
        free(nodes);
        return 0;
    }

    size_t e_cap = 256U, e_len = 0U;
    hm_jedge_t *edges = (hm_jedge_t *)calloc(e_cap, sizeof(hm_jedge_t));
    if (!edges) { free(nodes); return -1; }

    if (sqlite3_prepare_v2(db, "SELECT src_id, relation, dst_id FROM edges", -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (e_len >= e_cap) {
                e_cap *= 2U;
                hm_jedge_t *tmp = (hm_jedge_t *)realloc(edges, e_cap * sizeof(hm_jedge_t));
                if (!tmp) { sqlite3_finalize(st); free(edges); free(nodes); return -1; }
                edges = tmp;
            }
            int64_t s_id = sqlite3_column_int64(st, 0);
            const char *rel = (const char *)sqlite3_column_text(st, 1);
            int64_t d_id = sqlite3_column_int64(st, 2);
            int rcode = 1;
            if (rel && strcmp(rel, "contradicts") == 0) rcode = 2;
            else if (rel && strcmp(rel, "supersedes") == 0) rcode = 3;
            edges[e_len++] = (hm_jedge_t){ .src_id = s_id, .dst_id = d_id, .rel = rcode };
        }
        sqlite3_finalize(st);
    }

    for (size_t pass = 0U; pass < n_len + 2U; pass++) {
        bool changed = false;
        for (size_t i = 0U; i < n_len; i++) {
            int64_t uid = nodes[i].id;
            bool next_in = true;
            int64_t blocker = 0;
            const char *why = "";

            if (nodes[i].retired != 0) {
                next_in = false;
                why = "retired";
            } else {
                int n_sup_edges = 0;
                int n_sup_in = 0;
                int64_t first_dead_sup = 0;

                for (size_t e = 0U; e < e_len; e++) {
                    if (edges[e].dst_id != uid) continue;
                    int sidx = hm_find_jnode_idx(nodes, n_len, edges[e].src_id);
                    bool src_in = (sidx >= 0) ? nodes[sidx].cur_in : false;

                    if (edges[e].rel == 3 && src_in) {
                        next_in = false;
                        blocker = edges[e].src_id;
                        why = "superseded";
                        break;
                    }
                    if (edges[e].rel == 2 && src_in) {
                        next_in = false;
                        blocker = edges[e].src_id;
                        why = "contradicted";
                    }
                    if (edges[e].rel == 1) {
                        n_sup_edges++;
                        if (src_in) n_sup_in++;
                        else if (first_dead_sup == 0) first_dead_sup = edges[e].src_id;
                    }
                }
                if (next_in && n_sup_edges > 0 && n_sup_in == 0) {
                    next_in = false;
                    blocker = first_dead_sup;
                    why = "unsupported";
                }
            }

            if (nodes[i].cur_in != next_in || nodes[i].blocker_id != blocker || strcmp(nodes[i].reason, why) != 0) {
                nodes[i].cur_in = next_in;
                nodes[i].blocker_id = blocker;
                snprintf(nodes[i].reason, sizeof(nodes[i].reason), "%s", why);
                changed = true;
            }
        }
        if (!changed) break;
    }

    int64_t now = hm_now_sec();
    sqlite3_stmt *up = NULL;
    if (sqlite3_prepare_v2(
            db,
            "UPDATE beliefs SET status = ?, retracted_reason = ?, retracted_by = ?, updated_at = ? WHERE id = ?",
            -1, &up, NULL) == SQLITE_OK) {
        for (size_t i = 0U; i < n_len; i++) {
            if (nodes[i].cur_in != nodes[i].was_in || (!nodes[i].cur_in && nodes[i].reason[0])) {
                sqlite3_reset(up);
                sqlite3_bind_text(up, 1, nodes[i].cur_in ? "IN" : "RETRACTED", -1, SQLITE_STATIC);
                sqlite3_bind_text(up, 2, nodes[i].cur_in ? "" : nodes[i].reason, -1, SQLITE_STATIC);
                if (!nodes[i].cur_in && nodes[i].blocker_id > 0) {
                    sqlite3_bind_int64(up, 3, nodes[i].blocker_id);
                } else {
                    sqlite3_bind_null(up, 3);
                }
                sqlite3_bind_int64(up, 4, now);
                sqlite3_bind_int64(up, 5, nodes[i].id);
                (void)sqlite3_step(up);

                if (nodes[i].was_in && !nodes[i].cur_in && out_retracted && out_retracted->count < 128U) {
                    out_retracted->ids[out_retracted->count++] = nodes[i].id;
                } else if (!nodes[i].was_in && nodes[i].cur_in && out_restored && out_restored->count < 128U) {
                    out_restored->ids[out_restored->count++] = nodes[i].id;
                }
            }
        }
        sqlite3_finalize(up);
    }

    free(edges);
    free(nodes);
    return 0;
}

#endif /* HMEMORY_CORE_H */
