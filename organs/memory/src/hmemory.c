#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#include "hmemory_core.h"

typedef struct {
    int64_t id;
    char    uid[32];
    char    kind[24];
    char    status[16];
    char    retracted_reason[24];
    int64_t retracted_by;
    char   *title;
    char   *body;
    char   *tags;
    char   *stem_bag;
    double  entrenchment;
    int64_t access_count;
    int64_t created_at;
    int64_t updated_at;
    int64_t last_accessed_at;
    double  bm25_raw;
    double  activation;
    double  score;
} hm_hit_t;

static void hm_free_hits(hm_hit_t *hits, size_t n) {
    if (!hits) return;
    for (size_t i = 0; i < n; i++) {
        free(hits[i].title);
        free(hits[i].body);
        free(hits[i].tags);
        free(hits[i].stem_bag);
    }
    free(hits);
}

static char *hm_strdup(const char *s) {
    if (!s) s = "";
    size_t n = strlen(s);
    char *p = (char *)malloc(n + 1U);
    if (p) memcpy(p, s, n + 1U);
    return p;
}

static int hm_cmp_hits_desc(const void *a, const void *b) {
    const hm_hit_t *ha = (const hm_hit_t *)a;
    const hm_hit_t *hb = (const hm_hit_t *)b;
    if (hb->score > ha->score) return 1;
    if (hb->score < ha->score) return -1;
    if (hb->id > ha->id) return 1;
    if (hb->id < ha->id) return -1;
    return 0;
}

static bool hm_valid_kind(const char *k) {
    static const char *const KINDS[] = {
        "decision", "bugfix", "fact", "constraint", "lesson", "preference", "note"
    };
    if (!k || !k[0]) return false;
    for (size_t i = 0; i < sizeof(KINDS) / sizeof(KINDS[0]); i++) {
        if (strcmp(k, KINDS[i]) == 0) return true;
    }
    return false;
}

static void hm_emit_error(bool as_json, const char *msg) {
    if (as_json) {
        hm_json_t j;
        hm_j_init(&j, 256U);
        hm_j_raw(&j, "{\"ok\":false,\"error\":");
        hm_j_str(&j, msg ? msg : "error");
        hm_j_ch(&j, '}');
        printf("%s\n", j.buf ? j.buf : "{\"ok\":false}");
        hm_j_free(&j);
    } else {
        fprintf(stderr, "hmemory: error: %s\n", msg ? msg : "unknown error");
    }
}

static void hm_print_help(void) {
    printf(
        "hmemory %s -- standalone C11 + SQLite WAL/FTS5 cognitive memory with JTMS\n\n"
        "Usage:\n"
        "  hmemory ingest -t \"<title>\" -b \"<body>\" [--kind decision|bugfix|fact|constraint]\n"
        "                 [--tags \"t1,t2\"] [--supersedes <id>] [--db <path>] [--json]\n"
        "  hmemory query \"<query>\" [--limit 8] [--include-retracted] [--db <path>] [--json]\n"
        "  hmemory context [\"<focus_query>\"] [--budget-tokens 600] [--db <path>] [--json]\n"
        "  hmemory link <src_id> <supports|contradicts|supersedes> <dst_id> [--db <path>] [--json]\n"
        "  hmemory explain <id> [--db <path>] [--json]\n"
        "  hmemory stats [--db <path>] [--json]\n\n"
        "Environment:\n"
        "  HEPHAESTUS_MEMORY_DB -> XDG_DATA_HOME/hephaestus/memory.db -> ~/.hephaestus/memory/memory.db\n",
        HMEMORY_VERSION
    );
}

/* Build FTS5 OR expression over folded tokens and bilingual stems */
static char *hm_build_fts_expr(const char *query, hm_tokbag_t *out_raw_q) {
    hm_tokbag_t qbag;
    qbag.count = 0U;
    if (out_raw_q) {
        out_raw_q->count = 0U;
        hm_extract_bilingual_stems(query, out_raw_q, true);
    }
    hm_extract_bilingual_stems(query, &qbag, false);
    if (qbag.count == 0U) return NULL;

    size_t cap = qbag.count * 64U + 32U;
    char *expr = (char *)malloc(cap);
    if (!expr) return NULL;
    size_t pos = 0U;
    expr[0] = '\0';

    for (size_t i = 0; i < qbag.count; i++) {
        const char *tok = qbag.items[i];
        int n = snprintf(expr + pos, cap - pos, "%s\"%s\"*", (i > 0U) ? " OR " : "", tok);
        if (n <= 0 || pos + (size_t)n >= cap) break;
        pos += (size_t)n;
    }
    return (pos > 0U) ? expr : (free(expr), (char *)NULL);
}

static double hm_compute_coverage(const hm_tokbag_t *raw_q, const char *doc_stems) {
    if (!raw_q || raw_q->count == 0U || !doc_stems || !doc_stems[0]) return 0.0;
    size_t matched = 0U;
    for (size_t i = 0; i < raw_q->count; i++) {
        const char *qt = raw_q->items[i];
        char en_s[64], tr_s[64];
        hm_stem_en(qt, en_s, sizeof(en_s));
        hm_stem_tr(qt, tr_s, sizeof(tr_s));
        if (strstr(doc_stems, qt) != NULL ||
            (en_s[0] && strstr(doc_stems, en_s) != NULL) ||
            (tr_s[0] && strstr(doc_stems, tr_s) != NULL)) {
            matched++;
        }
    }
    return (double)matched / (double)raw_q->count;
}

static size_t hm_search_beliefs(
    sqlite3    *db,
    const char *query,
    bool        include_retracted,
    size_t      limit,
    bool        bump_access,
    hm_hit_t  **out_hits
) {
    *out_hits = NULL;
    if (!db || limit == 0U) return 0U;

    int64_t now = hm_now_sec();
    hm_tokbag_t raw_q;
    raw_q.count = 0U;
    char *fts_expr = (query && query[0]) ? hm_build_fts_expr(query, &raw_q) : NULL;

    sqlite3_stmt *st = NULL;
    bool using_fts = false;

    if (fts_expr) {
        const char *sql_fts = include_retracted
            ? "SELECT b.id, b.uid, b.kind, b.status, b.retracted_reason, COALESCE(b.retracted_by, 0), "
              "b.title, b.body, b.tags, f.stem_bag, b.entrenchment, b.access_count, "
              "b.created_at, b.updated_at, b.last_accessed_at, "
              "bm25(beliefs_fts, 0.0, 2.5, 1.0, 1.6, 2.2) "
              "FROM beliefs_fts f JOIN beliefs b ON b.id = CAST(f.belief_id AS INTEGER) "
              "WHERE beliefs_fts MATCH ? LIMIT 128"
            : "SELECT b.id, b.uid, b.kind, b.status, b.retracted_reason, COALESCE(b.retracted_by, 0), "
              "b.title, b.body, b.tags, f.stem_bag, b.entrenchment, b.access_count, "
              "b.created_at, b.updated_at, b.last_accessed_at, "
              "bm25(beliefs_fts, 0.0, 2.5, 1.0, 1.6, 2.2) "
              "FROM beliefs_fts f JOIN beliefs b ON b.id = CAST(f.belief_id AS INTEGER) "
              "WHERE beliefs_fts MATCH ? AND b.status = 'IN' LIMIT 128";
        if (sqlite3_prepare_v2(db, sql_fts, -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, fts_expr, -1, SQLITE_STATIC);
            using_fts = true;
        }
    } else if (query && query[0]) {
        const char *sql_sub = include_retracted
            ? "SELECT b.id, b.uid, b.kind, b.status, b.retracted_reason, COALESCE(b.retracted_by, 0), "
              "b.title, b.body, b.tags, '', b.entrenchment, b.access_count, "
              "b.created_at, b.updated_at, b.last_accessed_at, -1.0 "
              "FROM beliefs b WHERE instr(lower(b.title || ' ' || b.body), lower(?)) > 0 "
              "ORDER BY b.updated_at DESC, b.id DESC LIMIT 128"
            : "SELECT b.id, b.uid, b.kind, b.status, b.retracted_reason, COALESCE(b.retracted_by, 0), "
              "b.title, b.body, b.tags, '', b.entrenchment, b.access_count, "
              "b.created_at, b.updated_at, b.last_accessed_at, -1.0 "
              "FROM beliefs b WHERE b.status = 'IN' AND instr(lower(b.title || ' ' || b.body), lower(?)) > 0 "
              "ORDER BY b.updated_at DESC, b.id DESC LIMIT 128";
        if (sqlite3_prepare_v2(db, sql_sub, -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, query, -1, SQLITE_STATIC);
        }
    } else {
        const char *sql_all = include_retracted
            ? "SELECT b.id, b.uid, b.kind, b.status, b.retracted_reason, COALESCE(b.retracted_by, 0), "
              "b.title, b.body, b.tags, '', b.entrenchment, b.access_count, "
              "b.created_at, b.updated_at, b.last_accessed_at, 0.0 "
              "FROM beliefs b ORDER BY b.updated_at DESC, b.id DESC LIMIT 128"
            : "SELECT b.id, b.uid, b.kind, b.status, b.retracted_reason, COALESCE(b.retracted_by, 0), "
              "b.title, b.body, b.tags, '', b.entrenchment, b.access_count, "
              "b.created_at, b.updated_at, b.last_accessed_at, 0.0 "
              "FROM beliefs b WHERE b.status = 'IN' ORDER BY b.updated_at DESC, b.id DESC LIMIT 128";
        (void)sqlite3_prepare_v2(db, sql_all, -1, &st, NULL);
    }

    if (!st) {
        free(fts_expr);
        return 0U;
    }

    size_t cap = 32U, count = 0U;
    hm_hit_t *hits = (hm_hit_t *)calloc(cap, sizeof(hm_hit_t));
    if (!hits) {
        sqlite3_finalize(st);
        free(fts_expr);
        return 0U;
    }

    while (sqlite3_step(st) == SQLITE_ROW) {
        if (count >= cap) {
            cap *= 2U;
            hm_hit_t *nh = (hm_hit_t *)realloc(hits, cap * sizeof(hm_hit_t));
            if (!nh) break;
            hits = nh;
        }
        hm_hit_t *h = &hits[count];
        memset(h, 0, sizeof(*h));
        h->id = sqlite3_column_int64(st, 0);
        const char *u  = (const char *)sqlite3_column_text(st, 1);
        const char *k  = (const char *)sqlite3_column_text(st, 2);
        const char *s  = (const char *)sqlite3_column_text(st, 3);
        const char *rr = (const char *)sqlite3_column_text(st, 4);
        h->retracted_by = sqlite3_column_int64(st, 5);
        snprintf(h->uid, sizeof(h->uid), "%s", u ? u : "");
        snprintf(h->kind, sizeof(h->kind), "%s", k ? k : "fact");
        snprintf(h->status, sizeof(h->status), "%s", s ? s : "IN");
        snprintf(h->retracted_reason, sizeof(h->retracted_reason), "%s", rr ? rr : "");
        h->title    = hm_strdup((const char *)sqlite3_column_text(st, 6));
        h->body     = hm_strdup((const char *)sqlite3_column_text(st, 7));
        h->tags     = hm_strdup((const char *)sqlite3_column_text(st, 8));
        h->stem_bag = hm_strdup((const char *)sqlite3_column_text(st, 9));
        h->entrenchment     = sqlite3_column_double(st, 10);
        h->access_count     = sqlite3_column_int64(st, 11);
        h->created_at       = sqlite3_column_int64(st, 12);
        h->updated_at       = sqlite3_column_int64(st, 13);
        h->last_accessed_at = sqlite3_column_int64(st, 14);
        h->bm25_raw         = sqlite3_column_double(st, 15);

        h->activation = hm_actr_activation(h->access_count, h->last_accessed_at, now);
        double bm25_pos = using_fts ? fmax(0.0, -h->bm25_raw) : 0.0;
        double cov = using_fts ? hm_compute_coverage(&raw_q, h->stem_bag) : 0.0;
        double status_bonus = (strcmp(h->status, "IN") == 0) ? 0.35 : 0.0;

        if (using_fts) {
            h->score = bm25_pos + 3.20 * cov + 0.90 * h->activation + 0.35 * log(1.0 + h->entrenchment) + status_bonus;
        } else {
            h->score = 1.25 * h->activation + 0.75 * h->entrenchment + status_bonus;
        }
        count++;
    }
    sqlite3_finalize(st);
    free(fts_expr);

    if (count > 1U) {
        qsort(hits, count, sizeof(hm_hit_t), hm_cmp_hits_desc);
    }
    if (count > limit) {
        for (size_t i = limit; i < count; i++) {
            free(hits[i].title);
            free(hits[i].body);
            free(hits[i].tags);
            free(hits[i].stem_bag);
        }
        count = limit;
    }

    if (bump_access && count > 0U) {
        sqlite3_stmt *up = NULL;
        if (sqlite3_prepare_v2(
                db,
                "UPDATE beliefs SET access_count = access_count + 1, last_accessed_at = ? WHERE id = ? AND status = 'IN'",
                -1, &up, NULL) == SQLITE_OK) {
            for (size_t i = 0; i < count; i++) {
                if (strcmp(hits[i].status, "IN") != 0) continue;
                sqlite3_reset(up);
                sqlite3_bind_int64(up, 1, now);
                sqlite3_bind_int64(up, 2, hits[i].id);
                (void)sqlite3_step(up);
                hits[i].access_count += 1;
            }
            sqlite3_finalize(up);
        }
    }

    *out_hits = hits;
    return count;
}

static int cmd_ingest(int argc, char **argv, const char *db_override, bool as_json) {
    const char *title = NULL;
    const char *body = NULL;
    const char *kind = "fact";
    const char *tags = "";
    const char *supersedes_spec = NULL;

    for (int i = 0; i < argc; i++) {
        if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--title") == 0) && i + 1 < argc) {
            title = argv[++i];
        } else if ((strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--body") == 0) && i + 1 < argc) {
            body = argv[++i];
        } else if ((strcmp(argv[i], "--kind") == 0 || strcmp(argv[i], "-k") == 0) && i + 1 < argc) {
            kind = argv[++i];
        } else if (strcmp(argv[i], "--tags") == 0 && i + 1 < argc) {
            tags = argv[++i];
        } else if (strcmp(argv[i], "--supersedes") == 0 && i + 1 < argc) {
            supersedes_spec = argv[++i];
        } else if (strcmp(argv[i], "--json") == 0) {
            as_json = true;
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_override = argv[++i];
        } else {
            char msg[160];
            snprintf(msg, sizeof(msg), "unknown or incomplete ingest flag: %s", argv[i]);
            hm_emit_error(as_json, msg);
            return 2;
        }
    }

    if (!title || !title[0] || !body || !body[0]) {
        hm_emit_error(as_json, "both -t <title> and -b <body> are required");
        return 2;
    }
    if (!hm_valid_kind(kind)) {
        hm_emit_error(as_json, "invalid --kind (expected decision|bugfix|fact|constraint)");
        return 2;
    }

    char db_path[1024], err[256];
    hm_resolve_db_path(db_override, db_path, sizeof(db_path));
    sqlite3 *db = NULL;
    if (hm_open_db(db_path, true, &db, err, sizeof(err)) != 0 || !db) {
        hm_emit_error(as_json, err[0] ? err : "cannot open memory database");
        return 1;
    }

    int64_t sup_id = -1;
    if (supersedes_spec && supersedes_spec[0]) {
        sup_id = hm_resolve_belief_id(db, supersedes_spec, NULL, 0U);
        if (sup_id <= 0) {
            sqlite3_close(db);
            hm_emit_error(as_json, "target belief in --supersedes not found");
            return 1;
        }
    }

    int64_t now = hm_now_sec();
    double entrench = hm_kind_entrenchment(kind);

    if (sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        hm_emit_error(as_json, "failed to start sqlite transaction");
        return 1;
    }

    char seed[512];
    snprintf(seed, sizeof(seed), "%.160s|%.240s|%lld|%d", title, body, (long long)now, (int)getpid());
    uint64_t h = hm_mix64_str(seed);
    char uid[32];
    snprintf(uid, sizeof(uid), "m_%012llx", (unsigned long long)(h & 0xFFFFFFFFFFFFULL));

    sqlite3_stmt *ins = NULL;
    const char *ins_sql =
        "INSERT INTO beliefs(uid, kind, title, body, tags, status, entrenchment, access_count, created_at, updated_at, last_accessed_at) "
        "VALUES (?, ?, ?, ?, ?, 'IN', ?, 1, ?, ?, ?)";
    if (sqlite3_prepare_v2(db, ins_sql, -1, &ins, NULL) != SQLITE_OK) {
        (void)sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        sqlite3_close(db);
        hm_emit_error(as_json, "failed to prepare belief insert");
        return 1;
    }
    sqlite3_bind_text(ins, 1, uid, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins, 2, kind, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins, 3, title, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins, 4, body, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins, 5, tags ? tags : "", -1, SQLITE_STATIC);
    sqlite3_bind_double(ins, 6, entrench);
    sqlite3_bind_int64(ins, 7, now);
    sqlite3_bind_int64(ins, 8, now);
    sqlite3_bind_int64(ins, 9, now);

    if (sqlite3_step(ins) != SQLITE_DONE) {
        /* Handle rare UID collision by mixing row count */
        sqlite3_reset(ins);
        h = hm_mix64_bytes(&h, sizeof(h), (uint64_t)now);
        snprintf(uid, sizeof(uid), "m_%012llx", (unsigned long long)(h & 0xFFFFFFFFFFFFULL));
        sqlite3_bind_text(ins, 1, uid, -1, SQLITE_STATIC);
        if (sqlite3_step(ins) != SQLITE_DONE) {
            sqlite3_finalize(ins);
            (void)sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
            sqlite3_close(db);
            hm_emit_error(as_json, "belief insert failed");
            return 1;
        }
    }
    sqlite3_finalize(ins);
    int64_t new_id = sqlite3_last_insert_rowid(db);

    char *stem_bag = hm_build_stem_bag_str(title, body, tags);
    sqlite3_stmt *fts = NULL;
    if (sqlite3_prepare_v2(
            db,
            "INSERT INTO beliefs_fts(belief_id, title_raw, body_raw, tags_raw, stem_bag) VALUES (?, ?, ?, ?, ?)",
            -1, &fts, NULL) == SQLITE_OK) {
        char id_s[32];
        snprintf(id_s, sizeof(id_s), "%lld", (long long)new_id);
        sqlite3_bind_text(fts, 1, id_s, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(fts, 2, title, -1, SQLITE_STATIC);
        sqlite3_bind_text(fts, 3, body, -1, SQLITE_STATIC);
        sqlite3_bind_text(fts, 4, tags ? tags : "", -1, SQLITE_STATIC);
        sqlite3_bind_text(fts, 5, stem_bag ? stem_bag : "", -1, SQLITE_STATIC);
        (void)sqlite3_step(fts);
        sqlite3_finalize(fts);
    }
    free(stem_bag);

    hm_idlist_t retracted = { .count = 0U };
    hm_idlist_t restored  = { .count = 0U };

    if (sup_id > 0 && sup_id != new_id) {
        sqlite3_stmt *est = NULL;
        if (sqlite3_prepare_v2(
                db,
                "INSERT OR IGNORE INTO edges(src_id, relation, dst_id, created_at) VALUES (?, 'supersedes', ?, ?)",
                -1, &est, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(est, 1, new_id);
            sqlite3_bind_int64(est, 2, sup_id);
            sqlite3_bind_int64(est, 3, now);
            (void)sqlite3_step(est);
            sqlite3_finalize(est);
        }
        (void)hm_recompute_jtms(db, &retracted, &restored);
    }

    (void)sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
    sqlite3_close(db);

    if (as_json) {
        hm_json_t j;
        hm_j_init(&j, 512U);
        hm_j_raw(&j, "{\"ok\":true,\"id\":");
        hm_j_i64(&j, new_id);
        hm_j_raw(&j, ",\"uid\":");
        hm_j_str(&j, uid);
        hm_j_raw(&j, ",\"kind\":");
        hm_j_str(&j, kind);
        hm_j_raw(&j, ",\"status\":\"IN\",\"title\":");
        hm_j_str(&j, title);
        hm_j_raw(&j, ",\"tags\":");
        hm_j_tags_arr(&j, tags);
        hm_j_raw(&j, ",\"supersedes\":");
        if (sup_id > 0) hm_j_i64(&j, sup_id);
        else hm_j_raw(&j, "null");
        hm_j_raw(&j, ",\"retracted_ids\":[");
        for (size_t i = 0; i < retracted.count; i++) {
            if (i > 0U) hm_j_ch(&j, ',');
            hm_j_i64(&j, retracted.ids[i]);
        }
        hm_j_raw(&j, "],\"created_at\":");
        hm_j_i64(&j, now);
        hm_j_ch(&j, '}');
        printf("%s\n", j.buf);
        hm_j_free(&j);
    } else {
        printf("ingested #%lld (%s) [%s] status=IN: %s\n", (long long)new_id, uid, kind, title);
        if (retracted.count > 0U) {
            printf("  jtms retracted:");
            for (size_t i = 0; i < retracted.count; i++) {
                printf(" #%lld", (long long)retracted.ids[i]);
            }
            printf("\n");
        }
    }
    return 0;
}

static int cmd_query(int argc, char **argv, const char *db_override, bool as_json) {
    const char *query = NULL;
    int limit = 8;
    bool include_retracted = false;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            limit = atoi(argv[++i]);
            if (limit < 1) limit = 1;
            if (limit > 100) limit = 100;
        } else if (strcmp(argv[i], "--include-retracted") == 0) {
            include_retracted = true;
        } else if (strcmp(argv[i], "--json") == 0) {
            as_json = true;
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_override = argv[++i];
        } else if (argv[i][0] != '-' && !query) {
            query = argv[i];
        } else {
            char msg[160];
            snprintf(msg, sizeof(msg), "unexpected query argument: %s", argv[i]);
            hm_emit_error(as_json, msg);
            return 2;
        }
    }

    if (!query || !query[0]) {
        hm_emit_error(as_json, "missing search query");
        return 2;
    }

    char db_path[1024], err[256];
    hm_resolve_db_path(db_override, db_path, sizeof(db_path));
    sqlite3 *db = NULL;
    if (hm_open_db(db_path, false, &db, err, sizeof(err)) != 0) {
        hm_emit_error(as_json, err);
        return 1;
    }

    hm_hit_t *hits = NULL;
    size_t count = db ? hm_search_beliefs(db, query, include_retracted, (size_t)limit, true, &hits) : 0U;
    if (db) sqlite3_close(db);

    if (as_json) {
        hm_json_t j;
        hm_j_init(&j, 1024U);
        hm_j_raw(&j, "{\"ok\":true,\"query\":");
        hm_j_str(&j, query);
        hm_j_raw(&j, ",\"include_retracted\":");
        hm_j_raw(&j, include_retracted ? "true" : "false");
        hm_j_raw(&j, ",\"count\":");
        hm_j_i64(&j, (int64_t)count);
        hm_j_raw(&j, ",\"results\":[");
        for (size_t i = 0; i < count; i++) {
            if (i > 0U) hm_j_ch(&j, ',');
            const hm_hit_t *h = &hits[i];
            hm_j_raw(&j, "{\"id\":");
            hm_j_i64(&j, h->id);
            hm_j_raw(&j, ",\"uid\":");
            hm_j_str(&j, h->uid);
            hm_j_raw(&j, ",\"kind\":");
            hm_j_str(&j, h->kind);
            hm_j_raw(&j, ",\"status\":");
            hm_j_str(&j, h->status);
            hm_j_raw(&j, ",\"jtms_status\":");
            hm_j_str(&j, strcmp(h->status, "IN") == 0 ? "IN" : "OUT/RETRACTED");
            hm_j_raw(&j, ",\"title\":");
            hm_j_str(&j, h->title);
            hm_j_raw(&j, ",\"body\":");
            hm_j_str(&j, h->body);
            hm_j_raw(&j, ",\"tags\":");
            hm_j_tags_arr(&j, h->tags);
            hm_j_raw(&j, ",\"score\":");
            hm_j_dbl(&j, h->score);
            hm_j_raw(&j, ",\"activation\":");
            hm_j_dbl(&j, h->activation);
            hm_j_raw(&j, ",\"access_count\":");
            hm_j_i64(&j, h->access_count);
            hm_j_raw(&j, ",\"retracted_reason\":");
            if (h->retracted_reason[0]) hm_j_str(&j, h->retracted_reason);
            else hm_j_raw(&j, "null");
            hm_j_raw(&j, ",\"retracted_by\":");
            if (h->retracted_by > 0) hm_j_i64(&j, h->retracted_by);
            else hm_j_raw(&j, "null");
            hm_j_raw(&j, ",\"created_at\":");
            hm_j_i64(&j, h->created_at);
            hm_j_ch(&j, '}');
        }
        hm_j_raw(&j, "]}");
        printf("%s\n", j.buf);
        hm_j_free(&j);
    } else {
        if (count == 0U) {
            printf("no matching beliefs for \"%s\"\n", query);
        } else {
            for (size_t i = 0; i < count; i++) {
                const hm_hit_t *h = &hits[i];
                printf("#%lld (%s) [%s | %s | score=%.2f] %s\n  %s\n",
                       (long long)h->id, h->uid, h->kind,
                       strcmp(h->status, "IN") == 0 ? "IN" : "OUT/RETRACTED",
                       h->score, h->title, h->body);
            }
        }
    }

    hm_free_hits(hits, count);
    return 0;
}

static int cmd_context(int argc, char **argv, const char *db_override, bool as_json) {
    const char *focus_query = NULL;
    int budget_tokens = 600;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--budget-tokens") == 0 && i + 1 < argc) {
            budget_tokens = atoi(argv[++i]);
            if (budget_tokens < 1) budget_tokens = 1;
            if (budget_tokens > 32000) budget_tokens = 32000;
        } else if ((strcmp(argv[i], "--query") == 0 || strcmp(argv[i], "-q") == 0) && i + 1 < argc) {
            focus_query = argv[++i];
        } else if (strcmp(argv[i], "--json") == 0) {
            as_json = true;
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_override = argv[++i];
        } else if (argv[i][0] != '-' && !focus_query) {
            focus_query = argv[i];
        } else {
            char msg[160];
            snprintf(msg, sizeof(msg), "unexpected context argument: %s", argv[i]);
            hm_emit_error(as_json, msg);
            return 2;
        }
    }

    char db_path[1024], err[256];
    hm_resolve_db_path(db_override, db_path, sizeof(db_path));
    sqlite3 *db = NULL;
    if (hm_open_db(db_path, false, &db, err, sizeof(err)) != 0) {
        hm_emit_error(as_json, err);
        return 1;
    }

    hm_hit_t *focus_hits = NULL;
    size_t n_focus = 0U;
    hm_hit_t *salient_hits = NULL;
    size_t n_salient = 0U;

    if (db) {
        if (focus_query && focus_query[0]) {
            n_focus = hm_search_beliefs(db, focus_query, false, 32U, true, &focus_hits);
        }
        n_salient = hm_search_beliefs(db, NULL, false, 32U, false, &salient_hits);
        sqlite3_close(db);
    }

    /* Merge deduplicated candidate pool (focus matches first, then high-salience active beliefs) */
    hm_hit_t *pool[64];
    size_t n_pool = 0U;
    for (size_t i = 0; i < n_focus && n_pool < 64U; i++) {
        pool[n_pool++] = &focus_hits[i];
    }
    for (size_t i = 0; i < n_salient && n_pool < 64U; i++) {
        bool seen = false;
        for (size_t k = 0; k < n_pool; k++) {
            if (pool[k]->id == salient_hits[i].id) { seen = true; break; }
        }
        if (!seen) pool[n_pool++] = &salient_hits[i];
    }

    size_t lines_cap = (size_t)budget_tokens * 5U + 512U;
    char *lines_buf = (char *)malloc(lines_cap);
    char *block_buf = (char *)malloc(lines_cap + 256U);
    if (!lines_buf || !block_buf) {
        free(lines_buf);
        free(block_buf);
        hm_free_hits(focus_hits, n_focus);
        hm_free_hits(salient_hits, n_salient);
        hm_emit_error(as_json, "out of memory");
        return 1;
    }
    lines_buf[0] = '\0';
    size_t lines_len = 0U;
    int64_t selected_ids[64];
    size_t selected_cnt = 0U;

    for (size_t i = 0; i < n_pool && selected_cnt < 64U; i++) {
        const hm_hit_t *h = pool[i];
        static const size_t CLIP_STEPS[] = { 320U, 180U, 96U, 48U };
        bool fitted = false;

        for (size_t s = 0; s < sizeof(CLIP_STEPS) / sizeof(CLIP_STEPS[0]); s++) {
            char t_clean[160], b_clean[384], line[640];
            hm_clip_utf8_clean(h->title, 96U, t_clean, sizeof(t_clean));
            hm_clip_utf8_clean(h->body, CLIP_STEPS[s], b_clean, sizeof(b_clean));
            if (h->tags && h->tags[0] && s < 2U) {
                snprintf(line, sizeof(line), "- [%s #%lld] %s: %s (tags: %s)\n",
                         h->kind, (long long)h->id, t_clean, b_clean, h->tags);
            } else {
                snprintf(line, sizeof(line), "- [%s #%lld] %s: %s\n",
                         h->kind, (long long)h->id, t_clean, b_clean);
            }
            size_t l_len = strlen(line);
            if (lines_len + l_len + 1U >= lines_cap) continue;

            memcpy(lines_buf + lines_len, line, l_len + 1U);
            snprintf(block_buf, lines_cap + 256U,
                     "<memory_context budget_tokens=\"%d\" active_beliefs=\"%zu\">\n%s</memory_context>",
                     budget_tokens, selected_cnt + 1U, lines_buf);

            if (hm_estimate_tokens(block_buf) <= budget_tokens) {
                lines_len += l_len;
                selected_ids[selected_cnt++] = h->id;
                fitted = true;
                break;
            }
            lines_buf[lines_len] = '\0';
        }
        (void)fitted;
    }

    snprintf(block_buf, lines_cap + 256U,
             "<memory_context budget_tokens=\"%d\" active_beliefs=\"%zu\">\n%s</memory_context>",
             budget_tokens, selected_cnt, lines_buf);
    int used_tokens = hm_estimate_tokens(block_buf);
    if (used_tokens > budget_tokens) {
        snprintf(block_buf, lines_cap + 256U, "<memory_context/>");
        used_tokens = hm_estimate_tokens(block_buf);
        selected_cnt = 0U;
        if (used_tokens > budget_tokens) {
            block_buf[0] = '\0';
            used_tokens = 0;
        }
    }

    if (as_json) {
        hm_json_t j;
        hm_j_init(&j, lines_len + 512U);
        hm_j_raw(&j, "{\"ok\":true,\"focus_query\":");
        if (focus_query && focus_query[0]) hm_j_str(&j, focus_query);
        else hm_j_raw(&j, "null");
        hm_j_raw(&j, ",\"budget_tokens\":");
        hm_j_i64(&j, budget_tokens);
        hm_j_raw(&j, ",\"used_tokens\":");
        hm_j_i64(&j, used_tokens);
        hm_j_raw(&j, ",\"selected_count\":");
        hm_j_i64(&j, (int64_t)selected_cnt);
        hm_j_raw(&j, ",\"selected_ids\":[");
        for (size_t i = 0; i < selected_cnt; i++) {
            if (i > 0U) hm_j_ch(&j, ',');
            hm_j_i64(&j, selected_ids[i]);
        }
        hm_j_raw(&j, "],\"context\":");
        hm_j_str(&j, block_buf);
        hm_j_ch(&j, '}');
        printf("%s\n", j.buf);
        hm_j_free(&j);
    } else {
        printf("%s\n", block_buf);
    }

    free(lines_buf);
    free(block_buf);
    hm_free_hits(focus_hits, n_focus);
    hm_free_hits(salient_hits, n_salient);
    return 0;
}

static int cmd_link(int argc, char **argv, const char *db_override, bool as_json) {
    const char *pos_args[3] = { NULL, NULL, NULL };
    int n_pos = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            as_json = true;
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_override = argv[++i];
        } else if (argv[i][0] != '-' && n_pos < 3) {
            pos_args[n_pos++] = argv[i];
        } else {
            hm_emit_error(as_json, "usage: hmemory link <src_id> <supports|contradicts|supersedes> <dst_id>");
            return 2;
        }
    }

    if (n_pos != 3) {
        hm_emit_error(as_json, "usage: hmemory link <src_id> <supports|contradicts|supersedes> <dst_id>");
        return 2;
    }

    char rel[16];
    if (hm_strcasecmp(pos_args[1], "supports") == 0) snprintf(rel, sizeof(rel), "supports");
    else if (hm_strcasecmp(pos_args[1], "contradicts") == 0) snprintf(rel, sizeof(rel), "contradicts");
    else if (hm_strcasecmp(pos_args[1], "supersedes") == 0) snprintf(rel, sizeof(rel), "supersedes");
    else {
        hm_emit_error(as_json, "relation must be supports, contradicts, or supersedes");
        return 2;
    }

    char db_path[1024], err[256];
    hm_resolve_db_path(db_override, db_path, sizeof(db_path));
    sqlite3 *db = NULL;
    if (hm_open_db(db_path, false, &db, err, sizeof(err)) != 0 || !db) {
        hm_emit_error(as_json, err[0] ? err : "memory database does not exist yet");
        return 1;
    }

    int64_t src_id = hm_resolve_belief_id(db, pos_args[0], NULL, 0U);
    int64_t dst_id = hm_resolve_belief_id(db, pos_args[2], NULL, 0U);
    if (src_id <= 0 || dst_id <= 0) {
        sqlite3_close(db);
        hm_emit_error(as_json, (src_id <= 0) ? "source belief not found" : "destination belief not found");
        return 1;
    }
    if (src_id == dst_id) {
        sqlite3_close(db);
        hm_emit_error(as_json, "self-referential JTMS edge is not allowed");
        return 1;
    }
    if ((strcmp(rel, "supports") == 0 || strcmp(rel, "supersedes") == 0) && hm_would_cycle(db, src_id, dst_id)) {
        sqlite3_close(db);
        hm_emit_error(as_json, "JTMS cycle detected in supports/supersedes graph");
        return 1;
    }

    int64_t now = hm_now_sec();
    (void)sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);

    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(
            db,
            "INSERT OR IGNORE INTO edges(src_id, relation, dst_id, created_at) VALUES (?, ?, ?, ?)",
            -1, &ins, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(ins, 1, src_id);
        sqlite3_bind_text(ins, 2, rel, -1, SQLITE_STATIC);
        sqlite3_bind_int64(ins, 3, dst_id);
        sqlite3_bind_int64(ins, 4, now);
        (void)sqlite3_step(ins);
        sqlite3_finalize(ins);
    }

    hm_idlist_t retracted = { .count = 0U };
    hm_idlist_t restored  = { .count = 0U };
    (void)hm_recompute_jtms(db, &retracted, &restored);

    char dst_status[16] = "IN";
    sqlite3_stmt *qst = NULL;
    if (sqlite3_prepare_v2(db, "SELECT status FROM beliefs WHERE id = ?", -1, &qst, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(qst, 1, dst_id);
        if (sqlite3_step(qst) == SQLITE_ROW) {
            const char *s = (const char *)sqlite3_column_text(qst, 0);
            if (s) snprintf(dst_status, sizeof(dst_status), "%s", s);
        }
        sqlite3_finalize(qst);
    }

    (void)sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
    sqlite3_close(db);

    if (as_json) {
        hm_json_t j;
        hm_j_init(&j, 512U);
        hm_j_raw(&j, "{\"ok\":true,\"src_id\":");
        hm_j_i64(&j, src_id);
        hm_j_raw(&j, ",\"relation\":");
        hm_j_str(&j, rel);
        hm_j_raw(&j, ",\"dst_id\":");
        hm_j_i64(&j, dst_id);
        hm_j_raw(&j, ",\"dst_status\":");
        hm_j_str(&j, dst_status);
        hm_j_raw(&j, ",\"dst_jtms_status\":");
        hm_j_str(&j, strcmp(dst_status, "IN") == 0 ? "IN" : "OUT/RETRACTED");
        hm_j_raw(&j, ",\"retracted_ids\":[");
        for (size_t i = 0; i < retracted.count; i++) {
            if (i > 0U) hm_j_ch(&j, ',');
            hm_j_i64(&j, retracted.ids[i]);
        }
        hm_j_raw(&j, "],\"restored_ids\":[");
        for (size_t i = 0; i < restored.count; i++) {
            if (i > 0U) hm_j_ch(&j, ',');
            hm_j_i64(&j, restored.ids[i]);
        }
        hm_j_raw(&j, "]}");
        printf("%s\n", j.buf);
        hm_j_free(&j);
    } else {
        printf("linked #%lld --%s--> #%lld (dst status: %s)\n",
               (long long)src_id, rel, (long long)dst_id,
               strcmp(dst_status, "IN") == 0 ? "IN" : "OUT/RETRACTED");
    }
    return 0;
}

static int cmd_explain(int argc, char **argv, const char *db_override, bool as_json) {
    const char *target_spec = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            as_json = true;
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_override = argv[++i];
        } else if (argv[i][0] != '-' && !target_spec) {
            target_spec = argv[i];
        } else {
            hm_emit_error(as_json, "usage: hmemory explain <id> [--json]");
            return 2;
        }
    }
    if (!target_spec || !target_spec[0]) {
        hm_emit_error(as_json, "missing belief id");
        return 2;
    }

    char db_path[1024], err[256];
    hm_resolve_db_path(db_override, db_path, sizeof(db_path));
    sqlite3 *db = NULL;
    if (hm_open_db(db_path, false, &db, err, sizeof(err)) != 0 || !db) {
        hm_emit_error(as_json, "memory database not found");
        return 1;
    }

    int64_t bid = hm_resolve_belief_id(db, target_spec, NULL, 0U);
    if (bid <= 0) {
        sqlite3_close(db);
        hm_emit_error(as_json, "belief not found");
        return 1;
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db,
            "SELECT uid, kind, title, body, tags, status, retracted_reason, COALESCE(retracted_by, 0), "
            "entrenchment, access_count, created_at, updated_at, last_accessed_at "
            "FROM beliefs WHERE id = ?", -1, &st, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        hm_emit_error(as_json, "explain query failed");
        return 1;
    }
    sqlite3_bind_int64(st, 1, bid);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        sqlite3_close(db);
        hm_emit_error(as_json, "belief not found");
        return 1;
    }

    char uid[32], kind[24], status[16], reason[24];
    snprintf(uid, sizeof(uid), "%s", (const char *)sqlite3_column_text(st, 0));
    snprintf(kind, sizeof(kind), "%s", (const char *)sqlite3_column_text(st, 1));
    char *title = hm_strdup((const char *)sqlite3_column_text(st, 2));
    char *body  = hm_strdup((const char *)sqlite3_column_text(st, 3));
    char *tags  = hm_strdup((const char *)sqlite3_column_text(st, 4));
    snprintf(status, sizeof(status), "%s", (const char *)sqlite3_column_text(st, 5));
    snprintf(reason, sizeof(reason), "%s", (const char *)sqlite3_column_text(st, 6));
    int64_t ret_by   = sqlite3_column_int64(st, 7);
    double entrench  = sqlite3_column_double(st, 8);
    int64_t acc_cnt  = sqlite3_column_int64(st, 9);
    int64_t c_at     = sqlite3_column_int64(st, 10);
    int64_t u_at     = sqlite3_column_int64(st, 11);
    int64_t l_at     = sqlite3_column_int64(st, 12);
    sqlite3_finalize(st);

    bool is_in = (strcmp(status, "IN") == 0);
    double act = hm_actr_activation(acc_cnt, l_at, hm_now_sec());

    if (as_json) {
        hm_json_t j;
        hm_j_init(&j, 1024U);
        hm_j_raw(&j, "{\"ok\":true,\"id\":");
        hm_j_i64(&j, bid);
        hm_j_raw(&j, ",\"uid\":");
        hm_j_str(&j, uid);
        hm_j_raw(&j, ",\"kind\":");
        hm_j_str(&j, kind);
        hm_j_raw(&j, ",\"status\":");
        hm_j_str(&j, status);
        hm_j_raw(&j, ",\"jtms_status\":");
        hm_j_str(&j, is_in ? "IN" : "OUT/RETRACTED");
        hm_j_raw(&j, ",\"active\":");
        hm_j_raw(&j, is_in ? "true" : "false");
        hm_j_raw(&j, ",\"retracted_reason\":");
        if (reason[0]) hm_j_str(&j, reason);
        else hm_j_raw(&j, "null");
        hm_j_raw(&j, ",\"retracted_by\":");
        if (ret_by > 0) hm_j_i64(&j, ret_by);
        else hm_j_raw(&j, "null");
        hm_j_raw(&j, ",\"title\":");
        hm_j_str(&j, title);
        hm_j_raw(&j, ",\"body\":");
        hm_j_str(&j, body);
        hm_j_raw(&j, ",\"tags\":");
        hm_j_tags_arr(&j, tags);
        hm_j_raw(&j, ",\"entrenchment\":");
        hm_j_dbl(&j, entrench);
        hm_j_raw(&j, ",\"activation\":");
        hm_j_dbl(&j, act);
        hm_j_raw(&j, ",\"access_count\":");
        hm_j_i64(&j, acc_cnt);
        hm_j_raw(&j, ",\"created_at\":");
        hm_j_i64(&j, c_at);
        hm_j_raw(&j, ",\"updated_at\":");
        hm_j_i64(&j, u_at);

        /* Incoming edges */
        hm_j_raw(&j, ",\"incoming_edges\":[");
        if (sqlite3_prepare_v2(
                db,
                "SELECT e.src_id, b.uid, e.relation, b.status, b.title "
                "FROM edges e JOIN beliefs b ON b.id = e.src_id WHERE e.dst_id = ? ORDER BY e.id ASC",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(st, 1, bid);
            bool first = true;
            while (sqlite3_step(st) == SQLITE_ROW) {
                if (!first) hm_j_ch(&j, ',');
                first = false;
                hm_j_raw(&j, "{\"src_id\":");
                hm_j_i64(&j, sqlite3_column_int64(st, 0));
                hm_j_raw(&j, ",\"src_uid\":");
                hm_j_str(&j, (const char *)sqlite3_column_text(st, 1));
                hm_j_raw(&j, ",\"relation\":");
                hm_j_str(&j, (const char *)sqlite3_column_text(st, 2));
                hm_j_raw(&j, ",\"src_status\":");
                hm_j_str(&j, (const char *)sqlite3_column_text(st, 3));
                hm_j_raw(&j, ",\"src_title\":");
                hm_j_str(&j, (const char *)sqlite3_column_text(st, 4));
                hm_j_ch(&j, '}');
            }
            sqlite3_finalize(st);
        }
        hm_j_raw(&j, "],\"outgoing_edges\":[");
        if (sqlite3_prepare_v2(
                db,
                "SELECT e.dst_id, b.uid, e.relation, b.status, b.title "
                "FROM edges e JOIN beliefs b ON b.id = e.dst_id WHERE e.src_id = ? ORDER BY e.id ASC",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(st, 1, bid);
            bool first = true;
            while (sqlite3_step(st) == SQLITE_ROW) {
                if (!first) hm_j_ch(&j, ',');
                first = false;
                hm_j_raw(&j, "{\"dst_id\":");
                hm_j_i64(&j, sqlite3_column_int64(st, 0));
                hm_j_raw(&j, ",\"dst_uid\":");
                hm_j_str(&j, (const char *)sqlite3_column_text(st, 1));
                hm_j_raw(&j, ",\"relation\":");
                hm_j_str(&j, (const char *)sqlite3_column_text(st, 2));
                hm_j_raw(&j, ",\"dst_status\":");
                hm_j_str(&j, (const char *)sqlite3_column_text(st, 3));
                hm_j_raw(&j, ",\"dst_title\":");
                hm_j_str(&j, (const char *)sqlite3_column_text(st, 4));
                hm_j_ch(&j, '}');
            }
            sqlite3_finalize(st);
        }
        hm_j_raw(&j, "]}");
        printf("%s\n", j.buf);
        hm_j_free(&j);
    } else {
        printf("belief #%lld (%s)\n", (long long)bid, uid);
        printf("  kind:       %s\n", kind);
        printf("  jtms:       %s", is_in ? "IN" : "OUT/RETRACTED");
        if (!is_in && reason[0]) {
            if (ret_by > 0) printf(" (%s by #%lld)", reason, (long long)ret_by);
            else printf(" (%s)", reason);
        }
        printf("\n  title:      %s\n  body:       %s\n", title, body);
        if (tags && tags[0]) printf("  tags:       %s\n", tags);
        printf("  activation: %.3f (access_count=%lld, entrenchment=%.2f)\n",
               act, (long long)acc_cnt, entrench);

        if (sqlite3_prepare_v2(
                db,
                "SELECT e.src_id, e.relation, b.status, b.title "
                "FROM edges e JOIN beliefs b ON b.id = e.src_id WHERE e.dst_id = ? ORDER BY e.id ASC",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(st, 1, bid);
            while (sqlite3_step(st) == SQLITE_ROW) {
                printf("  <- #%lld [%s] %s this (%s)\n",
                       (long long)sqlite3_column_int64(st, 0),
                       (const char *)sqlite3_column_text(st, 2),
                       (const char *)sqlite3_column_text(st, 1),
                       (const char *)sqlite3_column_text(st, 3));
            }
            sqlite3_finalize(st);
        }
        if (sqlite3_prepare_v2(
                db,
                "SELECT e.dst_id, e.relation, b.status, b.title "
                "FROM edges e JOIN beliefs b ON b.id = e.dst_id WHERE e.src_id = ? ORDER BY e.id ASC",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(st, 1, bid);
            while (sqlite3_step(st) == SQLITE_ROW) {
                printf("  -> %s #%lld [%s] (%s)\n",
                       (const char *)sqlite3_column_text(st, 1),
                       (long long)sqlite3_column_int64(st, 0),
                       (const char *)sqlite3_column_text(st, 2),
                       (const char *)sqlite3_column_text(st, 3));
            }
            sqlite3_finalize(st);
        }
    }

    free(title);
    free(body);
    free(tags);
    sqlite3_close(db);
    return 0;
}

static int cmd_stats(int argc, char **argv, const char *db_override, bool as_json) {
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            as_json = true;
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_override = argv[++i];
        } else {
            hm_emit_error(as_json, "usage: hmemory stats [--db <path>] [--json]");
            return 2;
        }
    }

    char db_path[1024], err[256];
    hm_resolve_db_path(db_override, db_path, sizeof(db_path));
    sqlite3 *db = NULL;
    if (hm_open_db(db_path, false, &db, err, sizeof(err)) != 0) {
        hm_emit_error(as_json, err);
        return 1;
    }

    int64_t total_b = 0, active_b = 0, retracted_b = 0, edges_n = 0;
    int64_t k_dec = 0, k_bug = 0, k_fact = 0, k_con = 0;
    int64_t r_sup = 0, r_con = 0, r_ver = 0;
    bool initialized = (db != NULL);

    if (db) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(
                db,
                "SELECT COUNT(*), "
                "COALESCE(SUM(CASE WHEN status='IN' THEN 1 ELSE 0 END), 0), "
                "COALESCE(SUM(CASE WHEN status!='IN' THEN 1 ELSE 0 END), 0) FROM beliefs",
                -1, &st, NULL) == SQLITE_OK) {
            if (sqlite3_step(st) == SQLITE_ROW) {
                total_b     = sqlite3_column_int64(st, 0);
                active_b    = sqlite3_column_int64(st, 1);
                retracted_b = sqlite3_column_int64(st, 2);
            }
            sqlite3_finalize(st);
        }
        if (sqlite3_prepare_v2(
                db,
                "SELECT kind, COUNT(*) FROM beliefs WHERE status='IN' GROUP BY kind",
                -1, &st, NULL) == SQLITE_OK) {
            while (sqlite3_step(st) == SQLITE_ROW) {
                const char *k = (const char *)sqlite3_column_text(st, 0);
                int64_t c = sqlite3_column_int64(st, 1);
                if (!k) continue;
                if (strcmp(k, "decision") == 0) k_dec = c;
                else if (strcmp(k, "bugfix") == 0) k_bug = c;
                else if (strcmp(k, "fact") == 0) k_fact = c;
                else if (strcmp(k, "constraint") == 0) k_con = c;
            }
            sqlite3_finalize(st);
        }
        if (sqlite3_prepare_v2(db, "SELECT relation, COUNT(*) FROM edges GROUP BY relation", -1, &st, NULL) == SQLITE_OK) {
            while (sqlite3_step(st) == SQLITE_ROW) {
                const char *r = (const char *)sqlite3_column_text(st, 0);
                int64_t c = sqlite3_column_int64(st, 1);
                edges_n += c;
                if (!r) continue;
                if (strcmp(r, "supports") == 0) r_sup = c;
                else if (strcmp(r, "contradicts") == 0) r_con = c;
                else if (strcmp(r, "supersedes") == 0) r_ver = c;
            }
            sqlite3_finalize(st);
        }
        sqlite3_close(db);
    }

    if (as_json) {
        hm_json_t j;
        hm_j_init(&j, 512U);
        hm_j_raw(&j, "{\"ok\":true,\"initialized\":");
        hm_j_raw(&j, initialized ? "true" : "false");
        hm_j_raw(&j, ",\"db_path\":");
        hm_j_str(&j, db_path);
        hm_j_raw(&j, ",\"total_beliefs\":");
        hm_j_i64(&j, total_b);
        hm_j_raw(&j, ",\"active_beliefs\":");
        hm_j_i64(&j, active_b);
        hm_j_raw(&j, ",\"in_beliefs\":");
        hm_j_i64(&j, active_b);
        hm_j_raw(&j, ",\"retracted_beliefs\":");
        hm_j_i64(&j, retracted_b);
        hm_j_raw(&j, ",\"out_beliefs\":");
        hm_j_i64(&j, retracted_b);
        hm_j_raw(&j, ",\"edges\":");
        hm_j_i64(&j, edges_n);
        hm_j_raw(&j, ",\"total_edges\":");
        hm_j_i64(&j, edges_n);
        hm_j_raw(&j, ",\"by_kind\":{\"decision\":");
        hm_j_i64(&j, k_dec);
        hm_j_raw(&j, ",\"bugfix\":");
        hm_j_i64(&j, k_bug);
        hm_j_raw(&j, ",\"fact\":");
        hm_j_i64(&j, k_fact);
        hm_j_raw(&j, ",\"constraint\":");
        hm_j_i64(&j, k_con);
        hm_j_raw(&j, "},\"by_relation\":{\"supports\":");
        hm_j_i64(&j, r_sup);
        hm_j_raw(&j, ",\"contradicts\":");
        hm_j_i64(&j, r_con);
        hm_j_raw(&j, ",\"supersedes\":");
        hm_j_i64(&j, r_ver);
        hm_j_raw(&j, "}}");
        printf("%s\n", j.buf);
        hm_j_free(&j);
    } else {
        printf("hmemory stats\n");
        printf("  db_path:           %s (%s)\n", db_path, initialized ? "initialized" : "uninitialized");
        printf("  active_beliefs:    %lld\n", (long long)active_b);
        printf("  retracted_beliefs: %lld\n", (long long)retracted_b);
        printf("  jtms_edges:        %lld (supports=%lld contradicts=%lld supersedes=%lld)\n",
               (long long)edges_n, (long long)r_sup, (long long)r_con, (long long)r_ver);
    }
    return 0;
}

int main(int argc, char **argv) {
    bool as_json = false;
    const char *db_override = NULL;
    int sub_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            hm_print_help();
            return 0;
        }
        if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-V") == 0) {
            printf("hmemory %s\n", HMEMORY_VERSION);
            return 0;
        }
        if (sub_idx < 0 && strcmp(argv[i], "--json") == 0) {
            as_json = true;
            continue;
        }
        if (sub_idx < 0 && strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_override = argv[++i];
            continue;
        }
        if (sub_idx < 0) {
            sub_idx = i;
            break;
        }
    }

    if (sub_idx < 0) {
        hm_print_help();
        return 0;
    }

    const char *cmd = argv[sub_idx];
    int sub_argc = argc - (sub_idx + 1);
    char **sub_argv = argv + (sub_idx + 1);

    /* Allow --help anywhere after subcommand */
    for (int i = 0; i < sub_argc; i++) {
        if (strcmp(sub_argv[i], "--help") == 0 || strcmp(sub_argv[i], "-h") == 0) {
            hm_print_help();
            return 0;
        }
    }

    if (strcmp(cmd, "ingest") == 0)  return cmd_ingest(sub_argc, sub_argv, db_override, as_json);
    if (strcmp(cmd, "query") == 0)   return cmd_query(sub_argc, sub_argv, db_override, as_json);
    if (strcmp(cmd, "context") == 0) return cmd_context(sub_argc, sub_argv, db_override, as_json);
    if (strcmp(cmd, "link") == 0)    return cmd_link(sub_argc, sub_argv, db_override, as_json);
    if (strcmp(cmd, "explain") == 0) return cmd_explain(sub_argc, sub_argv, db_override, as_json);
    if (strcmp(cmd, "stats") == 0)   return cmd_stats(sub_argc, sub_argv, db_override, as_json);

    char msg[160];
    snprintf(msg, sizeof(msg), "unknown subcommand '%s' (run 'hmemory --help')", cmd);
    hm_emit_error(as_json, msg);
    return 2;
}
