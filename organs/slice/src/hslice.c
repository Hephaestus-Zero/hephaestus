/*
 * hslice.c - Hephaestus Organ 1 Zero-Noise Structural AST Code Slicer (`hslice`)
 *
 * Architectural Core:
 *   1. Runtime-Loaded Tree-Sitter CST Slicer (`dlopen` on Linux/macOS, zero build-time deps)
 *      with automatic fallback to a zero-dependency C11 stateful comment/string/indent lexer.
 *   2. Shared `hsym` mmap Trigram + Compact Interned Pool Index (`hslice_common.h`) with
 *      deterministic lazy `mtime_ns` + file-size + FNV-1a freshness auto-refresh.
 *   3. Exact Symbol Slicing (`hslice <sym>`), Stack-Trace Line Zoom (`hslice <file>:<line>`),
 *      Exact Span Slicing (`hslice <file>:<start>-<end>`), Structural Skeleton (`hslice -s`),
 *      1-Shot Symbol + Bounded Callers (`hslice -x <sym> [dir]`), and Shareable Token-Savings
 *      Audit Receipt (`hslice --audit [dir] [--json]`).
 *
 * Build: cc -std=c11 -O3 -Wall -Wextra -Werror -o hslice src/hslice.c [-ldl]
 */
#include "hslice_common.h"
#include <dlfcn.h>

#define MAX_MATCHES     64
#define MAX_OUTLINE     512
#define MAX_SLICE_LINES 180
#define MAX_XREF_LINES  45

enum {
    LANG_NONE = 0,
    LANG_PY   = 1,
    LANG_TS   = 2,
    LANG_RUST = 3,
    LANG_GO   = 4,
    LANG_C    = 5,
    LANG_SH   = 6,
    LANG_JAVA = 7,
    LANG_CPP  = 8,
    LANG_JS   = 9,
    LANG_TSX  = 10
};

/* =========================================================================
 * Minimal Tree-Sitter C ABI Declarations (Runtime `dlopen`, Zero Header Deps)
 * ========================================================================= */
typedef struct TSTree TSTree;
typedef struct TSParser TSParser;
typedef struct TSLanguage TSLanguage;

typedef struct {
    uint32_t row;
    uint32_t column;
} TSPoint;

typedef struct {
    uint32_t      context[4];
    const void   *id;
    const TSTree *tree;
} TSNode;

typedef struct {
    bool                 loaded;
    bool                 tried;
    void                *core_handle;
    TSParser *         (*parser_new)(void);
    void               (*parser_delete)(TSParser *);
    bool               (*parser_set_language)(TSParser *, const TSLanguage *);
    TSTree *           (*parser_parse_string)(TSParser *, const TSTree *, const char *, uint32_t);
    void               (*tree_delete)(TSTree *);
    TSNode             (*tree_root_node)(const TSTree *);
    const char *       (*node_type)(TSNode);
    bool               (*node_is_null)(TSNode);
    bool               (*node_is_named)(TSNode);
    uint32_t           (*node_start_byte)(TSNode);
    uint32_t           (*node_end_byte)(TSNode);
    TSPoint            (*node_start_point)(TSNode);
    TSPoint            (*node_end_point)(TSNode);
    uint32_t           (*node_child_count)(TSNode);
    TSNode             (*node_child)(TSNode, uint32_t);
    uint32_t           (*node_named_child_count)(TSNode);
    TSNode             (*node_named_child)(TSNode, uint32_t);
    TSNode             (*node_parent)(TSNode);
    TSNode             (*node_prev_sibling)(TSNode);
    TSNode             (*node_descendant_for_byte_range)(TSNode, uint32_t, uint32_t);
    const TSLanguage    *langs[12];
    bool                 lang_tried[12];
} TsRuntime;

static TsRuntime g_ts;

static void *dlopen_candidates(const char *const *names) {
    static const char *const dirs[] = {
        "",
        "/usr/lib/",
        "/usr/local/lib/",
        "/opt/homebrew/lib/",
        "/usr/lib/x86_64-linux-gnu/",
        "/usr/lib/aarch64-linux-gnu/",
        "/usr/lib64/",
        NULL
    };
    for (int d = 0; dirs[d]; d++) {
        for (int n = 0; names[n]; n++) {
            char cand[PATH_MAX];
            if (dirs[d][0] == '\0') {
                snprintf(cand, sizeof(cand), "%s", names[n]);
            } else {
                snprintf(cand, sizeof(cand), "%s%s", dirs[d], names[n]);
            }
            void *h = dlopen(cand, RTLD_LAZY | RTLD_LOCAL);
            if (h) return h;
        }
    }
    return NULL;
}

static bool ts_runtime_init(void) {
    if (g_ts.tried) return g_ts.loaded;
    g_ts.tried = true;

    const char *no_ts = getenv("HEPHAESTUS_NO_TREESITTER");
    if (no_ts && strcmp(no_ts, "1") == 0) return false;

    static const char *const core_names[] = {
#if defined(__APPLE__)
        "libtree-sitter.dylib",
        "libtree-sitter.0.dylib",
#else
        "libtree-sitter.so.0",
        "libtree-sitter.so",
#endif
        NULL
    };
    void *h = dlopen_candidates(core_names);
    if (!h) return false;

#define LOAD_SYM(field, sym_name) do { \
    *(void **)(&g_ts.field) = dlsym(h, sym_name); \
    if (!g_ts.field) { dlclose(h); return false; } \
} while (0)

    LOAD_SYM(parser_new, "ts_parser_new");
    LOAD_SYM(parser_delete, "ts_parser_delete");
    LOAD_SYM(parser_set_language, "ts_parser_set_language");
    LOAD_SYM(parser_parse_string, "ts_parser_parse_string");
    LOAD_SYM(tree_delete, "ts_tree_delete");
    LOAD_SYM(tree_root_node, "ts_tree_root_node");
    LOAD_SYM(node_type, "ts_node_type");
    LOAD_SYM(node_is_null, "ts_node_is_null");
    LOAD_SYM(node_is_named, "ts_node_is_named");
    LOAD_SYM(node_start_byte, "ts_node_start_byte");
    LOAD_SYM(node_end_byte, "ts_node_end_byte");
    LOAD_SYM(node_start_point, "ts_node_start_point");
    LOAD_SYM(node_end_point, "ts_node_end_point");
    LOAD_SYM(node_child_count, "ts_node_child_count");
    LOAD_SYM(node_child, "ts_node_child");
    LOAD_SYM(node_named_child_count, "ts_node_named_child_count");
    LOAD_SYM(node_named_child, "ts_node_named_child");
    LOAD_SYM(node_parent, "ts_node_parent");
    LOAD_SYM(node_prev_sibling, "ts_node_prev_sibling");
    LOAD_SYM(node_descendant_for_byte_range, "ts_node_descendant_for_byte_range");
#undef LOAD_SYM

    g_ts.core_handle = h;
    g_ts.loaded = true;
    return true;
}

static const TSLanguage *ts_get_language(uint8_t lang) {
    if (lang >= 12 || !ts_runtime_init()) return NULL;
    if (g_ts.lang_tried[lang]) return g_ts.langs[lang];
    g_ts.lang_tried[lang] = true;

    const char *slug = NULL;
    const char *fn_name = NULL;
    switch (lang) {
        case LANG_C:    slug = "c";          fn_name = "tree_sitter_c"; break;
        case LANG_CPP:  slug = "cpp";        fn_name = "tree_sitter_cpp"; break;
        case LANG_PY:   slug = "python";     fn_name = "tree_sitter_python"; break;
        case LANG_RUST: slug = "rust";       fn_name = "tree_sitter_rust"; break;
        case LANG_GO:   slug = "go";         fn_name = "tree_sitter_go"; break;
        case LANG_JS:   slug = "javascript"; fn_name = "tree_sitter_javascript"; break;
        case LANG_TS:   slug = "typescript"; fn_name = "tree_sitter_typescript"; break;
        case LANG_TSX:  slug = "tsx";        fn_name = "tree_sitter_tsx"; break;
        case LANG_SH:   slug = "bash";       fn_name = "tree_sitter_bash"; break;
        case LANG_JAVA: slug = "java";       fn_name = "tree_sitter_java"; break;
        default: return NULL;
    }

    char n0[128], n1[128], n2[128];
#if defined(__APPLE__)
    snprintf(n0, sizeof(n0), "libtree-sitter-%s.dylib", slug);
    snprintf(n1, sizeof(n1), "libtree-sitter-%s.0.dylib", slug);
    snprintf(n2, sizeof(n2), "tree-sitter-%s.dylib", slug);
#else
    snprintf(n0, sizeof(n0), "libtree-sitter-%s.so", slug);
    snprintf(n1, sizeof(n1), "libtree-sitter-%s.so.0", slug);
    snprintf(n2, sizeof(n2), "tree-sitter-%s.so", slug);
#endif
    const char *const names[] = {n0, n1, n2, NULL};
    void *gh = dlopen_candidates(names);
    if (!gh && lang == LANG_TSX) {
        static const char *const ts_alt[] = {
#if defined(__APPLE__)
            "libtree-sitter-typescript.dylib",
#else
            "libtree-sitter-typescript.so",
            "libtree-sitter-typescript.so.0",
#endif
            NULL
        };
        gh = dlopen_candidates(ts_alt);
    }
    if (!gh) return NULL;

    const TSLanguage *(*lang_fn)(void) = NULL;
    *(void **)(&lang_fn) = dlsym(gh, fn_name);
    if (!lang_fn) {
        dlclose(gh);
        return NULL;
    }
    const TSLanguage *lobj = lang_fn();
    TSParser *probe = g_ts.parser_new();
    if (!probe || !g_ts.parser_set_language(probe, lobj)) {
        if (probe) g_ts.parser_delete(probe);
        dlclose(gh);
        return NULL;
    }
    g_ts.parser_delete(probe);
    g_ts.langs[lang] = lobj;
    return lobj;
}

/* =========================================================================
 * Language Detection & Line Index Utilities
 * ========================================================================= */
static uint8_t detect_lang_path(const char *path) {
    const char *slash = strrchr(path, '/');
    const char *base = slash ? (slash + 1) : path;
    const char *dot = strrchr(base, '.');
    if (!dot) return LANG_NONE;
    if (strcmp(dot, ".py") == 0 || strcmp(dot, ".pyi") == 0) return LANG_PY;
    if (strcmp(dot, ".ts") == 0 || strcmp(dot, ".mts") == 0) return LANG_TS;
    if (strcmp(dot, ".tsx") == 0) return LANG_TSX;
    if (strcmp(dot, ".js") == 0 || strcmp(dot, ".jsx") == 0 || strcmp(dot, ".mjs") == 0) return LANG_JS;
    if (strcmp(dot, ".rs") == 0) return LANG_RUST;
    if (strcmp(dot, ".go") == 0) return LANG_GO;
    if (strcmp(dot, ".c") == 0 || strcmp(dot, ".h") == 0) return LANG_C;
    if (strcmp(dot, ".cc") == 0 || strcmp(dot, ".cpp") == 0 || strcmp(dot, ".cxx") == 0 ||
        strcmp(dot, ".hpp") == 0 || strcmp(dot, ".hh") == 0) return LANG_CPP;
    if (strcmp(dot, ".java") == 0 || strcmp(dot, ".kt") == 0) return LANG_JAVA;
    if (strcmp(dot, ".sh") == 0 || strcmp(dot, ".bash") == 0 || strcmp(dot, ".zsh") == 0) return LANG_SH;
    return LANG_NONE;
}

static uint8_t normalize_lexer_lang(uint8_t lang) {
    if (lang == LANG_CPP) return LANG_C;
    if (lang == LANG_JS || lang == LANG_TSX) return LANG_TS;
    return lang;
}

static const char *lang_display_name(uint8_t lang) {
    switch (lang) {
        case LANG_PY:   return "python";
        case LANG_TS:   return "typescript";
        case LANG_TSX:  return "tsx";
        case LANG_JS:   return "javascript";
        case LANG_RUST: return "rust";
        case LANG_GO:   return "go";
        case LANG_C:    return "c";
        case LANG_CPP:  return "cpp";
        case LANG_JAVA: return "java";
        case LANG_SH:   return "shell";
        default:        return "text";
    }
}

typedef struct {
    char    *buf;
    size_t   size;
    size_t  *line_offs; /* 1-based: line_offs[1] = 0, line_offs[n_lines + 1] = size */
    uint32_t n_lines;
} MappedFile;

static bool open_mapped_file(const char *path, MappedFile *mf) {
    memset(mf, 0, sizeof(*mf));
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 || st.st_size > (16 * 1024 * 1024)) {
        close(fd);
        return false;
    }
    mf->size = (size_t)st.st_size;
    mf->buf = (char *)malloc(mf->size + 1);
    if (!mf->buf) {
        close(fd);
        return false;
    }
    size_t got = 0;
    while (got < mf->size) {
        ssize_t r = read(fd, mf->buf + got, mf->size - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    mf->size = got;
    mf->buf[mf->size] = '\0';

    uint32_t nl = 1;
    for (size_t i = 0; i < mf->size; i++) {
        if (mf->buf[i] == '\n') nl++;
    }
    if (mf->size > 0 && mf->buf[mf->size - 1] == '\n' && nl > 1) nl--;
    mf->n_lines = nl;
    mf->line_offs = (size_t *)malloc((size_t)(nl + 3) * sizeof(size_t));
    if (!mf->line_offs) {
        free(mf->buf);
        mf->buf = NULL;
        return false;
    }
    mf->line_offs[0] = 0;
    mf->line_offs[1] = 0;
    uint32_t cur = 1;
    for (size_t i = 0; i < mf->size; i++) {
        if (mf->buf[i] == '\n') {
            cur++;
            if (cur <= nl + 1) mf->line_offs[cur] = i + 1;
        }
    }
    mf->line_offs[nl + 1] = mf->size;
    return true;
}

static void close_mapped_file(MappedFile *mf) {
    free(mf->buf);
    free(mf->line_offs);
    memset(mf, 0, sizeof(*mf));
}

static void get_line_slice(const MappedFile *mf, uint32_t line_no, const char **out_s, size_t *out_len) {
    if (line_no < 1 || line_no > mf->n_lines) {
        *out_s = "";
        *out_len = 0;
        return;
    }
    size_t a = mf->line_offs[line_no];
    size_t b = mf->line_offs[line_no + 1];
    while (b > a && (mf->buf[b - 1] == '\n' || mf->buf[b - 1] == '\r')) b--;
    *out_s = mf->buf + a;
    *out_len = b - a;
}

static void compact_signature(const char *s, size_t len, char *out, size_t cap) {
    size_t i = 0;
    while (i < len && (s[i] == ' ' || s[i] == '\t')) i++;
    size_t j = 0;
    bool prev_ws = false;
    for (; i < len && j + 1 < cap; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\r' || c == '\n') break;
        if (c == ' ' || c == '\t') {
            if (!prev_ws) { out[j++] = ' '; prev_ws = true; }
        } else {
            out[j++] = (char)c;
            prev_ws = false;
        }
    }
    while (j > 0 && out[j - 1] == ' ') j--;
    out[j] = '\0';
}

/* =========================================================================
 * Outline / Block Struct & Tree-Sitter CST Slicing Engine
 * ========================================================================= */
typedef struct {
    char     name[192];
    char     sig[240];
    uint32_t start_line;
    uint32_t end_line;
    uint8_t  kind;
} SymSpan;

static bool is_ts_definition_type(const char *t, uint8_t *out_kind) {
    if (!t) return false;
    if (strcmp(t, "function_definition") == 0 ||
        strcmp(t, "function_declaration") == 0 ||
        strcmp(t, "function_item") == 0 ||
        strcmp(t, "generator_function_declaration") == 0) {
        if (out_kind) *out_kind = SK_FN;
        return true;
    }
    if (strcmp(t, "method_definition") == 0 ||
        strcmp(t, "method_declaration") == 0 ||
        strcmp(t, "constructor_declaration") == 0) {
        if (out_kind) *out_kind = SK_METHOD;
        return true;
    }
    if (strcmp(t, "class_definition") == 0 ||
        strcmp(t, "class_declaration") == 0 ||
        strcmp(t, "class_specifier") == 0 ||
        strcmp(t, "impl_item") == 0) {
        if (out_kind) *out_kind = SK_CLASS;
        return true;
    }
    if (strcmp(t, "struct_specifier") == 0 ||
        strcmp(t, "struct_item") == 0 ||
        strcmp(t, "union_specifier") == 0 ||
        strcmp(t, "interface_declaration") == 0 ||
        strcmp(t, "trait_item") == 0) {
        if (out_kind) *out_kind = SK_STRUCT;
        return true;
    }
    if (strcmp(t, "enum_specifier") == 0 ||
        strcmp(t, "enum_item") == 0 ||
        strcmp(t, "enum_declaration") == 0 ||
        strcmp(t, "type_definition") == 0 ||
        strcmp(t, "type_alias_declaration") == 0 ||
        strcmp(t, "type_declaration") == 0 ||
        strcmp(t, "type_item") == 0) {
        if (out_kind) *out_kind = SK_TYPE;
        return true;
    }
    if (strcmp(t, "preproc_function_def") == 0 ||
        strcmp(t, "macro_definition") == 0) {
        if (out_kind) *out_kind = SK_MACRO;
        return true;
    }
    return false;
}

static bool ts_extract_ident_recursive(const MappedFile *mf, TSNode n, int depth, char *out, size_t cap) {
    if (depth > 5 || g_ts.node_is_null(n)) return false;
    const char *nt = g_ts.node_type(n);
    if (!nt) return false;

    if (strcmp(nt, "compound_statement") == 0 ||
        strcmp(nt, "block") == 0 ||
        strcmp(nt, "statement_block") == 0 ||
        strcmp(nt, "declaration_list") == 0 ||
        strcmp(nt, "field_declaration_list") == 0 ||
        strcmp(nt, "enum_variant_list") == 0 ||
        strcmp(nt, "parameter_list") == 0 ||
        strcmp(nt, "formal_parameters") == 0 ||
        strcmp(nt, "parameters") == 0) {
        return false;
    }

    if (strcmp(nt, "identifier") == 0 ||
        strcmp(nt, "field_identifier") == 0 ||
        strcmp(nt, "type_identifier") == 0 ||
        strcmp(nt, "property_identifier") == 0) {
        uint32_t sb = g_ts.node_start_byte(n);
        uint32_t eb = g_ts.node_end_byte(n);
        if (eb > sb && eb <= mf->size && (eb - sb) < cap) {
            memcpy(out, mf->buf + sb, eb - sb);
            out[eb - sb] = '\0';
            return true;
        }
    }

    /* For C typedef struct { ... } TypeName; the trailing type_identifier is after field_declaration_list */
    if (strcmp(nt, "type_definition") == 0) {
        uint32_t nc = g_ts.node_named_child_count(n);
        for (uint32_t i = nc; i > 0; i--) {
            TSNode ch = g_ts.node_named_child(n, i - 1);
            const char *ct = g_ts.node_type(ch);
            if (ct && (strcmp(ct, "type_identifier") == 0 || strcmp(ct, "identifier") == 0)) {
                uint32_t sb = g_ts.node_start_byte(ch);
                uint32_t eb = g_ts.node_end_byte(ch);
                if (eb > sb && eb <= mf->size && (eb - sb) < cap) {
                    memcpy(out, mf->buf + sb, eb - sb);
                    out[eb - sb] = '\0';
                    return true;
                }
            }
        }
    }

    /* For Go method_declaration: skip receiver parameter_list (child 0) to pick field_identifier */
    uint32_t nc = g_ts.node_named_child_count(n);
    for (uint32_t i = 0; i < nc; i++) {
        TSNode ch = g_ts.node_named_child(n, i);
        if (ts_extract_ident_recursive(mf, ch, depth + 1, out, cap)) return true;
    }
    return false;
}

static void ts_expand_leading_attrs(TSNode n, uint32_t *start_line, uint32_t *end_line) {
    TSPoint sp = g_ts.node_start_point(n);
    TSPoint ep = g_ts.node_end_point(n);
    uint32_t sl = sp.row + 1;
    uint32_t el = (ep.column == 0 && ep.row > sp.row) ? ep.row : (ep.row + 1);

    TSNode p = g_ts.node_parent(n);
    if (!g_ts.node_is_null(p)) {
        const char *pt = g_ts.node_type(p);
        if (pt && (strcmp(pt, "decorated_definition") == 0 || strcmp(pt, "export_statement") == 0)) {
            TSPoint psp = g_ts.node_start_point(p);
            if (psp.row + 1 < sl) sl = psp.row + 1;
            n = p;
        }
    }

    TSNode prev = g_ts.node_prev_sibling(n);
    while (!g_ts.node_is_null(prev)) {
        const char *pvt = g_ts.node_type(prev);
        if (!pvt) break;
        if (strcmp(pvt, "attribute_item") == 0 ||
            strcmp(pvt, "decorator") == 0 ||
            strcmp(pvt, "comment") == 0) {
            TSPoint pv_ep = g_ts.node_end_point(prev);
            TSPoint pv_sp = g_ts.node_start_point(prev);
            if (pv_ep.row + 2 >= sl) {
                sl = pv_sp.row + 1;
                prev = g_ts.node_prev_sibling(prev);
                continue;
            }
        }
        break;
    }
    *start_line = sl;
    *end_line = el;
}

static void ts_collect_outline_walk(
    const MappedFile *mf, TSNode n, int depth, SymSpan *out, size_t *count, size_t cap
) {
    if (depth > 8 || *count >= cap || g_ts.node_is_null(n)) return;
    const char *nt = g_ts.node_type(n);
    uint8_t kind = 0;

    if (nt && strcmp(nt, "lexical_declaration") == 0) {
        /* Handle TS/JS `const foo = (...) => { ... }` */
        uint32_t nc = g_ts.node_named_child_count(n);
        for (uint32_t i = 0; i < nc; i++) {
            TSNode vd = g_ts.node_named_child(n, i);
            const char *vdt = g_ts.node_type(vd);
            if (vdt && strcmp(vdt, "variable_declarator") == 0 && g_ts.node_named_child_count(vd) >= 2) {
                TSNode val = g_ts.node_named_child(vd, 1);
                const char *vt = g_ts.node_type(val);
                if (vt && (strcmp(vt, "arrow_function") == 0 || strcmp(vt, "function_expression") == 0)) {
                    char nm[192];
                    if (ts_extract_ident_recursive(mf, vd, 0, nm, sizeof(nm)) && *count < cap) {
                        uint32_t sl = 1, el = 1;
                        ts_expand_leading_attrs(n, &sl, &el);
                        SymSpan *sp = &out[(*count)++];
                        snprintf(sp->name, sizeof(sp->name), "%s", nm);
                        const char *ls; size_t ll;
                        get_line_slice(mf, g_ts.node_start_point(n).row + 1, &ls, &ll);
                        compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                        sp->start_line = sl;
                        sp->end_line = el;
                        sp->kind = SK_FN;
                    }
                }
            }
        }
        return;
    }

    if (is_ts_definition_type(nt, &kind)) {
        /* Skip anonymous inline struct inside a C `type_definition` so typedef emits once */
        TSNode parent = g_ts.node_parent(n);
        const char *pt = g_ts.node_is_null(parent) ? NULL : g_ts.node_type(parent);
        bool inside_typedef = (pt && strcmp(pt, "type_definition") == 0);

        if (!inside_typedef) {
            char nm[192];
            if (ts_extract_ident_recursive(mf, n, 0, nm, sizeof(nm))) {
                uint32_t sl = 1, el = 1;
                ts_expand_leading_attrs(n, &sl, &el);
                if (el >= sl && *count < cap) {
                    SymSpan *sp = &out[(*count)++];
                    snprintf(sp->name, sizeof(sp->name), "%s", nm);
                    const char *ls; size_t ll;
                    get_line_slice(mf, g_ts.node_start_point(n).row + 1, &ls, &ll);
                    compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                    sp->start_line = sl;
                    sp->end_line = el;
                    sp->kind = kind;
                }
            }
        }

        /* Recurse into class/impl/struct/trait bodies for methods, not into function bodies */
        if (kind == SK_CLASS || kind == SK_STRUCT || (nt && strcmp(nt, "type_declaration") == 0)) {
            uint32_t nc = g_ts.node_named_child_count(n);
            for (uint32_t i = 0; i < nc; i++) {
                ts_collect_outline_walk(mf, g_ts.node_named_child(n, i), depth + 1, out, count, cap);
            }
        }
        return;
    }

    uint32_t nc = g_ts.node_named_child_count(n);
    for (uint32_t i = 0; i < nc; i++) {
        ts_collect_outline_walk(mf, g_ts.node_named_child(n, i), depth + 1, out, count, cap);
    }
}

static bool ts_extract_file_spans(const MappedFile *mf, uint8_t lang, SymSpan *out, size_t *out_n, size_t cap) {
    const TSLanguage *tsl = ts_get_language(lang);
    if (!tsl || mf->size == 0 || mf->size > UINT32_MAX) return false;
    TSParser *parser = g_ts.parser_new();
    if (!parser) return false;
    if (!g_ts.parser_set_language(parser, tsl)) {
        g_ts.parser_delete(parser);
        return false;
    }
    TSTree *tree = g_ts.parser_parse_string(parser, NULL, mf->buf, (uint32_t)mf->size);
    if (!tree) {
        g_ts.parser_delete(parser);
        return false;
    }
    *out_n = 0;
    TSNode root = g_ts.tree_root_node(tree);
    ts_collect_outline_walk(mf, root, 0, out, out_n, cap);
    g_ts.tree_delete(tree);
    g_ts.parser_delete(parser);
    return (*out_n > 0);
}

static bool ts_zoom_enclosing_line(
    const MappedFile *mf, uint8_t lang, uint32_t target_line,
    uint32_t *out_start, uint32_t *out_end, char *out_label, size_t lcap
) {
    const TSLanguage *tsl = ts_get_language(lang);
    if (!tsl || target_line < 1 || target_line > mf->n_lines) return false;
    TSParser *parser = g_ts.parser_new();
    if (!parser) return false;
    if (!g_ts.parser_set_language(parser, tsl)) {
        g_ts.parser_delete(parser);
        return false;
    }
    TSTree *tree = g_ts.parser_parse_string(parser, NULL, mf->buf, (uint32_t)mf->size);
    if (!tree) {
        g_ts.parser_delete(parser);
        return false;
    }

    uint32_t byte_off = (uint32_t)mf->line_offs[target_line];
    TSNode root = g_ts.tree_root_node(tree);
    TSNode cur = g_ts.node_descendant_for_byte_range(root, byte_off, byte_off);
    bool found = false;
    while (!g_ts.node_is_null(cur)) {
        uint8_t kind = 0;
        const char *nt = g_ts.node_type(cur);
        if (is_ts_definition_type(nt, &kind)) {
            uint32_t sl = 1, el = 1;
            ts_expand_leading_attrs(cur, &sl, &el);
            if (target_line >= sl && target_line <= el) {
                *out_start = sl;
                *out_end = el;
                char nm[128] = "";
                (void)ts_extract_ident_recursive(mf, cur, 0, nm, sizeof(nm));
                snprintf(out_label, lcap, "%s %s", hslice_kind_label(kind), nm[0] ? nm : nt);
                found = true;
                break;
            }
        }
        cur = g_ts.node_parent(cur);
    }
    g_ts.tree_delete(tree);
    g_ts.parser_delete(parser);
    return found;
}

/* =========================================================================
 * Zero-Dependency C11 Stateful Lexer Slicer (Universal Fallback)
 * ========================================================================= */
static bool is_ident_start_ch(unsigned char c) {
    return isalpha(c) || c == '_' || c == '$';
}

static bool is_ident_ch(unsigned char c) {
    return isalnum(c) || c == '_' || c == '$';
}

static size_t read_ident_tok(const char *s, size_t len, size_t pos, char *out, size_t cap) {
    if (pos >= len || !is_ident_start_ch((unsigned char)s[pos])) return 0;
    size_t st = pos;
    while (pos < len && is_ident_ch((unsigned char)s[pos])) pos++;
    size_t n = pos - st;
    if (out && cap > 0) {
        size_t cp = (n < cap - 1) ? n : (cap - 1);
        memcpy(out, s + st, cp);
        out[cp] = '\0';
    }
    return n;
}

static size_t skip_ws_inline(const char *s, size_t len, size_t pos) {
    while (pos < len && (s[pos] == ' ' || s[pos] == '\t')) pos++;
    return pos;
}

static size_t skip_balanced_inline(const char *s, size_t len, size_t pos, char open_c, char close_c) {
    if (pos >= len || s[pos] != open_c) return pos;
    int depth = 0;
    while (pos < len) {
        char c = s[pos++];
        if (c == '\\' && pos < len) { pos++; continue; }
        if (c == '"' || c == '\'' || c == '`') {
            char q = c;
            while (pos < len && s[pos] != q) {
                if (s[pos] == '\\' && pos + 1 < len) pos += 2;
                else pos++;
            }
            if (pos < len) pos++;
            continue;
        }
        if (c == open_c) depth++;
        else if (c == close_c) {
            depth--;
            if (depth == 0) return pos;
        }
    }
    return pos;
}

/*
 * Compute exact symbol end line using stateful comment/string/raw-string/indent tracking.
 */
static uint32_t lexer_compute_end_line(const MappedFile *mf, uint8_t raw_lang, uint32_t start_line) {
    uint8_t lang = normalize_lexer_lang(raw_lang);
    if (start_line < 1 || start_line > mf->n_lines) return start_line;

    if (lang == LANG_PY) {
        const char *l0; size_t len0;
        get_line_slice(mf, start_line, &l0, &len0);
        int base_indent = 0;
        for (size_t i = 0; i < len0; i++) {
            if (l0[i] == ' ') base_indent++;
            else if (l0[i] == '\t') base_indent += 4;
            else break;
        }

        uint32_t last_code = start_line;
        int paren_depth = 0;
        bool saw_colon = false;
        char triple_q = 0;

        for (uint32_t ln = start_line; ln <= mf->n_lines; ln++) {
            const char *ls; size_t ll;
            get_line_slice(mf, ln, &ls, &ll);

            if (triple_q) {
                last_code = ln;
                for (size_t i = 0; i < ll; i++) {
                    if (ls[i] == '\\' && i + 1 < ll) { i++; continue; }
                    if (i + 2 < ll && ls[i] == triple_q && ls[i + 1] == triple_q && ls[i + 2] == triple_q) {
                        triple_q = 0;
                        i += 2;
                    }
                }
                continue;
            }

            size_t p = 0;
            int ind = 0;
            while (p < ll && (ls[p] == ' ' || ls[p] == '\t')) {
                ind += (ls[p] == '\t') ? 4 : 1;
                p++;
            }
            if (p >= ll) continue; /* blank line */
            if (ls[p] == '#') {
                if (ind > base_indent) last_code = ln;
                continue;
            }

            if (ln > start_line && saw_colon && paren_depth <= 0 && ind <= base_indent) {
                break;
            }

            last_code = ln;
            for (size_t i = p; i < ll; i++) {
                char c = ls[i];
                if (c == '#') break;
                if ((c == '"' || c == '\'') && i + 2 < ll && ls[i + 1] == c && ls[i + 2] == c) {
                    char q = c;
                    i += 3;
                    bool closed = false;
                    while (i < ll) {
                        if (ls[i] == '\\' && i + 1 < ll) { i += 2; continue; }
                        if (i + 2 < ll && ls[i] == q && ls[i + 1] == q && ls[i + 2] == q) {
                            i += 2;
                            closed = true;
                            break;
                        }
                        i++;
                    }
                    if (!closed) {
                        triple_q = q;
                        break;
                    }
                    continue;
                }
                if (c == '"' || c == '\'') {
                    char q = c;
                    i++;
                    while (i < ll && ls[i] != q) {
                        if (ls[i] == '\\' && i + 1 < ll) i += 2;
                        else i++;
                    }
                    continue;
                }
                if (c == '(' || c == '[' || c == '{') paren_depth++;
                else if (c == ')' || c == ']' || c == '}') {
                    if (paren_depth > 0) paren_depth--;
                } else if (c == ':' && paren_depth == 0) {
                    saw_colon = true;
                }
            }
        }
        return last_code;
    }

    /* Brace-delimited languages (C, C++, Rust, Go, TS/JS, Java, Shell) */
    const char *s0; size_t l0;
    get_line_slice(mf, start_line, &s0, &l0);
    size_t p0 = skip_ws_inline(s0, l0, 0);
    if (lang == LANG_C && p0 < l0 && s0[p0] == '#') {
        uint32_t end_ln = start_line;
        while (end_ln <= mf->n_lines) {
            const char *ls; size_t ll;
            get_line_slice(mf, end_ln, &ls, &ll);
            while (ll > 0 && (ls[ll - 1] == ' ' || ls[ll - 1] == '\t')) ll--;
            if (ll > 0 && ls[ll - 1] == '\\' && end_ln < mf->n_lines) end_ln++;
            else break;
        }
        return end_ln;
    }

    int brace_depth = 0;
    int paren_depth = 0;
    bool opened_brace = false;
    bool in_block_comment = false;
    bool in_backtick = false;
    size_t rust_raw_hashes = 0;
    bool in_rust_raw = false;

    for (uint32_t ln = start_line; ln <= mf->n_lines; ln++) {
        const char *ls; size_t ll;
        get_line_slice(mf, ln, &ls, &ll);

        for (size_t i = 0; i < ll; i++) {
            char c = ls[i];

            if (in_block_comment) {
                if (c == '*' && i + 1 < ll && ls[i + 1] == '/') {
                    in_block_comment = false;
                    i++;
                }
                continue;
            }
            if (in_rust_raw) {
                if (c == '"') {
                    size_t h = 0;
                    while (i + 1 + h < ll && ls[i + 1 + h] == '#' && h < rust_raw_hashes) h++;
                    if (h == rust_raw_hashes) {
                        in_rust_raw = false;
                        i += h;
                    }
                }
                continue;
            }
            if (in_backtick) {
                if (lang == LANG_TS && c == '\\' && i + 1 < ll) { i++; continue; }
                if (c == '`') in_backtick = false;
                continue;
            }

            if (lang != LANG_SH && c == '/' && i + 1 < ll) {
                if (ls[i + 1] == '/') break;
                if (ls[i + 1] == '*') {
                    in_block_comment = true;
                    i++;
                    continue;
                }
            }
            if (lang == LANG_SH && c == '#') break;

            if (lang == LANG_RUST && c == 'r' && i + 1 < ll && (ls[i + 1] == '#' || ls[i + 1] == '"')) {
                size_t h = 0;
                size_t k = i + 1;
                while (k < ll && ls[k] == '#') { h++; k++; }
                if (k < ll && ls[k] == '"') {
                    in_rust_raw = true;
                    rust_raw_hashes = h;
                    i = k;
                    continue;
                }
            }

            if ((lang == LANG_GO || lang == LANG_TS) && c == '`') {
                in_backtick = true;
                continue;
            }

            if (c == '"') {
                i++;
                while (i < ll && ls[i] != '"') {
                    if (ls[i] == '\\' && i + 1 < ll) i += 2;
                    else i++;
                }
                continue;
            }

            if (c == '\'') {
                if (lang == LANG_RUST) {
                    /* Distinguish Rust lifetime `'a` from char literal `'x'` / `'\n'` */
                    if (i + 2 < ll && ls[i + 1] != '\\' && ls[i + 2] == '\'') {
                        i += 2;
                        continue;
                    }
                    if (i + 3 < ll && ls[i + 1] == '\\' && ls[i + 3] == '\'') {
                        i += 3;
                        continue;
                    }
                    continue;
                }
                i++;
                while (i < ll && ls[i] != '\'') {
                    if (ls[i] == '\\' && i + 1 < ll) i += 2;
                    else i++;
                }
                continue;
            }

            if (c == '(') paren_depth++;
            else if (c == ')' && paren_depth > 0) paren_depth--;
            else if (c == '{') {
                brace_depth++;
                opened_brace = true;
            } else if (c == '}') {
                brace_depth--;
                if (opened_brace && brace_depth <= 0) {
                    /* Include trailing `} TypeName;` on same line automatically */
                    return ln;
                }
            } else if (!opened_brace && paren_depth == 0 && c == ';') {
                return ln;
            }
        }
    }
    return start_line;
}

static bool is_c_control_kw(const char *w) {
    static const char *const kw[] = {
        "if", "for", "while", "switch", "return", "sizeof", "alignof",
        "catch", "else", "do", "case", "delete", "new", NULL
    };
    for (int i = 0; kw[i]; i++) {
        if (strcmp(w, kw[i]) == 0) return true;
    }
    return false;
}

static size_t lexer_extract_file_spans(const MappedFile *mf, uint8_t raw_lang, SymSpan *out, size_t cap) {
    uint8_t lang = normalize_lexer_lang(raw_lang);
    size_t count = 0;
    bool in_block_comment = false;
    char py_triple = 0;
    uint32_t attr_start_line = 0;

    for (uint32_t ln = 1; ln <= mf->n_lines && count < cap; ln++) {
        const char *ls; size_t ll;
        get_line_slice(mf, ln, &ls, &ll);

        if (lang == LANG_PY && py_triple) {
            for (size_t i = 0; i < ll; i++) {
                if (ls[i] == '\\' && i + 1 < ll) { i++; continue; }
                if (i + 2 < ll && ls[i] == py_triple && ls[i + 1] == py_triple && ls[i + 2] == py_triple) {
                    py_triple = 0;
                    i += 2;
                }
            }
            continue;
        }

        if (lang != LANG_PY && lang != LANG_SH && in_block_comment) {
            const char *endc = (const char *)memmem(ls, ll, "*/", 2);
            if (!endc) continue;
            size_t adv = (size_t)((endc + 2) - ls);
            ls += adv;
            ll -= adv;
            in_block_comment = false;
        }

        size_t p = 0;
        int indent = 0;
        while (p < ll && (ls[p] == ' ' || ls[p] == '\t')) {
            indent += (ls[p] == '\t') ? 4 : 1;
            p++;
        }
        if (p >= ll) {
            attr_start_line = 0;
            continue;
        }

        if (lang == LANG_PY) {
            for (size_t i = p; i < ll; i++) {
                if (ls[i] == '#') break;
                if ((ls[i] == '"' || ls[i] == '\'') && i + 2 < ll && ls[i + 1] == ls[i] && ls[i + 2] == ls[i]) {
                    char q = ls[i];
                    i += 3;
                    bool closed = false;
                    while (i < ll) {
                        if (ls[i] == '\\' && i + 1 < ll) { i += 2; continue; }
                        if (i + 2 < ll && ls[i] == q && ls[i + 1] == q && ls[i + 2] == q) {
                            closed = true; i += 2; break;
                        }
                        i++;
                    }
                    if (!closed) { py_triple = q; break; }
                }
            }
            if (ls[p] == '@') {
                if (attr_start_line == 0) attr_start_line = ln;
                continue;
            }
            if (ls[p] == '#') continue;

            char w1[64], name[192];
            size_t n1 = read_ident_tok(ls, ll, p, w1, sizeof(w1));
            size_t q = p;
            if (n1 == 5 && strcmp(w1, "async") == 0) {
                q = skip_ws_inline(ls, ll, p + n1);
                n1 = read_ident_tok(ls, ll, q, w1, sizeof(w1));
            }
            if (n1 == 3 && strcmp(w1, "def") == 0) {
                q = skip_ws_inline(ls, ll, q + 3);
                if (read_ident_tok(ls, ll, q, name, sizeof(name)) > 0) {
                    SymSpan *sp = &out[count++];
                    snprintf(sp->name, sizeof(sp->name), "%s", name);
                    compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                    sp->start_line = attr_start_line ? attr_start_line : ln;
                    sp->end_line = lexer_compute_end_line(mf, raw_lang, ln);
                    sp->kind = (indent > 0) ? SK_METHOD : SK_FN;
                }
            } else if (n1 == 5 && strcmp(w1, "class") == 0) {
                q = skip_ws_inline(ls, ll, q + 5);
                if (read_ident_tok(ls, ll, q, name, sizeof(name)) > 0) {
                    SymSpan *sp = &out[count++];
                    snprintf(sp->name, sizeof(sp->name), "%s", name);
                    compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                    sp->start_line = attr_start_line ? attr_start_line : ln;
                    sp->end_line = lexer_compute_end_line(mf, raw_lang, ln);
                    sp->kind = SK_CLASS;
                }
            }
            attr_start_line = 0;
            continue;
        }

        if (ls[p] == '/' && p + 1 < ll && ls[p + 1] == '/') continue;
        if (ls[p] == '/' && p + 1 < ll && ls[p + 1] == '*') {
            if (!memmem(ls + p + 2, ll - p - 2, "*/", 2)) in_block_comment = true;
            continue;
        }

        if (lang == LANG_RUST) {
            if (ls[p] == '#' && p + 1 < ll && ls[p + 1] == '[') {
                if (attr_start_line == 0) attr_start_line = ln;
                continue;
            }
            size_t q = p;
            char kw[64], name[192];
            for (;;) {
                size_t kn = read_ident_tok(ls, ll, q, kw, sizeof(kw));
                if (!kn) break;
                if (strcmp(kw, "pub") == 0) {
                    q = skip_ws_inline(ls, ll, q + kn);
                    if (q < ll && ls[q] == '(') q = skip_ws_inline(ls, ll, skip_balanced_inline(ls, ll, q, '(', ')'));
                    continue;
                }
                if (strcmp(kw, "async") == 0 || strcmp(kw, "unsafe") == 0 || strcmp(kw, "const") == 0) {
                    size_t nx = skip_ws_inline(ls, ll, q + kn);
                    char peek[32];
                    if (read_ident_tok(ls, ll, nx, peek, sizeof(peek)) > 0 &&
                        (strcmp(peek, "fn") == 0 || strcmp(peek, "unsafe") == 0 ||
                         strcmp(peek, "extern") == 0 || strcmp(peek, "trait") == 0 || strcmp(peek, "impl") == 0)) {
                        q = nx;
                        continue;
                    }
                }
                if (strcmp(kw, "extern") == 0) {
                    q = skip_ws_inline(ls, ll, q + kn);
                    if (q < ll && ls[q] == '"') {
                        q++;
                        while (q < ll && ls[q] != '"') q++;
                        if (q < ll) q++;
                        q = skip_ws_inline(ls, ll, q);
                    }
                    continue;
                }
                break;
            }
            size_t kn = read_ident_tok(ls, ll, q, kw, sizeof(kw));
            if (kn > 0) {
                uint8_t kind = 0;
                if (strcmp(kw, "fn") == 0) kind = (indent > 0) ? SK_METHOD : SK_FN;
                else if (strcmp(kw, "struct") == 0 || strcmp(kw, "trait") == 0) kind = SK_STRUCT;
                else if (strcmp(kw, "enum") == 0 || strcmp(kw, "type") == 0) kind = SK_TYPE;
                else if (strcmp(kw, "macro_rules") == 0) kind = SK_MACRO;
                if (kind != 0) {
                    q = skip_ws_inline(ls, ll, q + kn);
                    if (kind == SK_MACRO && q < ll && ls[q] == '!') q = skip_ws_inline(ls, ll, q + 1);
                    if (read_ident_tok(ls, ll, q, name, sizeof(name)) > 0) {
                        SymSpan *sp = &out[count++];
                        snprintf(sp->name, sizeof(sp->name), "%s", name);
                        compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                        sp->start_line = attr_start_line ? attr_start_line : ln;
                        sp->end_line = lexer_compute_end_line(mf, raw_lang, ln);
                        sp->kind = kind;
                    }
                }
            }
            attr_start_line = 0;
            continue;
        }

        if (lang == LANG_GO) {
            char kw[64], name[192];
            size_t kn = read_ident_tok(ls, ll, p, kw, sizeof(kw));
            if (kn == 4 && strcmp(kw, "func") == 0) {
                size_t q = skip_ws_inline(ls, ll, p + 4);
                uint8_t kind = SK_FN;
                if (q < ll && ls[q] == '(') {
                    q = skip_ws_inline(ls, ll, skip_balanced_inline(ls, ll, q, '(', ')'));
                    kind = SK_METHOD;
                }
                if (read_ident_tok(ls, ll, q, name, sizeof(name)) > 0) {
                    SymSpan *sp = &out[count++];
                    snprintf(sp->name, sizeof(sp->name), "%s", name);
                    compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                    sp->start_line = ln;
                    sp->end_line = lexer_compute_end_line(mf, raw_lang, ln);
                    sp->kind = kind;
                }
            } else if (kn == 4 && strcmp(kw, "type") == 0) {
                size_t q = skip_ws_inline(ls, ll, p + 4);
                size_t nn = read_ident_tok(ls, ll, q, name, sizeof(name));
                if (nn > 0) {
                    size_t r = skip_ws_inline(ls, ll, q + nn);
                    char tk[32] = "";
                    (void)read_ident_tok(ls, ll, r, tk, sizeof(tk));
                    SymSpan *sp = &out[count++];
                    snprintf(sp->name, sizeof(sp->name), "%s", name);
                    compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                    sp->start_line = ln;
                    sp->end_line = lexer_compute_end_line(mf, raw_lang, ln);
                    sp->kind = (strcmp(tk, "struct") == 0 || strcmp(tk, "interface") == 0) ? SK_STRUCT : SK_TYPE;
                }
            }
            continue;
        }

        if (lang == LANG_TS) {
            if (ls[p] == '@') {
                if (attr_start_line == 0) attr_start_line = ln;
                continue;
            }
            size_t q = p;
            char kw[64], name[192];
            for (;;) {
                size_t kn = read_ident_tok(ls, ll, q, kw, sizeof(kw));
                if (!kn) break;
                if (strcmp(kw, "export") == 0 || strcmp(kw, "default") == 0 || strcmp(kw, "declare") == 0 ||
                    strcmp(kw, "async") == 0 || strcmp(kw, "public") == 0 || strcmp(kw, "private") == 0 ||
                    strcmp(kw, "protected") == 0 || strcmp(kw, "static") == 0 || strcmp(kw, "abstract") == 0) {
                    q = skip_ws_inline(ls, ll, q + kn);
                    continue;
                }
                break;
            }
            size_t kn = read_ident_tok(ls, ll, q, kw, sizeof(kw));
            if (kn > 0) {
                uint8_t kind = 0;
                if (strcmp(kw, "function") == 0) kind = SK_FN;
                else if (strcmp(kw, "class") == 0) kind = SK_CLASS;
                else if (strcmp(kw, "interface") == 0) kind = SK_STRUCT;
                else if (strcmp(kw, "type") == 0 || strcmp(kw, "enum") == 0) kind = SK_TYPE;

                if (kind != 0) {
                    q = skip_ws_inline(ls, ll, q + kn);
                    if (q < ll && ls[q] == '*') q = skip_ws_inline(ls, ll, q + 1);
                    if (read_ident_tok(ls, ll, q, name, sizeof(name)) > 0) {
                        SymSpan *sp = &out[count++];
                        snprintf(sp->name, sizeof(sp->name), "%s", name);
                        compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                        sp->start_line = attr_start_line ? attr_start_line : ln;
                        sp->end_line = lexer_compute_end_line(mf, raw_lang, ln);
                        sp->kind = kind;
                    }
                } else if (strcmp(kw, "const") == 0 || strcmp(kw, "let") == 0) {
                    q = skip_ws_inline(ls, ll, q + kn);
                    if (read_ident_tok(ls, ll, q, name, sizeof(name)) > 0 && memmem(ls + q, ll - q, "=>", 2)) {
                        SymSpan *sp = &out[count++];
                        snprintf(sp->name, sizeof(sp->name), "%s", name);
                        compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                        sp->start_line = attr_start_line ? attr_start_line : ln;
                        sp->end_line = lexer_compute_end_line(mf, raw_lang, ln);
                        sp->kind = SK_FN;
                    }
                } else if (indent > 0 && !is_c_control_kw(kw)) {
                    size_t nx = skip_ws_inline(ls, ll, q + kn);
                    if (nx < ll && ls[nx] == '<') nx = skip_ws_inline(ls, ll, skip_balanced_inline(ls, ll, nx, '<', '>'));
                    if (nx < ll && ls[nx] == '(' && memchr(ls + nx, '{', ll - nx) != NULL) {
                        SymSpan *sp = &out[count++];
                        snprintf(sp->name, sizeof(sp->name), "%s", kw);
                        compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                        sp->start_line = attr_start_line ? attr_start_line : ln;
                        sp->end_line = lexer_compute_end_line(mf, raw_lang, ln);
                        sp->kind = SK_METHOD;
                    }
                }
            }
            attr_start_line = 0;
            continue;
        }

        if (lang == LANG_C || lang == LANG_JAVA) {
            if (ls[p] == '#') {
                size_t q = skip_ws_inline(ls, ll, p + 1);
                char kw[32], name[192];
                if (read_ident_tok(ls, ll, q, kw, sizeof(kw)) == 6 && strcmp(kw, "define") == 0) {
                    q = skip_ws_inline(ls, ll, q + 6);
                    if (read_ident_tok(ls, ll, q, name, sizeof(name)) >= 2) {
                        SymSpan *sp = &out[count++];
                        snprintf(sp->name, sizeof(sp->name), "%s", name);
                        compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                        sp->start_line = ln;
                        sp->end_line = lexer_compute_end_line(mf, raw_lang, ln);
                        sp->kind = SK_MACRO;
                    }
                }
                continue;
            }

            char kw[64], name[192];
            size_t kn = read_ident_tok(ls, ll, p, kw, sizeof(kw));
            if (kn > 0 && strcmp(kw, "typedef") == 0) {
                uint32_t el = lexer_compute_end_line(mf, raw_lang, ln);
                const char *es; size_t ell;
                get_line_slice(mf, el, &es, &ell);
                while (ell > 0 && (es[ell - 1] == ' ' || es[ell - 1] == '\t' || es[ell - 1] == ';')) ell--;
                size_t t = ell;
                while (t > 0 && is_ident_ch((unsigned char)es[t - 1])) t--;
                if (t < ell && is_ident_start_ch((unsigned char)es[t])) {
                    size_t nl = ell - t;
                    if (nl < sizeof(name)) {
                        memcpy(name, es + t, nl);
                        name[nl] = '\0';
                        SymSpan *sp = &out[count++];
                        snprintf(sp->name, sizeof(sp->name), "%s", name);
                        compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                        sp->start_line = ln;
                        sp->end_line = el;
                        sp->kind = SK_TYPE;
                    }
                }
                continue;
            }
            if (kn > 0 && (strcmp(kw, "struct") == 0 || strcmp(kw, "class") == 0 || strcmp(kw, "enum") == 0 || strcmp(kw, "interface") == 0)) {
                size_t q = skip_ws_inline(ls, ll, p + kn);
                size_t nn = read_ident_tok(ls, ll, q, name, sizeof(name));
                if (nn > 0 && memchr(ls + q + nn, ';', ll - (q + nn)) == NULL) {
                    SymSpan *sp = &out[count++];
                    snprintf(sp->name, sizeof(sp->name), "%s", name);
                    compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                    sp->start_line = ln;
                    sp->end_line = lexer_compute_end_line(mf, raw_lang, ln);
                    sp->kind = (strcmp(kw, "class") == 0) ? SK_CLASS :
                               (strcmp(kw, "enum") == 0 ? SK_TYPE : SK_STRUCT);
                    continue;
                }
            }

            if (indent <= 4) {
                /* Scan for top-level / class-level C/C++/Java function definition `ret_type fn_name(args) {` */
                size_t lp = SIZE_MAX;
                for (size_t i = p; i < ll; i++) {
                    if (ls[i] == '/' && i + 1 < ll && ls[i + 1] == '/') break;
                    if (ls[i] == '=' && lp == SIZE_MAX) break;
                    if (ls[i] == '(') { lp = i; break; }
                }
                if (lp != SIZE_MAX && lp > p) {
                    size_t e = lp;
                    while (e > p && (ls[e - 1] == ' ' || ls[e - 1] == '\t')) e--;
                    size_t b = e;
                    while (b > p && is_ident_ch((unsigned char)ls[b - 1])) b--;
                    if (e > b && is_ident_start_ch((unsigned char)ls[b])) {
                        size_t nl = e - b;
                        if (nl < sizeof(name)) {
                            memcpy(name, ls + b, nl);
                            name[nl] = '\0';
                            if (!is_c_control_kw(name)) {
                                size_t rp = skip_balanced_inline(ls, ll, lp, '(', ')');
                                bool has_body = false;
                                if (memchr(ls + (rp <= ll ? rp : lp), '{', ll - (rp <= ll ? rp : lp)) != NULL) {
                                    has_body = true;
                                } else if (memchr(ls + lp, ';', ll - lp) == NULL && ln + 1 <= mf->n_lines) {
                                    for (uint32_t k = ln + 1; k <= mf->n_lines && k <= ln + 4; k++) {
                                        const char *ns; size_t nll;
                                        get_line_slice(mf, k, &ns, &nll);
                                        if (memchr(ns, ';', nll) != NULL) break;
                                        if (memchr(ns, '{', nll) != NULL) { has_body = true; break; }
                                    }
                                }
                                if (has_body) {
                                    SymSpan *sp = &out[count++];
                                    snprintf(sp->name, sizeof(sp->name), "%s", name);
                                    compact_signature(ls, ll, sp->sig, sizeof(sp->sig));
                                    sp->start_line = ln;
                                    sp->end_line = lexer_compute_end_line(mf, raw_lang, ln);
                                    sp->kind = (indent > 0) ? SK_METHOD : SK_FN;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return count;
}

static size_t extract_file_spans(const MappedFile *mf, uint8_t lang, SymSpan *out, size_t cap) {
    size_t n = 0;
    if (ts_extract_file_spans(mf, lang, out, &n, cap) && n > 0) {
        return n;
    }
    return lexer_extract_file_spans(mf, lang, out, cap);
}

/* =========================================================================
 * Shared `hsym` Index Loader & Lazy `mtime_ns` Auto-Refresh
 * ========================================================================= */
typedef struct {
    void             *map;
    size_t            map_size;
    const HSymHeader *hdr;
    const SymDirRec  *dirs;
    const SymFileRec *files;
    const SymRec     *syms;
    const char       *pool;
    const TriBucket  *tri;
    const uint32_t   *post;
} OpenHSym;

static size_t materialize_sym_dir(
    const SymDirRec *dirs, uint32_t n_dirs, uint32_t dir_idx, const char *pool, char *out, size_t cap
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
        const char *nm = pool + d->name_off;
        size_t nl = d->name_len;
        if (i < depth - 1 && pos > 0 && out[pos - 1] != '/') {
            if (pos + 1 < cap) out[pos++] = '/';
        }
        if (pos + nl >= cap) nl = (cap > pos + 1) ? (cap - pos - 1) : 0;
        if (nl > 0) {
            memcpy(out + pos, nm, nl);
            pos += nl;
        }
    }
    out[pos] = '\0';
    return pos;
}

static size_t materialize_sym_file(
    const SymDirRec *dirs, uint32_t n_dirs, const SymFileRec *f, const char *pool, char *out, size_t cap
) {
    size_t pos = materialize_sym_dir(dirs, n_dirs, f->dir_idx, pool, out, cap);
    if (pos > 0 && out[pos - 1] != '/' && pos + 1 < cap) out[pos++] = '/';
    const char *fn = pool + f->name_off;
    size_t nl = f->name_len;
    if (pos + nl >= cap) nl = (cap > pos + 1) ? (cap - pos - 1) : 0;
    if (nl > 0) {
        memcpy(out + pos, fn, nl);
        pos += nl;
    }
    out[pos] = '\0';
    return pos;
}

static void close_hsym(OpenHSym *oh) {
    if (oh->map) munmap(oh->map, oh->map_size);
    memset(oh, 0, sizeof(*oh));
}

static bool map_hsym_raw(const char *idx_path, OpenHSym *oh) {
    memset(oh, 0, sizeof(*oh));
    int fd = open(idx_path, O_RDONLY);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(HSymHeader)) {
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
    oh->map = map;
    oh->map_size = (size_t)st.st_size;
    oh->hdr = h;
    oh->dirs = (const SymDirRec *)((const char *)map + h->dirs_off);
    oh->files = (const SymFileRec *)((const char *)map + h->files_off);
    oh->syms = (const SymRec *)((const char *)map + h->syms_off);
    oh->pool = (const char *)map + h->pool_off;
    oh->tri = (const TriBucket *)((const char *)map + h->trigrams_off);
    oh->post = (const uint32_t *)((const char *)map + h->postings_off);
    return true;
}

static bool is_hsym_stale(const OpenHSym *oh, bool check_all_files) {
    char pbuf[PATH_MAX];
    for (uint32_t i = 0; i < oh->hdr->n_dirs; i++) {
        if (oh->dirs[i].watch_id == 0xFFFFU) continue;
        materialize_sym_dir(oh->dirs, oh->hdr->n_dirs, i, oh->pool, pbuf, sizeof(pbuf));
        struct stat st;
        if (stat(pbuf, &st) != 0 || !S_ISDIR(st.st_mode)) return true;
        uint64_t mns = hslice_stat_mtime_ns(&st);
        if (mns != oh->dirs[i].mtime_ns || mns > oh->hdr->built_ns) return true;
    }
    if (check_all_files || oh->hdr->n_files <= 2048) {
        uint32_t cached_did = UINT32_MAX;
        char dpath[PATH_MAX];
        size_t dlen = 0;
        for (uint32_t fi = 0; fi < oh->hdr->n_files; fi++) {
            const SymFileRec *f = &oh->files[fi];
            if (f->dir_idx != cached_did) {
                cached_did = f->dir_idx;
                dlen = materialize_sym_dir(oh->dirs, oh->hdr->n_dirs, cached_did, oh->pool, dpath, sizeof(dpath));
            }
            if (dlen + 1 + f->name_len >= sizeof(pbuf)) continue;
            memcpy(pbuf, dpath, dlen);
            size_t pos = dlen;
            if (pos > 0 && pbuf[pos - 1] != '/') pbuf[pos++] = '/';
            memcpy(pbuf + pos, oh->pool + f->name_off, f->name_len);
            pbuf[pos + f->name_len] = '\0';
            struct stat st;
            if (stat(pbuf, &st) != 0) return true;
            uint64_t fmns = hslice_stat_mtime_ns(&st);
            if (fmns != f->mtime_ns || (uint32_t)st.st_size != f->size_lo || fmns > oh->hdr->built_ns) {
                return true;
            }
        }
    }
    return false;
}

static bool run_sibling_hfind_rebuild(const char *argv0, char *const *roots, int n_roots) {
    char hfind_bin[PATH_MAX];
    hslice_resolve_sibling_bin(argv0, "hfind", hfind_bin, sizeof(hfind_bin));

    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        char *args[48];
        int k = 0;
        args[k++] = hfind_bin;
        args[k++] = "--sym";
        args[k++] = "--rebuild";
        for (int i = 0; i < n_roots && k + 2 < 46; i++) {
            args[k++] = "--root";
            args[k++] = roots[i];
        }
        args[k] = NULL;
        execvp(hfind_bin, args);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool ensure_hsym_ready(const char *argv0, char *const *roots, int n_roots, bool check_all_files, OpenHSym *oh) {
    char idx_path[PATH_MAX];
    hslice_idx_path_for_roots(idx_path, sizeof(idx_path), "hsym", roots, n_roots);

    if (map_hsym_raw(idx_path, oh)) {
        if (!is_hsym_stale(oh, check_all_files)) {
            return true;
        }
        close_hsym(oh);
    }
    if (!run_sibling_hfind_rebuild(argv0, roots, n_roots)) return false;
    return map_hsym_raw(idx_path, oh);
}

/* =========================================================================
 * Crisp Slice Printer & Live Symbol Freshness Verification
 * ========================================================================= */
static void print_slice_block(
    const MappedFile *mf, const char *display_path, const char *label,
    uint32_t start_line, uint32_t end_line
) {
    if (mf->n_lines == 0) {
        printf("=== %s:0-0 [%s] (0/0 lines) ===\n", display_path, label ? label : "slice");
        return;
    }
    if (start_line < 1) start_line = 1;
    if (start_line > mf->n_lines) start_line = mf->n_lines;
    if (end_line > mf->n_lines) end_line = mf->n_lines;
    if (end_line < start_line) end_line = start_line;

    uint32_t total_span = end_line - start_line + 1;
    uint32_t emit_end = end_line;
    bool truncated = false;
    if (total_span > MAX_SLICE_LINES) {
        emit_end = start_line + MAX_SLICE_LINES - 1;
        truncated = true;
    }

    printf("=== %s:%u-%u [%s] (%u/%u lines) ===\n",
           display_path, start_line, end_line, label ? label : "slice", total_span, mf->n_lines);
    for (uint32_t ln = start_line; ln <= emit_end; ln++) {
        const char *ls; size_t ll;
        get_line_slice(mf, ln, &ls, &ll);
        printf("%4u | %.*s\n", ln, (int)ll, ls);
    }
    if (truncated) {
        printf(" ... | [truncated at %d lines; use `hslice %s:%u-%u` for remaining lines]\n",
               MAX_SLICE_LINES, display_path, emit_end + 1, end_line);
    }
}

static void rel_or_abs_path(const char *fpath, const char *root, char *out, size_t cap) {
    if (root && root[0]) {
        size_t rl = strlen(root);
        while (rl > 1 && root[rl - 1] == '/') rl--;
        if (strncmp(fpath, root, rl) == 0 && fpath[rl] == '/') {
            snprintf(out, cap, "%s", fpath + rl + 1);
            return;
        }
    }
    snprintf(out, cap, "%s", fpath);
}

typedef struct {
    char     path[PATH_MAX];
    char     name[192];
    uint32_t start_line;
    uint32_t end_line;
    uint8_t  kind;
    uint8_t  lang;
    int32_t  score;
} SliceCand;

static int cmp_slice_cand(const void *a, const void *b) {
    const SliceCand *x = (const SliceCand *)a;
    const SliceCand *y = (const SliceCand *)b;
    if (x->score != y->score) return (y->score > x->score) ? 1 : -1;
    int pc = strcmp(x->path, y->path);
    if (pc != 0) return pc;
    return (int)x->start_line - (int)y->start_line;
}

static size_t query_symbol_candidates(
    const OpenHSym *oh, const char *symbol, const char *file_hint,
    SliceCand *out, size_t cap
) {
    size_t slen = strlen(symbol);
    if (slen == 0) return 0;

    uint32_t *cand_ids = NULL;
    size_t n_cand_ids = 0;
    bool used_tri = false;

    if (slen >= 3) {
        size_t best_cnt = SIZE_MAX;
        uint32_t best_slot = 0;
        for (size_t i = 0; i + 2 < slen; i++) {
            uint32_t slot = hslice_pack_tri((unsigned char)symbol[i],
                                            (unsigned char)symbol[i + 1],
                                            (unsigned char)symbol[i + 2]);
            if (oh->tri[slot].count < best_cnt) {
                best_cnt = oh->tri[slot].count;
                best_slot = slot;
            }
        }
        used_tri = true;
        n_cand_ids = best_cnt;
        if (best_cnt > 0) {
            cand_ids = (uint32_t *)malloc(best_cnt * sizeof(uint32_t));
            if (cand_ids) {
                memcpy(cand_ids, oh->post + oh->tri[best_slot].offset, best_cnt * sizeof(uint32_t));
            }
        }
    }

    size_t fh_len = file_hint ? strlen(file_hint) : 0;
    size_t found = 0;
    size_t iter_n = used_tri ? n_cand_ids : oh->hdr->n_syms;

    uint32_t cached_fid = UINT32_MAX;
    char cached_path[PATH_MAX];
    size_t cached_plen = 0;

    for (size_t i = 0; i < iter_n; i++) {
        uint32_t sid = used_tri ? cand_ids[i] : (uint32_t)i;
        if (sid >= oh->hdr->n_syms) continue;
        const SymRec *sr = &oh->syms[sid];
        const char *sname = oh->pool + sr->name_off;

        int32_t sc = -1;
        if (sr->name_len == slen && strcmp(sname, symbol) == 0) {
            sc = 1000;
        } else if (sr->name_len == slen && strcasecmp(sname, symbol) == 0) {
            sc = 700;
        } else if (hslice_ci_strstr(sname, sr->name_len, symbol, slen) != NULL) {
            sc = 300 - (int32_t)(sr->name_len - slen) * 4;
        }
        if (sc < 0) continue;

        const SymFileRec *fr = &oh->files[sr->file_id];
        if (sr->file_id != cached_fid) {
            cached_fid = sr->file_id;
            cached_plen = materialize_sym_file(oh->dirs, oh->hdr->n_dirs, fr, oh->pool, cached_path, sizeof(cached_path));
        }
        if (fh_len > 0 && hslice_ci_strstr(cached_path, cached_plen, file_hint, fh_len) == NULL) {
            continue;
        }

        if (sr->kind == SK_FN || sr->kind == SK_CLASS || sr->kind == SK_STRUCT) sc += 30;
        else if (sr->kind == SK_METHOD || sr->kind == SK_TYPE) sc += 20;
        sc += (int32_t)fr->tier * 10;
        if (strstr(cached_path, "/tests/") || strstr(cached_path, "/test_")) sc -= 25;

        if (found < cap) {
            SliceCand *c = &out[found++];
            snprintf(c->path, sizeof(c->path), "%s", cached_path);
            snprintf(c->name, sizeof(c->name), "%s", sname);
            c->start_line = sr->start_line;
            c->end_line = sr->end_line;
            c->kind = sr->kind;
            c->lang = detect_lang_path(cached_path);
            c->score = sc;
        } else {
            /* Replace lowest if strictly better */
            size_t min_idx = 0;
            for (size_t k = 1; k < found; k++) {
                if (out[k].score < out[min_idx].score) min_idx = k;
            }
            if (sc > out[min_idx].score) {
                SliceCand *c = &out[min_idx];
                snprintf(c->path, sizeof(c->path), "%s", cached_path);
                snprintf(c->name, sizeof(c->name), "%s", sname);
                c->start_line = sr->start_line;
                c->end_line = sr->end_line;
                c->kind = sr->kind;
                c->lang = detect_lang_path(cached_path);
                c->score = sc;
            }
        }
    }

    free(cand_ids);
    if (found > 1) qsort(out, found, sizeof(SliceCand), cmp_slice_cand);
    return found;
}

static void refine_span_with_ast(const MappedFile *mf, SliceCand *c) {
    SymSpan spans[MAX_OUTLINE];
    size_t n_spans = extract_file_spans(mf, c->lang, spans, MAX_OUTLINE);
    for (size_t i = 0; i < n_spans; i++) {
        if (strcmp(spans[i].name, c->name) == 0 &&
            (spans[i].start_line == c->start_line ||
             (spans[i].start_line <= c->start_line && spans[i].end_line >= c->start_line))) {
            c->start_line = spans[i].start_line;
            c->end_line = spans[i].end_line;
            c->kind = spans[i].kind;
            return;
        }
    }
    for (size_t i = 0; i < n_spans; i++) {
        if (strcmp(spans[i].name, c->name) == 0) {
            c->start_line = spans[i].start_line;
            c->end_line = spans[i].end_line;
            c->kind = spans[i].kind;
            return;
        }
    }
    if (c->end_line <= c->start_line) {
        c->end_line = lexer_compute_end_line(mf, c->lang, c->start_line);
    }
}

/* =========================================================================
 * Mode 1: File:Line Zoom & File:Start-End Exact Span Slice
 * ========================================================================= */
static bool parse_file_colon_spec(
    const char *spec, char *out_file, size_t fcap,
    uint32_t *out_start, uint32_t *out_end, bool *is_range, char *out_sym_hint, size_t scap
) {
    const char *colon = strrchr(spec, ':');
    if (!colon || colon == spec || colon[1] == '\0') return false;
    /* Ignore C++ `Class::method` */
    if (colon > spec && colon[-1] == ':') return false;

    size_t flen = (size_t)(colon - spec);
    if (flen >= fcap) return false;
    memcpy(out_file, spec, flen);
    out_file[flen] = '\0';

    const char *rhs = colon + 1;
    if (rhs[0] == 'L' || rhs[0] == 'l') rhs++;
    if (isdigit((unsigned char)rhs[0])) {
        struct stat st;
        if (stat(out_file, &st) != 0 || !S_ISREG(st.st_mode)) return false;
        char *endp = NULL;
        unsigned long s = strtoul(rhs, &endp, 10);
        if (s == 0) s = 1;
        *out_start = (uint32_t)s;
        if (endp && (*endp == '-' || *endp == ':')) {
            const char *r2 = endp + 1;
            if (*r2 == 'L' || *r2 == 'l') r2++;
            unsigned long e = strtoul(r2, &endp, 10);
            *out_end = (e >= s) ? (uint32_t)e : (uint32_t)s;
            *is_range = true;
        } else {
            *out_end = (uint32_t)s;
            *is_range = false;
        }
        out_sym_hint[0] = '\0';
        return true;
    }

    /* `file_hint:symbol_name` shorthand */
    snprintf(out_sym_hint, scap, "%s", colon + 1);
    *out_start = 0;
    *out_end = 0;
    *is_range = false;
    return true;
}

static int cmd_slice_file_line(const char *fpath, uint32_t s_line, uint32_t e_line, bool is_range, const char *root) {
    MappedFile mf;
    if (!open_mapped_file(fpath, &mf)) {
        fprintf(stderr, "hslice: cannot open file '%s'\n", fpath);
        return 1;
    }
    char disp[PATH_MAX];
    rel_or_abs_path(fpath, root, disp, sizeof(disp));
    uint8_t lang = detect_lang_path(fpath);

    if (is_range) {
        print_slice_block(&mf, disp, "span", s_line, e_line);
        close_mapped_file(&mf);
        return 0;
    }

    /* Stack-trace single-line zoom: locate enclosing AST symbol */
    uint32_t zs = 0, ze = 0;
    char zlabel[256];
    if (ts_zoom_enclosing_line(&mf, lang, s_line, &zs, &ze, zlabel, sizeof(zlabel))) {
        print_slice_block(&mf, disp, zlabel, zs, ze);
        close_mapped_file(&mf);
        return 0;
    }

    SymSpan spans[MAX_OUTLINE];
    size_t n_spans = lexer_extract_file_spans(&mf, lang, spans, MAX_OUTLINE);
    const SymSpan *best = NULL;
    for (size_t i = 0; i < n_spans; i++) {
        if (s_line >= spans[i].start_line && s_line <= spans[i].end_line) {
            if (!best || (spans[i].end_line - spans[i].start_line) <= (best->end_line - best->start_line)) {
                best = &spans[i];
            }
        }
    }
    if (best) {
        snprintf(zlabel, sizeof(zlabel), "%s %s", hslice_kind_label(best->kind), best->name);
        print_slice_block(&mf, disp, zlabel, best->start_line, best->end_line);
    } else if (mf.n_lines == 0) {
        snprintf(zlabel, sizeof(zlabel), "context@L0");
        print_slice_block(&mf, disp, zlabel, 0, 0);
    } else {
        uint32_t target = (s_line > mf.n_lines) ? mf.n_lines : (s_line < 1 ? 1 : s_line);
        uint32_t ws = (target > 15) ? (target - 15) : 1;
        uint32_t we = (target + 15 <= mf.n_lines) ? (target + 15) : mf.n_lines;
        snprintf(zlabel, sizeof(zlabel), "context@L%u", target);
        print_slice_block(&mf, disp, zlabel, ws, we);
    }
    close_mapped_file(&mf);
    return 0;
}

/* =========================================================================
 * Mode 2: Structural Skeleton Outline (`hslice -s <file>`)
 * ========================================================================= */
static int cmd_skeleton(const char *fpath, const char *root) {
    MappedFile mf;
    if (!open_mapped_file(fpath, &mf)) {
        fprintf(stderr, "hslice: cannot open file '%s'\n", fpath);
        return 1;
    }
    uint8_t lang = detect_lang_path(fpath);
    SymSpan spans[MAX_OUTLINE];
    size_t n = extract_file_spans(&mf, lang, spans, MAX_OUTLINE);

    char disp[PATH_MAX];
    rel_or_abs_path(fpath, root, disp, sizeof(disp));
    printf("=== %s [skeleton: %zu symbols, %u lines, %s] ===\n",
           disp, n, mf.n_lines, lang_display_name(lang));
    for (size_t i = 0; i < n; i++) {
        printf("  L%-4u-%-4u  [%-6s] %s\n",
               spans[i].start_line, spans[i].end_line,
               hslice_kind_label(spans[i].kind), spans[i].sig);
    }
    close_mapped_file(&mf);
    return 0;
}

/* =========================================================================
 * Mode 3: Bounded Cross-Reference Callers (`hslice -x <sym> [dir]`)
 * ========================================================================= */
static bool has_exec_in_path(const char *bin) {
    const char *pe = getenv("PATH");
    if (!pe) return false;
    const char *p = pe;
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

static void emit_bounded_callers(
    const char *symbol, const char *search_dir,
    const char *def_abs_path, uint32_t def_start, uint32_t def_end
) {
    bool use_rg = has_exec_in_path("rg");
    char *argv_exec[32];
    int k = 0;
    if (use_rg) {
        argv_exec[k++] = "rg";
        argv_exec[k++] = "--no-heading";
        argv_exec[k++] = "--with-filename";
        argv_exec[k++] = "--line-number";
        argv_exec[k++] = "--color=never";
        argv_exec[k++] = "--max-columns=220";
        argv_exec[k++] = "-w";
        argv_exec[k++] = "--";
        argv_exec[k++] = (char *)symbol;
        argv_exec[k++] = (char *)(search_dir ? search_dir : ".");
    } else {
        argv_exec[k++] = "grep";
        argv_exec[k++] = "-rnI";
        argv_exec[k++] = "-H";
        argv_exec[k++] = "-w";
        argv_exec[k++] = "--exclude-dir=.git";
        argv_exec[k++] = "--exclude-dir=node_modules";
        argv_exec[k++] = "--exclude-dir=.venv";
        argv_exec[k++] = "--exclude-dir=target";
        argv_exec[k++] = "--exclude-dir=__pycache__";
        argv_exec[k++] = "--";
        argv_exec[k++] = (char *)symbol;
        argv_exec[k++] = (char *)(search_dir ? search_dir : ".");
    }
    argv_exec[k] = NULL;

    int pfd[2];
    if (pipe(pfd) != 0) return;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return; }
    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) { dup2(dn, STDERR_FILENO); close(dn); }
        close(pfd[1]);
        execvp(argv_exec[0], argv_exec);
        _exit(127);
    }
    close(pfd[1]);

    printf("\n=== Callers & References: %s ===\n", symbol);
    FILE *fp = fdopen(pfd[0], "r");
    int emitted = 0;
    bool truncated = false;
    char line[4096];
    if (fp) {
        while (fgets(line, sizeof(line), fp) != NULL) {
            /* Parse `path:line:content` to filter lines already inside the primary definition span */
            const char *c1 = strchr(line, ':');
            const char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
            if (c1 && c2 && def_abs_path) {
                char hit_file[PATH_MAX];
                size_t fl = (size_t)(c1 - line);
                if (fl < sizeof(hit_file)) {
                    memcpy(hit_file, line, fl);
                    hit_file[fl] = '\0';
                    char rp[PATH_MAX];
                    const char *resolved = realpath(hit_file, rp) ? rp : hit_file;
                    unsigned long lno = strtoul(c1 + 1, NULL, 10);
                    if (strcmp(resolved, def_abs_path) == 0 && lno >= def_start && lno <= def_end) {
                        continue;
                    }
                }
            }
            if (emitted < MAX_XREF_LINES) {
                printf("  %s", line);
                if (line[strlen(line) - 1] != '\n') putchar('\n');
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
    if (emitted == 0) {
        printf("  (no external callers found)\n");
    } else if (truncated) {
        printf("  ... [capped at %d caller lines]\n", MAX_XREF_LINES);
    }
}

/* =========================================================================
 * Mode 4: Shareable Repository Token-Savings Receipt (`hslice --audit`)
 * ========================================================================= */
typedef struct {
    char     symbol[192];
    char     location[PATH_MAX];
    uint64_t file_tokens;
    uint64_t slice_tokens;
    uint64_t saved_tokens;
    double   saved_pct;
} AuditRow;

static int cmp_audit_row_desc(const void *a, const void *b) {
    const AuditRow *x = (const AuditRow *)a;
    const AuditRow *y = (const AuditRow *)b;
    if (x->saved_tokens != y->saved_tokens) return (y->saved_tokens > x->saved_tokens) ? 1 : -1;
    if (y->saved_pct > x->saved_pct) return 1;
    if (y->saved_pct < x->saved_pct) return -1;
    return strcmp(x->symbol, y->symbol);
}

static void format_u64_commas(uint64_t v, char *out, size_t cap) {
    char raw[32];
    int n = snprintf(raw, sizeof(raw), "%" PRIu64, v);
    if (n <= 0) { snprintf(out, cap, "0"); return; }
    size_t j = 0;
    for (int i = 0; i < n && j + 2 < cap; i++) {
        if (i > 0 && ((n - i) % 3) == 0) out[j++] = ',';
        out[j++] = raw[i];
    }
    out[j] = '\0';
}

static int cmd_audit(const char *argv0, const char *target_dir, bool json_out) {
    const char *cli_roots[1];
    int n_cli = 0;
    if (target_dir && target_dir[0]) {
        cli_roots[0] = target_dir;
        n_cli = 1;
    }
    char rbufs[MAX_ROOTS][PATH_MAX];
    char *roots[MAX_ROOTS];
    int n_roots = hslice_discover_roots(cli_roots, n_cli, rbufs, roots);

    OpenHSym oh;
    if (!ensure_hsym_ready(argv0, roots, n_roots, true, &oh)) {
        fprintf(stderr, "hslice: failed to index repository for --audit\n");
        return 1;
    }

    uint64_t total_file_tok = 0;
    uint64_t total_slice_tok = 0;
    uint32_t total_files = 0;
    uint32_t total_syms = 0;

    size_t cap_rows = oh.hdr->n_syms ? oh.hdr->n_syms : 16;
    AuditRow *rows = (AuditRow *)calloc(cap_rows, sizeof(AuditRow));
    size_t n_rows = 0;

    char fpath[PATH_MAX];
    char relp[PATH_MAX];
    for (uint32_t fi = 0; fi < oh.hdr->n_files; fi++) {
        const SymFileRec *fr = &oh.files[fi];
        if (fr->sym_count == 0) continue;
        materialize_sym_file(oh.dirs, oh.hdr->n_dirs, fr, oh.pool, fpath, sizeof(fpath));

        MappedFile mf;
        if (!open_mapped_file(fpath, &mf) || mf.size == 0) {
            close_mapped_file(&mf);
            continue;
        }
        total_files++;
        uint64_t ftok = (mf.size + 3) / 4;
        if (ftok == 0) ftok = 1;
        rel_or_abs_path(fpath, roots[0], relp, sizeof(relp));

        SymSpan spans[MAX_OUTLINE];
        size_t n_spans = extract_file_spans(&mf, detect_lang_path(fpath), spans, MAX_OUTLINE);

        if (n_spans > 0) {
            for (size_t si = 0; si < n_spans; si++) {
                uint32_t sl = spans[si].start_line < 1 ? 1 : spans[si].start_line;
                uint32_t el = spans[si].end_line > mf.n_lines ? mf.n_lines : spans[si].end_line;
                if (el < sl) el = sl;
                size_t sb = mf.line_offs[sl];
                size_t eb = mf.line_offs[el + 1];
                size_t sbytes = (eb > sb) ? (eb - sb) : 4;
                uint64_t stok = (sbytes + 3) / 4;
                if (stok == 0) stok = 1;
                if (stok > ftok) stok = ftok;

                total_syms++;
                total_file_tok += ftok;
                total_slice_tok += stok;

                if (rows && n_rows == cap_rows) {
                    cap_rows *= 2;
                    rows = (AuditRow *)realloc(rows, cap_rows * sizeof(AuditRow));
                }
                if (rows && n_rows < cap_rows) {
                    AuditRow *ar = &rows[n_rows++];
                    hslice_copy_str(ar->symbol, sizeof(ar->symbol), spans[si].name);
                    int ln = snprintf(ar->location, sizeof(ar->location), "%s:%u", relp, sl);
                    if (ln < 0 || (size_t)ln >= sizeof(ar->location)) {
                        ar->location[sizeof(ar->location) - 1] = '\0';
                    }
                    ar->file_tokens = ftok;
                    ar->slice_tokens = stok;
                    ar->saved_tokens = (ftok > stok) ? (ftok - stok) : 0;
                    ar->saved_pct = ftok > 0 ? ((1.0 - ((double)stok / (double)ftok)) * 100.0) : 0.0;
                }
            }
        } else {
            for (uint32_t k = 0; k < fr->sym_count; k++) {
                const SymRec *sr = &oh.syms[fr->first_sym + k];
                uint32_t sl = sr->start_line < 1 ? 1 : sr->start_line;
                uint32_t el = sr->end_line > mf.n_lines ? mf.n_lines : sr->end_line;
                if (el < sl) el = lexer_compute_end_line(&mf, detect_lang_path(fpath), sl);
                size_t sb = mf.line_offs[sl];
                size_t eb = mf.line_offs[el + 1];
                size_t sbytes = (eb > sb) ? (eb - sb) : 4;
                uint64_t stok = (sbytes + 3) / 4;
                if (stok == 0) stok = 1;
                if (stok > ftok) stok = ftok;

                total_syms++;
                total_file_tok += ftok;
                total_slice_tok += stok;
            }
        }
        close_mapped_file(&mf);
    }

    if (rows && n_rows > 1) qsort(rows, n_rows, sizeof(AuditRow), cmp_audit_row_desc);

    double saved_pct = (total_file_tok > 0)
        ? ((1.0 - ((double)total_slice_tok / (double)total_file_tok)) * 100.0)
        : 0.0;
    double density_x = (total_slice_tok > 0)
        ? ((double)total_file_tok / (double)total_slice_tok)
        : 1.0;

    size_t top_n = (n_rows < 5) ? n_rows : 5;
    if (json_out) {
        char re[PATH_MAX * 2];
        hslice_json_escape(roots[0], re, sizeof(re));
        printf("{\"ok\":true,\"root\":\"%s\",\"files\":%u,\"symbols\":%u,"
               "\"file_tokens\":%" PRIu64 ",\"slice_tokens\":%" PRIu64 ","
               "\"total_file_tokens\":%" PRIu64 ",\"total_slice_tokens\":%" PRIu64 ","
               "\"saved_pct\":%.1f,\"density_x\":%.1f,\"top_symbols\":[",
               re, total_files, total_syms,
               total_file_tok, total_slice_tok,
               total_file_tok, total_slice_tok,
               saved_pct, density_x);
        for (size_t i = 0; i < top_n; i++) {
            char se[384], le[PATH_MAX * 2];
            hslice_json_escape(rows[i].symbol, se, sizeof(se));
            hslice_json_escape(rows[i].location, le, sizeof(le));
            printf("%s{\"symbol\":\"%s\",\"location\":\"%s\",\"file_tokens\":%" PRIu64
                   ",\"slice_tokens\":%" PRIu64 ",\"saved_pct\":%.1f}",
                   i > 0 ? "," : "", se, le,
                   rows[i].file_tokens, rows[i].slice_tokens, rows[i].saved_pct);
        }
        printf("]}\n");
    } else {
        const char *rbase = strrchr(roots[0], '/');
        rbase = (rbase && rbase[1]) ? (rbase + 1) : roots[0];
        char ft_str[32], st_str[32];
        format_u64_commas(total_file_tok, ft_str, sizeof(ft_str));
        format_u64_commas(total_slice_tok, st_str, sizeof(st_str));

        printf("hslice token audit: %s (%u files, %u symbols)\n", rbase, total_files, total_syms);
        printf("------------------------------------------------------------------------------\n");
        printf("%-22s %-30s %9s %9s %6s\n", "symbol", "location", "file_tok", "slice_tok", "saved");
        printf("------------------------------------------------------------------------------\n");
        for (size_t i = 0; i < top_n; i++) {
            char f1[24], s1[24], loc_disp[36];
            format_u64_commas(rows[i].file_tokens, f1, sizeof(f1));
            format_u64_commas(rows[i].slice_tokens, s1, sizeof(s1));
            size_t ll = strlen(rows[i].location);
            if (ll <= 30) {
                hslice_copy_str(loc_disp, sizeof(loc_disp), rows[i].location);
            } else {
                memcpy(loc_disp, "...", 3);
                memcpy(loc_disp + 3, rows[i].location + (ll - 27), 27);
                loc_disp[30] = '\0';
            }
            printf("%-22.22s %-30s %9s %9s %5.1f%%\n",
                   rows[i].symbol, loc_disp, f1, s1, rows[i].saved_pct);
        }
        printf("------------------------------------------------------------------------------\n");
        printf("all %u indexed symbols    %14s %10s %5.1f%%\n",
               total_syms, ft_str, st_str, saved_pct);
        printf("context density: %.1fx  (%.1f%% fewer tokens vs whole-file reads)\n",
               density_x, saved_pct);
    }

    free(rows);
    close_hsym(&oh);
    return 0;
}

/* =========================================================================
 * Mode 5: Primary Symbol Lookup & Slice (`hslice <symbol>` / `hslice -x`)
 * ========================================================================= */
static int cmd_slice_symbol(
    const char *argv0, const char *symbol, const char *file_hint,
    const char **cli_roots, int n_cli_roots, bool include_xref, const char *xref_dir
) {
    char rbufs[MAX_ROOTS][PATH_MAX];
    char *roots[MAX_ROOTS];
    int n_roots = hslice_discover_roots(cli_roots, n_cli_roots, rbufs, roots);

    OpenHSym oh;
    if (!ensure_hsym_ready(argv0, roots, n_roots, false, &oh)) {
        fprintf(stderr, "hslice: failed to open or build symbol index\n");
        return 1;
    }

    SliceCand cands[MAX_MATCHES];
    size_t n_cands = query_symbol_candidates(&oh, symbol, file_hint, cands, MAX_MATCHES);
    if (n_cands == 0) {
        /* Full per-file mtime verification in case an existing file gained a new symbol in-place */
        if (is_hsym_stale(&oh, true)) {
            close_hsym(&oh);
            if (run_sibling_hfind_rebuild(argv0, roots, n_roots)) {
                char idx_path[PATH_MAX];
                hslice_idx_path_for_roots(idx_path, sizeof(idx_path), "hsym", roots, n_roots);
                if (map_hsym_raw(idx_path, &oh)) {
                    n_cands = query_symbol_candidates(&oh, symbol, file_hint, cands, MAX_MATCHES);
                }
            }
        }
    }
    close_hsym(&oh);

    if (n_cands == 0) {
        fprintf(stderr, "hslice: symbol '%s' not found\n", symbol);
        return 1;
    }

    /* Emit exact matches (up to 3 if tied/exact), plus compact disambiguation hint if more exist */
    size_t emit_n = 1;
    for (size_t i = 1; i < n_cands && emit_n < 3; i++) {
        if (cands[i].score >= 950 && cands[0].score >= 950) emit_n++;
    }

    char primary_abs[PATH_MAX] = "";
    uint32_t primary_s = 0, primary_e = 0;
    int emitted_ok = 0;

    for (size_t i = 0; i < emit_n; i++) {
        MappedFile mf;
        if (!open_mapped_file(cands[i].path, &mf)) continue;
        refine_span_with_ast(&mf, &cands[i]);

        char disp[PATH_MAX];
        rel_or_abs_path(cands[i].path, roots[0], disp, sizeof(disp));
        char label[256];
        snprintf(label, sizeof(label), "%s %s", hslice_kind_label(cands[i].kind), cands[i].name);

        if (emitted_ok > 0) putchar('\n');
        print_slice_block(&mf, disp, label, cands[i].start_line, cands[i].end_line);
        if (emitted_ok == 0) {
            char rp[PATH_MAX];
            hslice_copy_str(primary_abs, sizeof(primary_abs), realpath(cands[i].path, rp) ? rp : cands[i].path);
            primary_s = cands[i].start_line;
            primary_e = cands[i].end_line;
        }
        emitted_ok++;
        close_mapped_file(&mf);
    }

    if (emitted_ok == 0) {
        fprintf(stderr, "hslice: matched files for '%s' are no longer readable\n", symbol);
        return 1;
    }

    if (n_cands > emit_n) {
        size_t extra = (n_cands - emit_n > 5) ? 5 : (n_cands - emit_n);
        printf("\n[other matches: ");
        for (size_t i = 0; i < extra; i++) {
            const SliceCand *sc = &cands[emit_n + i];
            char disp[PATH_MAX];
            rel_or_abs_path(sc->path, roots[0], disp, sizeof(disp));
            printf("%s%s:%u (%s)", i > 0 ? ", " : "", disp, sc->start_line, sc->name);
        }
        printf("]\n");
    }

    if (include_xref) {
        const char *sdir = (xref_dir && xref_dir[0]) ? xref_dir : roots[0];
        emit_bounded_callers(symbol, sdir, primary_abs, primary_s, primary_e);
    }
    return 0;
}

/* =========================================================================
 * CLI Entrypoint
 * ========================================================================= */
static void print_help(void) {
    printf("hslice v%s - Hephaestus Organ 1 Structural AST Code Slicer\n\n"
           "Usage:\n"
           "  hslice <symbol>                      Extract exact AST function, class, or struct slice\n"
           "  hslice -x <symbol> [dir]             Extract symbol definition + bounded callers/references\n"
           "  hslice <file>:<line>                 Stack-trace zoom to enclosing AST function/class\n"
           "  hslice <file>:<start>-<end>          Extract exact line span from file\n"
           "  hslice -s <file>                     Emit compact structural symbol skeleton of file\n"
           "  hslice --audit [dir] [--json]        Compute repository token-savings receipt (-A)\n\n"
           "Options:\n"
           "  -s, --skeleton <file>                Structural file outline mode\n"
           "  -x, --xref                         Include bounded cross-file callers\n"
           "  -f, --file <substr>                Restrict symbol lookup to matching file path\n"
           "  -A, --audit [dir]                    Repository token-savings audit receipt\n"
           "  -j, --json                           Emit JSON (with --audit)\n"
           "      --root <dir>                     Explicit workspace root (repeatable)\n"
           "  -V, --version                        Show version\n"
           "  -h, --help                           Show this help\n",
           HSLICE_VERSION);
}

int main(int argc, char **argv) {
    bool skeleton_mode = false;
    bool xref_mode = false;
    bool audit_mode = false;
    bool json_out = false;
    const char *file_hint = NULL;
    const char *cli_roots[MAX_ROOTS];
    int n_cli_roots = 0;
    const char *pos[8];
    int n_pos = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            print_help();
            return 0;
        }
        if (strcmp(a, "-V") == 0 || strcmp(a, "--version") == 0) {
            printf("hslice %s\n", HSLICE_VERSION);
            return 0;
        }
        if (strcmp(a, "-s") == 0 || strcmp(a, "--skeleton") == 0 || strcmp(a, "--outline") == 0) {
            skeleton_mode = true;
            continue;
        }
        if (strcmp(a, "-x") == 0 || strcmp(a, "--xref") == 0) {
            xref_mode = true;
            continue;
        }
        if (strcmp(a, "-A") == 0 || strcmp(a, "--audit") == 0) {
            audit_mode = true;
            continue;
        }
        if (strcmp(a, "-j") == 0 || strcmp(a, "--json") == 0) {
            json_out = true;
            continue;
        }
        if ((strcmp(a, "-f") == 0 || strcmp(a, "--file") == 0) && i + 1 < argc) {
            file_hint = argv[++i];
            continue;
        }
        if (strcmp(a, "--root") == 0 && i + 1 < argc) {
            if (n_cli_roots < MAX_ROOTS) cli_roots[n_cli_roots++] = argv[++i];
            else i++;
            continue;
        }
        if (strcmp(a, "--") == 0) {
            for (int k = i + 1; k < argc && n_pos < 8; k++) pos[n_pos++] = argv[k];
            break;
        }
        if (a[0] == '-') {
            fprintf(stderr, "hslice: unknown option '%s' (try --help)\n", a);
            return 2;
        }
        if (n_pos < 8) pos[n_pos++] = a;
    }

    if (audit_mode) {
        const char *adir = (n_pos > 0) ? pos[0] : (n_cli_roots > 0 ? cli_roots[0] : NULL);
        return cmd_audit(argv[0], adir, json_out);
    }

    if (n_pos == 0) {
        print_help();
        return 2;
    }

    char rbufs[MAX_ROOTS][PATH_MAX];
    char *roots[MAX_ROOTS];
    int n_roots = hslice_discover_roots(cli_roots, n_cli_roots, rbufs, roots);
    (void)n_roots;

    if (skeleton_mode) {
        return cmd_skeleton(pos[0], roots[0]);
    }

    char spec_file[PATH_MAX];
    char sym_from_spec[192];
    uint32_t s_line = 0, e_line = 0;
    bool is_range = false;
    if (!xref_mode && parse_file_colon_spec(pos[0], spec_file, sizeof(spec_file),
                                            &s_line, &e_line, &is_range,
                                            sym_from_spec, sizeof(sym_from_spec))) {
        if (s_line > 0) {
            return cmd_slice_file_line(spec_file, s_line, e_line, is_range, roots[0]);
        }
        if (sym_from_spec[0]) {
            return cmd_slice_symbol(argv[0], sym_from_spec, spec_file, cli_roots, n_cli_roots, false, NULL);
        }
    }

    const char *xref_dir = NULL;
    if (n_pos >= 2) {
        struct stat st;
        if (stat(pos[1], &st) == 0 && S_ISDIR(st.st_mode)) {
            xref_dir = pos[1];
            if (n_cli_roots == 0) {
                cli_roots[0] = pos[1];
                n_cli_roots = 1;
            }
        }
    }
    return cmd_slice_symbol(argv[0], pos[0], file_hint, cli_roots, n_cli_roots, xref_mode, xref_dir);
}
