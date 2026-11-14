#ifndef HMEMORY_STEM_H
#define HMEMORY_STEM_H

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deterministic 64-bit string mixer for compact UIDs and deduplication */
static inline uint64_t hm_mix64_bytes(const void *data, size_t len, uint64_t seed) {
    const unsigned char *p = (const unsigned char *)data;
    uint64_t h = 0x9E3779B97F4A7C15ULL ^ seed;
    for (size_t i = 0; i < len; i++) {
        h = (h ^ (uint64_t)p[i]) * 0xBF58476D1CE4E5B9ULL;
        h ^= h >> 29U;
    }
    h = (h ^ (h >> 30U)) * 0x94D049BB133111EBULL;
    h ^= h >> 31U;
    return h ? h : 1ULL;
}

static inline uint64_t hm_mix64_str(const char *s) {
    return s ? hm_mix64_bytes(s, strlen(s), 0x484D454DULL) : 1ULL;
}

static inline int hm_strcasecmp(const char *a, const char *b) {
    if (!a || !b) return (a == b) ? 0 : (a ? 1 : -1);
    while (*a && *b) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        a++;
        b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

/* Decode one UTF-8 character and fold Turkish & Latin diacritics to lowercase ASCII */
static inline size_t hm_fold_utf8_step(const unsigned char *s, size_t len, size_t *idx, char out_ch[4]) {
    size_t i = *idx;
    unsigned char b0 = s[i];
    if (b0 < 0x80U) {
        *idx = i + 1U;
        out_ch[0] = (b0 >= 'A' && b0 <= 'Z') ? (char)(b0 - 'A' + 'a') : (char)b0;
        return 1U;
    }
    if ((b0 & 0xE0U) == 0xC0U && (i + 1U) < len) {
        unsigned char b1 = s[i + 1U];
        if ((b1 & 0xC0U) == 0x80U) {
            *idx = i + 2U;
            if (b0 == 0xCCU && b1 == 0x87U) {
                return 0U; /* Combining dot above U+0307 */
            }
            uint32_t cp = ((uint32_t)(b0 & 0x1FU) << 6U) | (uint32_t)(b1 & 0x3FU);
            switch (cp) {
                case 0x00C7U: case 0x00E7U: out_ch[0] = 'c'; return 1U;
                case 0x011EU: case 0x011FU: out_ch[0] = 'g'; return 1U;
                case 0x0130U: case 0x0131U: case 0x00CEU: case 0x00EEU:
                case 0x00CCU: case 0x00ECU: case 0x00CDU: case 0x00EDU: out_ch[0] = 'i'; return 1U;
                case 0x00D6U: case 0x00F6U: case 0x00D2U: case 0x00F2U:
                case 0x00D3U: case 0x00F3U: case 0x00D4U: case 0x00F4U: out_ch[0] = 'o'; return 1U;
                case 0x015EU: case 0x015FU: out_ch[0] = 's'; return 1U;
                case 0x00DCU: case 0x00FCU: case 0x00DBU: case 0x00FBU:
                case 0x00D9U: case 0x00F9U: case 0x00DAU: case 0x00FAU: out_ch[0] = 'u'; return 1U;
                case 0x00C0U: case 0x00E0U: case 0x00C1U: case 0x00E1U:
                case 0x00C2U: case 0x00E2U: case 0x00C4U: case 0x00E4U: out_ch[0] = 'a'; return 1U;
                case 0x00C8U: case 0x00E8U: case 0x00C9U: case 0x00E9U:
                case 0x00CAU: case 0x00EAU: case 0x00CBU: case 0x00EBU: out_ch[0] = 'e'; return 1U;
                default: out_ch[0] = ' '; return 1U;
            }
        }
    }
    if ((b0 & 0xF0U) == 0xE0U && (i + 2U) < len) {
        *idx = i + 3U;
        out_ch[0] = ' ';
        return 1U;
    }
    if ((b0 & 0xF8U) == 0xF0U && (i + 3U) < len) {
        *idx = i + 4U;
        out_ch[0] = ' ';
        return 1U;
    }
    *idx = i + 1U;
    out_ch[0] = ' ';
    return 1U;
}

static inline bool hm_is_stopword(const char *w) {
    static const char *const STOPS[] = {
        "the", "and", "for", "with", "from", "that", "this", "into", "when",
        "where", "which", "while", "were", "been", "have", "has", "had",
        "are", "was", "not", "but", "can", "will", "just", "than", "then",
        "bir", "icin", "ile", "ama", "fakat", "ancak", "veya", "gibi",
        "kadar", "daha", "cok", "olan", "olarak", "oldu", "olur", "ise"
    };
    for (size_t i = 0; i < sizeof(STOPS) / sizeof(STOPS[0]); i++) {
        if (strcmp(w, STOPS[i]) == 0) return true;
    }
    return false;
}

static inline bool hm_is_protected_root(const char *w) {
    static const char *const ROOTS[] = {
        "postgres", "postgresql", "sqlite", "sqlite3", "redis", "status", "process",
        "address", "canvas", "serverless", "class", "pass", "glass", "bus", "gas",
        "macos", "linux", "posix", "fts5", "wal", "jtms", "mutex", "index", "matrix",
        "series", "species", "alias", "basis", "analysis", "crisis", "thesis",
        "sistem", "adres", "servis", "analiz", "proses", "indeks", "matris",
        "stres", "kriz", "test", "disk", "risk", "port", "lock", "task",
        "bellek", "mimari", "karar", "kural", "cozum", "sorun", "katman",
        "veritabani", "tablo", "zincir", "kayit", "vakit", "nakit", "metin",
        "sehir", "fikir", "isim", "kisim", "resim", "devir", "cevir", "hukum"
    };
    for (size_t i = 0; i < sizeof(ROOTS) / sizeof(ROOTS[0]); i++) {
        if (strcmp(w, ROOTS[i]) == 0) return true;
    }
    return false;
}

static inline const char *hm_tr_vowel_restore(const char *w) {
    static const struct { const char *inflected; const char *root; } PAIRS[] = {
        {"kayd", "kayit"}, {"vakt", "vakit"}, {"nakd", "nakit"}, {"izn", "izin"},
        {"ism", "isim"},   {"kism", "kisim"}, {"resm", "resim"}, {"sehr", "sehir"},
        {"fikr", "fikir"}, {"beyn", "beyin"}, {"metn", "metin"}, {"devr", "devir"},
        {"cevr", "cevir"}, {"ayr", "ayir"},   {"hacm", "hacim"}, {"hukm", "hukum"},
        {"sekl", "sekil"}, {"akl", "akil"}
    };
    for (size_t i = 0; i < sizeof(PAIRS) / sizeof(PAIRS[0]); i++) {
        if (strcmp(w, PAIRS[i].inflected) == 0) return PAIRS[i].root;
    }
    return NULL;
}

static inline bool hm_ends_with(const char *w, size_t wlen, const char *sfx, size_t min_stem) {
    size_t slen = strlen(sfx);
    return (wlen >= slen + min_stem) && (memcmp(w + wlen - slen, sfx, slen) == 0);
}

static inline bool hm_strip_any_suffix(char *w, size_t *wlen, const char *const *list, size_t count, size_t min_stem) {
    if (hm_is_protected_root(w)) return false;
    for (size_t i = 0; i < count; i++) {
        size_t slen = strlen(list[i]);
        if (*wlen >= slen + min_stem && memcmp(w + *wlen - slen, list[i], slen) == 0) {
            /* Guard Turkish causative -stir/-ldir/-ndir against copula -tir/-dir */
            if (slen == 3U && (strcmp(list[i], "tir") == 0 || strcmp(list[i], "dir") == 0 ||
                               strcmp(list[i], "tur") == 0 || strcmp(list[i], "dur") == 0)) {
                if (*wlen >= 6U) {
                    char prev = w[*wlen - 4U];
                    if (prev == 's' || prev == 'n' || prev == 'l') continue;
                }
            }
            *wlen -= slen;
            w[*wlen] = '\0';
            return true;
        }
    }
    return false;
}

static inline bool hm_is_vowel(char c) {
    return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u';
}

/* Produce English stem if English morphology applies */
static inline void hm_stem_en(const char *in, char *out, size_t out_cap) {
    size_t n = strlen(in);
    if (n >= out_cap) n = out_cap - 1U;
    memcpy(out, in, n);
    out[n] = '\0';
    if (n <= 3U || hm_is_protected_root(out)) return;

    /* Step 1: Plurals */
    if (hm_ends_with(out, n, "ies", 2U)) {
        out[n - 3U] = 'y';
        n = n - 2U;
        out[n] = '\0';
    } else if (hm_ends_with(out, n, "sses", 2U)) {
        n -= 2U;
        out[n] = '\0';
    } else if (hm_ends_with(out, n, "ches", 2U) || hm_ends_with(out, n, "shes", 2U) ||
               hm_ends_with(out, n, "xes", 2U) || hm_ends_with(out, n, "zes", 2U)) {
        n -= 2U;
        out[n] = '\0';
    } else if (n >= 5U && out[n - 1U] == 's' && out[n - 2U] != 's' &&
               out[n - 2U] != 'u' && out[n - 2U] != 'i') {
        n -= 1U;
        out[n] = '\0';
    }

    if (hm_is_protected_root(out)) return;

    /* Step 2: Past / gerund (-ing, -ed) */
    bool trimmed_verb = false;
    if (hm_ends_with(out, n, "ing", 3U)) {
        bool has_v = false;
        for (size_t i = 0; i < n - 3U; i++) if (hm_is_vowel(out[i])) has_v = true;
        if (has_v) {
            n -= 3U;
            out[n] = '\0';
            trimmed_verb = true;
        }
    } else if (hm_ends_with(out, n, "ied", 2U)) {
        out[n - 3U] = 'y';
        n -= 2U;
        out[n] = '\0';
    } else if (hm_ends_with(out, n, "ed", 3U)) {
        bool has_v = false;
        for (size_t i = 0; i < n - 2U; i++) if (hm_is_vowel(out[i])) has_v = true;
        if (has_v) {
            n -= 2U;
            out[n] = '\0';
            trimmed_verb = true;
        }
    }
    if (trimmed_verb && n >= 4U) {
        if (out[n - 1U] == out[n - 2U] && out[n - 1U] != 'l' && out[n - 1U] != 's' && out[n - 1U] != 'z') {
            n -= 1U;
            out[n] = '\0';
        } else if (hm_ends_with(out, n, "at", 2U) || hm_ends_with(out, n, "bl", 2U) || hm_ends_with(out, n, "iz", 2U)) {
            if (n + 1U < out_cap) {
                out[n++] = 'e';
                out[n] = '\0';
            }
        }
    }

    /* Step 3: Nominal/derivational */
    static const char *const EN_DERIV[] = {
        "ational", "tional", "ization", "isation", "fulness", "iveness", "ousness",
        "ation", "ition", "ment", "ness", "able", "ible", "ally", "ly"
    };
    (void)hm_strip_any_suffix(out, &n, EN_DERIV, sizeof(EN_DERIV) / sizeof(EN_DERIV[0]), 4U);

    /* Normalize trailing silent 'e' so cache/caching -> cach, pool/pooling -> pool */
    if (n >= 5U && out[n - 1U] == 'e' && !hm_is_protected_root(out)) {
        n -= 1U;
        out[n] = '\0';
    }
    if (n >= 4U && out[n - 1U] == 'y' && !hm_is_vowel(out[n - 2U])) {
        out[n - 1U] = 'i';
    }
}

/* Produce Turkish stem if agglutinative Turkish suffixes apply */
static inline void hm_stem_tr(const char *in, char *out, size_t out_cap) {
    size_t n = strlen(in);
    if (n >= out_cap) n = out_cap - 1U;
    memcpy(out, in, n);
    out[n] = '\0';
    if (n <= 3U || hm_is_protected_root(out)) return;

    const char *vr = hm_tr_vowel_restore(out);
    if (vr) {
        snprintf(out, out_cap, "%s", vr);
        return;
    }

    static const char *const TR_COPULA[] = {
        "dirlar", "dirler", "tirlar", "tirler", "siniz", "sunuz",
        "dir", "tir", "dur", "tur", "sin", "sun", "yiz", "yuz"
    };
    static const char *const TR_CASE[] = {
        "ndaki", "ndeki", "daki", "deki", "taki", "teki",
        "ndan", "nden", "tan", "ten", "dan", "den",
        "nda", "nde", "ta", "te", "da", "de",
        "nin", "nun", "yin", "yun", "yla", "yle", "la", "le",
        "ye", "ya", "ne", "na", "yi", "yu", "ni", "nu"
    };
    static const char *const TR_POSS[] = {
        "larimiz", "lerimiz", "lariniz", "leriniz", "larini", "lerini",
        "larinda", "lerinde", "larindan", "lerinden",
        "imiz", "umuz", "iniz", "unuz", "lari", "leri",
        "lar", "ler", "miz", "muz", "niz", "nuz", "si", "su", "im", "um", "in", "un"
    };
    static const char *const TR_VERBAL[] = {
        "ebiliyor", "abiliyor", "ebilir", "abilir", "emiyor", "amiyor",
        "duklari", "diklari", "dugumuz", "digimiz", "dugu", "digi", "tugu", "tigi",
        "acagi", "ecegi", "acak", "ecek", "iyorlar", "uyorlar", "iyor", "uyor",
        "makta", "mekte", "masi", "mesi", "mak", "mek", "madan", "meden",
        "arak", "erek", "dik", "duk", "tik", "tuk", "mis", "mus", "di", "du", "ti", "tu"
    };
    static const char *const TR_DERIV[] = {
        "lik", "luk", "siz", "suz", "sal", "sel"
    };

    (void)hm_strip_any_suffix(out, &n, TR_COPULA, sizeof(TR_COPULA) / sizeof(TR_COPULA[0]), 3U);
    bool stripped_case = hm_strip_any_suffix(out, &n, TR_CASE, sizeof(TR_CASE) / sizeof(TR_CASE[0]), 3U);
    bool stripped_poss = hm_strip_any_suffix(out, &n, TR_POSS, sizeof(TR_POSS) / sizeof(TR_POSS[0]), 3U);
    if (stripped_poss && n >= 5U && !hm_is_protected_root(out)) {
        (void)hm_strip_any_suffix(out, &n, TR_CASE, sizeof(TR_CASE) / sizeof(TR_CASE[0]), 3U);
    }
    bool stripped_verb = false;
    if (!hm_is_protected_root(out)) {
        stripped_verb = hm_strip_any_suffix(out, &n, TR_VERBAL, sizeof(TR_VERBAL) / sizeof(TR_VERBAL[0]), 3U);
        if (!stripped_verb && n >= 6U && !hm_is_protected_root(out)) {
            static const char *const TR_VN[] = { "ma", "me" };
            stripped_verb = hm_strip_any_suffix(out, &n, TR_VN, 2U, 4U);
        }
    }

    if (!stripped_verb && !hm_is_protected_root(out) && n >= 4U) {
        char last = out[n - 1U];
        if (last == 'i' || last == 'u' || last == 'a' || last == 'e') {
            char cand[64];
            size_t clen = n - 1U;
            if (clen < sizeof(cand)) {
                memcpy(cand, out, clen);
                cand[clen] = '\0';
                const char *irr = hm_tr_vowel_restore(cand);
                if (irr) {
                    snprintf(out, out_cap, "%s", irr);
                    return;
                }
                if (clen >= 4U && (cand[clen - 1U] == 'g' || cand[clen - 1U] == 'b' || cand[clen - 1U] == 'd')) {
                    memcpy(out, cand, clen + 1U);
                    n = clen;
                } else if (!stripped_poss && n >= 5U && (last == 'i' || last == 'u')) {
                    memcpy(out, cand, clen + 1U);
                    n = clen;
                } else if (!stripped_case && !stripped_poss && n >= 5U) {
                    memcpy(out, cand, clen + 1U);
                    n = clen;
                }
            }
        }
    }

    if (!stripped_verb && n >= 7U && !hm_is_protected_root(out)) {
        (void)hm_strip_any_suffix(out, &n, TR_DERIV, sizeof(TR_DERIV) / sizeof(TR_DERIV[0]), 4U);
    }

    const char *vr2 = hm_tr_vowel_restore(out);
    if (vr2) {
        snprintf(out, out_cap, "%s", vr2);
        return;
    }
    if (n >= 4U && !hm_is_protected_root(out)) {
        if (out[n - 1U] == 'g') out[n - 1U] = 'k';
        else if (out[n - 1U] == 'b') out[n - 1U] = 'p';
        else if (out[n - 1U] == 'd') out[n - 1U] = 't';
    }
}

typedef struct {
    char   items[256][48];
    size_t count;
} hm_tokbag_t;

static inline void hm_tokbag_add(hm_tokbag_t *bag, const char *tok) {
    if (!tok || strlen(tok) < 2U || hm_is_stopword(tok) || bag->count >= 256U) return;
    for (size_t i = 0; i < bag->count; i++) {
        if (strcmp(bag->items[i], tok) == 0) return;
    }
    snprintf(bag->items[bag->count++], 48U, "%s", tok);
}

/* Extract deduplicated bilingual (EN + TR) ASCII-folded tokens and stems */
static inline void hm_extract_bilingual_stems(const char *text, hm_tokbag_t *bag, bool raw_only) {
    if (!text) return;
    const unsigned char *s = (const unsigned char *)text;
    size_t len = strlen(text);
    size_t idx = 0U;
    char cur[64];
    size_t clen = 0U;

    while (idx <= len) {
        char ch[4] = {0};
        bool is_end = (idx == len);
        size_t n = 0U;
        if (!is_end) {
            n = hm_fold_utf8_step(s, len, &idx, ch);
            if (n == 0U) continue;
        } else {
            idx++;
        }
        char c = (!is_end && n == 1U) ? ch[0] : ' ';
        bool alnum = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');

        /* Strip Turkish proper-noun apostrophe suffixes ("SQLite'da" -> "sqlite") */
        if (!is_end && c == '\'' && clen >= 2U) {
            while (idx < len) {
                size_t prev = idx;
                char skip_ch[4];
                size_t sn = hm_fold_utf8_step(s, len, &idx, skip_ch);
                if (sn == 0U) continue;
                char sc = (sn == 1U) ? skip_ch[0] : ' ';
                if (!((sc >= 'a' && sc <= 'z') || (sc >= '0' && sc <= '9'))) {
                    idx = prev;
                    break;
                }
            }
            c = ' ';
            alnum = false;
        }

        if (alnum) {
            if (clen < sizeof(cur) - 1U) cur[clen++] = c;
        } else if (clen > 0U) {
            cur[clen] = '\0';
            if (clen >= 2U && !hm_is_stopword(cur)) {
                hm_tokbag_add(bag, cur);
                if (!raw_only) {
                    char en_s[64], tr_s[64];
                    hm_stem_en(cur, en_s, sizeof(en_s));
                    hm_stem_tr(cur, tr_s, sizeof(tr_s));
                    if (strcmp(en_s, cur) != 0) hm_tokbag_add(bag, en_s);
                    if (strcmp(tr_s, cur) != 0) hm_tokbag_add(bag, tr_s);
                }
            }
            clen = 0U;
        }
    }
}

static inline char *hm_build_stem_bag_str(const char *title, const char *body, const char *tags) {
    hm_tokbag_t bag;
    bag.count = 0U;
    hm_extract_bilingual_stems(title, &bag, false);
    hm_extract_bilingual_stems(tags, &bag, false);
    hm_extract_bilingual_stems(body, &bag, false);

    size_t cap = bag.count * 50U + 16U;
    char *out = (char *)malloc(cap);
    if (!out) return NULL;
    size_t pos = 0U;
    out[0] = '\0';
    for (size_t i = 0; i < bag.count; i++) {
        size_t l = strlen(bag.items[i]);
        if (pos + l + 2U >= cap) break;
        if (pos > 0U) out[pos++] = ' ';
        memcpy(out + pos, bag.items[i], l);
        pos += l;
    }
    out[pos] = '\0';
    return out;
}

/* Conservative subword token estimator ensuring strict adherence to --budget-tokens */
static inline int hm_estimate_tokens(const char *text) {
    if (!text || !text[0]) return 0;
    size_t bytes = strlen(text);
    size_t words = 0U;
    bool in_w = false;
    for (size_t i = 0; i < bytes; i++) {
        if (isspace((unsigned char)text[i])) {
            in_w = false;
        } else if (!in_w) {
            in_w = true;
            words++;
        }
    }
    int by_bytes = (int)((bytes + 2U) / 3U);
    int by_words = (int)((double)words * 1.38 + 1.0);
    return (by_bytes > by_words) ? by_bytes : by_words;
}

/* UTF-8 codepoint & word-boundary safe text clipper for tight context emission */
static inline void hm_clip_utf8_clean(const char *src, size_t max_bytes, char *out, size_t out_cap) {
    if (!out || out_cap == 0U) return;
    out[0] = '\0';
    if (!src || max_bytes == 0U) return;

    char flat[2048];
    size_t w = 0U;
    bool prev_sp = true;
    for (size_t i = 0; src[i] != '\0' && w + 1U < sizeof(flat); i++) {
        char c = src[i];
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        if (c == '<') c = '(';
        else if (c == '>') c = ')';
        if (c == ' ') {
            if (prev_sp) continue;
            prev_sp = true;
        } else {
            prev_sp = false;
        }
        flat[w++] = c;
    }
    while (w > 0U && flat[w - 1U] == ' ') w--;
    flat[w] = '\0';

    size_t lim = (max_bytes < out_cap - 1U) ? max_bytes : (out_cap - 1U);
    if (w <= lim) {
        memcpy(out, flat, w + 1U);
        return;
    }
    if (lim <= 4U) {
        memcpy(out, flat, lim);
        out[lim] = '\0';
        return;
    }

    size_t cut = lim - 3U;
    while (cut > 0U && (((unsigned char)flat[cut] & 0xC0U) == 0x80U)) cut--;

    size_t space_cut = 0U;
    for (size_t i = cut; i > lim / 2U; i--) {
        if (flat[i] == ' ') {
            space_cut = i;
            break;
        }
    }
    if (space_cut > 0U) cut = space_cut;
    while (cut > 0U && (flat[cut - 1U] == ' ' || flat[cut - 1U] == ',' || flat[cut - 1U] == ';')) cut--;

    memcpy(out, flat, cut);
    memcpy(out + cut, "...", 4U);
}

#endif /* HMEMORY_STEM_H */
