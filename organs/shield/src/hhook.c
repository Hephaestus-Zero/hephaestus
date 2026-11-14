/*
 * hhook.c - Hephaestus Organ 2: Sub-Millisecond PreToolUse & Shell Guard
 *
 * Portable C11 implementation:
 *   - `hhook check "<cmd>" [--json]`: structural POSIX/Bash command verifier
 *   - `PreToolUse` JSON stdin hook mode (`claude-pre`, `cursor-pre`, `agy-pre`,
 *     or zero-argument stdin hook invocation for Claude Code / Cursor / MCP)
 *
 * Quote- and subshell-aware lexical/structural shell analyzer:
 *   - Accurately ignores quoted literals (`echo "rm -rf / > /etc/passwd"`),
 *     `[[ $a > $b ]]` comparisons, heredoc bodies, comments, and `2>&1` / `/dev/null`
 *   - Descends into `$(...)`, `"$(...)"`, backticks `` `...` ``, process
 *     substitutions `<(...)` / `>(...)`, and nested `sh -c` / `bash -c` / `eval`
 *   - Blocks destructive wipes (`rm -rf /`, `~`, `--no-preserve-root`,
 *     `mkfs.*`, `wipefs`, `dd of=/dev/sd*`, `chmod -R 777 /`)
 *   - Blocks shell fork bombs (`:(){ :|:& };:` and generalized recursive `fn(){ fn|fn& }`)
 *   - Blocks secret read + network egress exfiltration (`~/.ssh`, `~/.aws`,
 *     `~/.gnupg`, `.env`, API tokens paired with `curl`, `wget`, `nc`, `dig`, `/dev/tcp/`)
 *   - Blocks dangerous output redirections (`/etc`, `/usr`, `/boot`,
 *     `/dev/sda`, `~/.ssh`, `~/.bashrc`, `/dev/tcp`) and remote pipe-to-shell
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
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define HHOOK_VERSION   "0.1.0"
#define MAX_CMD_WORDS   128
#define MAX_WORD_LEN    2048
#define MAX_HEREDOCS    8
#define MAX_SCAN_DEPTH  16
#define MAX_STDIN_JSON  (256U * 1024U)

typedef struct {
    char home[PATH_MAX];
    char cwd[PATH_MAX];

    bool blocked;
    char rule[48];
    char reason[256];

    /* Cross-segment exfiltration & pipeline state */
    bool touches_secret;
    char secret_label[96];
    bool has_net_egress;
    char net_label[64];

    /* Active shell function definition tracking (for fork-bomb detection) */
    char active_fn[64];
    int  fn_self_calls;
    bool fn_has_pipe;
    bool fn_has_bg;
} GuardCtx;

typedef struct {
    char delim[64];
    bool strip_tabs;
} HeredocSpec;

/* Forward declaration for recursive subshell & nested `sh -c` scanning */
static void scan_shell_slice(GuardCtx *ctx, const char *s, size_t start, size_t end,
                             char stop_char, int depth);

/* -------------------------------------------------------------------------
 * String, Path & JSON Helpers
 * ------------------------------------------------------------------------- */

static void resolve_home(char *out, size_t cap) {
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

static const char *ci_strstr(const char *hay, const char *needle) {
    if (!hay || !needle) return NULL;
    if (!needle[0]) return hay;
    size_t nl = strlen(needle);
    char c0 = (char)tolower((unsigned char)needle[0]);
    for (const char *p = hay; *p; p++) {
        if ((char)tolower((unsigned char)*p) == c0 && strncasecmp(p, needle, nl) == 0) {
            return p;
        }
    }
    return NULL;
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

static void flag_block(GuardCtx *ctx, const char *rule, const char *reason) {
    if (!ctx || ctx->blocked) return;
    ctx->blocked = true;
    snprintf(ctx->rule, sizeof(ctx->rule), "%.*s", (int)sizeof(ctx->rule) - 1,
             rule ? rule : "policy_block");
    snprintf(ctx->reason, sizeof(ctx->reason), "%.*s", (int)sizeof(ctx->reason) - 1,
             reason ? reason : "blocked by Hephaestus Shield");
}

static void normalize_path_lexical(const char *raw, const char *cwd, const char *home,
                                   char *out, size_t cap) {
    char expanded[PATH_MAX * 2];
    if (!raw || !raw[0]) {
        out[0] = '\0';
        return;
    }
    if (raw[0] == '~' && (raw[1] == '\0' || raw[1] == '/')) {
        snprintf(expanded, sizeof(expanded), "%s%s", home, raw + 1);
    } else if (strncmp(raw, "$HOME", 5) == 0 && (raw[5] == '\0' || raw[5] == '/')) {
        snprintf(expanded, sizeof(expanded), "%s%s", home, raw + 5);
    } else if (strncmp(raw, "${HOME}", 7) == 0 && (raw[7] == '\0' || raw[7] == '/')) {
        snprintf(expanded, sizeof(expanded), "%s%s", home, raw + 7);
    } else if (raw[0] == '/') {
        snprintf(expanded, sizeof(expanded), "%s", raw);
    } else {
        snprintf(expanded, sizeof(expanded), "%s/%s",
                 (cwd && cwd[0]) ? cwd : "/", raw);
    }

    const char *segs[128];
    size_t lens[128];
    int depth = 0;
    const char *p = expanded;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *st = p;
        while (*p && *p != '/') p++;
        size_t l = (size_t)(p - st);
        if (l == 1 && st[0] == '.') continue;
        if (l == 2 && st[0] == '.' && st[1] == '.') {
            if (depth > 0) depth--;
            continue;
        }
        if (depth < 128) {
            segs[depth] = st;
            lens[depth] = l;
            depth++;
        }
    }

    size_t pos = 0;
    out[pos++] = '/';
    for (int i = 0; i < depth; i++) {
        if (i > 0 && pos + 1 < cap) out[pos++] = '/';
        size_t cp = lens[i];
        if (pos + cp >= cap) cp = cap - 1 - pos;
        if (cp > 0) {
            memcpy(out + pos, segs[i], cp);
            pos += cp;
        }
    }
    out[pos] = '\0';
}

static bool path_has_prefix_dir(const char *p, const char *dir) {
    if (!p || !dir || !dir[0]) return false;
    if (strcmp(dir, "/") == 0) return p[0] == '/';
    size_t dl = strlen(dir);
    return (strncmp(p, dir, dl) == 0 && (p[dl] == '\0' || p[dl] == '/'));
}

static const char *basename_ptr(const char *s) {
    if (!s) return "";
    const char *sl = strrchr(s, '/');
    return sl ? (sl + 1) : s;
}

/* -------------------------------------------------------------------------
 * Write / Redirection Target Policy
 * ------------------------------------------------------------------------- */

static bool is_safe_dev_sink(const char *p) {
    return (strcmp(p, "/dev/null") == 0 ||
            strcmp(p, "/dev/stdout") == 0 ||
            strcmp(p, "/dev/stderr") == 0 ||
            strcmp(p, "/dev/tty") == 0 ||
            strcmp(p, "/dev/zero") == 0 ||
            strncmp(p, "/dev/fd/", 8) == 0 ||
            strncmp(p, "/dev/shm/", 9) == 0);
}

static void inspect_write_target(GuardCtx *ctx, const char *raw_target, bool is_redirect) {
    if (!raw_target || !raw_target[0] || ctx->blocked) return;

    /* Descriptor duplication like &1, &2, &- in 2>&1 */
    if (is_redirect && raw_target[0] == '&') {
        if (raw_target[1] == '-' || isdigit((unsigned char)raw_target[1])) return;
    }

    /* Bash raw TCP/UDP pseudo-socket redirect */
    if (strncmp(raw_target, "/dev/tcp/", 9) == 0 || strncmp(raw_target, "/dev/udp/", 9) == 0) {
        ctx->has_net_egress = true;
        snprintf(ctx->net_label, sizeof(ctx->net_label), "/dev/tcp");
        flag_block(ctx, "raw_socket_redirect",
                   "unquoted shell redirection to /dev/tcp or /dev/udp network socket");
        return;
    }

    char norm[PATH_MAX];
    normalize_path_lexical(raw_target, ctx->cwd, ctx->home, norm, sizeof(norm));
    if (is_safe_dev_sink(norm)) return;

    /* Raw disk & kernel memory devices */
    if (strncmp(norm, "/dev/", 5) == 0) {
        const char *dv = norm + 5;
        if (strncmp(dv, "sd", 2) == 0 || strncmp(dv, "nvme", 4) == 0 ||
            strncmp(dv, "vd", 2) == 0 || strncmp(dv, "hd", 2) == 0 ||
            strncmp(dv, "mmcblk", 6) == 0 || strncmp(dv, "loop", 4) == 0 ||
            strncmp(dv, "dm-", 3) == 0 || strncmp(dv, "disk", 4) == 0 ||
            strncmp(dv, "rdisk", 5) == 0 || strcmp(dv, "mem") == 0 ||
            strcmp(dv, "kmem") == 0 || strcmp(dv, "port") == 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "destructive write/redirect to block/kernel device '%.160s'", norm);
            flag_block(ctx, "destructive_device_write", msg);
            return;
        }
    }

    /* Critical OS trees */
    static const char *const sys_trees[] = {
        "/etc", "/usr", "/boot", "/bin", "/sbin", "/lib", "/lib64",
        "/proc", "/sys", "/root", "/System", "/Library/LaunchDaemons", NULL
    };
    for (int i = 0; sys_trees[i]; i++) {
        if (path_has_prefix_dir(norm, sys_trees[i])) {
            char msg[256];
            snprintf(msg, sizeof(msg), "dangerous write/redirect to protected system path '%.160s'", norm);
            flag_block(ctx, "dangerous_redirect", msg);
            return;
        }
    }

    /* Sensitive $HOME credential & shell-persistence files */
    if (ctx->home[0] && strcmp(ctx->home, "/") != 0 && path_has_prefix_dir(norm, ctx->home)) {
        size_t hl = strlen(ctx->home);
        const char *sub = (norm[hl] == '/') ? (norm + hl + 1) : "";
        static const char *const sens_home[] = {
            ".ssh", ".gnupg", ".aws", ".kube", ".docker", ".netrc",
            ".bashrc", ".bash_profile", ".bash_login", ".profile",
            ".zshrc", ".zprofile", ".zshenv", ".gitconfig",
            ".npmrc", ".pypirc", ".git-credentials",
            ".claude/settings.json", ".claude/settings.local.json", NULL
        };
        for (int i = 0; sens_home[i]; i++) {
            size_t sl = strlen(sens_home[i]);
            if (strncmp(sub, sens_home[i], sl) == 0 && (sub[sl] == '\0' || sub[sl] == '/')) {
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "dangerous write/redirect to sensitive home credential/rc path '~/%.160s'", sub);
                flag_block(ctx, "dangerous_redirect", msg);
                return;
            }
        }
    }
}

/* -------------------------------------------------------------------------
 * Secret Source & Command Structural Classifiers
 * ------------------------------------------------------------------------- */

static bool word_references_secret(const GuardCtx *ctx, const char *w, char *label_out, size_t lcap) {
    if (!w || !w[0]) return false;

    /* Strip leading curl @file upload prefix */
    if (w[0] == '@' && w[1] != '\0' && w[1] != '-') w++;
    const char *eq = strchr(w, '=');
    if (eq && eq[1] == '@') w = eq + 2;
    else if (eq && (eq[1] == '/' || eq[1] == '~' || eq[1] == '.')) w = eq + 1;

    /* Sensitive environment variable expansions */
    static const char *const secret_vars[] = {
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
        "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GITHUB_TOKEN", "GH_TOKEN",
        "GITLAB_TOKEN", "NPM_TOKEN", "PYPI_API_TOKEN", "STRIPE_SECRET_KEY",
        "PRIVATE_KEY", "SSH_AUTH_SOCK", "DATABASE_URL", NULL
    };
    for (int i = 0; secret_vars[i]; i++) {
        if (strstr(w, secret_vars[i]) != NULL && strchr(w, '$') != NULL) {
            snprintf(label_out, lcap, "$%s", secret_vars[i]);
            return true;
        }
    }

    /* Path-based credential stores */
    static const char *const secret_substrings[] = {
        "/.ssh/", ".ssh/id_", ".ssh/config", "authorized_keys",
        "/.aws/credentials", ".aws/credentials",
        "/.gnupg/", ".gnupg/private-keys",
        "/.kube/config", ".kube/config",
        "/.docker/config.json",
        "/.netrc", "_netrc", "/.git-credentials", "/.npmrc", "/.pypirc",
        "/.config/gh/hosts.yml", "/etc/shadow", "/etc/gshadow", "/etc/sudoers",
        "Login Data", "cookies.sqlite", "key4.db", NULL
    };
    for (int i = 0; secret_substrings[i]; i++) {
        if (strstr(w, secret_substrings[i]) != NULL) {
            snprintf(label_out, lcap, "%s", secret_substrings[i]);
            return true;
        }
    }

    const char *base = basename_ptr(w);
    if (strcmp(base, ".env") == 0 || strncmp(base, ".env.", 5) == 0 ||
        strcmp(base, ".netrc") == 0 || strcmp(base, "id_rsa") == 0 ||
        strcmp(base, "id_ed25519") == 0 || strcmp(base, "id_ecdsa") == 0) {
        /* Ignore benign .env.example / .env.sample / .env.template */
        if (strcmp(base, ".env.example") != 0 &&
            strcmp(base, ".env.sample") != 0 &&
            strcmp(base, ".env.template") != 0) {
            snprintf(label_out, lcap, "%s", base);
            return true;
        }
    }

    if (ctx && ctx->home[0]) {
        char norm[PATH_MAX];
        if (w[0] == '~' || w[0] == '/' || strncmp(w, "$HOME", 5) == 0) {
            normalize_path_lexical(w, ctx->cwd, ctx->home, norm, sizeof(norm));
            size_t hl = strlen(ctx->home);
            if (strncmp(norm, ctx->home, hl) == 0 && norm[hl] == '/') {
                const char *sub = norm + hl + 1;
                if (strncmp(sub, ".ssh", 4) == 0 || strncmp(sub, ".aws", 4) == 0 ||
                    strncmp(sub, ".gnupg", 6) == 0 || strncmp(sub, ".kube", 5) == 0) {
                    snprintf(label_out, lcap, "~/%.*s", 48, sub);
                    return true;
                }
            }
        }
    }
    return false;
}

static bool is_net_egress_tool(const char *cmd_base) {
    static const char *const net_tools[] = {
        "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet",
        "ftp", "tftp", "scp", "sftp", "dig", "nslookup", "host", "websocat", NULL
    };
    for (int i = 0; net_tools[i]; i++) {
        if (strcmp(cmd_base, net_tools[i]) == 0) return true;
    }
    return false;
}

static bool is_shell_interpreter(const char *cmd_base) {
    return (strcmp(cmd_base, "sh") == 0 ||
            strcmp(cmd_base, "bash") == 0 ||
            strcmp(cmd_base, "zsh") == 0 ||
            strcmp(cmd_base, "dash") == 0 ||
            strcmp(cmd_base, "ksh") == 0 ||
            strcmp(cmd_base, "ash") == 0);
}

static bool is_pipe_exec_sink(const char *cmd_base) {
    return (is_shell_interpreter(cmd_base) ||
            strcmp(cmd_base, "python") == 0 ||
            strcmp(cmd_base, "python3") == 0 ||
            strcmp(cmd_base, "perl") == 0 ||
            strcmp(cmd_base, "ruby") == 0 ||
            strcmp(cmd_base, "node") == 0 ||
            strcmp(cmd_base, "php") == 0);
}

static bool is_env_assignment_word(const char *w) {
    if (!w || (!isalpha((unsigned char)w[0]) && w[0] != '_')) return false;
    for (const char *p = w + 1; *p; p++) {
        if (*p == '=') return true;
        if (!isalnum((unsigned char)*p) && *p != '_') return false;
    }
    return false;
}

static bool is_critical_rm_target(const GuardCtx *ctx, const char *arg) {
    if (!arg || !arg[0]) return false;

    /* Raw unexpanded forms */
    if (strcmp(arg, "/") == 0 || strcmp(arg, "/*") == 0 ||
        strcmp(arg, "/.") == 0 || strcmp(arg, "/..") == 0 ||
        strcmp(arg, "~") == 0 || strcmp(arg, "~/") == 0 || strcmp(arg, "~/*") == 0 ||
        strcmp(arg, "$HOME") == 0 || strcmp(arg, "$HOME/") == 0 || strcmp(arg, "$HOME/*") == 0 ||
        strcmp(arg, "${HOME}") == 0 || strcmp(arg, "${HOME}/") == 0 || strcmp(arg, "${HOME}/*") == 0 ||
        strcmp(arg, "..") == 0 || strcmp(arg, "../") == 0 || strcmp(arg, "../*") == 0) {
        return true;
    }

    /* Strip trailing wildcard to check root directory target */
    char trimmed[PATH_MAX];
    snprintf(trimmed, sizeof(trimmed), "%.*s", (int)sizeof(trimmed) - 1, arg);
    size_t tl = strlen(trimmed);
    while (tl > 1 && (trimmed[tl - 1] == '*' || trimmed[tl - 1] == '/')) {
        trimmed[--tl] = '\0';
    }

    char norm[PATH_MAX];
    normalize_path_lexical(trimmed, ctx->cwd, ctx->home, norm, sizeof(norm));
    if (strcmp(norm, "/") == 0 || strcmp(norm, "/home") == 0 || strcmp(norm, "/Users") == 0 ||
        strcmp(norm, "/etc") == 0 || strcmp(norm, "/usr") == 0 || strcmp(norm, "/boot") == 0 ||
        strcmp(norm, "/bin") == 0 || strcmp(norm, "/sbin") == 0 || strcmp(norm, "/lib") == 0 ||
        strcmp(norm, "/lib64") == 0 || strcmp(norm, "/var") == 0 || strcmp(norm, "/root") == 0 ||
        strcmp(norm, "/dev") == 0 || strcmp(norm, "/proc") == 0 || strcmp(norm, "/sys") == 0) {
        return true;
    }
    if (ctx->home[0] && strcmp(norm, ctx->home) == 0) {
        return true;
    }
    return false;
}

static void inspect_simple_command(GuardCtx *ctx, int wcnt, char words[][MAX_WORD_LEN],
                                   const bool *word_quoted, bool prev_was_net_pipe,
                                   bool *this_is_net_pipe_src, int depth) {
    *this_is_net_pipe_src = false;
    if (wcnt <= 0 || ctx->blocked) return;

    /* Skip leading VAR=val assignments and command wrappers (sudo, env, nohup, nice, command, exec) */
    int idx = 0;
    while (idx < wcnt) {
        if (!word_quoted[idx] && is_env_assignment_word(words[idx])) {
            char slabel[96];
            if (word_references_secret(ctx, words[idx], slabel, sizeof(slabel))) {
                ctx->touches_secret = true;
                snprintf(ctx->secret_label, sizeof(ctx->secret_label), "%s", slabel);
            }
            idx++;
            continue;
        }
        const char *b = basename_ptr(words[idx]);
        if (strcmp(b, "sudo") == 0 || strcmp(b, "doas") == 0 || strcmp(b, "env") == 0 ||
            strcmp(b, "nohup") == 0 || strcmp(b, "command") == 0 || strcmp(b, "builtin") == 0 ||
            strcmp(b, "exec") == 0 || strcmp(b, "time") == 0 || strcmp(b, "nice") == 0) {
            idx++;
            while (idx < wcnt && words[idx][0] == '-' && strcmp(words[idx], "--") != 0) {
                /* Skip sudo -u <user> or nice -n <prio> option arguments */
                if ((strcmp(b, "sudo") == 0 && (strcmp(words[idx], "-u") == 0 || strcmp(words[idx], "-g") == 0)) ||
                    (strcmp(b, "nice") == 0 && strcmp(words[idx], "-n") == 0)) {
                    idx += 2;
                } else {
                    idx++;
                }
            }
            if (idx < wcnt && strcmp(words[idx], "--") == 0) idx++;
            continue;
        }
        break;
    }
    if (idx >= wcnt) return;

    const char *cmd = words[idx];
    const char *base = basename_ptr(cmd);

    /* Track self-calls inside active shell function definition (fork-bomb detector) */
    if (ctx->active_fn[0] != '\0' && strcmp(cmd, ctx->active_fn) == 0) {
        ctx->fn_self_calls++;
        if (ctx->fn_self_calls >= 2 && (ctx->fn_has_pipe || ctx->fn_has_bg)) {
            flag_block(ctx, "fork_bomb",
                       "recursive self-piped/backgrounded shell function fork bomb detected");
            return;
        }
    }

    /* 1. Remote fetch piped directly into shell/interpreter (`curl ... | sh`) */
    if (strcmp(base, "curl") == 0 || strcmp(base, "wget") == 0) {
        *this_is_net_pipe_src = true;
    }
    if (prev_was_net_pipe && is_pipe_exec_sink(base)) {
        flag_block(ctx, "remote_pipe_to_shell",
                   "piping remote network output (curl/wget) directly into interpreter");
        return;
    }

    /* 2. Nested shell evaluation: `sh -c "..."`, `bash -lc "..."`, `eval ...` */
    if (is_shell_interpreter(base) && depth < MAX_SCAN_DEPTH) {
        bool has_interactive = false;
        for (int i = idx + 1; i < wcnt; i++) {
            const char *arg = words[i];
            if (arg[0] == '-' && arg[1] != '-') {
                if (strchr(arg + 1, 'i') != NULL) has_interactive = true;
                if (strchr(arg + 1, 'c') != NULL && i + 1 < wcnt) {
                    const char *script = words[i + 1];
                    scan_shell_slice(ctx, script, 0, strlen(script), '\0', depth + 1);
                    if (ctx->blocked) return;
                    break;
                }
            }
        }
        if (has_interactive && ctx->has_net_egress) {
            flag_block(ctx, "reverse_shell", "interactive shell combined with network socket");
            return;
        }
    } else if (strcmp(base, "eval") == 0 && idx + 1 < wcnt && depth < MAX_SCAN_DEPTH) {
        char joined[MAX_WORD_LEN * 2];
        size_t pos = 0;
        for (int i = idx + 1; i < wcnt; i++) {
            size_t wl = strlen(words[i]);
            if (pos + wl + 2 >= sizeof(joined)) break;
            if (pos > 0) joined[pos++] = ' ';
            memcpy(joined + pos, words[i], wl);
            pos += wl;
        }
        joined[pos] = '\0';
        scan_shell_slice(ctx, joined, 0, pos, '\0', depth + 1);
        if (ctx->blocked) return;
    }

    /* 3. Inline Python / Perl / Node fork bombs & covert network exfil */
    if (strcmp(base, "python") == 0 || strcmp(base, "python3") == 0 ||
        strcmp(base, "perl") == 0 || strcmp(base, "node") == 0) {
        for (int i = idx + 1; i < wcnt; i++) {
            if ((strcmp(words[i], "-c") == 0 || strcmp(words[i], "-e") == 0) && i + 1 < wcnt) {
                const char *code = words[i + 1];
                if ((strstr(code, "os.fork(") && strstr(code, "while")) ||
                    (strstr(code, "fork") && strstr(code, "while(1)"))) {
                    flag_block(ctx, "fork_bomb", "inline script fork bomb detected");
                    return;
                }
                if (strstr(code, "urllib") || strstr(code, "requests.") ||
                    strstr(code, "http.client") || strstr(code, "socket.") ||
                    strstr(code, "fetch(")) {
                    ctx->has_net_egress = true;
                    snprintf(ctx->net_label, sizeof(ctx->net_label), "%s-net", base);
                }
                char sl[96];
                if (word_references_secret(ctx, code, sl, sizeof(sl))) {
                    ctx->touches_secret = true;
                    snprintf(ctx->secret_label, sizeof(ctx->secret_label), "%s", sl);
                }
            }
        }
    }

    /* 4. Destructive filesystem / block-device wipe commands */
    if (strcmp(base, "rm") == 0) {
        bool recursive = false;
        bool end_opts = false;
        for (int i = idx + 1; i < wcnt; i++) {
            const char *a = words[i];
            if (!end_opts && strcmp(a, "--") == 0) {
                end_opts = true;
                continue;
            }
            if (!end_opts && a[0] == '-' && a[1] != '\0') {
                if (strcmp(a, "--no-preserve-root") == 0 ||
                    strncmp(a, "--no-preserve-root=", 19) == 0) {
                    flag_block(ctx, "destructive_cmd", "rm --no-preserve-root is prohibited");
                    return;
                }
                if (strcmp(a, "--recursive") == 0) {
                    recursive = true;
                } else if (a[1] != '-') {
                    if (strchr(a + 1, 'r') != NULL || strchr(a + 1, 'R') != NULL) {
                        recursive = true;
                    }
                }
                continue;
            }
            if (recursive && is_critical_rm_target(ctx, a)) {
                char msg[256];
                snprintf(msg, sizeof(msg), "destructive recursive rm targeting '%s'", a);
                flag_block(ctx, "destructive_cmd", msg);
                return;
            }
        }
    } else if (strcmp(base, "mkfs") == 0 || strncmp(base, "mkfs.", 5) == 0 ||
               strcmp(base, "wipefs") == 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "destructive filesystem format/wipe utility '%s'", base);
        flag_block(ctx, "destructive_cmd", msg);
        return;
    } else if (strcmp(base, "dd") == 0) {
        for (int i = idx + 1; i < wcnt; i++) {
            if (strncmp(words[i], "of=", 3) == 0) {
                inspect_write_target(ctx, words[i] + 3, false);
                if (ctx->blocked) return;
            }
        }
    } else if (strcmp(base, "chmod") == 0 || strcmp(base, "chown") == 0) {
        bool recursive = false;
        bool world_writable = false;
        for (int i = idx + 1; i < wcnt; i++) {
            const char *a = words[i];
            if (strcmp(a, "-R") == 0 || strcmp(a, "--recursive") == 0 ||
                (a[0] == '-' && a[1] != '-' && strchr(a + 1, 'R') != NULL)) {
                recursive = true;
                continue;
            }
            if (strcmp(a, "777") == 0 || strcmp(a, "0777") == 0 || strcmp(a, "a+rwx") == 0) {
                world_writable = true;
                continue;
            }
            if (recursive && (strcmp(a, "/") == 0 || strcmp(a, "/*") == 0 ||
                              strcmp(a, "/etc") == 0 || strcmp(a, "/usr") == 0 ||
                              (world_writable && is_critical_rm_target(ctx, a)))) {
                char msg[256];
                snprintf(msg, sizeof(msg), "destructive recursive %s on '%s'", base, a);
                flag_block(ctx, "destructive_cmd", msg);
                return;
            }
        }
    }

    /* 5. Reverse shell flags on nc / ncat / socat */
    if (strcmp(base, "nc") == 0 || strcmp(base, "ncat") == 0 || strcmp(base, "netcat") == 0) {
        for (int i = idx + 1; i < wcnt; i++) {
            if ((strcmp(words[i], "-e") == 0 || strcmp(words[i], "-c") == 0) && i + 1 < wcnt) {
                flag_block(ctx, "reverse_shell", "netcat -e/-c remote shell execution is prohibited");
                return;
            }
        }
    } else if (strcmp(base, "socat") == 0) {
        for (int i = idx + 1; i < wcnt; i++) {
            if (ci_strstr(words[i], "EXEC:") != NULL || ci_strstr(words[i], "SYSTEM:") != NULL) {
                flag_block(ctx, "reverse_shell", "socat EXEC/SYSTEM shell bind is prohibited");
                return;
            }
        }
    }

    /* 6. Untrusted external --mcp-config */
    for (int i = idx + 1; i < wcnt; i++) {
        const char *mcp_arg = NULL;
        if (strcmp(words[i], "--mcp-config") == 0 && i + 1 < wcnt) mcp_arg = words[i + 1];
        else if (strncmp(words[i], "--mcp-config=", 13) == 0) mcp_arg = words[i] + 13;
        if (mcp_arg && (strncmp(mcp_arg, "/tmp/", 5) == 0 ||
                        strncmp(mcp_arg, "/var/tmp/", 9) == 0 ||
                        strncmp(mcp_arg, "http://", 7) == 0 ||
                        strncmp(mcp_arg, "https://", 8) == 0 ||
                        strstr(mcp_arg, "/Downloads/") != NULL)) {
            flag_block(ctx, "untrusted_mcp", "loading --mcp-config from untrusted external/temp path");
            return;
        }
    }

    /* 7. Secret read + network egress tracking (skip literal args to echo/printf) */
    bool is_pure_display = (strcmp(base, "echo") == 0 || strcmp(base, "printf") == 0);
    if (is_net_egress_tool(base)) {
        ctx->has_net_egress = true;
        snprintf(ctx->net_label, sizeof(ctx->net_label), "%s", base);
    } else if (strcmp(base, "rsync") == 0) {
        for (int i = idx + 1; i < wcnt; i++) {
            if (strchr(words[i], ':') != NULL || strncmp(words[i], "rsync://", 8) == 0) {
                ctx->has_net_egress = true;
                snprintf(ctx->net_label, sizeof(ctx->net_label), "rsync");
            }
        }
    }

    if (strcmp(base, "printenv") == 0 || (strcmp(base, "env") == 0 && idx == wcnt - 1)) {
        /* Full environment dump only counts as secret source if paired with egress */
        if (ctx->has_net_egress) {
            ctx->touches_secret = true;
            snprintf(ctx->secret_label, sizeof(ctx->secret_label), "environment dump");
        }
    }

    if (!is_pure_display) {
        for (int i = idx + 1; i < wcnt; i++) {
            char sl[96];
            if (word_references_secret(ctx, words[i], sl, sizeof(sl))) {
                ctx->touches_secret = true;
                snprintf(ctx->secret_label, sizeof(ctx->secret_label), "%s", sl);
            }
        }
    } else {
        /* Even in echo/printf, unquoted $SECRET_KEY expansion is real secret access */
        for (int i = idx + 1; i < wcnt; i++) {
            if (strchr(words[i], '$') != NULL) {
                char sl[96];
                if (word_references_secret(ctx, words[i], sl, sizeof(sl))) {
                    ctx->touches_secret = true;
                    snprintf(ctx->secret_label, sizeof(ctx->secret_label), "%s", sl);
                }
            }
        }
    }

    if (ctx->touches_secret && ctx->has_net_egress) {
        char msg[256];
        snprintf(msg, sizeof(msg), "secret source (%s) paired with network egress (%s)",
                 ctx->secret_label, ctx->net_label);
        flag_block(ctx, "secret_exfiltration", msg);
    }
}

/* -------------------------------------------------------------------------
 * Quote- & Subshell-Aware POSIX/Bash Lexer
 * ------------------------------------------------------------------------- */

static size_t skip_backtick_subst(GuardCtx *ctx, const char *s, size_t i, size_t end,
                                  bool in_dquote, int depth) {
    /* s[i] == '`' */
    size_t pos = i + 1;
    char inner[4096];
    size_t ilen = 0;

    while (pos < end && s[pos] != '`') {
        if (s[pos] == '\\' && pos + 1 < end) {
            char nx = s[pos + 1];
            if (nx == '$' || nx == '`' || nx == '\\' || (in_dquote && nx == '"')) {
                if (ilen + 1 < sizeof(inner)) inner[ilen++] = nx;
                pos += 2;
                continue;
            }
        }
        if (ilen + 1 < sizeof(inner)) inner[ilen++] = s[pos];
        pos++;
    }
    inner[ilen] = '\0';
    if (ilen > 0 && depth < MAX_SCAN_DEPTH) {
        scan_shell_slice(ctx, inner, 0, ilen, '\0', depth + 1);
    }
    return (pos < end && s[pos] == '`') ? (pos + 1) : pos;
}

static size_t skip_arith_parens(GuardCtx *ctx, const char *s, size_t i, size_t end, int depth) {
    /* Enters after "$((", returns index past matching "))" */
    int pdepth = 2;
    size_t pos = i;
    while (pos < end && pdepth > 0) {
        if (s[pos] == '\\' && pos + 1 < end) {
            pos += 2;
            continue;
        }
        if (s[pos] == '$' && pos + 1 < end && s[pos + 1] == '(') {
            if (pos + 2 < end && s[pos + 2] == '(') {
                pos = skip_arith_parens(ctx, s, pos + 3, end, depth + 1);
            } else {
                scan_shell_slice(ctx, s, pos + 2, end, ')', depth + 1);
                /* Advance pos to matching ')' */
                int sd = 1;
                pos += 2;
                while (pos < end && sd > 0) {
                    if (s[pos] == '\\' && pos + 1 < end) { pos += 2; continue; }
                    if (s[pos] == '\'') {
                        pos++;
                        while (pos < end && s[pos] != '\'') pos++;
                        if (pos < end) pos++;
                        continue;
                    }
                    if (s[pos] == '(') sd++;
                    else if (s[pos] == ')') sd--;
                    pos++;
                }
            }
            continue;
        }
        if (s[pos] == '`') {
            pos = skip_backtick_subst(ctx, s, pos, end, false, depth);
            continue;
        }
        if (s[pos] == '(') pdepth++;
        else if (s[pos] == ')') pdepth--;
        pos++;
    }
    return pos;
}

/* Lexes a $-construct starting at s[i] == '$', appending static text to wbuf */
static size_t lex_dollar(GuardCtx *ctx, const char *s, size_t i, size_t end,
                         char *wbuf, size_t *wlen, size_t wcap, int depth) {
    if (i + 1 >= end) {
        if (*wlen + 1 < wcap) wbuf[(*wlen)++] = '$';
        return i + 1;
    }
    char nx = s[i + 1];

    /* $'...' ANSI-C quoting */
    if (nx == '\'') {
        size_t p = i + 2;
        while (p < end && s[p] != '\'') {
            if (s[p] == '\\' && p + 1 < end) {
                if (*wlen + 1 < wcap) wbuf[(*wlen)++] = s[p + 1];
                p += 2;
                continue;
            }
            if (*wlen + 1 < wcap) wbuf[(*wlen)++] = s[p];
            p++;
        }
        return (p < end) ? (p + 1) : p;
    }

    /* $(( ... )) arithmetic expansion */
    if (nx == '(' && i + 2 < end && s[i + 2] == '(') {
        return skip_arith_parens(ctx, s, i + 3, end, depth);
    }

    /* $( ... ) command substitution */
    if (nx == '(') {
        if (depth < MAX_SCAN_DEPTH) {
            scan_shell_slice(ctx, s, i + 2, end, ')', depth + 1);
        }
        /* Advance past matching ')' respecting quotes */
        size_t p = i + 2;
        int sd = 1;
        bool dq = false;
        while (p < end && sd > 0) {
            char c = s[p];
            if (c == '\\' && p + 1 < end) { p += 2; continue; }
            if (!dq && c == '\'') {
                p++;
                while (p < end && s[p] != '\'') p++;
                if (p < end) p++;
                continue;
            }
            if (c == '"') { dq = !dq; p++; continue; }
            if (!dq) {
                if (c == '(') sd++;
                else if (c == ')') sd--;
            }
            p++;
        }
        return p;
    }

    /* ${ ... } parameter expansion (may contain inner $(...) or `...`) */
    if (nx == '{') {
        size_t p = i + 2;
        int bd = 1;
        if (*wlen + 2 < wcap) {
            wbuf[(*wlen)++] = '$';
            wbuf[(*wlen)++] = '{';
        }
        while (p < end && bd > 0) {
            char c = s[p];
            if (c == '\\' && p + 1 < end) {
                if (*wlen + 1 < wcap) wbuf[(*wlen)++] = s[p + 1];
                p += 2;
                continue;
            }
            if (c == '$' && p + 1 < end && (s[p + 1] == '(' || s[p + 1] == '{')) {
                p = lex_dollar(ctx, s, p, end, wbuf, wlen, wcap, depth);
                continue;
            }
            if (c == '`') {
                p = skip_backtick_subst(ctx, s, p, end, false, depth);
                continue;
            }
            if (c == '{') bd++;
            else if (c == '}') bd--;
            if (*wlen + 1 < wcap) wbuf[(*wlen)++] = c;
            p++;
        }
        return p;
    }

    /* $VAR simple variable reference */
    if (*wlen + 1 < wcap) wbuf[(*wlen)++] = '$';
    size_t p = i + 1;
    if (isalpha((unsigned char)s[p]) || s[p] == '_') {
        while (p < end && (isalnum((unsigned char)s[p]) || s[p] == '_')) {
            if (*wlen + 1 < wcap) wbuf[(*wlen)++] = s[p];
            p++;
        }
    } else if (isdigit((unsigned char)s[p]) || strchr("?#$!*-@", s[p]) != NULL) {
        if (*wlen + 1 < wcap) wbuf[(*wlen)++] = s[p];
        p++;
    }
    return p;
}

static bool is_unquoted_meta(char c, char stop_char) {
    if (stop_char != '\0' && c == stop_char) return true;
    return (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
            c == ';' || c == '|' || c == '&' ||
            c == '<' || c == '>' || c == '(' || c == ')');
}

/* Lexes one shell word starting at s[pos]. Returns new pos. */
static size_t lex_word(GuardCtx *ctx, const char *s, size_t pos, size_t end,
                       char stop_char, char *wbuf, size_t wcap, bool *had_quotes, int depth) {
    size_t wlen = 0;
    *had_quotes = false;

    while (pos < end && !is_unquoted_meta(s[pos], stop_char)) {
        char c = s[pos];
        if (c == '\\') {
            *had_quotes = true;
            if (pos + 1 < end) {
                if (s[pos + 1] != '\n' && wlen + 1 < wcap) wbuf[wlen++] = s[pos + 1];
                pos += 2;
            } else {
                pos++;
            }
            continue;
        }
        if (c == '\'') {
            *had_quotes = true;
            pos++;
            while (pos < end && s[pos] != '\'') {
                if (wlen + 1 < wcap) wbuf[wlen++] = s[pos];
                pos++;
            }
            if (pos < end) pos++;
            continue;
        }
        if (c == '"') {
            *had_quotes = true;
            pos++;
            while (pos < end && s[pos] != '"') {
                if (s[pos] == '\\' && pos + 1 < end) {
                    char esc = s[pos + 1];
                    if (esc == '$' || esc == '`' || esc == '"' || esc == '\\' || esc == '\n') {
                        if (esc != '\n' && wlen + 1 < wcap) wbuf[wlen++] = esc;
                        pos += 2;
                        continue;
                    }
                }
                if (s[pos] == '$') {
                    pos = lex_dollar(ctx, s, pos, end, wbuf, &wlen, wcap, depth);
                    continue;
                }
                if (s[pos] == '`') {
                    pos = skip_backtick_subst(ctx, s, pos, end, true, depth);
                    continue;
                }
                if (wlen + 1 < wcap) wbuf[wlen++] = s[pos];
                pos++;
            }
            if (pos < end) pos++;
            continue;
        }
        if (c == '$') {
            pos = lex_dollar(ctx, s, pos, end, wbuf, &wlen, wcap, depth);
            continue;
        }
        if (c == '`') {
            pos = skip_backtick_subst(ctx, s, pos, end, false, depth);
            continue;
        }
        if (wlen + 1 < wcap) wbuf[wlen++] = c;
        pos++;
    }
    wbuf[wlen] = '\0';
    return pos;
}

static size_t consume_pending_heredocs(const char *s, size_t pos, size_t end,
                                       HeredocSpec *hdocs, int *hcnt) {
    for (int h = 0; h < *hcnt && pos < end; h++) {
        size_t dlen = strlen(hdocs[h].delim);
        while (pos < end) {
            size_t ls = pos;
            while (pos < end && s[pos] != '\n') pos++;
            size_t le = pos;
            if (pos < end && s[pos] == '\n') pos++;
            if (le > ls && s[le - 1] == '\r') le--;
            if (hdocs[h].strip_tabs) {
                while (ls < le && s[ls] == '\t') ls++;
            }
            if ((le - ls) == dlen && memcmp(s + ls, hdocs[h].delim, dlen) == 0) {
                break;
            }
        }
    }
    *hcnt = 0;
    return pos;
}

static void scan_shell_slice(GuardCtx *ctx, const char *s, size_t start, size_t end,
                             char stop_char, int depth) {
    if (!ctx || !s || ctx->blocked || depth > MAX_SCAN_DEPTH) return;

    /* Heap-allocate command word table per recursion level so stack stays tiny */
    char (*words)[MAX_WORD_LEN] = (char (*)[MAX_WORD_LEN])calloc(MAX_CMD_WORDS, sizeof(*words));
    bool *wquoted = (bool *)calloc(MAX_CMD_WORDS, sizeof(bool));
    if (!words || !wquoted) {
        free(words);
        free(wquoted);
        return;
    }

    int wcnt = 0;
    bool in_double_bracket = false;
    bool prev_was_net_pipe = false;
    char pending_fn[64] = {0};
    int fn_brace_depth = 0;

    HeredocSpec hdocs[MAX_HEREDOCS];
    int hcnt = 0;

    size_t pos = start;
    while (pos < end && !ctx->blocked) {
        char c = s[pos];

        if (stop_char != '\0' && c == stop_char) {
            break;
        }

        /* Whitespace */
        if (c == ' ' || c == '\t' || c == '\r') {
            pos++;
            continue;
        }

        /* Comments (valid at start of word) */
        if (c == '#') {
            while (pos < end && s[pos] != '\n') pos++;
            continue;
        }

        /* Newline: flush command and consume heredoc bodies */
        if (c == '\n') {
            bool is_net_src = false;
            inspect_simple_command(ctx, wcnt, words, wquoted, prev_was_net_pipe, &is_net_src, depth);
            wcnt = 0;
            prev_was_net_pipe = false;
            in_double_bracket = false;
            pos++;
            if (hcnt > 0) pos = consume_pending_heredocs(s, pos, end, hdocs, &hcnt);
            continue;
        }

        /* Command separators & pipelines: ; & && | || */
        if (c == ';' || c == '&' || c == '|') {
            bool is_pipe = (c == '|' && (pos + 1 >= end || s[pos + 1] != '|'));
            bool is_bg   = (c == '&' && (pos + 1 >= end || s[pos + 1] != '&'));

            if (ctx->active_fn[0] != '\0') {
                if (is_pipe) ctx->fn_has_pipe = true;
                if (is_bg) ctx->fn_has_bg = true;
            }

            /* Handle &>/path and &>>/path combined stdout+stderr redirects */
            if (c == '&' && pos + 1 < end && s[pos + 1] == '>' && !in_double_bracket) {
                pos += 2;
                if (pos < end && s[pos] == '>') pos++;
                while (pos < end && (s[pos] == ' ' || s[pos] == '\t')) pos++;
                char rtarget[MAX_WORD_LEN];
                bool rq = false;
                pos = lex_word(ctx, s, pos, end, stop_char, rtarget, sizeof(rtarget), &rq, depth);
                inspect_write_target(ctx, rtarget, true);
                continue;
            }

            bool is_net_src = false;
            inspect_simple_command(ctx, wcnt, words, wquoted, prev_was_net_pipe, &is_net_src, depth);
            wcnt = 0;
            in_double_bracket = false;
            prev_was_net_pipe = is_pipe ? is_net_src : false;

            if ((c == '&' || c == '|' || c == ';') && pos + 1 < end && s[pos + 1] == c) {
                pos += 2;
            } else {
                pos++;
            }
            continue;
        }

        /* Process substitution <(...) or >(...) */
        if ((c == '<' || c == '>') && pos + 1 < end && s[pos + 1] == '(') {
            scan_shell_slice(ctx, s, pos + 2, end, ')', depth + 1);
            size_t p = pos + 2;
            int sd = 1;
            while (p < end && sd > 0) {
                if (s[p] == '\\' && p + 1 < end) { p += 2; continue; }
                if (s[p] == '(') sd++;
                else if (s[p] == ')') sd--;
                p++;
            }
            pos = p;
            continue;
        }

        /* Redirections <, <<, <<<, >, >>, >|, <> */
        if (c == '<' || c == '>') {
            if (in_double_bracket) {
                /* Inside [[ ... ]], < and > are lexicographical comparison operators */
                pos++;
                continue;
            }
            if (c == '<' && pos + 1 < end && s[pos + 1] == '<') {
                if (pos + 2 < end && s[pos + 2] == '<') {
                    /* Here-string <<< word */
                    pos += 3;
                    while (pos < end && (s[pos] == ' ' || s[pos] == '\t')) pos++;
                    char hs[MAX_WORD_LEN];
                    bool hq = false;
                    pos = lex_word(ctx, s, pos, end, stop_char, hs, sizeof(hs), &hq, depth);
                    continue;
                }
                /* Heredoc << or <<- */
                pos += 2;
                bool strip = false;
                if (pos < end && s[pos] == '-') { strip = true; pos++; }
                while (pos < end && (s[pos] == ' ' || s[pos] == '\t')) pos++;
                char delim[MAX_WORD_LEN];
                bool dq = false;
                pos = lex_word(ctx, s, pos, end, stop_char, delim, sizeof(delim), &dq, depth);
                if (delim[0] && hcnt < MAX_HEREDOCS) {
                    snprintf(hdocs[hcnt].delim, sizeof(hdocs[hcnt].delim), "%.*s",
                             (int)sizeof(hdocs[hcnt].delim) - 1, delim);
                    hdocs[hcnt].strip_tabs = strip;
                    hcnt++;
                }
                continue;
            }

            bool is_out = (c == '>');
            pos++;
            if (pos < end && (s[pos] == '>' || s[pos] == '|' || s[pos] == '&')) {
                if (c == '<' && s[pos] == '>') is_out = true; /* <> read-write open */
                if (s[pos] == '&') {
                    pos++;
                    while (pos < end && (s[pos] == ' ' || s[pos] == '\t')) pos++;
                    char rtarget[MAX_WORD_LEN];
                    bool rq = false;
                    pos = lex_word(ctx, s, pos, end, stop_char, rtarget, sizeof(rtarget), &rq, depth);
                    if (is_out && rtarget[0] != '\0' && rtarget[0] != '-' &&
                        !isdigit((unsigned char)rtarget[0])) {
                        inspect_write_target(ctx, rtarget, true);
                    }
                    continue;
                }
                pos++;
            }
            while (pos < end && (s[pos] == ' ' || s[pos] == '\t')) pos++;
            char rtarget[MAX_WORD_LEN];
            bool rq = false;
            pos = lex_word(ctx, s, pos, end, stop_char, rtarget, sizeof(rtarget), &rq, depth);
            if (is_out) {
                inspect_write_target(ctx, rtarget, true);
            } else {
                /* Input redirect `< ~/.ssh/id_rsa` counts as reading a secret */
                char sl[96];
                if (word_references_secret(ctx, rtarget, sl, sizeof(sl))) {
                    ctx->touches_secret = true;
                    snprintf(ctx->secret_label, sizeof(ctx->secret_label), "%s", sl);
                    if (ctx->has_net_egress) {
                        char msg[256];
                        snprintf(msg, sizeof(msg),
                                 "secret input redirect (%s) paired with network egress (%s)",
                                 ctx->secret_label, ctx->net_label);
                        flag_block(ctx, "secret_exfiltration", msg);
                    }
                }
            }
            continue;
        }

        /* Parentheses: either function header `fname()` or subshell `(...)` */
        if (c == '(') {
            size_t look = pos + 1;
            while (look < end && (s[look] == ' ' || s[look] == '\t')) look++;
            if (look < end && s[look] == ')' && wcnt >= 1 && !wquoted[wcnt - 1]) {
                /* Shell function definition header: `<name>()` or `function <name>()` */
                const char *fn = words[wcnt - 1];
                snprintf(pending_fn, sizeof(pending_fn), "%.*s", (int)sizeof(pending_fn) - 1, fn);
                wcnt = 0;
                pos = look + 1;
                continue;
            }
            /* Subshell group (...) */
            bool is_net_src = false;
            inspect_simple_command(ctx, wcnt, words, wquoted, prev_was_net_pipe, &is_net_src, depth);
            wcnt = 0;
            if (pending_fn[0] != '\0') {
                snprintf(ctx->active_fn, sizeof(ctx->active_fn), "%s", pending_fn);
                ctx->fn_self_calls = 0;
                ctx->fn_has_pipe = false;
                ctx->fn_has_bg = false;
                pending_fn[0] = '\0';
            }
            scan_shell_slice(ctx, s, pos + 1, end, ')', depth + 1);
            ctx->active_fn[0] = '\0';
            size_t p = pos + 1;
            int sd = 1;
            bool dq = false;
            while (p < end && sd > 0) {
                if (s[p] == '\\' && p + 1 < end) { p += 2; continue; }
                if (!dq && s[p] == '\'') {
                    p++;
                    while (p < end && s[p] != '\'') p++;
                    if (p < end) p++;
                    continue;
                }
                if (s[p] == '"') { dq = !dq; p++; continue; }
                if (!dq) {
                    if (s[p] == '(') sd++;
                    else if (s[p] == ')') sd--;
                }
                p++;
            }
            pos = p;
            continue;
        }

        if (c == ')') {
            pos++;
            continue;
        }

        /* Lex a regular word token */
        char tok[MAX_WORD_LEN];
        bool quoted = false;
        size_t next_pos = lex_word(ctx, s, pos, end, stop_char, tok, sizeof(tok), &quoted, depth);
        if (next_pos == pos) {
            pos++;
            continue;
        }
        pos = next_pos;

        /* Handle numeric fd prefix immediately preceding < or > (e.g., 2>&1, 2>/dev/null) */
        if (!quoted && (pos < end && (s[pos] == '<' || s[pos] == '>'))) {
            bool all_digits = (tok[0] != '\0');
            for (const char *d = tok; *d; d++) {
                if (!isdigit((unsigned char)*d)) { all_digits = false; break; }
            }
            if (all_digits) continue;
        }

        /* Handle brace groups `{` and `}` (in bash/ash `{` may glue to token like `{:` in `:(){:|:&};:`) */
        if (!quoted && tok[0] == '{') {
            if (wcnt == 2 && !wquoted[0] && strcmp(words[0], "function") == 0) {
                snprintf(pending_fn, sizeof(pending_fn), "%.*s", (int)sizeof(pending_fn) - 1, words[1]);
                wcnt = 0;
            }
            if (pending_fn[0] != '\0') {
                snprintf(ctx->active_fn, sizeof(ctx->active_fn), "%s", pending_fn);
                ctx->fn_self_calls = 0;
                ctx->fn_has_pipe = false;
                ctx->fn_has_bg = false;
                pending_fn[0] = '\0';
                fn_brace_depth = 1;
            } else if (ctx->active_fn[0] != '\0') {
                fn_brace_depth++;
            }
            if (tok[1] == '\0') continue;
            memmove(tok, tok + 1, strlen(tok));
        }

        if (!quoted && strcmp(tok, "}") == 0) {
            bool is_net_src = false;
            inspect_simple_command(ctx, wcnt, words, wquoted, prev_was_net_pipe, &is_net_src, depth);
            wcnt = 0;
            if (ctx->active_fn[0] != '\0' && fn_brace_depth > 0) {
                fn_brace_depth--;
                if (fn_brace_depth == 0) {
                    if (ctx->fn_self_calls >= 2 && (ctx->fn_has_pipe || ctx->fn_has_bg)) {
                        flag_block(ctx, "fork_bomb",
                                   "recursive self-piped/backgrounded shell function fork bomb detected");
                    }
                    ctx->active_fn[0] = '\0';
                }
            }
            continue;
        }

        /* Track [[ ... ]] test blocks */
        if (!quoted && wcnt == 0 && strcmp(tok, "[[") == 0) {
            in_double_bracket = true;
        } else if (!quoted && in_double_bracket && strcmp(tok, "]]") == 0) {
            in_double_bracket = false;
        }

        /* Skip control-flow keywords at command start so inner commands parse cleanly */
        if (!quoted && wcnt == 0 &&
            (strcmp(tok, "then") == 0 || strcmp(tok, "do") == 0 ||
             strcmp(tok, "else") == 0 || strcmp(tok, "elif") == 0 ||
             strcmp(tok, "fi") == 0 || strcmp(tok, "done") == 0 ||
             strcmp(tok, "if") == 0 || strcmp(tok, "while") == 0 ||
             strcmp(tok, "until") == 0 || strcmp(tok, "!") == 0)) {
            continue;
        }

        /* Trailing `}` glued to last word in compact fork bomb `:(){ :|:&};:` */
        bool had_trailing_brace = false;
        size_t tlen = strlen(tok);
        if (!quoted && tlen > 1 && tok[tlen - 1] == '}' && ctx->active_fn[0] != '\0') {
            tok[tlen - 1] = '\0';
            had_trailing_brace = true;
        }

        if (wcnt < MAX_CMD_WORDS) {
            snprintf(words[wcnt], MAX_WORD_LEN, "%s", tok);
            wquoted[wcnt] = quoted;
            wcnt++;
        }

        if (had_trailing_brace) {
            bool is_net_src = false;
            inspect_simple_command(ctx, wcnt, words, wquoted, prev_was_net_pipe, &is_net_src, depth);
            wcnt = 0;
            if (ctx->fn_self_calls >= 2 && (ctx->fn_has_pipe || ctx->fn_has_bg)) {
                flag_block(ctx, "fork_bomb",
                           "recursive self-piped/backgrounded shell function fork bomb detected");
            }
            ctx->active_fn[0] = '\0';
            fn_brace_depth = 0;
        }
    }

    if (!ctx->blocked && wcnt > 0) {
        bool is_net_src = false;
        inspect_simple_command(ctx, wcnt, words, wquoted, prev_was_net_pipe, &is_net_src, depth);
    }

    free(words);
    free(wquoted);
}

static bool evaluate_command(const char *cmd, const char *cwd_override,
                             char *rule_out, size_t rcap, char *reason_out, size_t mcap) {
    GuardCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    resolve_home(ctx.home, sizeof(ctx.home));
    if (cwd_override && cwd_override[0]) {
        snprintf(ctx.cwd, sizeof(ctx.cwd), "%.*s", (int)sizeof(ctx.cwd) - 1, cwd_override);
    } else if (!getcwd(ctx.cwd, sizeof(ctx.cwd))) {
        snprintf(ctx.cwd, sizeof(ctx.cwd), "/");
    }

    if (cmd && cmd[0]) {
        scan_shell_slice(&ctx, cmd, 0, strlen(cmd), '\0', 0);
    }

    if (ctx.blocked) {
        snprintf(rule_out, rcap, "%s", ctx.rule);
        snprintf(reason_out, mcap, "%s", ctx.reason);
        return false;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * Minimal Zero-Dependency JSON String Extractor for PreToolUse Payloads
 * ------------------------------------------------------------------------- */

static bool extract_json_string_key(const char *json, const char *key,
                                    char *out, size_t cap) {
    if (!json || !key || cap == 0) return false;
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    size_t plen = strlen(pat);

    const char *p = json;
    while ((p = strstr(p, pat)) != NULL) {
        const char *q = p + plen;
        while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
        if (*q != ':') {
            p = q;
            continue;
        }
        q++;
        while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
        if (*q != '"') {
            p = q;
            continue;
        }
        q++;
        size_t oi = 0;
        while (*q && *q != '"') {
            if (*q == '\\' && q[1]) {
                q++;
                char esc = *q++;
                char decoded = esc;
                if (esc == 'n') decoded = '\n';
                else if (esc == 'r') decoded = '\r';
                else if (esc == 't') decoded = '\t';
                else if (esc == 'b') decoded = '\b';
                else if (esc == 'f') decoded = '\f';
                else if (esc == 'u' && isxdigit((unsigned char)q[0]) &&
                         isxdigit((unsigned char)q[1]) &&
                         isxdigit((unsigned char)q[2]) &&
                         isxdigit((unsigned char)q[3])) {
                    char hex[5] = { q[0], q[1], q[2], q[3], '\0' };
                    unsigned val = (unsigned)strtoul(hex, NULL, 16);
                    q += 4;
                    if (val < 0x80 && oi + 1 < cap) out[oi++] = (char)val;
                    continue;
                }
                if (oi + 1 < cap) out[oi++] = decoded;
            } else {
                if (oi + 1 < cap) out[oi++] = *q;
                q++;
            }
        }
        out[oi] = '\0';
        return true;
    }
    return false;
}

static int run_pretooluse_stdin(void) {
    char *buf = (char *)malloc(MAX_STDIN_JSON + 1);
    if (!buf) return 0;

    size_t got = 0;
    while (got < MAX_STDIN_JSON) {
        ssize_t n = read(STDIN_FILENO, buf + got, MAX_STDIN_JSON - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    buf[got] = '\0';
    if (got == 0) {
        free(buf);
        return 0;
    }

    char tool_name[128] = {0};
    if (!extract_json_string_key(buf, "tool_name", tool_name, sizeof(tool_name))) {
        if (!extract_json_string_key(buf, "tool", tool_name, sizeof(tool_name))) {
            (void)extract_json_string_key(buf, "name", tool_name, sizeof(tool_name));
        }
    }

    char cwd[PATH_MAX] = {0};
    (void)extract_json_string_key(buf, "cwd", cwd, sizeof(cwd));

    bool is_shell_tool = (tool_name[0] == '\0' ||
                          strcasecmp(tool_name, "Bash") == 0 ||
                          strcasecmp(tool_name, "RunCommand") == 0 ||
                          strcasecmp(tool_name, "run_command") == 0 ||
                          strcasecmp(tool_name, "run_terminal_cmd") == 0 ||
                          strcasecmp(tool_name, "execute_command") == 0 ||
                          strcasecmp(tool_name, "shell") == 0);

    bool is_write_tool = (strcasecmp(tool_name, "Write") == 0 ||
                          strcasecmp(tool_name, "WriteFile") == 0 ||
                          strcasecmp(tool_name, "write_to_file") == 0 ||
                          strcasecmp(tool_name, "Edit") == 0 ||
                          strcasecmp(tool_name, "MultiEdit") == 0 ||
                          strcasecmp(tool_name, "Replace") == 0);

    char rule[48] = {0};
    char reason[256] = {0};
    bool allowed = true;

    if (is_shell_tool) {
        char *cmd = (char *)malloc(MAX_STDIN_JSON);
        if (cmd) {
            cmd[0] = '\0';
            if (extract_json_string_key(buf, "command", cmd, MAX_STDIN_JSON) ||
                extract_json_string_key(buf, "CommandLine", cmd, MAX_STDIN_JSON)) {
                allowed = evaluate_command(cmd, cwd, rule, sizeof(rule), reason, sizeof(reason));
            }
            free(cmd);
        }
    } else if (is_write_tool) {
        char fpath[PATH_MAX] = {0};
        if (extract_json_string_key(buf, "file_path", fpath, sizeof(fpath)) ||
            extract_json_string_key(buf, "path", fpath, sizeof(fpath)) ||
            extract_json_string_key(buf, "target_file", fpath, sizeof(fpath))) {
            GuardCtx ctx;
            memset(&ctx, 0, sizeof(ctx));
            resolve_home(ctx.home, sizeof(ctx.home));
            if (cwd[0]) snprintf(ctx.cwd, sizeof(ctx.cwd), "%.*s", (int)sizeof(ctx.cwd) - 1, cwd);
            else if (!getcwd(ctx.cwd, sizeof(ctx.cwd))) snprintf(ctx.cwd, sizeof(ctx.cwd), "/");
            inspect_write_target(&ctx, fpath, false);
            if (ctx.blocked) {
                allowed = false;
                snprintf(rule, sizeof(rule), "%s", ctx.rule);
                snprintf(reason, sizeof(reason), "%s", ctx.reason);
            }
        }
    }

    free(buf);

    if (allowed) {
        return 0;
    }

    char full_msg[384];
    snprintf(full_msg, sizeof(full_msg), "Hephaestus Shield blocked [%s]: %s", rule, reason);

    printf("{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\","
           "\"permissionDecision\":\"deny\",\"permissionDecisionReason\":");
    json_print_escaped(stdout, full_msg);
    printf("},\"permission\":\"deny\",\"decision\":\"block\",\"rule\":");
    json_print_escaped(stdout, rule);
    printf(",\"reason\":");
    json_print_escaped(stdout, full_msg);
    printf("}\n");

    fprintf(stderr, "%s\n", full_msg);
    return 2;
}

/* -------------------------------------------------------------------------
 * CLI Entrypoint
 * ------------------------------------------------------------------------- */

static void print_usage(FILE *fp) {
    fprintf(fp,
        "hhook %s - Hephaestus Organ 2: Sub-Millisecond PreToolUse & Shell Guard\n"
        "\n"
        "Usage:\n"
        "  hhook check <command> [--json]\n"
        "  hhook [claude-pre | cursor-pre | agy-pre] < payload.json\n"
        "  hhook --help | --version\n"
        "\n"
        "Modes:\n"
        "  check        Structurally inspect a shell command string (exit 0 allow, 1 block).\n"
        "  claude-pre   Read PreToolUse JSON from stdin (also default when stdin is piped).\n",
        HHOOK_VERSION);
}

int main(int argc, char **argv) {
    if (argc == 1) {
        if (isatty(STDIN_FILENO)) {
            print_usage(stderr);
            return 2;
        }
        return run_pretooluse_stdin();
    }

    const char *sub = argv[1];
    if (strcmp(sub, "--help") == 0 || strcmp(sub, "-h") == 0 || strcmp(sub, "help") == 0) {
        print_usage(stdout);
        return 0;
    }
    if (strcmp(sub, "--version") == 0 || strcmp(sub, "-v") == 0 || strcmp(sub, "version") == 0) {
        printf("hhook %s\n", HHOOK_VERSION);
        return 0;
    }
    if (strcmp(sub, "claude-pre") == 0 || strcmp(sub, "cursor-pre") == 0 ||
        strcmp(sub, "agy-pre") == 0 || strcmp(sub, "pre-tool-use") == 0 ||
        strcmp(sub, "hook") == 0) {
        return run_pretooluse_stdin();
    }

    if (strcmp(sub, "check") == 0) {
        bool json_mode = false;
        const char *cmd = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) {
                json_mode = true;
            } else if (!cmd) {
                cmd = argv[i];
            } else {
                fprintf(stderr, "hhook check: unexpected extra argument '%s'\n", argv[i]);
                return 2;
            }
        }
        if (!cmd) {
            fprintf(stderr, "Usage: hhook check <command> [--json]\n");
            return 2;
        }

        char rule[48] = {0};
        char reason[256] = {0};
        bool ok = evaluate_command(cmd, NULL, rule, sizeof(rule), reason, sizeof(reason));
        if (ok) {
            if (json_mode) {
                printf("{\"ok\":true,\"allowed\":true,\"decision\":\"allow\"}\n");
            } else {
                printf("ALLOW: command passed shield preflight\n");
            }
            return 0;
        } else {
            if (json_mode) {
                printf("{\"ok\":true,\"allowed\":false,\"decision\":\"block\",\"rule\":");
                json_print_escaped(stdout, rule);
                printf(",\"reason\":");
                json_print_escaped(stdout, reason);
                printf("}\n");
            } else {
                fprintf(stderr, "BLOCK [%s]: %s\n", rule, reason);
            }
            return 1;
        }
    }

    fprintf(stderr, "hhook: unknown subcommand '%s' (see 'hhook --help')\n", sub);
    return 2;
}
