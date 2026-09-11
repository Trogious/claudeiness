/*
 * claudeiness — Detect selected processes and update Slack status.
 *
 * Detection strategy (layered, cross-referenced):
 *
 * 1. BSD process table scan via sysctl(KERN_PROC_UID)
 *    - Ground truth for what is actually running
 *    - Matches selected executable names (defaults to Claude Code)
 *    - Skips zombies
 *
 * 2. Executable path validation via proc_pidpath()
 *    - Confirms the binary is the real Claude Code executable
 *    - Checks Mach-O magic bytes to reject scripts named "claude"
 *    - Falls back to trusting process name if path can't be read
 *
 * 3. Session file enrichment from ~/.claude/sessions/ *.json
 *    - Adds sessionId, cwd, startedAt metadata
 *    - NOT used for counting — only enrichment
 *    - Stale files (dead PIDs) are naturally ignored
 *
 * 4. Slack status update via users.profile.set
 *    - Token from SLACK_TOKEN environment variable
 *    - Skipped if token is not set
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <dirent.h>
#include <pwd.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/wait.h>

#define EXIT_COMMAND_NOT_FOUND 127

/* ── Data structures ─────────────────────────────────────────────── */

#define MAX_SESSIONS 64
#define MAX_PATH 1024
#define MAX_ARGS 4096
#define MAX_PROCESSES 16
#define MAX_PROCESS_NAME 255
#define MAX_STATUS_TEXT 101

typedef struct {
    const char *names[MAX_PROCESSES];
    int count;
} process_config_t;

typedef struct {
    pid_t pid;
    int   process_index;
    char  tty[32];
    char  args[MAX_ARGS];
    char  cwd[MAX_PATH];
    char  exe_path[MAX_PATH];
    /* Enrichment from session files */
    char  session_id[128];
    int   has_session_file;
    time_t started_at;    /* 0 = unknown */
} process_session_t;

static int is_claude(const char *name) {
    return strcasecmp(name, "claude") == 0;
}

static int add_process(process_config_t *config, const char *name) {
    if (!name[0] || name[0] == '-' || strlen(name) > MAX_PROCESS_NAME ||
        strchr(name, '/')) {
        fprintf(stderr, "Error: --process requires an executable name (1–255 bytes), not a path\n");
        return 0;
    }
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        if (*p < 0x20 || *p == 0x7f) {
            fprintf(stderr, "Error: process names cannot contain control characters\n");
            return 0;
        }
    }
    for (int i = 0; i < config->count; i++) {
        if (strcasecmp(config->names[i], name) == 0) return 1;
    }
    if (config->count == MAX_PROCESSES) {
        fprintf(stderr, "Error: at most %d process names can be monitored\n", MAX_PROCESSES);
        return 0;
    }
    config->names[config->count++] = is_claude(name) ? "claude" : name;
    return 1;
}

/* ── Step 1: BSD process table scan ──────────────────────────────── */

/*
 * Check if a string looks like a semver version (e.g. "2.1.89").
 * Claude Code installed via `claude --install` uses the version number
 * as the binary filename, so p_comm becomes "2.1.89" instead of "claude".
 */
static int is_version_string(const char *s) {
    if (!s || !(*s >= '0' && *s <= '9')) return 0;
    int dots = 0;
    for (const char *p = s; *p; p++) {
        if (*p == '.') dots++;
        else if (*p < '0' || *p > '9') return 0;
    }
    return dots >= 1;
}

static int validate_claude_binary(pid_t pid);

/* Prefer the full executable basename: macOS truncates p_comm. */
static int match_process(const process_config_t *config, const char *comm,
                         const char *path) {
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;
    for (int i = 0; i < config->count; i++) {
        if (!is_claude(config->names[i]) &&
            strcasecmp(config->names[i], path[0] ? basename : comm) == 0) {
            return i;
        }
    }
    for (int i = 0; i < config->count; i++) {
        if (is_claude(config->names[i]) &&
            (strcmp(comm, "claude") == 0 || is_version_string(comm)))
            return i;  /* Claude-specific binary validation follows. */
    }
    return -1;
}

/* Query the current user's live processes and collect selected executables. */
static int find_processes(process_session_t *out, int max,
                          const process_config_t *config) {
    uid_t uid = getuid();
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_UID, (int)uid };
    size_t buf_size = 0;

    /* First call: get required buffer size */
    if (sysctl(mib, 4, NULL, &buf_size, NULL, 0) < 0) {
        perror("sysctl(KERN_PROC_UID) size");
        return 0;
    }

    /* Add 20% headroom for new processes appearing between calls */
    buf_size = buf_size * 6 / 5;
    struct kinfo_proc *procs = malloc(buf_size);
    if (!procs) return 0;

    /* Second call: fill buffer */
    if (sysctl(mib, 4, procs, &buf_size, NULL, 0) < 0) {
        perror("sysctl(KERN_PROC_UID) fill");
        free(procs);
        return 0;
    }

    int count = (int)(buf_size / sizeof(struct kinfo_proc));
    int found = 0;

    for (int i = 0; i < count && found < max; i++) {
        struct kinfo_proc *p = &procs[i];

        /* Skip zombies */
        if (p->kp_proc.p_stat == SZOMB)
            continue;

        if (config->count == 1 && is_claude(config->names[0]) &&
            strcmp(p->kp_proc.p_comm, "claude") != 0 &&
            !is_version_string(p->kp_proc.p_comm))
            continue;

        char path[PROC_PIDPATHINFO_MAXSIZE] = "";
        if (proc_pidpath(p->kp_proc.p_pid, path, sizeof(path)) <= 0)
            path[0] = '\0';
        int process_index = match_process(config, p->kp_proc.p_comm, path);
        if (process_index < 0 ||
            (is_claude(config->names[process_index]) &&
             !validate_claude_binary(p->kp_proc.p_pid)))
            continue;

        process_session_t *s = &out[found];
        memset(s, 0, sizeof(*s));
        s->pid = p->kp_proc.p_pid;
        s->process_index = process_index;
        snprintf(s->exe_path, sizeof(s->exe_path), "%s", path);

        /* TTY device → name */
        dev_t tdev = p->kp_eproc.e_tdev;
        if (tdev != 0 && tdev != (dev_t)-1) {
            char *dn = devname(tdev, S_IFCHR);
            if (dn) snprintf(s->tty, sizeof(s->tty), "%s", dn);
        }

        /* Full command-line args via KERN_PROCARGS2 */
        {
            int args_mib[3] = { CTL_KERN, KERN_PROCARGS2, s->pid };
            size_t args_size = 0;
            if (sysctl(args_mib, 3, NULL, &args_size, NULL, 0) == 0 && args_size > 0) {
                char *buf = malloc(args_size);
                if (buf && sysctl(args_mib, 3, buf, &args_size, NULL, 0) == 0 &&
                    args_size >= sizeof(int)) {
                    /* Layout: [int argc][exec_path\0][padding\0s][argv0\0 argv1\0 ...] */
                    int argc;
                    memcpy(&argc, buf, sizeof(int));
                    size_t off = sizeof(int);

                    /* Skip exec path */
                    while (off < args_size && buf[off] != '\0') off++;
                    /* Skip null padding */
                    while (off < args_size && buf[off] == '\0') off++;

                    /* Collect argv */
                    size_t out_off = 0;
                    int arg_i = 0;
                    while (off < args_size && arg_i < argc) {
                        size_t len = strnlen(&buf[off], args_size - off);
                        if (len > 0) {
                            if (out_off > 0 && out_off < MAX_ARGS - 1)
                                s->args[out_off++] = ' ';
                            size_t copy_len = len;
                            if (out_off + copy_len >= MAX_ARGS - 1)
                                copy_len = MAX_ARGS - 1 - out_off;
                            memcpy(&s->args[out_off], &buf[off], copy_len);
                            out_off += copy_len;
                        }
                        off += len + 1;
                        arg_i++;
                    }
                    s->args[out_off] = '\0';
                }
                free(buf);
            }
            if (s->args[0] == '\0')
                snprintf(s->args, sizeof(s->args), "%s", config->names[process_index]);
        }

        /* Current working directory via proc_pidinfo */
        {
            struct proc_vnodepathinfo vpi;
            int ret = proc_pidinfo(s->pid, PROC_PIDVNODEPATHINFO, 0,
                                   &vpi, sizeof(vpi));
            if (ret == (int)sizeof(vpi) && vpi.pvi_cdir.vip_path[0] != '\0') {
                snprintf(s->cwd, sizeof(s->cwd), "%s", vpi.pvi_cdir.vip_path);
            }
        }

        found++;
    }

    free(procs);
    return found;
}

/* ── Step 2: Executable path validation ──────────────────────────── */

/*
 * Check if a file starts with a Mach-O magic number.
 * This distinguishes the real Claude Code binary from shell scripts
 * that happen to be named "claude".
 */
static int is_macho_binary(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    uint32_t magic;
    ssize_t n = read(fd, &magic, sizeof(magic));
    close(fd);

    if (n != sizeof(magic)) return 0;

    return magic == MH_MAGIC_64  || magic == MH_CIGAM_64 ||
           magic == MH_MAGIC     || magic == MH_CIGAM    ||
           magic == FAT_MAGIC    || magic == FAT_CIGAM;
}

/*
 * Validate that a PID is running the actual Claude Code binary.
 * Returns 1 if valid, 0 if definitely not Claude Code.
 */
static int validate_claude_binary(pid_t pid) {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    int ret = proc_pidpath(pid, path, sizeof(path));

    if (ret <= 0) {
        /*
         * Can't determine path (permissions? race condition?).
         * Better to over-count than miss a real session.
         */
        return 1;
    }

    /* Known install locations */
    if (strcmp(path, "/opt/homebrew/bin/claude") == 0 ||
        strcmp(path, "/usr/local/bin/claude") == 0) {
        return 1;
    }

    /*
     * Resolve symlinks — homebrew often symlinks from Cellar.
     * Also covers npm global installs, volta, etc.
     */
    char resolved[MAX_PATH];
    if (realpath(path, resolved)) {
        if (strcmp(resolved, "/opt/homebrew/bin/claude") == 0 ||
            strcmp(resolved, "/usr/local/bin/claude") == 0) {
            return 1;
        }
    }

    /*
     * Claude Code installed via `claude --install` puts the binary at
     * ~/.local/share/claude/versions/<version> and proc_pidpath resolves
     * to that versioned path (basename is e.g. "2.1.89", not "claude").
     */
    if (strstr(path, "/.local/share/claude/versions/") != NULL) {
        return is_macho_binary(path);
    }

    /*
     * For any other path ending in "/claude", accept if it's a Mach-O binary
     * (reject shell scripts, Python scripts, etc. that happen to be named claude).
     */
    const char *basename = strrchr(path, '/');
    if (basename && strcmp(basename + 1, "claude") == 0) {
        return is_macho_binary(path);
    }

    return 0;
}

/* ── Step 3: Session file enrichment ─────────────────────────────── */

/*
 * Minimal JSON string value extractor.
 * Finds "key":"value" and copies value into out.
 * Handles escaped quotes. Returns 1 on success.
 */
static int json_get_string(const char *json, const char *key, char *out, size_t out_size) {
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *pos = strstr(json, needle);
    if (!pos) return 0;

    pos += strlen(needle);
    /* Skip whitespace and colon */
    while (*pos == ' ' || *pos == ':' || *pos == '\t') pos++;
    if (*pos != '"') return 0;
    pos++; /* skip opening quote */

    size_t i = 0;
    while (*pos && *pos != '"' && i < out_size - 1) {
        if (*pos == '\\' && *(pos + 1)) {
            pos++; /* skip escape char */
        }
        out[i++] = *pos++;
    }
    out[i] = '\0';
    return 1;
}

/*
 * Extract a numeric value for "key":12345 from JSON.
 */
static int json_get_number(const char *json, const char *key, long long *out) {
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *pos = strstr(json, needle);
    if (!pos) return 0;

    pos += strlen(needle);
    while (*pos == ' ' || *pos == ':' || *pos == '\t') pos++;

    char *end;
    *out = strtoll(pos, &end, 10);
    return end != pos;
}

/*
 * Scan ~/.claude/sessions/ *.json and enrich matching sessions.
 */
static void enrich_from_session_files(process_session_t *sessions, int count,
                                       const process_config_t *config) {
    struct passwd *pw = getpwuid(getuid());
    if (!pw) return;

    char dir_path[MAX_PATH];
    snprintf(dir_path, sizeof(dir_path), "%s/.claude/sessions", pw->pw_dir);

    DIR *dir = opendir(dir_path);
    if (!dir) return;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        size_t namelen = strlen(ent->d_name);
        if (namelen < 6 || strcmp(&ent->d_name[namelen - 5], ".json") != 0)
            continue;

        char filepath[MAX_PATH];
        snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, ent->d_name);

        FILE *f = fopen(filepath, "r");
        if (!f) continue;

        char buf[4096];
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';

        long long file_pid;
        if (!json_get_number(buf, "pid", &file_pid))
            continue;

        /* Find matching live session */
        for (int i = 0; i < count; i++) {
            if (is_claude(config->names[sessions[i].process_index]) &&
                sessions[i].pid == (pid_t)file_pid) {
                sessions[i].has_session_file = 1;
                json_get_string(buf, "sessionId", sessions[i].session_id,
                                sizeof(sessions[i].session_id));
                /* cwd from session file as fallback */
                if (sessions[i].cwd[0] == '\0') {
                    json_get_string(buf, "cwd", sessions[i].cwd,
                                    sizeof(sessions[i].cwd));
                }
                long long ts;
                if (json_get_number(buf, "startedAt", &ts)) {
                    sessions[i].started_at = (time_t)(ts / 1000);
                }
                break;
            }
        }
    }
    closedir(dir);
}

/* ── Step 4: Slack status update ─────────────────────────────────── */

#define MAX_STATUS_EMOJIS 7

/* Append a label without splitting a UTF-8 character at the status limit. */
static void append_status_label(char *out, size_t out_size, const char *label) {
    size_t off = strlen(out);
    size_t separator = off > 0 ? 1 : 0;
    if (off + separator + 1 >= out_size) return;
    size_t len = strlen(label);
    size_t available = out_size - off - separator - 1;
    size_t copy = len < available ? len : available;
    while (copy > 0 && ((unsigned char)label[copy] & 0xc0) == 0x80) copy--;
    if (copy == 0) return;
    if (separator) out[off++] = ' ';
    memcpy(out + off, label, copy);
    out[off + copy] = '\0';
}

/* Keep Claude's emoji count; identify other apps by name and process count. */
static void build_status_text(const process_config_t *config, const int *counts,
                              char *out, size_t out_size) {
    if (out_size == 0) return;
    out[0] = '\0';
    for (int i = 0; i < config->count; i++) {
        if (counts[i] <= 0) continue;
        if (is_claude(config->names[i])) {
            int n = counts[i] > MAX_STATUS_EMOJIS ? MAX_STATUS_EMOJIS : counts[i];
            for (int j = 0; j < n; j++)
                append_status_label(out, out_size, ":claude_code:");
        } else {
            char label[MAX_PROCESS_NAME + 32];
            if (counts[i] == 1)
                snprintf(label, sizeof(label), "%s", config->names[i]);
            else
                snprintf(label, sizeof(label), "%s (%d)", config->names[i], counts[i]);
            append_status_label(out, out_size, label);
        }
    }
}

static void write_json_string(FILE *out, const char *value) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\')
            fprintf(out, "\\%c", *p);
        else if (*p < 0x20)
            fprintf(out, "\\u%04x", *p);
        else
            fputc(*p, out);
    }
    fputc('"', out);
}

/*
 * POST to Slack users.profile.set using /usr/bin/curl.
 * We shell out to curl rather than pulling in libcurl as a dependency.
 * The token and body are passed via argv to exec, not interpolated into a shell string.
 */
static int update_slack_status(const char *token, const process_config_t *config,
                               const int *counts) {
    char status_text[MAX_STATUS_TEXT];
    build_status_text(config, counts, status_text, sizeof(status_text));
    const char *emoji = status_text[0] ? ":computer:" : "";
    for (int i = 0; i < config->count; i++) {
        if (is_claude(config->names[i]) && counts[i] > 0) emoji = ":claude_code:";
    }

    char *body = NULL;
    size_t body_size = 0;
    FILE *payload = open_memstream(&body, &body_size);
    if (!payload) return -1;
    fputs("{\"profile\":{\"status_text\":", payload);
    write_json_string(payload, status_text);
    fprintf(payload, ",\"status_emoji\":\"%s\",\"status_expiration\":0}}", emoji);
    if (fclose(payload) != 0) {
        free(body);
        return -1;
    }

    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);

    /* Build curl argv directly and capture its response through a pipe. */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        free(body);
        return -1;
    }

    pid_t cpid = fork();
    if (cpid < 0) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        free(body);
        return -1;
    }

    if (cpid == 0) {
        /* Child: run curl, capture stdout+stderr */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        execlp("curl", "curl", "-s",
               "-X", "POST",
               "-H", "Content-Type: application/json; charset=utf-8",
               "-H", auth_header,
               "-d", body,
               "https://slack.com/api/users.profile.set",
               (char *)NULL);
        _exit(127);
    }

    free(body);

    /* Parent: read response */
    close(pipefd[1]);

    char response[4096];
    size_t total = 0;
    ssize_t nr;
    while ((nr = read(pipefd[0], response + total, sizeof(response) - total - 1)) > 0) {
        total += (size_t)nr;
    }
    close(pipefd[0]);
    response[total] = '\0';

    int status;
    waitpid(cpid, &status, 0);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "curl failed (exit %d): %s\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1, response);
        return -1;
    }

    /* Check for "ok":true in response */
    if (strstr(response, "\"ok\":true") || strstr(response, "\"ok\": true")) {
        return 0;
    }

    fprintf(stderr, "Slack API error: %s\n", response);
    return -1;
}

/* ── Detect + validate (combined) ────────────────────────────────── */

static int detect_sessions(process_session_t *sessions, int max,
                           const process_config_t *config, int *counts) {
    memset(counts, 0, sizeof(int) * MAX_PROCESSES);
    int count = find_processes(sessions, max, config);
    for (int i = 0; i < count; i++)
        counts[sessions[i].process_index]++;
    for (int i = 0; i < config->count; i++) {
        if (is_claude(config->names[i]) && counts[i] > 0) {
            enrich_from_session_files(sessions, count, config);
            break;
        }
    }
    return count;
}

/* ── Output helpers ──────────────────────────────────────────────── */

static void print_timestamp(void) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", tm);
    printf("[%s] ", ts);
}

static void print_sessions(process_session_t *sessions, int count,
                           const process_config_t *config) {
    print_timestamp();
    if (config->count == 1 && is_claude(config->names[0]))
        printf("Detected %d Claude Code session%s\n", count, count == 1 ? "" : "s");
    else {
        printf("Detected %d process%s (", count, count == 1 ? "" : "es");
        for (int i = 0; i < config->count; i++)
            printf("%s%s", i ? ", " : "", config->names[i]);
        printf(")\n");
    }

    for (int i = 0; i < count; i++) {
        process_session_t *s = &sessions[i];
        printf("  PID %-6d | %s", s->pid, config->names[s->process_index]);
        if (s->tty[0]) printf(" | %s", s->tty);
        if (s->cwd[0]) printf(" | %s", s->cwd);
        if (s->session_id[0]) printf(" | session: %s", s->session_id);
        if (s->started_at > 0) {
            struct tm *stm = localtime(&s->started_at);
            char started[32];
            strftime(started, sizeof(started), "%H:%M:%S", stm);
            printf(" | started: %s", started);
        }
        printf(" | %s\n", s->args);
    }
}

static void print_json_field(const char *key, const char *value) {
    printf(",\"%s\":", key);
    write_json_string(stdout, value);
}

static void print_json(process_session_t *sessions, int count,
                       const process_config_t *config) {
    printf("{\"count\":%d,\"sessions\":[", count);
    for (int i = 0; i < count; i++) {
        process_session_t *s = &sessions[i];
        if (i > 0) printf(",");
        printf("{\"pid\":%d", s->pid);
        print_json_field("process", config->names[s->process_index]);
        if (s->tty[0]) print_json_field("tty", s->tty);
        if (s->cwd[0]) print_json_field("cwd", s->cwd);
        if (s->exe_path[0]) print_json_field("exe", s->exe_path);
        if (s->session_id[0]) print_json_field("sessionId", s->session_id);
        if (s->started_at > 0) printf(",\"startedAt\":%ld", (long)s->started_at);
        print_json_field("args", s->args);
        printf("}");
    }
    printf("]}\n");
}

/* ── Main ────────────────────────────────────────────────────────── */

#define DEFAULT_POLL_SECONDS 2

static volatile int g_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

static void write_xml_string(FILE *out, const char *value) {
    fputs("        <string>", out);
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        switch (*p) {
            case '&': fputs("&amp;", out); break;
            case '<': fputs("&lt;", out); break;
            case '>': fputs("&gt;", out); break;
            case '"': fputs("&quot;", out); break;
            case '\'': fputs("&apos;", out); break;
            default: fputc(*p, out); break;
        }
    }
    fputs("</string>\n", out);
}

static int write_service_plist(FILE *out, const char *binary_path, const char *token,
                               const process_config_t *config, int poll_interval,
                               int json_output, int quiet) {
    fputs("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
          "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\""
          " \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
          "<plist version=\"1.0\">\n<dict>\n"
          "    <key>Label</key>\n    <string>com.claudeiness.agent</string>\n"
          "    <key>ProgramArguments</key>\n    <array>\n", out);
    write_xml_string(out, binary_path);
    write_xml_string(out, "--watch");
    for (int i = 0; i < config->count; i++) {
        write_xml_string(out, "--process");
        write_xml_string(out, config->names[i]);
    }
    char interval[32];
    snprintf(interval, sizeof(interval), "%d", poll_interval);
    write_xml_string(out, "--interval");
    write_xml_string(out, interval);
    if (json_output) write_xml_string(out, "--json");
    if (quiet) write_xml_string(out, "--quiet");
    fputs("    </array>\n    <key>EnvironmentVariables</key>\n    <dict>\n"
          "        <key>SLACK_TOKEN</key>\n", out);
    write_xml_string(out, token);
    fputs("    </dict>\n    <key>RunAtLoad</key>\n    <true/>\n"
          "    <key>KeepAlive</key>\n    <true/>\n"
          "    <key>StandardOutPath</key>\n    <string>/tmp/claudeiness.log</string>\n"
          "    <key>StandardErrorPath</key>\n    <string>/tmp/claudeiness.error.log</string>\n"
          "</dict>\n</plist>\n", out);
    return !ferror(out);
}

static int install_service(const process_config_t *config, int poll_interval,
                           int json_output, int quiet) {
    /* Resolve own binary path */
    char binary_path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(getpid(), binary_path, sizeof(binary_path)) <= 0) {
        fprintf(stderr, "Error: cannot determine binary path: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /* Build plist destination path */
    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') {
        fprintf(stderr, "Error: HOME environment variable not set\n");
        return EXIT_FAILURE;
    }
    char plist_path[MAX_PATH];
    int plist_path_len = snprintf(plist_path, sizeof(plist_path),
             "%s/Library/LaunchAgents/com.claudeiness.agent.plist", home);
    if (plist_path_len < 0 || (size_t)plist_path_len >= sizeof(plist_path)) {
        fprintf(stderr, "Error: HOME path too long\n");
        return EXIT_FAILURE;
    }

    /* Read SLACK_TOKEN for embedding; use placeholder if absent */
    const char *token = getenv("SLACK_TOKEN");
    const char *token_value = (token && token[0] != '\0')
                              ? token
                              : "YOUR_SLACK_TOKEN_HERE";

    /* Write plist with the same process selection and watch options. */
    FILE *f = fopen(plist_path, "w");
    if (!f) {
        fprintf(stderr, "Error: cannot write plist to %s: %s\n",
                plist_path, strerror(errno));
        return EXIT_FAILURE;
    }
    int wrote = write_service_plist(f, binary_path, token_value, config,
                                    poll_interval, json_output, quiet);
    int closed = fclose(f);
    if (!wrote || closed != 0) {
        fprintf(stderr, "Error: failed to write plist to %s\n", plist_path);
        return EXIT_FAILURE;
    }

    /* Load the service via launchctl (fork/exec to avoid shell injection) */
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Warning: fork failed: %s\n"
                        "The plist was written to %s — load it manually if needed.\n",
                strerror(errno), plist_path);
        return EXIT_FAILURE;
    }
    if (pid == 0) {
        /* child */
        execl("/bin/launchctl", "launchctl", "load", plist_path, (char *)NULL);
        _exit(EXIT_COMMAND_NOT_FOUND);
    }
    /* parent: wait for launchctl */
    int wstatus = 0;
    waitpid(pid, &wstatus, 0);
    int exit_code = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
    if (exit_code != 0) {
        fprintf(stderr, "Warning: launchctl load exited with status %d\n"
                        "The plist was written to %s — load it manually if needed.\n",
                exit_code, plist_path);
        return EXIT_FAILURE;
    }

    printf("Service installed and loaded.\n");
    printf("  Plist:   %s\n", plist_path);
    printf("  Binary:  %s\n", binary_path);
    if (!token || token[0] == '\0') {
        printf("\nIMPORTANT: SLACK_TOKEN was not set.\n"
               "Edit the plist and replace YOUR_SLACK_TOKEN_HERE with your token,\n"
               "then run: launchctl unload \"%s\" && launchctl load \"%s\"\n",
               plist_path, plist_path);
    }
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    int json_output = 0;
    int watch_mode = 0;
    int quiet = 0;
    int poll_interval = DEFAULT_POLL_SECONDS;
    int install_service_mode = 0;
    process_config_t config = {0};

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--process") == 0 || strcmp(argv[i], "-p") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --process requires an executable name\n");
                return EXIT_FAILURE;
            }
            if (!add_process(&config, argv[++i])) return EXIT_FAILURE;
        } else if (strncmp(argv[i], "--process=", 10) == 0) {
            if (!add_process(&config, argv[i] + 10)) return EXIT_FAILURE;
        } else if (strcmp(argv[i], "--json") == 0) {
            json_output = 1;
        } else if (strcmp(argv[i], "--watch") == 0 || strcmp(argv[i], "-w") == 0) {
            watch_mode = 1;
        } else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            poll_interval = atoi(argv[++i]);
            if (poll_interval < 1) poll_interval = 1;
        } else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) {
            quiet = 1;
        } else if (strcmp(argv[i], "--install-service") == 0) {
            install_service_mode = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            fprintf(stderr,
                "Usage: claudeiness [--process NAME ...] [--json] [--watch [--interval N]]\n"
                "       claudeiness --install-service [--process NAME ...] [--interval N]\n\n"
                "Detects selected processes and updates Slack status (default: Claude Code).\n\n"
                "Modes:\n"
                "  (default)          One-shot: detect, print, update Slack, exit.\n"
                "  --watch, -w        Watch: poll every N seconds (default %d),\n"
                "                     update Slack when any selected process count changes.\n"
                "  --install-service  Generate and install a launchd plist so watch\n"
                "                     mode starts automatically at login.\n\n"
                "Options:\n"
                "  --process, -p NAME  Monitor this executable name (repeatable, max 16).\n"
                "                     Replaces the default Claude selection; case-insensitive,\n"
                "                     exact name matching (excludes app helper processes).\n"
                "  --json          Output as JSON\n"
                "  --quiet, -q     Suppress all output\n"
                "  --interval N    Poll interval in seconds (default %d, min 1)\n\n"
                "Examples:\n"
                "  claudeiness --process Obsidian\n"
                "  claudeiness --watch --process claude --process Obsidian\n\n"
                "Environment:\n"
                "  SLACK_TOKEN   Slack OAuth token (scope: users.profile:write)\n"
                "                If not set, Slack update is skipped.\n"
                "                Set before running --install-service to embed in plist.\n",
                DEFAULT_POLL_SECONDS, DEFAULT_POLL_SECONDS);
            return EXIT_SUCCESS;
        } else {
            fprintf(stderr, "Error: unknown option or missing value: %s\n", argv[i]);
            return EXIT_FAILURE;
        }
    }

    if (config.count == 0) add_process(&config, "claude");
    if (install_service_mode)
        return install_service(&config, poll_interval, json_output, quiet);

    const char *token = getenv("SLACK_TOKEN");
    int has_token = token && token[0] != '\0';

    if (!watch_mode) {
        /* ── One-shot mode ──────────────────────────────────── */
        process_session_t sessions[MAX_SESSIONS];
        int counts[MAX_PROCESSES];
        int count = detect_sessions(sessions, MAX_SESSIONS, &config, counts);

        if (!quiet) {
            if (json_output)
                print_json(sessions, count, &config);
            else
                print_sessions(sessions, count, &config);
        }

        if (!has_token) {
            if (!quiet && !json_output)
                printf("\nSkipping Slack update (set SLACK_TOKEN to enable)\n");
            return EXIT_SUCCESS;
        }

        int result = update_slack_status(token, &config, counts);
        if (result == 0) {
            if (!quiet && !json_output) {
                char status_text[MAX_STATUS_TEXT];
                build_status_text(&config, counts, status_text, sizeof(status_text));
                printf("Slack status updated: %s\n",
                       count > 0 ? status_text : "(cleared)");
            }
        } else {
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    /* ── Watch mode ─────────────────────────────────────────── */

    if (!has_token) {
        fprintf(stderr, "Error: --watch requires SLACK_TOKEN to be set\n");
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (!quiet && !json_output) {
        print_timestamp();
        printf("Watching for ");
        for (int i = 0; i < config.count; i++)
            printf("%s%s", i ? ", " : "", config.names[i]);
        printf(" (polling every %ds)...\n", poll_interval);
        fflush(stdout);
    }

    int prev_counts[MAX_PROCESSES] = {0};
    int has_previous = 0;  /* Force the initial update. */

    while (g_running) {
        process_session_t sessions[MAX_SESSIONS];
        int counts[MAX_PROCESSES];
        int count = detect_sessions(sessions, MAX_SESSIONS, &config, counts);

        if (!has_previous || memcmp(counts, prev_counts, sizeof(counts)) != 0) {
            if (!quiet) {
                if (json_output)
                    print_json(sessions, count, &config);
                else
                    print_sessions(sessions, count, &config);
            }

            int result = update_slack_status(token, &config, counts);
            if (!quiet) {
                if (result == 0) {
                    if (!json_output) {
                        char status_text[MAX_STATUS_TEXT];
                        build_status_text(&config, counts, status_text, sizeof(status_text));
                        print_timestamp();
                        printf("Slack status → %s\n",
                               count > 0 ? status_text : "(cleared)");
                    }
                } else {
                    if (!json_output) {
                        print_timestamp();
                        printf("Slack update failed (will retry on next poll)\n");
                    }
                }
                fflush(stdout);
            }

            if (result == 0) {
                memcpy(prev_counts, counts, sizeof(counts));
                has_previous = 1;
            }
        }

        sleep((unsigned int)poll_interval);
    }

    /* Clean exit: clear Slack status */
    if (!quiet && !json_output) {
        print_timestamp();
        printf("Shutting down, clearing Slack status...\n");
    }
    int empty_counts[MAX_PROCESSES] = {0};
    update_slack_status(token, &config, empty_counts);

    return EXIT_SUCCESS;
}
