#define main claudeiness_main
#include "../Sources/claudeiness.c"
#undef main
#include <assert.h>

int main(int argc, char **argv) {
    process_config_t config = {0};
    assert(add_process(&config, "Obsidian"));
    assert(add_process(&config, "obsidian"));
    assert(config.count == 1);
    assert(add_process(&config, "CLAUDE"));
    assert(config.count == 2);
    assert(strcmp(config.names[1], "claude") == 0);

    assert(match_process(&config, "Obsidian", "/Applications/Obsidian.app/Contents/MacOS/Obsidian") == 0);
    assert(match_process(&config, "obsidian", "") == 0);
    assert(match_process(&config, "Obsidian", "/tmp/Obsidian Helper") == -1);
    assert(match_process(&config, "2.1.89", "/tmp/.local/share/claude/versions/2.1.89") == 1);
    assert(match_process(&config, "unrelated", "/tmp/unrelated") == -1);
    assert(add_process(&config, "An App With A Very Long Name"));
    assert(match_process(&config, "An App With A V", "/tmp/An App With A Very Long Name") == 2);
    assert(match_process(&config, "An App With A V", "/tmp/An App With A Very Long Name Helper") == -1);

    int counts[MAX_PROCESSES] = {1, 2};
    char status[MAX_STATUS_TEXT];
    build_status_text(&config, counts, status, sizeof(status));
    assert(strcmp(status, "Obsidian :claude_code: :claude_code:") == 0);
    counts[0] = 2;
    counts[1] = 0;
    build_status_text(&config, counts, status, sizeof(status));
    assert(strcmp(status, "Obsidian (2)") == 0);
    memset(counts, 0, sizeof(counts));
    build_status_text(&config, counts, status, sizeof(status));
    assert(strcmp(status, "") == 0);
    counts[1] = 20;
    build_status_text(&config, counts, status, sizeof(status));
    assert(strcmp(status, ":claude_code: :claude_code: :claude_code: :claude_code: :claude_code: :claude_code: :claude_code:") == 0);
    char tiny[4] = "";
    append_status_label(tiny, sizeof(tiny), "aéz");
    assert(strcmp(tiny, "aé") == 0);
    tiny[0] = '\0';
    append_status_label(tiny, 3, "aéz");
    assert(strcmp(tiny, "a") == 0);

    char *json = NULL;
    size_t size = 0;
    FILE *out = open_memstream(&json, &size);
    assert(out);
    write_json_string(out, "App \"Name\"\\\n");
    assert(fclose(out) == 0);
    assert(strcmp(json, "\"App \\\"Name\\\"\\\\\\u000a\"") == 0);
    free(json);

    if (argc == 2 && strcmp(argv[1], "--plist") == 0) {
        process_config_t plist_config = {{"Obsidian & \"Notes\"", "claude"}, 2};
        assert(write_service_plist(stdout, "/tmp/My & tools/claudeiness", "fake<&\"'>",
                                   &plist_config, 17, 1, 1));
    } else {
        puts("Unit tests passed");
    }
    return 0;
}
