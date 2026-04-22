#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pes.h"

// ─── LOAD ─────────────────────────────
int index_load(Index *index) {
    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) {
        index->count = 0;
        return 0;
    }

    index->count = 0;

    while (!feof(f)) {
        IndexEntry e;
        char hex[HASH_HEX_SIZE + 1];

        int r = fscanf(f, "%u %64s %lu %u %s",
                       &e.mode,
                       hex,
                       &e.mtime_sec,
                       &e.size,
                       e.path);

        if (r == 5) {
            if (hex_to_hash(hex, &e.hash) == 0)
                index->entries[index->count++] = e;
        }
    }

    fclose(f);
    return 0;
}

// ─── SAVE ─────────────────────────────
int index_save(const Index *index) {
    char tmp[] = ".pes/index.tmp";

    FILE *f = fopen(tmp, "w");
    if (!f) return -1;

    for (int i = 0; i < index->count; i++) {
        char hex[HASH_HEX_SIZE + 1];
        hash_to_hex(&index->entries[i].hash, hex);

        fprintf(f, "%u %s %lu %u %s\n",
                index->entries[i].mode,
                hex,
                index->entries[i].mtime_sec,
                index->entries[i].size,
                index->entries[i].path);
    }

    fflush(f);
    fsync(fileno(f));
    fclose(f);

    return rename(tmp, INDEX_FILE);
}

// ─── ADD ─────────────────────────────
int index_add(Index *index, const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    char *buf = malloc(st.st_size);
    if (!buf) return -1;

    if (fread(buf, 1, st.st_size, f) != (size_t)st.st_size) {
        fclose(f);
        free(buf);
        return -1;
    }
    fclose(f);

    ObjectID blob;
    if (object_write(OBJ_BLOB, buf, st.st_size, &blob) != 0) {
        free(buf);
        return -1;
    }

    free(buf);

    IndexEntry *e = index_find(index, path);
    if (!e) e = &index->entries[index->count++];

    e->mode = st.st_mode;
    e->hash = blob;
    e->mtime_sec = st.st_mtime;
    e->size = st.st_size;
    snprintf(e->path, sizeof(e->path), "%s", path);

    return index_save(index);
}
IndexEntry* index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

int index_status(const Index *index) {
    printf("Staged changes:\n");
    if (index->count == 0) {
        printf("  (nothing to show)\n");
    } else {
        for (int i = 0; i < index->count; i++) {
            printf("  staged: %s\n", index->entries[i].path);
        }
    }

    printf("\nUnstaged changes:\n");
    printf("  (simplified view)\n");

    printf("\nUntracked files:\n");
    printf("  (simplified view)\n");

    return 0;
}
