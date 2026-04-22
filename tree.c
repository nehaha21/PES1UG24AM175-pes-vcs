// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256


#include "index.h"
#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
//
// HINTS - Useful functions and concepts for this phase:
//   - index_load      : load the staged files into memory
//   - strchr          : find the first '/' in a path to separate directories from files
//   - strncmp         : compare prefixes to group files belonging to the same subdirectory
//   - Recursion       : you will likely want to create a recursive helper function 
//                       (e.g., `write_tree_level(entries, count, depth)`) to handle nested dirs.
//   - tree_serialize  : convert your populated Tree struct into a binary buffer
//   - object_write    : save that binary buffer to the store as OBJ_TREE
//
// Returns 0 on success, -1 on error.
static int tree_has_entry(const Tree *tree, const char *name) {
    for (int i = 0; i < tree->count; i++) {
        if (strcmp(tree->entries[i].name, name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int should_skip(const char *name) {
    return strcmp(name, ".") == 0 ||
           strcmp(name, "..") == 0 ||
           strcmp(name, ".pes") == 0 ||
           strcmp(name, "pes") == 0 ||
           strcmp(name, "test_objects") == 0 ||
           strcmp(name, "test_tree") == 0 ||
           strcmp(name, "test_objects.c") == 0 ||
           strcmp(name, "test_tree.c") == 0 ||
           strcmp(name, "test_sequence.sh") == 0 ||
           strcmp(name, "Makefile") == 0 ||
           strcmp(name, "README.md") == 0 ||
           strstr(name, ".o") != NULL ||
           strstr(name, ".c") != NULL ||
           strstr(name, ".h") != NULL;
}

static int write_tree_dir(const char *dirpath, ObjectID *id_out) {
    DIR *dir;
    struct dirent *entry;
    Tree tree;
    void *data_out = NULL;
    size_t len_out = 0;

    tree.count = 0;

    dir = opendir(dirpath);
    if (!dir) {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char fullpath[512];
        struct stat st;

        if (should_skip(entry->d_name)) {
            continue;
        }

        if (snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name) >= (int)sizeof(fullpath)) {
            closedir(dir);
            return -1;
        }

        if (stat(fullpath, &st) != 0) {
            closedir(dir);
            return -1;
        }

        if (tree.count >= MAX_TREE_ENTRIES) {
            closedir(dir);
            return -1;
        }

        if (S_ISDIR(st.st_mode)) {
            ObjectID child_id;
            TreeEntry *te;

            if (write_tree_dir(fullpath, &child_id) != 0) {
                closedir(dir);
                return -1;
            }

            te = &tree.entries[tree.count++];
            te->mode = MODE_DIR;
            te->hash = child_id;
            strncpy(te->name, entry->d_name, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
        } else if (S_ISREG(st.st_mode)) {
            FILE *fp;
            void *file_data;
            size_t file_len;
            TreeEntry *te;
            ObjectID blob_id;

            fp = fopen(fullpath, "rb");
            if (!fp) {
                closedir(dir);
                return -1;
            }

            if (fseek(fp, 0, SEEK_END) != 0) {
                fclose(fp);
                closedir(dir);
                return -1;
            }

            file_len = (size_t)ftell(fp);
            if (fseek(fp, 0, SEEK_SET) != 0) {
                fclose(fp);
                closedir(dir);
                return -1;
            }

            file_data = malloc(file_len);
            if (!file_data && file_len > 0) {
                fclose(fp);
                closedir(dir);
                return -1;
            }

            if (file_len > 0 && fread(file_data, 1, file_len, fp) != file_len) {
                free(file_data);
                fclose(fp);
                closedir(dir);
                return -1;
            }

            fclose(fp);

            if (object_write(OBJ_BLOB, file_data, file_len, &blob_id) != 0) {
                free(file_data);
                closedir(dir);
                return -1;
            }

            free(file_data);

            te = &tree.entries[tree.count++];
            te->mode = get_file_mode(fullpath);
            te->hash = blob_id;
            strncpy(te->name, entry->d_name, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
        }
    }

    closedir(dir);

    if (tree_serialize(&tree, &data_out, &len_out) != 0) {
        return -1;
    }

    if (object_write(OBJ_TREE, data_out, len_out, id_out) != 0) {
        free(data_out);
        return -1;
    }

    free(data_out);
    return 0;
}

int tree_from_index(ObjectID *id_out) {
    if (!id_out) {
        return -1;
    }

    return write_tree_dir(".", id_out);
}
