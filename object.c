#include <errno.h>
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}


void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str = NULL;
    char header[128];
    int header_len;
    size_t full_len;
    unsigned char *full_buf = NULL;
    char final_path[512];
    char shard_dir[512];
    char tmp_path[512];
    char hex[HASH_HEX_SIZE + 1];
    int fd = -1;
    int dirfd = -1;
    ssize_t written = 0;
    size_t total_written = 0;

    if (!data || !id_out) return -1;

    switch (type) {
        case OBJ_BLOB:   type_str = "blob";   break;
        case OBJ_TREE:   type_str = "tree";   break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (header_len < 0 || (size_t)header_len + 1 >= sizeof(header)) return -1;

    full_len = (size_t)header_len + 1 + len;
    full_buf = malloc(full_len);
    if (!full_buf) return -1;

    memcpy(full_buf, header, (size_t)header_len);
    full_buf[header_len] = '\0';
    memcpy(full_buf + header_len + 1, data, len);

    compute_hash(full_buf, full_len, id_out);

    if (object_exists(id_out)) {
        free(full_buf);
        return 0;
    }

    object_path(id_out, final_path, sizeof(final_path));
    hash_to_hex(id_out, hex);

    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);

    if (mkdir(OBJECTS_DIR, 0755) < 0 && errno != EEXIST) {
        free(full_buf);
        return -1;
    }

    if (mkdir(shard_dir, 0755) < 0 && errno != EEXIST) {
        free(full_buf);
        return -1;
    }

    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp-%ld", shard_dir, (long)getpid());

    fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full_buf);
        return -1;
    }

    while (total_written < full_len) {
        written = write(fd, full_buf + total_written, full_len - total_written);
        if (written < 0) {
            close(fd);
            unlink(tmp_path);
            free(full_buf);
            return -1;
        }
        total_written += (size_t)written;
    }

    if (fsync(fd) < 0) {
        close(fd);
        unlink(tmp_path);
        free(full_buf);
        return -1;
    }

    if (close(fd) < 0) {
        unlink(tmp_path);
        free(full_buf);
        return -1;
    }
    fd = -1;

    if (rename(tmp_path, final_path) < 0) {
        unlink(tmp_path);
        free(full_buf);
        return -1;
    }

    dirfd = open(shard_dir, O_RDONLY | O_DIRECTORY);
    if (dirfd >= 0) {
        fsync(dirfd);
        close(dirfd);
    }

    free(full_buf);
    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    FILE *fp = NULL;
    unsigned char *file_buf = NULL;
    unsigned char *data_buf = NULL;
    long file_size;
    unsigned char *nul_pos;
    size_t header_len;
    char type_str[16];
    size_t parsed_len;
    int scanned;
    ObjectID computed;

    if (!id || !type_out || !data_out || !len_out) return -1;

    *data_out = NULL;
    *len_out = 0;

    object_path(id, path, sizeof(path));

    fp = fopen(path, "rb");
    if (!fp) return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return -1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    file_buf = malloc((size_t)file_size);
    if (!file_buf) {
        fclose(fp);
        return -1;
    }

    if (file_size > 0 && fread(file_buf, 1, (size_t)file_size, fp) != (size_t)file_size) {
        fclose(fp);
        free(file_buf);
        return -1;
    }
    fclose(fp);

    compute_hash(file_buf, (size_t)file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(file_buf);
        return -1;
    }

    nul_pos = memchr(file_buf, '\0', (size_t)file_size);
    if (!nul_pos) {
        free(file_buf);
        return -1;
    }

    header_len = (size_t)(nul_pos - file_buf);

    scanned = sscanf((char *)file_buf, "%15s %zu", type_str, &parsed_len);
    if (scanned != 2) {
        free(file_buf);
        return -1;
    }

    if (strcmp(type_str, "blob") == 0) {
        *type_out = OBJ_BLOB;
    } else if (strcmp(type_str, "tree") == 0) {
        *type_out = OBJ_TREE;
    } else if (strcmp(type_str, "commit") == 0) {
        *type_out = OBJ_COMMIT;
    } else {
        free(file_buf);
        return -1;
    }

    if (header_len + 1 + parsed_len != (size_t)file_size) {
        free(file_buf);
        return -1;
    }

    data_buf = malloc(parsed_len);
    if (!data_buf && parsed_len > 0) {
        free(file_buf);
        return -1;
    }

    if (parsed_len > 0) {
        memcpy(data_buf, file_buf + header_len + 1, parsed_len);
    }

    *data_out = data_buf;
    *len_out = parsed_len;

    free(file_buf);
    return 0;
}
// minor change
// minor change 2
