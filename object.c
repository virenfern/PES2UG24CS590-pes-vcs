// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

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

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
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

// ─── IMPLEMENTED ────────────────────────────────────────────────────────────

/*
 * object_write — Store data in the content-addressable object store.
 *
 * Object format on disk:
 *   "<type> <size>\0<data>"
 *
 * Steps:
 *   1. Build header string: e.g. "blob 16\0"
 *   2. Allocate full object buffer = header + data
 *   3. Compute SHA-256 of the full object (header + data)
 *   4. Check for deduplication — if object already exists, return early
 *   5. Create the shard directory (.pes/objects/XX/) with mkdir
 *   6. Write to a temp file in the shard directory
 *   7. fsync() the temp file
 *   8. rename() temp → final path (atomic on POSIX)
 *   9. fsync() the directory to persist the rename
 *  10. Store computed hash in *id_out
 *
 * Returns 0 on success, -1 on error.
 */
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // 1. Determine type string
    const char *type_str;
    switch (type) {
        case OBJ_BLOB:   type_str = "blob";   break;
        case OBJ_TREE:   type_str = "tree";   break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    // 2. Build header: "<type> <size>\0"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    // header_len does NOT include the null terminator written by snprintf,
    // but we want to include the '\0' in the object, so total header size = header_len + 1
    size_t full_len = (size_t)header_len + 1 + len;

    // 3. Allocate and build full object buffer
    uint8_t *full_obj = malloc(full_len);
    if (!full_obj) return -1;

    memcpy(full_obj, header, (size_t)header_len + 1); // copy header including '\0'
    memcpy(full_obj + header_len + 1, data, len);

    // 4. Compute SHA-256 of the full object
    compute_hash(full_obj, full_len, id_out);

    // 5. Deduplication: if object already exists, we are done
    if (object_exists(id_out)) {
        free(full_obj);
        return 0;
    }

    // 6. Build shard directory path and create it
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755); // ignore error if it already exists

    // 7. Build final object path
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));

    // 8. Build temp file path in the same shard directory
    char tmp_path[520];
    snprintf(tmp_path, sizeof(tmp_path), "%s/%.2s/tmp_XXXXXX", OBJECTS_DIR, hex);

    // 9. Open temp file and write
    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        free(full_obj);
        return -1;
    }

    ssize_t written = write(fd, full_obj, full_len);
    free(full_obj);

    if (written < 0 || (size_t)written != full_len) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }

    // 10. fsync the temp file to ensure data reaches disk
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }
    close(fd);

    // 11. Atomically rename temp → final path
    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        return -1;
    }

    // 12. fsync the shard directory to persist the rename
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    return 0;
}

/*
 * object_read — Retrieve and verify an object from the store.
 *
 * Steps:
 *   1. Build the file path from the hash using object_path()
 *   2. Open and read the entire file into memory
 *   3. Verify integrity: recompute SHA-256 and compare to expected hash
 *   4. Parse the header to extract type and size
 *   5. Find the '\0' separator between header and data
 *   6. Allocate buffer, copy data portion, set *data_out and *len_out
 *
 * Returns 0 on success, -1 on error.
 * Caller must free(*data_out).
 */
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // 1. Build the file path
    char path[512];
    object_path(id, path, sizeof(path));

    // 2. Open the file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // 3. Get file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(f);
        return -1;
    }

    // 4. Read entire file into memory
    uint8_t *buf = malloc((size_t)file_size);
    if (!buf) {
        fclose(f);
        return -1;
    }

    if (fread(buf, 1, (size_t)file_size, f) != (size_t)file_size) {
        fclose(f);
        free(buf);
        return -1;
    }
    fclose(f);

    // 5. Verify integrity: recompute hash and compare to the requested hash
    ObjectID computed;
    compute_hash(buf, (size_t)file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1; // Data is corrupted
    }

    // 6. Find the '\0' separator between header and data
    uint8_t *null_byte = memchr(buf, '\0', (size_t)file_size);
    if (!null_byte) {
        free(buf);
        return -1; // Malformed object
    }

    // 7. Parse the type from the header ("blob <size>\0", "tree <size>\0", etc.)
    char type_str[16] = {0};
    if (sscanf((char *)buf, "%15s", type_str) != 1) {
        free(buf);
        return -1;
    }

    if (strcmp(type_str, "blob") == 0) {
        *type_out = OBJ_BLOB;
    } else if (strcmp(type_str, "tree") == 0) {
        *type_out = OBJ_TREE;
    } else if (strcmp(type_str, "commit") == 0) {
        *type_out = OBJ_COMMIT;
    } else {
        free(buf);
        return -1; // Unknown type
    }

    // 8. Compute data pointer and length
    uint8_t *data_start = null_byte + 1;
    size_t data_len = (size_t)file_size - (size_t)(data_start - buf);

    // 9. Allocate and copy the data portion
    uint8_t *data_copy = malloc(data_len + 1); // +1 for safety null terminator
    if (!data_copy) {
        free(buf);
        return -1;
    }
    memcpy(data_copy, data_start, data_len);
    data_copy[data_len] = '\0'; // Safety null terminator

    free(buf);

    *data_out = data_copy;
    *len_out = data_len;
    return 0;
}
