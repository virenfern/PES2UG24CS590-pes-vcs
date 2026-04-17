// index.c — Staging area implementation
//
// Text format of .pes/index (one entry per line, sorted by path):
//
//   <mode-octal> <64-char-hex-hash> <mtime-seconds> <size> <path>
//
// Example:
//   100644 a1b2c3d4e5f6...  1699900000 42 README.md
//   100644 f7e8d9c0b1a2...  1699900100 128 src/main.c
//
// PROVIDED functions: index_find, index_remove, index_status
// TODO functions:     index_load, index_save, index_add

#include "index.h"
#include "object.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#define MAX_PATH_LEN 512

// ─── PROVIDED ────────────────────────────────────────────────────────────────

IndexEntry* index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

int index_remove(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0) {
            int remaining = index->count - i - 1;
            if (remaining > 0)
                memmove(&index->entries[i], &index->entries[i + 1],
                        remaining * sizeof(IndexEntry));
            index->count--;
            return index_save(index);
        }
    }
    fprintf(stderr, "error: '%s' is not in the index\n", path);
    return -1;
}

int index_status(const Index *index) {
    printf("Staged changes:\n");
    int staged_count = 0;
    for (int i = 0; i < index->count; i++) {
        printf("  staged:     %s\n", index->entries[i].path);
        staged_count++;
    }
    if (staged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Unstaged changes:\n");
    int unstaged_count = 0;
    for (int i = 0; i < index->count; i++) {
        struct stat st;
        if (stat(index->entries[i].path, &st) != 0) {
            printf("  deleted:    %s\n", index->entries[i].path);
            unstaged_count++;
        } else {
            if (st.st_mtime != (time_t)index->entries[i].mtime_sec ||
                st.st_size != (off_t)index->entries[i].size) {
                printf("  modified:   %s\n", index->entries[i].path);
                unstaged_count++;
            }
        }
    }
    if (unstaged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Untracked files:\n");
    int untracked_count = 0;
    DIR *dir = opendir(".");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            if (strcmp(ent->d_name, ".pes") == 0) continue;
            if (strcmp(ent->d_name, "pes") == 0) continue;
            if (strstr(ent->d_name, ".o") != NULL) continue;

            int is_tracked = 0;
            for (int i = 0; i < index->count; i++) {
                if (strcmp(index->entries[i].path, ent->d_name) == 0) {
                    is_tracked = 1;
                    break;
                }
            }

            if (!is_tracked) {
                struct stat st;
                stat(ent->d_name, &st);
                if (S_ISREG(st.st_mode)) {
                    printf("  untracked:  %s\n", ent->d_name);
                    untracked_count++;
                }
            }
        }
        closedir(dir);
    }
    if (untracked_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    return 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

/*
 * index_load — Read .pes/index into an Index struct.
 *
 * KEY FIX: Do NOT memset(index, 0, sizeof(Index)).
 *
 * sizeof(Index) = MAX_INDEX_ENTRIES * sizeof(IndexEntry).
 * With MAX_INDEX_ENTRIES=1024 and IndexEntry containing a path[512],
 * that is ~600 KB.  The Index is almost certainly stack-allocated in
 * pes.c, so a memset of that size overflows the default 8 MB stack,
 * causing the segfault you observed on `pes add`.
 *
 * Fix: only zero `index->count`, then zero each IndexEntry slot
 * individually as we fill it in.
 */
int index_load(Index *index) {
    index->count = 0;   // ← only reset the count, never memset the whole struct

    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) return 0;   // no index file yet → empty index, not an error

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') continue;

        if (index->count >= MAX_INDEX_ENTRIES) {
            fprintf(stderr, "error: index full (> %d entries)\n", MAX_INDEX_ENTRIES);
            fclose(f);
            return -1;
        }

        // Zero only this one slot before parsing into it.
        IndexEntry *e = &index->entries[index->count];
        memset(e, 0, sizeof(IndexEntry));

        char hex[HASH_HEX_SIZE + 2];
        unsigned long      mode  = 0;
        unsigned long long mtime = 0;
        unsigned long long size  = 0;
        char path[MAX_PATH_LEN];

        int parsed = sscanf(line, "%lo %64s %llu %llu %511s",
                            &mode, hex, &mtime, &size, path);
        if (parsed != 5) {
            fprintf(stderr, "error: malformed index line: %s\n", line);
            fclose(f);
            return -1;
        }

        e->mode      = (uint32_t)mode;
        e->mtime_sec = (uint64_t)mtime;
        e->size      = (uint64_t)size;

        if (hex_to_hash(hex, &e->hash) != 0) {
            fprintf(stderr, "error: bad hash in index: %s\n", hex);
            fclose(f);
            return -1;
        }

        snprintf(e->path, sizeof(e->path), "%s", path);
        index->count++;
    }

    fclose(f);
    return 0;
}

static int compare_index_entries(const void *a, const void *b) {
    return strcmp(((const IndexEntry *)a)->path,
                  ((const IndexEntry *)b)->path);
}

/*
 * index_save — Atomically write the index to .pes/index.
 *
 * KEY FIX: allocate the sorted copy on the heap, not the stack.
 * Declaring `Index sorted = *index;` on the stack would add another
 * ~600 KB frame on top of the caller's frame → stack overflow.
 */
int index_save(const Index *index) {
    // Heap-allocate the sorted copy (only the live entries).
    IndexEntry *sorted = NULL;
    if (index->count > 0) {
        sorted = malloc(index->count * sizeof(IndexEntry));
        if (!sorted) return -1;
        memcpy(sorted, index->entries, index->count * sizeof(IndexEntry));
        qsort(sorted, index->count, sizeof(IndexEntry), compare_index_entries);
    }

    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", INDEX_FILE);

    FILE *f = fopen(tmp_path, "w");
    if (!f) { free(sorted); return -1; }

    for (int i = 0; i < index->count; i++) {
        const IndexEntry *e = &sorted[i];
        char hex[HASH_HEX_SIZE + 1];
        hash_to_hex(&e->hash, hex);

        if (fprintf(f, "%lo %s %llu %llu %s\n",
                    (unsigned long)e->mode,
                    hex,
                    (unsigned long long)e->mtime_sec,
                    (unsigned long long)e->size,
                    e->path) < 0) {
            fclose(f);
            unlink(tmp_path);
            free(sorted);
            return -1;
        }
    }

    free(sorted);

    if (fflush(f) != 0)          { fclose(f); unlink(tmp_path); return -1; }
    if (fsync(fileno(f)) != 0)   { fclose(f); unlink(tmp_path); return -1; }
    fclose(f);

    if (rename(tmp_path, INDEX_FILE) != 0) { unlink(tmp_path); return -1; }
    return 0;
}

/*
 * index_add — Stage a file for the next commit.
 */
int index_add(Index *index, const char *path) {
    // 1. Read the file into a heap buffer.
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open '%s': ", path);
        perror(NULL);
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long file_size = ftell(f);
    if (file_size < 0)              { fclose(f); return -1; }
    rewind(f);

    size_t fsz = (size_t)file_size;
    // malloc(0) is implementation-defined; always allocate at least 1 byte.
    uint8_t *contents = malloc(fsz + 1);
    if (!contents) { fclose(f); return -1; }

    size_t nread = (fsz > 0) ? fread(contents, 1, fsz, f) : 0;
    fclose(f);

    if (nread != fsz) {
        fprintf(stderr, "error: short read on '%s'\n", path);
        free(contents);
        return -1;
    }

    // 2. Write blob to object store.
    ObjectID blob_id;
    if (object_write(OBJ_BLOB, contents, fsz, &blob_id) != 0) {
        fprintf(stderr, "error: object_write failed for '%s'\n", path);
        free(contents);
        return -1;
    }
    free(contents);

    // 3. Get file metadata.
    struct stat st;
    if (lstat(path, &st) != 0) { perror("lstat"); return -1; }
    uint32_t mode = (st.st_mode & S_IXUSR) ? 0100755 : 0100644;

    // 4. Upsert index entry (zero new slots individually, not the whole array).
    IndexEntry *existing = index_find(index, path);
    if (existing) {
        existing->hash      = blob_id;
        existing->mode      = mode;
        existing->mtime_sec = (uint64_t)st.st_mtime;
        existing->size      = (uint64_t)st.st_size;
    } else {
        if (index->count >= MAX_INDEX_ENTRIES) {
            fprintf(stderr, "error: index is full\n");
            return -1;
        }
        IndexEntry *e = &index->entries[index->count];
        memset(e, 0, sizeof(IndexEntry));
        e->hash      = blob_id;
        e->mode      = mode;
        e->mtime_sec = (uint64_t)st.st_mtime;
        e->size      = (uint64_t)st.st_size;
        snprintf(e->path, sizeof(e->path), "%s", path);
        index->count++;
    }

    // 5. Persist.
    return index_save(index);
}
