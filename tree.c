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

#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "index.h"
#include "object.h"
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
        if (!space) return -1;

        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1;

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1;

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0';

        ptr = null_byte + 1;

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
    size_t max_size = tree->count * 296;
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];

        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf

        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── IMPLEMENTED ────────────────────────────────────────────────────────────

/*
 * write_tree_level — Recursive helper for tree_from_index.
 *
 * Given an array of IndexEntry pointers whose paths share a common prefix
 * (the current "directory level"), build a Tree object and write it to the
 * object store.
 *
 * Strategy:
 *   For each entry in the slice:
 *     - If the path has NO '/' after stripping the prefix → it's a file blob
 *       → add a leaf entry directly (mode + hash from the index entry).
 *     - If the path HAS a '/' → it belongs to a subdirectory.
 *       → Collect ALL entries that share the same first path component.
 *       → Recurse into that sub-slice to get a subtree hash.
 *       → Add one tree entry for that component.
 *   We advance through the array in order and skip components we've
 *   already handled to avoid duplicate subtrees.
 *
 * Parameters:
 *   entries  — array of IndexEntry (the full index, sorted by path)
 *   count    — number of entries in the slice
 *   prefix   — the directory prefix consumed so far (empty string for root)
 *   id_out   — receives the hash of the written tree object
 *
 * Returns 0 on success, -1 on error.
 */
static int write_tree_level(const IndexEntry *entries, int count,
                            const char *prefix, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    size_t prefix_len = strlen(prefix);

    int i = 0;
    while (i < count) {
        const char *path = entries[i].path;

        // Strip the common prefix from the path to get the relative name
        const char *rel = path + prefix_len;

        // Find the first '/' in the relative path
        const char *slash = strchr(rel, '/');

        if (slash == NULL) {
            // ── Leaf entry (file) ──────────────────────────────────────────
            // No subdirectory component; add directly as a blob entry.
            if (tree.count >= MAX_TREE_ENTRIES) return -1;

            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = entries[i].mode;
            snprintf(te->name, sizeof(te->name), "%s", rel);
            te->name[sizeof(te->name) - 1] = '\0';
            te->hash = entries[i].hash;

            i++;

        } else {
            // ── Subtree entry (directory) ──────────────────────────────────
            // Extract the directory component name (e.g. "src" from "src/main.c")
            size_t dir_name_len = (size_t)(slash - rel);
            char dir_name[256] = {0};
            if (dir_name_len >= sizeof(dir_name)) return -1;
            memcpy(dir_name, rel, dir_name_len);
            dir_name[dir_name_len] = '\0';

            // Build the new prefix for the recursive call: prefix + dir_name + "/"
            char sub_prefix[512] = {0};
            snprintf(sub_prefix, sizeof(sub_prefix), "%s%s/", prefix, dir_name);
            size_t sub_prefix_len = strlen(sub_prefix);

            // Collect all entries that belong to this subdirectory
            int j = i;
            while (j < count && strncmp(entries[j].path, sub_prefix, sub_prefix_len) == 0) {
                j++;
            }

            // Recurse: write the subtree for entries[i..j-1]
            ObjectID sub_id;
            if (write_tree_level(entries + i, j - i, sub_prefix, &sub_id) != 0)
                return -1;

            // Add a tree entry for the directory
            if (tree.count >= MAX_TREE_ENTRIES) return -1;

            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = MODE_DIR;
            snprintf(te->name, sizeof(te->name), "%s", dir_name);
            te->hash = sub_id;

            i = j; // Skip past the entries we just handled
        }
    }

    // Serialize the Tree struct into binary format
    void *tree_data;
    size_t tree_len;
    if (tree_serialize(&tree, &tree_data, &tree_len) != 0) return -1;

    // Write the tree object to the object store
    int rc = object_write(OBJ_TREE, tree_data, tree_len, id_out);
    free(tree_data);
    return rc;
}

/*
 * tree_from_index — Build a tree hierarchy from the current index.
 *
 * Loads the index, then calls write_tree_level on all entries starting
 * from the root (empty prefix).  The resulting root tree hash is stored
 * in *id_out.
 *
 * Returns 0 on success, -1 on error.
 */
int tree_from_index(ObjectID *id_out) {
    // Load the current index
    Index index;
    if (index_load(&index) != 0) return -1;

    if (index.count == 0) {
        // Nothing staged — create an empty tree object
        Tree empty_tree;
        empty_tree.count = 0;
        void *tree_data;
        size_t tree_len;
        if (tree_serialize(&empty_tree, &tree_data, &tree_len) != 0) return -1;
        int rc = object_write(OBJ_TREE, tree_data, tree_len, id_out);
        free(tree_data);
        return rc;
    }

    // Build the tree recursively from the root level (prefix = "")
    return write_tree_level(index.entries, index.count, "", id_out);
}// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "index.h"
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
        if (!space) return -1;

        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1;

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1;

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0';

        ptr = null_byte + 1;

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
    size_t max_size = tree->count * 296;
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];

        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf

        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── IMPLEMENTED ────────────────────────────────────────────────────────────

/*
 * write_tree_level — Recursive helper for tree_from_index.
 *
 * Given an array of IndexEntry pointers whose paths share a common prefix
 * (the current "directory level"), build a Tree object and write it to the
 * object store.
 *
 * Strategy:
 *   For each entry in the slice:
 *     - If the path has NO '/' after stripping the prefix → it's a file blob
 *       → add a leaf entry directly (mode + hash from the index entry).
 *     - If the path HAS a '/' → it belongs to a subdirectory.
 *       → Collect ALL entries that share the same first path component.
 *       → Recurse into that sub-slice to get a subtree hash.
 *       → Add one tree entry for that component.
 *   We advance through the array in order and skip components we've
 *   already handled to avoid duplicate subtrees.
 *
 * Parameters:
 *   entries  — array of IndexEntry (the full index, sorted by path)
 *   count    — number of entries in the slice
 *   prefix   — the directory prefix consumed so far (empty string for root)
 *   id_out   — receives the hash of the written tree object
 *
 * Returns 0 on success, -1 on error.
 */
static int write_tree_level(const IndexEntry *entries, int count,
                            const char *prefix, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    size_t prefix_len = strlen(prefix);

    int i = 0;
    while (i < count) {
        const char *path = entries[i].path;

        // Strip the common prefix from the path to get the relative name
        const char *rel = path + prefix_len;

        // Find the first '/' in the relative path
        const char *slash = strchr(rel, '/');

        if (slash == NULL) {
            // ── Leaf entry (file) ──────────────────────────────────────────
            // No subdirectory component; add directly as a blob entry.
            if (tree.count >= MAX_TREE_ENTRIES) return -1;

            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = entries[i].mode;
            strncpy(te->name, rel, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
            te->hash = entries[i].hash;

            i++;

        } else {
            // ── Subtree entry (directory) ──────────────────────────────────
            // Extract the directory component name (e.g. "src" from "src/main.c")
            size_t dir_name_len = (size_t)(slash - rel);
            char dir_name[256] = {0};
            if (dir_name_len >= sizeof(dir_name)) return -1;
            memcpy(dir_name, rel, dir_name_len);
            dir_name[dir_name_len] = '\0';

            // Build the new prefix for the recursive call: prefix + dir_name + "/"
            char sub_prefix[512] = {0};
            snprintf(sub_prefix, sizeof(sub_prefix), "%s%s/", prefix, dir_name);
            size_t sub_prefix_len = strlen(sub_prefix);

            // Collect all entries that belong to this subdirectory
            int j = i;
            while (j < count && strncmp(entries[j].path, sub_prefix, sub_prefix_len) == 0) {
                j++;
            }

            // Recurse: write the subtree for entries[i..j-1]
            ObjectID sub_id;
            if (write_tree_level(entries + i, j - i, sub_prefix, &sub_id) != 0)
                return -1;

            // Add a tree entry for the directory
            if (tree.count >= MAX_TREE_ENTRIES) return -1;

            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = MODE_DIR;
            strncpy(te->name, dir_name, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
            te->hash = sub_id;

            i = j; // Skip past the entries we just handled
        }
    }

    // Serialize the Tree struct into binary format
    void *tree_data;
    size_t tree_len;
    if (tree_serialize(&tree, &tree_data, &tree_len) != 0) return -1;

    // Write the tree object to the object store
    int rc = object_write(OBJ_TREE, tree_data, tree_len, id_out);
    free(tree_data);
    return rc;
}

/*
 * tree_from_index — Build a tree hierarchy from the current index.
 *
 * Loads the index, then calls write_tree_level on all entries starting
 * from the root (empty prefix).  The resulting root tree hash is stored
 * in *id_out.
 *
 * Returns 0 on success, -1 on error.
 */
int tree_from_index(ObjectID *id_out) {
    // Load the current index
    Index index;
    if (index_load(&index) != 0) return -1;

    if (index.count == 0) {
        // Nothing staged — create an empty tree object
        Tree empty_tree;
        empty_tree.count = 0;
        void *tree_data;
        size_t tree_len;
        if (tree_serialize(&empty_tree, &tree_data, &tree_len) != 0) return -1;
        int rc = object_write(OBJ_TREE, tree_data, tree_len, id_out);
        free(tree_data);
        return rc;
    }

    // Build the tree recursively from the root level (prefix = "")
    return write_tree_level(index.entries, index.count, "", id_out);
}
