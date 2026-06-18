/*
 * CyberNova Antivirus — Linux LSM Kernel Module
 *
 * Hooks security_file_open to compute SHA-256 hash of every
 * opened executable and checks against a runtime blocklist.
 * Blocks execution via -EPERM for matching hashes.
 *
 * Blocklist updates via securityfs:
 *   mount -t securityfs securityfs /sys/kernel/security
 *   echo <hex_hash> [severity] [description] > /sys/kernel/security/cybernova/blocklist
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD modules
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/rbtree.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/securityfs.h>
#include <crypto/hash.h>

#define CYBERNOVA_MOD_NAME "cybernova_av"
#define CYBERNOVA_HASH_LEN 32
#define CYBERNOVA_MAX_DESC 256

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CyberNova Security");
MODULE_DESCRIPTION("CyberNova Antivirus LSM — file access interception via hash blocklist");
MODULE_VERSION("1.0.0");

// ── Blocklist Entry (Red-Black Tree) ─────────────────────────────────────────

struct cybernova_entry {
    struct rb_node node;
    u8 hash[CYBERNOVA_HASH_LEN];
    u32 severity;
    char description[CYBERNOVA_MAX_DESC];
};

static struct rb_root cybernova_root = RB_ROOT;
static DEFINE_MUTEX(cybernova_lock);
static atomic64_t cybernova_total_blocks = ATOMIC64_INIT(0);
static atomic64_t cybernova_total_checks = ATOMIC64_INIT(0);
static struct dentry *cybernova_dir = NULL;
static struct dentry *cybernova_blocklist_file = NULL;
static struct dentry *cybernova_stats_file = NULL;

// ── Hash Helpers ─────────────────────────────────────────────────────────────

static int hex_char_to_int(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -EINVAL;
}

static bool hex_to_hash(const char *hex, u8 *hash)
{
    for (int i = 0; i < CYBERNOVA_HASH_LEN; i++) {
        int hi = hex_char_to_int(hex[i * 2]);
        int lo = hex_char_to_int(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        hash[i] = (hi << 4) | lo;
    }
    return true;
}

// ── RB-Tree Operations ───────────────────────────────────────────────────────

static int hash_compare(const u8 *a, const u8 *b)
{
    return memcmp(a, b, CYBERNOVA_HASH_LEN);
}

static struct cybernova_entry *entry_lookup(const u8 *hash)
{
    struct rb_node *node = cybernova_root.rb_node;
    while (node) {
        struct cybernova_entry *e = rb_entry(node, struct cybernova_entry, node);
        int cmp = hash_compare(hash, e->hash);
        if (cmp < 0)
            node = node->rb_left;
        else if (cmp > 0)
            node = node->rb_right;
        else
            return e;
    }
    return NULL;
}

static int entry_insert(const u8 *hash, u32 severity, const char *desc)
{
    struct cybernova_entry *existing = entry_lookup(hash);
    if (existing) {
        existing->severity = severity;
        if (desc)
            strscpy(existing->description, desc, CYBERNOVA_MAX_DESC);
        return 0;
    }

    struct cybernova_entry *e = kzalloc(sizeof(*e), GFP_KERNEL);
    if (!e) return -ENOMEM;

    memcpy(e->hash, hash, CYBERNOVA_HASH_LEN);
    e->severity = severity;
    if (desc)
        strscpy(e->description, desc, CYBERNOVA_MAX_DESC);

    struct rb_node **new = &cybernova_root.rb_node;
    struct rb_node *parent = NULL;

    while (*new) {
        struct cybernova_entry *this = rb_entry(*new, struct cybernova_entry, node);
        parent = *new;
        int cmp = hash_compare(hash, this->hash);
        if (cmp < 0)
            new = &((*new)->rb_left);
        else if (cmp > 0)
            new = &((*new)->rb_right);
        else {
            kfree(e);
            return 0; // race — already inserted
        }
    }

    rb_link_node(&e->node, parent, new);
    rb_insert_color(&e->node, &cybernova_root);
    return 0;
}

static void entry_clear_all(void)
{
    struct rb_node *node = rb_first(&cybernova_root);
    while (node) {
        struct rb_node *next = rb_next(node);
        struct cybernova_entry *e = rb_entry(node, struct cybernova_entry, node);
        rb_erase(node, &cybernova_root);
        kfree(e);
        node = next;
    }
}

// ── File Hash Computation ────────────────────────────────────────────────────

static int compute_file_hash(struct file *file, u8 *hash_out)
{
    struct crypto_shash *tfm = NULL;
    struct shash_desc *desc = NULL;
    loff_t i = 0;
    int ret;
    u8 *buf = NULL;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) return PTR_ERR(tfm);

    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf) {
        kfree(desc);
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    ret = crypto_shash_init(desc);
    if (ret) goto out;

    // Read file in PAGE_SIZE chunks and feed to hash
    while ((ret = kernel_read(file, buf, PAGE_SIZE, &i)) > 0) {
        ret = crypto_shash_update(desc, buf, ret);
        if (ret) goto out;
    }

    ret = crypto_shash_final(desc, hash_out);

out:
    kfree(buf);
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

// ── LSM Hook: security_file_open ─────────────────────────────────────────────

static int cybernova_file_open(struct file *file)
{
    struct inode *inode = file_inode(file);
    u8 hash[CYBERNOVA_HASH_LEN];
    int ret = 0;

    atomic64_inc(&cybernova_total_checks);

    // Only intercept executable opens
    if (!(file->f_flags & FMODE_EXEC))
        return 0;

    // Ignore pseudo-filesystems
    if (!inode || !inode->i_sb)
        return 0;

    // Only regular files on writable filesystems
    if (!S_ISREG(inode->i_mode))
        return 0;

    // Compute SHA-256
    ret = compute_file_hash(file, hash);
    if (ret) {
        pr_warn("CyberNova: Failed to hash file — denying execution (fail-closed)\n");
        atomic64_inc(&cybernova_total_blocks);
        return -EPERM; // Can't verify = deny (fail-closed)
    }

    // Check blocklist
    mutex_lock(&cybernova_lock);
    struct cybernova_entry *entry = entry_lookup(hash);
    if (entry) {
        atomic64_inc(&cybernova_total_blocks);
        pr_warn("CyberNova: Blocked malicious file (%s)\n", entry->description);
        mutex_unlock(&cybernova_lock);
        return -EPERM;
    }
    mutex_unlock(&cybernova_lock);

    return 0;
}

static struct security_hook_list cybernova_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(file_open, cybernova_file_open),
};

// ── SecurityFS Interface ─────────────────────────────────────────────────────

static ssize_t blocklist_write(struct file *filp, const char __user *ubuf,
                                size_t len, loff_t *off)
{
    char *buf, *line, *next;
    ssize_t ret = len;

    buf = memdup_user_nul(ubuf, len);
    if (IS_ERR(buf))
        return PTR_ERR(buf);

    mutex_lock(&cybernova_lock);

    line = buf;
    while (line && *line) {
        next = strchr(line, '\n');
        if (next) *next++ = '\0';

        // Strip trailing whitespace/newline
        char *end = line + strlen(line) - 1;
        while (end > line && (*end == ' ' || *end == '\t' || *end == '\r'))
            *end-- = '\0';

        if (strlen(line) < 64)
            goto next_line;

        // Parse: <64-char-hex-hash> [severity] [description...]
        char *hash_str = line;
        char *sev_str = NULL;
        char *desc_str = NULL;

        if (hash_str[64] == ' ') {
            hash_str[64] = '\0';
            sev_str = hash_str + 65;
        } else if (hash_str[64] != '\0') {
            goto next_line;
        }

        // Special command: "clear" resets all entries
        if (strcmp(line, "clear") == 0) {
            entry_clear_all();
            goto next_line;
        }

        u8 hash[CYBERNOVA_HASH_LEN];
        if (!hex_to_hash(hash_str, hash))
            goto next_line;

        u32 severity = 50;
        if (sev_str) {
            char *space = strchr(sev_str, ' ');
            if (space) {
                *space = '\0';
                desc_str = space + 1;
            }
            if (kstrtou32(sev_str, 10, &severity))
                severity = 50;
        }

        entry_insert(hash, min(severity, 100u), desc_str);

next_line:
        line = next;
    }

    mutex_unlock(&cybernova_lock);
    kfree(buf);
    return ret;
}

static int blocklist_show(struct seq_file *m, void *v)
{
    mutex_lock(&cybernova_lock);
    struct rb_node *node;
    for (node = rb_first(&cybernova_root); node; node = rb_next(node)) {
        struct cybernova_entry *e = rb_entry(node, struct cybernova_entry, node);
        seq_printf(m, "%*phN %u %s\n",
                   CYBERNOVA_HASH_LEN, e->hash,
                   e->severity, e->description);
    }
    mutex_unlock(&cybernova_lock);
    return 0;
}

static int blocklist_open(struct inode *inode, struct file *file)
{
    return single_open(file, blocklist_show, NULL);
}

static const struct file_operations blocklist_fops = {
    .owner = THIS_MODULE,
    .open = blocklist_open,
    .read = seq_read,
    .write = blocklist_write,
    .release = single_release,
};

static int stats_show(struct seq_file *m, void *v)
{
    seq_printf(m, "total_checks: %lld\n", atomic64_read(&cybernova_total_checks));
    seq_printf(m, "total_blocks: %lld\n", atomic64_read(&cybernova_total_blocks));
    seq_printf(m, "blocklist_entries: %d\n", (int)atomic_read(&cybernova_root.rb_node));
    return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, stats_show, NULL);
}

static const struct file_operations stats_fops = {
    .owner = THIS_MODULE,
    .open = stats_open,
    .read = seq_read,
    .release = single_release,
};

// ── Module Init / Exit ───────────────────────────────────────────────────────

static int __init cybernova_init(void)
{
    int ret;

    // Register LSM hooks
    security_add_hooks(cybernova_hooks, ARRAY_SIZE(cybernova_hooks), CYBERNOVA_MOD_NAME);

    // Create securityfs interface
    cybernova_dir = securityfs_create_dir(CYBERNOVA_MOD_NAME, NULL);
    if (IS_ERR(cybernova_dir)) {
        pr_err("CyberNova: Failed to create securityfs dir: %ld\n",
               PTR_ERR(cybernova_dir));
        return PTR_ERR(cybernova_dir);
    }

    cybernova_blocklist_file = securityfs_create_file(
        "blocklist", 0600, cybernova_dir, NULL, &blocklist_fops);
    if (IS_ERR(cybernova_blocklist_file)) {
        pr_err("CyberNova: Failed to create blocklist file\n");
        securityfs_remove(cybernova_dir);
        return PTR_ERR(cybernova_blocklist_file);
    }

    cybernova_stats_file = securityfs_create_file(
        "stats", 0444, cybernova_dir, NULL, &stats_fops);
    if (IS_ERR(cybernova_stats_file)) {
        pr_err("CyberNova: Failed to create stats file\n");
        securityfs_remove(cybernova_blocklist_file);
        securityfs_remove(cybernova_dir);
        return PTR_ERR(cybernova_stats_file);
    }

    pr_info("CyberNova LSM loaded — intercepting file executions\n");
    return 0;
}

static void __exit cybernova_exit(void)
{
    mutex_lock(&cybernova_lock);
    entry_clear_all();
    mutex_unlock(&cybernova_lock);

    if (cybernova_stats_file)
        securityfs_remove(cybernova_stats_file);
    if (cybernova_blocklist_file)
        securityfs_remove(cybernova_blocklist_file);
    if (cybernova_dir)
        securityfs_remove(cybernova_dir);

    pr_info("CyberNova LSM unloaded — %lld total blocks\n",
            atomic64_read(&cybernova_total_blocks));
}

module_init(cybernova_init);
module_exit(cybernova_exit);
