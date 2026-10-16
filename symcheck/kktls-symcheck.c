/* SPDX-License-Identifier: Apache-2.0 */
/*
 * kktls-symcheck: does our shared library export everything the device's one does?
 *
 *   kktls-symcheck [--allow-missing FILE] OURS.so DEVICE.so
 *        exit 0: every export of DEVICE.so is exported by OURS.so, except the names listed in FILE
 *        exit 1: some are not (one line per symbol on stderr)
 *        exit 2: usage error, an unreadable FILE, or a library that is not a readable ELF32 little-endian ARM/x86
 *                shared object with a .dynsym (or the two libraries are for different machines, or one of them
 *                exports nothing: a stripped or broken library cannot vouch for the device's ABI)
 *   kktls-symcheck --list LIB.so       print the exports of LIB.so with their kind, sorted, one per line (exit 0 or 2)
 *
 * FILE: one symbol name per line; blank lines and lines starting with '#' are ignored. It names the internal exports
 * the stock AOSP 4.4 library has and ours dropped on purpose (allow-missing-libssl.txt next to this file); an OEM
 * library's extra exports stay required.
 *
 * An export is a .dynsym entry that is defined (st_shndx != SHN_UNDEF), has GLOBAL or WEAK binding, DEFAULT or
 * PROTECTED visibility and type FUNC, OBJECT, TLS or GNU_IFUNC (the same set as openssl-abi-check.py `symbols`, which
 * reads readelf output and so has no visibility filter; a HIDDEN entry in .dynsym cannot be bound from outside).
 * A name that ours exports with another kind (a function where the device has an object, or the reverse) counts as
 * missing. FUNC and GNU_IFUNC are the same kind. Symbol versions are ignored (Android 4.4 has none).
 *
 * The recovery that runs it has no nm/readelf, so this is a static binary per ABI (Android.mk next to this file).
 * The file is read into memory and parsed byte-wise (no struct casts): safe on unaligned or hostile input and
 * buildable on any host for the tests. Only the section headers are used; a library without them (sstrip) is bad
 * input (exit 2), the installer then refuses.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILE (256u * 1024u * 1024u)

#define ET_DYN 3
#define EM_386 3
#define EM_ARM 40
#define SHT_STRTAB 3
#define SHT_DYNSYM 11
#define SHDR_SIZE 40u
#define SYM_SIZE 16u
#define STB_GLOBAL 1
#define STB_WEAK 2
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_TLS 6
#define STT_GNU_IFUNC 10
#define STV_DEFAULT 0
#define STV_PROTECTED 3

struct sym {
    const char *name;
    unsigned kind; /* STT_OBJECT, STT_FUNC (also for GNU_IFUNC) or STT_TLS */
};

struct lib {
    const char *path;
    unsigned char *buf;
    size_t size;
    unsigned machine;
    struct sym *syms;
    size_t nsyms;
};

static int bad(const struct lib *l, const char *why)
{
    fprintf(stderr, "kktls-symcheck: %s: %s\n", l->path, why);
    return -1;
}

static uint32_t rd16(const unsigned char *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8; }
static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* [off, off+len) inside the file? 64-bit arithmetic: no wrap for 32-bit inputs */
static int in_file(const struct lib *l, uint64_t off, uint64_t len) { return off <= l->size && len <= l->size - off; }

static int read_file(struct lib *l)
{
    FILE *f = fopen(l->path, "rb");
    size_t cap = 0, n;
    unsigned char *b = NULL;
    if (!f) {
        fprintf(stderr, "kktls-symcheck: %s: %s\n", l->path, strerror(errno));
        return -1;
    }
    l->size = 0;
    for (;;) {
        if (l->size == cap) {
            unsigned char *nb;
            if (cap >= MAX_FILE) {
                fclose(f);
                free(b);
                return bad(l, "file too large");
            }
            cap = cap ? cap * 2 : 65536;
            nb = realloc(b, cap);
            if (!nb) {
                fclose(f);
                free(b);
                return bad(l, "out of memory");
            }
            b = nb;
        }
        n = fread(b + l->size, 1, cap - l->size, f);
        if (n == 0)
            break;
        l->size += n;
    }
    if (ferror(f)) {
        fclose(f);
        free(b);
        return bad(l, "read error");
    }
    fclose(f);
    l->buf = b;
    return 0;
}

static int cmp_sym(const void *a, const void *b)
{
    const struct sym *x = a, *y = b;
    int c = strcmp(x->name, y->name);
    if (c)
        return c;
    return (x->kind > y->kind) - (x->kind < y->kind);
}

static int load(struct lib *l)
{
    const unsigned char *e, *sh, *ds = NULL, *ss;
    uint32_t shoff, shnum, i, symoff, symsz, link, stroff, strsz;

    if (read_file(l))
        return -1;
    e = l->buf;
    if (l->size < 52 || memcmp(e, "\177ELF", 4) != 0)
        return bad(l, "not an ELF file");
    if (e[4] != 1 || e[5] != 1 || e[6] != 1)
        return bad(l, "not ELF32 little-endian version 1");
    if (rd16(e + 16) != ET_DYN)
        return bad(l, "not a shared object (ET_DYN)");
    l->machine = rd16(e + 18);
    if (l->machine != EM_ARM && l->machine != EM_386)
        return bad(l, "machine is neither ARM nor x86");
    shoff = rd32(e + 32);
    shnum = rd16(e + 48);
    if (shoff == 0 || shnum == 0)
        return bad(l, "no section headers");
    if (rd16(e + 46) != SHDR_SIZE)
        return bad(l, "unexpected e_shentsize");
    if (!in_file(l, shoff, (uint64_t)shnum * SHDR_SIZE))
        return bad(l, "section headers beyond end of file");
    sh = e + shoff;
    for (i = 0; i < shnum; i++)
        if (rd32(sh + i * SHDR_SIZE + 4) == SHT_DYNSYM) {
            ds = sh + i * SHDR_SIZE;
            break;
        }
    if (!ds)
        return bad(l, "no .dynsym section");
    symoff = rd32(ds + 16);
    symsz = rd32(ds + 20);
    link = rd32(ds + 24);
    if (rd32(ds + 36) != SYM_SIZE || symsz % SYM_SIZE != 0)
        return bad(l, "bad .dynsym entry size");
    if (!in_file(l, symoff, symsz))
        return bad(l, ".dynsym beyond end of file");
    if (link == 0 || link >= shnum)
        return bad(l, "bad .dynsym string table link");
    ss = sh + link * SHDR_SIZE;
    if (rd32(ss + 4) != SHT_STRTAB)
        return bad(l, ".dynsym string table is not SHT_STRTAB");
    stroff = rd32(ss + 16);
    strsz = rd32(ss + 20);
    if (!in_file(l, stroff, strsz))
        return bad(l, ".dynstr beyond end of file");

    l->syms = malloc((symsz / SYM_SIZE + 1) * sizeof(*l->syms));
    if (!l->syms)
        return bad(l, "out of memory");
    l->nsyms = 0;
    for (i = 1; i < symsz / SYM_SIZE; i++) { /* entry 0 is the null symbol */
        const unsigned char *s = e + symoff + i * SYM_SIZE;
        uint32_t name = rd32(s), info = s[12], other = s[13], shndx = rd16(s + 14);
        uint32_t bind = info >> 4, type = info & 15, vis = other & 3;
        const char *n;
        if (name >= strsz)
            return bad(l, "symbol name offset beyond .dynstr");
        n = (const char *)e + stroff + name;
        if (!memchr(n, 0, strsz - name))
            return bad(l, "symbol name not terminated in .dynstr");
        if (shndx == 0 || (bind != STB_GLOBAL && bind != STB_WEAK) || (vis != STV_DEFAULT && vis != STV_PROTECTED))
            continue;
        if (type == STT_GNU_IFUNC)
            type = STT_FUNC;
        if ((type != STT_FUNC && type != STT_OBJECT && type != STT_TLS) || !*n)
            continue;
        l->syms[l->nsyms].name = n;
        l->syms[l->nsyms].kind = type;
        l->nsyms++;
    }
    qsort(l->syms, l->nsyms, sizeof(*l->syms), cmp_sym);
    return 0;
}

/* --allow-missing FILE: names (NUL-terminated in place), sorted for bsearch; returns the count or -1 */
static char **allow;
static size_t nallow;

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static int load_allow(const char *path)
{
    struct lib f;
    char *p, *end;
    memset(&f, 0, sizeof(f));
    f.path = path;
    if (read_file(&f))
        return -1;
    if (memchr(f.buf, 0, f.size))
        return bad(&f, "NUL byte in the list");
    allow = malloc((f.size / 2 + 1) * sizeof(*allow)); /* a name takes at least 2 bytes with its newline */
    if (!allow)
        return bad(&f, "out of memory");
    p = (char *)f.buf;
    end = p + f.size;
    while (p < end) {
        char *nl = memchr(p, '\n', (size_t)(end - p)), *e = nl ? nl : end;
        while (e > p && (e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
            e--;
        if (e > p && *p != '#') {
            if (!nl && e == end) { /* last line without a newline: no room to terminate it in place */
                char *c = malloc((size_t)(e - p) + 1);
                if (!c)
                    return bad(&f, "out of memory");
                memcpy(c, p, (size_t)(e - p));
                c[e - p] = 0;
                allow[nallow++] = c;
            } else {
                *e = 0;
                allow[nallow++] = p;
            }
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    qsort(allow, nallow, sizeof(*allow), cmp_str);
    return 0;
}

static int allowed(const char *name) { return nallow && bsearch(&name, allow, nallow, sizeof(*allow), cmp_str); }

static int cmp_name(const void *key, const void *elem)
{
    return strcmp(((const struct sym *)key)->name, ((const struct sym *)elem)->name);
}

static const char *kind_name(unsigned k)
{
    return k == STT_FUNC ? "function" : k == STT_OBJECT ? "object" : "tls";
}

int main(int argc, char **argv)
{
    struct lib ours, dev;
    size_t i, missing = 0;

    memset(&ours, 0, sizeof(ours));
    memset(&dev, 0, sizeof(dev));
    if (argc == 3 && strcmp(argv[1], "--list") == 0) {
        ours.path = argv[2];
        if (load(&ours))
            return 2;
        for (i = 0; i < ours.nsyms; i++)
            if (i == 0 || cmp_sym(&ours.syms[i - 1], &ours.syms[i]) != 0)
                printf("%s %s\n", ours.syms[i].name, kind_name(ours.syms[i].kind));
        return fflush(stdout) == 0 ? 0 : 2;
    }
    if (argc == 5 && strcmp(argv[1], "--allow-missing") == 0) {
        if (load_allow(argv[2]))
            return 2;
        argc -= 2;
        argv += 2;
    }
    if (argc != 3 || argv[1][0] == '-') {
        fprintf(stderr, "usage: kktls-symcheck [--allow-missing FILE] OURS.so DEVICE.so\n"
                        "       kktls-symcheck --list LIB.so\n");
        return 2;
    }
    ours.path = argv[1];
    dev.path = argv[2];
    if (load(&ours) || load(&dev))
        return 2;
    if (ours.nsyms == 0 || dev.nsyms == 0) { /* a stripped or broken libssl/libcrypto: nothing to compare against */
        fprintf(stderr, "kktls-symcheck: %s exports nothing\n", ours.nsyms == 0 ? ours.path : dev.path);
        return 2;
    }
    if (ours.machine != dev.machine) {
        fprintf(stderr, "kktls-symcheck: %s and %s are for different machines\n", ours.path, dev.path);
        return 2;
    }
    for (i = 0; i < dev.nsyms; i++) {
        const struct sym *d = &dev.syms[i], *o;
        if ((i > 0 && cmp_sym(&dev.syms[i - 1], d) == 0) || allowed(d->name))
            continue;
        o = bsearch(d, ours.syms, ours.nsyms, sizeof(*ours.syms), cmp_name);
        if (o) { /* bsearch hits any entry of that name: go to the first, then look for the same kind */
            while (o > ours.syms && strcmp(o[-1].name, d->name) == 0)
                o--;
            for (; o < ours.syms + ours.nsyms && strcmp(o->name, d->name) == 0; o++)
                if (o->kind == d->kind)
                    break;
            if (o < ours.syms + ours.nsyms && strcmp(o->name, d->name) == 0)
                continue;
            fprintf(stderr, "%s (%s in %s, another kind in %s)\n", d->name, kind_name(d->kind), dev.path, ours.path);
        } else {
            fprintf(stderr, "%s\n", d->name);
        }
        missing++;
    }
    if (missing) {
        fprintf(stderr, "kktls-symcheck: %lu export(s) of %s missing in %s\n", (unsigned long)missing, dev.path,
                ours.path);
        return 1;
    }
    return 0;
}
