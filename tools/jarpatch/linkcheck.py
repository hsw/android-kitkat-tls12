#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""linkcheck.py: the jar patcher's link check, one class index per runtime.

    python3 -I linkcheck.py --dex FILE...            print the classes, members and references of dex/jar/apk files
                                                     (exit 0 ok, 2 usage or tool error: an unreadable file)

The patcher (kktls-jarpatch.py) calls run() after staging the patched classes.dex files. Two runtimes are checked:
dalvik (the device's BOOTCLASSPATH, with core.jar) and art (the same with core.jar replaced by core-libart.jar, as the
4.4 ART runtime does; skipped on a Dalvik-only ROM). For each runtime:

  outbound  every type, field and method reference of every replacement class (parsed from its smali file) must
            resolve against the patched boot class path;
  inbound   every type, field and method reference of every dex in scope (the boot class path jars, the other
            /system/framework jars, /system/app and /system/priv-app with classes.dex) that resolved against the
            device's own boot class path must still resolve against the patched one. A jar or apk outside the boot
            class path also sees its own classes (after the boot class path, which wins); only classes.dex is read
            (4.4 system code is single-dex). References that did not resolve before the patch either (optional
            libraries, a vendor's dangling reference) are counted, not refused: the patch did not break them;
  placement every patched jar must be on the runtime's boot class path, and no other boot jar may define a
            replacement class or a check class (the set's classes the donor's libjavacrypto.so uses) or carry a
            resource the patch writes (java/security/security.properties): the first definition on BOOTCLASSPATH
            is the one the runtime loads, for classes and resources alike.

Resolution follows the class, its superclasses and all their interfaces (transitively), for fields and methods
alike; an array type resolves members on java.lang.Object. Members match by name and descriptor; static/instance kind
and access flags are not checked. Types used only by debug info (`.local`) and the types of system annotations
(`.annotation system Ldalvik/annotation/...;`, never loaded) are not references. Only the inbound references whose
owner's hierarchy contains a class of the replacement set are resolved (any other reference resolves the same way
before and after).

Stdlib only: the dex tables (strings, types, protos, fields, methods, class definitions and class data) are read
directly.
"""
import collections
import os
import re
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # `python3 -I` leaves the script dir out
import normalize  # noqa: E402
import rawzip  # noqa: E402

NO_INDEX = 0xffffffff
OBJECT = "Ljava/lang/Object;"
PRIMS = "ZBSCIJFDV"
# the /system directories whose jars and apks are in scope (the patcher's odex check and its adb copy use them too)
SUBDIRS = (("framework", ".jar"), ("app", ".apk"), ("priv-app", ".apk"))
DEX_MAGIC = b"dex\n"
HEADER_SIZE = 0x70
# the header's (size, offset) pairs of the id tables, in file order
ID_TABLES = (("string", 0x38), ("type", 0x40), ("proto", 0x48), ("field", 0x50), ("method", 0x58), ("class", 0x60))
# what a reference names; FIELD and METHOD are also the indexes of the member sets in a class tuple of Dex.classes
TYPE, FIELD, METHOD = 1, 2, 3
OUT, IN, DUP, RES, OFF = "out", "in", "dup", "res", "off"
# one failed reference: where and what are the refusal's columns, target the unresolved reference of an outbound miss
#   OUT: where = jar name, what = replacement class, target = its reference
#   IN:  where = /system path of the dex, what = its reference, target = None
#   DUP: where = jar name, what = replacement or check class, target = "earlier"/"later" + the other BOOTCLASSPATH
#        jar's path
#   RES: where = jar name, what = resource path the patch writes, target = as for DUP
#   OFF: where = jar name, what = "-", target = "" (a patched jar this runtime's BOOTCLASSPATH does not name)
Miss = collections.namedtuple("Miss", "where what target direction")


class LinkError(Exception):
    pass


# --- dex reader ----------------------------------------------------------------------------------------------------

def dex_header(data, name="dex"):
    """{string|type|proto|field|method|class: (size, offset)} of a dex file's id tables (data: at least the
    header)."""
    if len(data) < HEADER_SIZE or not data.startswith(DEX_MAGIC):
        raise LinkError("%s: not a dex file" % name)
    return {k: struct.unpack_from("<2I", data, off) for k, off in ID_TABLES}


def id_counts(data):
    """{type|proto|field|method: count} from a dex header (each must stay below 65536 in a single-dex jar)."""
    h = dex_header(data)
    return {k: h[k][0] for k in ("type", "proto", "field", "method")}


def _uleb(data, off):
    res = shift = 0
    while True:
        b = data[off]
        off += 1
        res |= (b & 0x7f) << shift
        if b < 0x80:
            return res, off
        shift += 7
        if shift > 28:
            raise LinkError("bad uleb128")


class Dex(object):
    """The tables of one dex file.

    classes  {descriptor: (superclass or None, (interfaces), frozenset("name:type"), frozenset("name(args)ret"))}
    types    [descriptor]                      every type_id
    fields   [(class, "name:type")]            every field_id
    methods  [(class, "name(args)ret")]        every method_id
    """

    def __init__(self, data, name="dex"):
        self.name = name
        header = dex_header(data, name)
        try:
            self._parse(data, header)
        except (struct.error, IndexError) as e:
            raise LinkError("%s: truncated or corrupt dex (%s)" % (name, e))

    def _parse(self, data, header):
        u = struct.unpack_from
        (ns, so), (nt, to), (np_, po), (nf, fo), (nm, mo), (nc, co) = (header[k] for k, _ in ID_TABLES)
        soffs = u("<%dI" % ns, data, so) if ns else ()
        cache = {}

        def string(i):
            s = cache.get(i)
            if s is None:
                _, p = _uleb(data, soffs[i])          # utf16 length
                e = data.index(b"\0", p)
                raw = data[p:e].replace(b"\xc0\x80", b"\0")   # MUTF-8 NUL
                try:
                    s = raw.decode("utf-8", "surrogatepass")
                except UnicodeDecodeError:
                    s = raw.decode("utf-8", "replace")
                cache[i] = s
            return s

        types = [string(i) for i in u("<%dI" % nt, data, to)] if nt else []

        def type_list(off):
            if not off:
                return ()
            n = u("<I", data, off)[0]
            return tuple(types[i] for i in u("<%dH" % n, data, off + 4)) if n else ()

        protos = []
        for k in range(np_):
            _, ret, par = u("<3I", data, po + 12 * k)
            protos.append("(%s)%s" % ("".join(type_list(par)), types[ret]))
        self.types = types
        self.fields = []
        for k in range(nf):
            c, t, n = u("<HHI", data, fo + 8 * k)
            self.fields.append((types[c], "%s:%s" % (string(n), types[t])))
        self.methods = []
        for k in range(nm):
            c, p, n = u("<HHI", data, mo + 8 * k)
            self.methods.append((types[c], string(n) + protos[p]))
        self.classes = {}
        for k in range(nc):
            ci, _, sup, ifo, _, _, cdo, _ = u("<8I", data, co + 32 * k)
            desc = types[ci]
            if desc in self.classes:
                raise LinkError("%s: class %s defined twice" % (self.name, desc))
            fields, methods = [], []
            if cdo:
                p = cdo
                counts = []
                for _ in range(4):
                    v, p = _uleb(data, p)
                    counts.append(v)
                for n_items, is_field in ((counts[0], True), (counts[1], True), (counts[2], False),
                                          (counts[3], False)):
                    idx = 0
                    for _ in range(n_items):
                        d, p = _uleb(data, p)
                        idx += d
                        _, p = _uleb(data, p)              # access flags
                        if is_field:
                            fields.append(self.fields[idx][1])
                        else:
                            _, p = _uleb(data, p)          # code_off
                            methods.append(self.methods[idx][1])
            self.classes[desc] = (None if sup == NO_INDEX else types[sup], type_list(ifo), frozenset(fields),
                                  frozenset(methods))


def read_dex(path):
    """Dex of a .dex file or of a jar/apk's classes.dex; None when the zip has no classes.dex."""
    name = os.path.basename(path)
    try:
        with open(path, "rb") as f:
            head = f.read(4)
        if head == DEX_MAGIC:
            with open(path, "rb") as f:
                return Dex(f.read(), name)
        with zipfile.ZipFile(path) as z:
            if "classes.dex" not in z.namelist():
                return None
            return Dex(z.read("classes.dex"), name)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError) as e:
        raise LinkError("%s: %s" % (path, e))


# --- smali references (the replacement classes) ------------------------------------------------------------------

MEMBER = re.compile(r"(\[*L[^;\s]+;|\[+[ZBSCIJFD])->([^\s(:]+)(?:(\([^)\s]*\)[^\s,{}]+)|:([^\s,{}]+))")
TOKEN = re.compile(r"[^\s,{}=]+")


def parse_types(desc):
    """Class descriptors in a sequence of field type descriptors (`I[Lfoo;Lbar;`), element types of arrays."""
    res, i = [], 0
    while i < len(desc):
        c = desc[i]
        if c == "[":
            i += 1
            continue
        if c in PRIMS:
            i += 1
            continue
        if c == "L":
            e = desc.find(";", i)
            if e < 0:
                raise LinkError("bad type descriptor %r" % desc)
            res.append(desc[i:e + 1])
            i = e + 1
            continue
        raise LinkError("bad type descriptor %r" % desc)
    return res


def parse_proto(proto):
    """Class descriptors of a method descriptor `(args)ret`."""
    if not proto.startswith("(") or ")" not in proto:
        raise LinkError("bad method descriptor %r" % proto)
    args, ret = proto[1:].split(")", 1)
    return parse_types(args) + parse_types(ret)


def element(desc):
    d = desc.lstrip("[")
    return d if d.startswith("L") else None


def smali_refs(text):
    """(types, fields, methods) one class's smali text references: types {descriptor}, fields {(class,
    "name:type")}, methods {(class, "name(args)ret")}; array owners are kept as written."""
    types, fields, methods = set(), set(), set()
    for line in text.split("\n"):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(normalize.DEBUG_PREFIX):
            continue
        # string and char literals emptied (never references), the trailing comment dropped
        s = "".join(t[0] * 2 if lit else t for lit, t in normalize.segments(normalize.strip_comment(s)))
        if s.startswith(".annotation system "):
            continue
        for m in MEMBER.finditer(s):
            owner, name, proto, ftype = m.groups()
            if proto is not None:
                methods.add((owner, name + proto))
                types.update(parse_proto(proto))
            else:
                fields.add((owner, "%s:%s" % (name, ftype)))
                types.update(parse_types(ftype))
            if element(owner):
                types.add(element(owner))
        s = MEMBER.sub(" ", s)
        for tok in TOKEN.findall(s):
            if tok.startswith("."):
                continue
            if "(" in tok:
                types.update(parse_proto(tok[tok.index("("):]))
                continue
            if ":" in tok:
                tok = tok.rsplit(":", 1)[1]
            if tok.startswith(("L", "[")) and tok.endswith(";"):
                types.update(parse_types(tok))
    return types, fields, methods


# --- resolution ----------------------------------------------------------------------------------------------------

class World(object):
    """Class lookup for one runtime: the boot class path first (first definition wins), then a jar/apk's own
    classes."""

    def __init__(self, boot, own=None, changed=frozenset(), boot_memo=None):
        self.boot = boot                    # {desc: class tuple}, first definition along the BCP
        self.own = own or {}
        self.changed = changed              # the replacement set's classes (touches)
        self.boot_memo = boot_memo if boot_memo is not None else {}   # shared by the worlds of one boot and changed
        self.memo = {}

    def get(self, desc):
        c = self.boot.get(desc)
        return c if c is not None else self.own.get(desc)

    def has_type(self, desc):
        e = element(desc)
        return True if e is None else self.get(e) is not None

    def chain(self, desc):
        """The class and every superclass and interface it inherits from (defined ones only), breadth first."""
        seen, out, todo = set(), [], [desc]
        while todo:
            d = todo.pop(0)
            if d is None or d in seen:
                continue
            seen.add(d)
            c = self.get(d)
            if c is None:
                continue
            out.append((d, c))
            todo.append(c[0])
            todo.extend(c[1])
        return out

    def resolve(self, owner, member, kind):
        """The class defining member (`name:type` for kind FIELD, `name(args)ret` for kind METHOD) as seen from owner,
        or None. Constructors (`<init>`, and `<clinit>`) are not inherited: owner itself must declare them (Dalvik
        resolves invoke-direct in the named class only)."""
        if kind == METHOD and member.startswith("<"):
            c = None if owner.startswith("[") else self.get(owner)
            return owner if c is not None and member in c[METHOD] else None
        e = owner if not owner.startswith("[") else (OBJECT if self.has_type(owner) else None)
        if e is None or self.get(e) is None:
            return None
        chain = self.chain(e)
        if e != OBJECT and not any(d == OBJECT for d, _ in chain):
            chain += self.chain(OBJECT)     # interfaces inherit Object's methods
        for d, c in chain:
            if member in c[kind]:
                return d
        return None

    def touches(self, desc):
        """True when desc or a class it inherits from is in the replacement set."""
        e = element(desc) if desc.startswith("[") else desc
        if e is None:
            return False
        memo = self.boot_memo if e in self.boot else self.memo
        r = memo.get(e)
        if r is None:
            r = e in self.changed or any(d in self.changed for d, _ in self.chain(e))
            memo[e] = r
        return r


def boot_classes(dexes):
    res = {}
    for dx in dexes:
        for d, c in dx.classes.items():
            res.setdefault(d, c)
    return res


def duplicates(names, dexes, replaced):
    """[(jar, class, "earlier"|"later", other jar name)] for each replacement or check class (replaced: {jar without
    .jar: {descriptor}}) that another jar of the boot class path (names, in order, with their dexes) defines too: the
    runtime loads the first definition on BOOTCLASSPATH, so an earlier copy shadows the patched (or checked) one, and
    a later copy is a vendor's second implementation the series (or the check) does not cover."""
    defs = {}
    for i, (n, dx) in enumerate(zip(names, dexes)):
        for d in dx.classes:
            defs.setdefault(d, []).append(i)
    res = []
    for i, n in enumerate(names):
        j = n[:-len(".jar")]
        for c in sorted(replaced.get(j, ())):
            for k in defs.get(c, ()):
                if k != i:
                    res.append((j, c, "earlier" if k < i else "later", names[k]))
    return res


def jar_entries(path):
    """{name} of a jar's file entries (directories left out)."""
    try:
        with zipfile.ZipFile(path) as z:
            return {n for n in z.namelist() if not n.endswith("/")}
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError) as e:
        raise LinkError("%s: %s" % (path, e))


def ref_text(kind, owner, member=None):
    return owner if kind == TYPE else "%s->%s" % (owner, member)


def inbound(dx, before, after, stats):
    """[ref text] of dx's references that resolve in before and not in after (both worlds share changed)."""
    changed = after.changed
    misses = []
    for t in dx.types:
        e = element(t)
        if e is None or e not in changed:
            continue
        stats["refs_checked"] += 1
        b, a = before.has_type(t), after.has_type(t)
        if not b:
            stats["unresolved_before"] += 1
        elif not a:
            misses.append(ref_text(TYPE, t))
    for kind, refs in ((FIELD, dx.fields), (METHOD, dx.methods)):
        for owner, member in refs:
            if not (before.touches(owner) or after.touches(owner)):
                continue
            stats["refs_checked"] += 1
            if before.resolve(owner, member, kind) is None:
                stats["unresolved_before"] += 1
            elif after.resolve(owner, member, kind) is None:
                misses.append(ref_text(kind, owner, member))
    stats["refs_total"] += len(dx.types) + len(dx.fields) + len(dx.methods)
    return misses


def outbound(text, world):
    """Sorted references of one replacement class's smali text that do not resolve in world."""
    types, fields, methods = smali_refs(text)
    miss = {t for t in types if world.get(t) is None}
    for kind, refs in ((FIELD, fields), (METHOD, methods)):
        for owner, member in refs:
            if world.resolve(owner, member, kind) is None:
                miss.add(ref_text(kind, owner, member))
    return sorted(miss), len(types) + len(fields) + len(methods)


def runtimes(bootclasspath, dalvik_only):
    """[(name, [jar basenames])]: dalvik with core.jar, art with core-libart.jar in its place."""
    names = [os.path.basename(p) for p in bootclasspath]
    if "core.jar" not in names:
        raise LinkError("BOOTCLASSPATH has no core.jar")
    res = [("dalvik", names)]
    if not dalvik_only:
        res.append(("art", ["core-libart.jar" if n == "core.jar" else n for n in names]))
    return res


def run(root, bootclasspath, staged, replaced, changed, dalvik_only, log=None, checked=None, entries=None):
    """Link check of a staged patch.

    root          the /system copy (framework/, app/, priv-app/)
    bootclasspath the device's BOOTCLASSPATH entries (/system/framework/<jar>.jar)
    staged        {jar name without .jar: patched classes.dex path}
    replaced      {jar: {descriptor: smali path}} the replacement classes (added or changed by the series)
    changed       {jar: {descriptor}} every class of the set (changed, added or removed)
    checked       {jar: {descriptor}} the set's check classes (the device's class must equal stock: the donor's
                  libjavacrypto.so uses them)
    entries       {jar: {path}} the resources the patch writes (replaced or added non-class entries, such as
                  java/security/security.properties; removed ones left out, like removed classes)
    Every staged jar must be on each runtime's boot class path (core-libart.jar stands for core.jar on art), and no
    other boot jar may define a replaced or check class or carry a written resource (the boot class loader returns
    the first copy on BOOTCLASSPATH).
    Returns (stats {runtime: {...}}, misses [(where, what, why)]); misses empty = the check passed.
    """
    log = log or (lambda m: None)
    checked = checked or {}
    entries = entries or {}
    fw = os.path.join(root, "framework")
    cache, ecache = {}, {}

    def dex_of(path):
        if path not in cache:
            cache[path] = read_dex(path)
        return cache[path]

    def device_jar(n):
        p = os.path.join(fw, n)
        if not os.path.isfile(p):
            raise LinkError("BOOTCLASSPATH names %s, not in /system/framework" % n)
        return p

    others = []
    for sub, ext in SUBDIRS:
        d = os.path.join(root, sub)
        if os.path.isdir(d):
            others += [(sub, n) for n in sorted(os.listdir(d)) if n.endswith(ext)]
    misses = {}      # {Miss: [runtime]}
    stats = {}
    for rt, names in runtimes(bootclasspath, dalvik_only):
        st = {"bootclasspath": len(names), "dex": 0, "no_dex": 0, "classes": 0, "refs_total": 0, "refs_checked": 0,
              "unresolved_before": 0, "regressions": 0, "outbound_classes": 0, "outbound_refs": 0, "outbound_misses": 0}
        jar = {n: n[:-len(".jar")] for n in names}
        jars = {jar[n] for n in names if jar[n] in staged}
        # a patched jar this runtime does not load: its fix would never run (the other runtime's core jar aside)
        for j in sorted(set(staged) - jars - {"core-libart" if rt == "dalvik" else "core"}):
            misses.setdefault(Miss(j, "-", "", OFF), []).append(rt)
        ch = set()
        for j in jars:
            ch |= set(changed.get(j, ()))
        bdex = [dex_of(device_jar(n)) for n in names]
        adex = [dex_of(staged[jar[n]]) if jar[n] in staged else d for n, d in zip(names, bdex)]
        if any(d is None for d in bdex + adex):
            raise LinkError("a BOOTCLASSPATH jar has no classes.dex")
        bboot, aboot = boot_classes(bdex), boot_classes(adex)
        st["classes"] = len(aboot)
        bmemo, amemo = {}, {}
        before, after = World(bboot, None, ch, bmemo), World(aboot, None, ch, amemo)
        log("link check %s: %d boot jars, %d classes" % (rt, len(names), len(aboot)))
        # a replacement or check class defined by another boot jar too (the patched dex for the staged jars)
        own = {j: set(replaced.get(j, ())) | set(checked.get(j, ())) for j in jars}
        for j, c, where, other in duplicates(names, adex, own):
            misses.setdefault(Miss(j, c, "%s /system/framework/%s" % (where, other), DUP), []).append(rt)
        # a written resource that another boot jar carries too (a patched jar keeps the device jar's other entries)
        for n in names:
            if n not in ecache:
                ecache[n] = jar_entries(device_jar(n))
        wrote = [set(entries.get(jar[n], ())) if jar[n] in jars else set() for n in names]
        held = [ecache[n] | w for n, w in zip(names, wrote)]
        for i, n in enumerate(names):
            for p in sorted(wrote[i]):
                for k, o in enumerate(names):
                    if k != i and p in held[k]:
                        misses.setdefault(Miss(jar[n], p, "%s /system/framework/%s" % (
                            "earlier" if k < i else "later", o), RES), []).append(rt)
        # outbound: the replacement classes
        for j in sorted(jars):
            for c, p in sorted(replaced.get(j, {}).items()):
                with open(p, encoding="utf-8") as f:
                    bad, n = outbound(f.read(), after)
                st["outbound_classes"] += 1
                st["outbound_refs"] += n
                st["outbound_misses"] += len(bad)
                for r in bad:
                    misses.setdefault(Miss(j, c, r, OUT), []).append(rt)
        # inbound: the boot class path (patched dex for the staged jars) ...
        for n, dx in zip(names, adex):
            st["dex"] += 1
            for r in inbound(dx, before, after, st):
                misses.setdefault(Miss("/system/framework/" + n, r, None, IN), []).append(rt)
        # ... the other framework jars and the apps, each with its own classes after the boot class path
        skip = set(names) | {"core.jar", "core-libart.jar"}
        for sub, n in others:
            if sub == "framework" and n in skip:
                continue
            dx = dex_of(os.path.join(root, sub, n))
            if dx is None:
                st["no_dex"] += 1
                continue
            st["dex"] += 1
            b, a = World(bboot, dx.classes, ch, bmemo), World(aboot, dx.classes, ch, amemo)
            for r in inbound(dx, b, a, st):
                misses.setdefault(Miss("/system/%s/%s" % (sub, n), r, None, IN), []).append(rt)
        st["regressions"] = sum(1 for k, v in misses.items() if k.direction == IN and rt in v)
        stats[rt] = st
    res = []
    for m, rts in sorted(misses.items()):
        if m.direction == OUT:
            res.append((m.where, m.what, "references %s, which does not resolve on the patched boot class path (%s)"
                        % (m.target, ", ".join(rts))))
        elif m.direction == RES:
            where, other = m.target.split(" ", 1)
            res.append((m.where, m.what, "also in %s, %s on BOOTCLASSPATH (%s): %s" % (
                other, where, ", ".join(rts), "the runtime would load that copy, not the patched one"
                if where == "earlier" else "a second copy the series does not cover")))
        elif m.direction == DUP:
            where, other = m.target.split(" ", 1)
            check = m.what in checked.get(m.where, ()) and m.what not in replaced.get(m.where, {})
            res.append((m.where, m.what, "also defined in %s, %s on BOOTCLASSPATH (%s): %s" % (
                other, where, ", ".join(rts),
                ("the runtime would load that copy, not the checked one" if check else
                 "the runtime would load that copy, not the patched one") if where == "earlier" else
                ("a second copy the check does not cover" if check else
                 "a second copy the series does not cover"))))
        elif m.direction == OFF:
            res.append((m.where, m.what, "/system/framework/%s.jar is patched, but BOOTCLASSPATH does not name it "
                        "(%s): the runtime would not load the patched classes" % (m.where, ", ".join(rts))))
        else:
            res.append((m.where, m.what, "resolved before the patch, not after (%s)" % ", ".join(rts)))
    return stats, res


def main(argv):
    return rawzip.cli("linkcheck", _main, argv)


def _main(argv):
    if len(argv) < 2 or argv[0] != "--dex":
        print("usage: linkcheck.py --dex FILE...", file=sys.stderr)
        return 2
    for p in argv[1:]:
        try:
            dx = read_dex(p)
        except LinkError as e:
            print("linkcheck: %s" % e, file=sys.stderr)
            return 2
        if dx is None:
            print("# %s: no classes.dex" % p)
            continue
        print("# %s: %d classes, %d types, %d fields, %d methods" %
              (p, len(dx.classes), len(dx.types), len(dx.fields), len(dx.methods)))
        for d in sorted(dx.classes):
            sup, ifs, fs, ms = dx.classes[d]
            print("class %s super %s%s" % (d, sup or "-", "".join(" implements " + i for i in ifs)))
            for x in sorted(fs):
                print("  field %s" % x)
            for x in sorted(ms):
                print("  method %s" % x)
        for t in dx.types:
            print("ref type %s" % t)
        for o, m in dx.fields:
            print("ref field %s->%s" % (o, m))
        for o, m in dx.methods:
            print("ref method %s->%s" % (o, m))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
