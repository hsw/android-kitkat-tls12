#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""emu_layer_d.py: make the layer-D emulator pair from the layer-A aosp_arm pair and a device build with layer D
(layer D is system-only since the factory moved into core.jar).

The emulator boots an aosp_arm-eng image. Layer A already carries the default factory
(io.github.hsw.kktls.KktlsDefaultSSLSocketFactory in core.jar, libcore/0025); without the layer-D files it keeps the
platform factory. The aosp_arm product does not install a device product's PRODUCT_PACKAGES, so this copies the layer-A pair and
adds exactly the files layer D adds on a device:

  system.img   /framework/kktls-conscrypt.jar, /framework/kktls-sslfilter.jar, /lib/libkktls_conscrypt_jni.so  (new;
               review 1b: the aar's .so under its own basename, the rewritten jar loads "kktls_conscrypt_jni")
               written with debugfs: root:root 0644, security.selinux = that of /framework/core.jar, fixed times
  ramdisk.img  copied byte for byte: layer D has no boot jar. Its BOOTCLASSPATH must equal the D build's generated
               PRODUCT_BOOT_JARS list and name no kktls-* jar.

The image's core.jar must define the default factory (a layer-A image built before libcore/0025 carried it is refused).
The jars are dex (product independent: the aosp_arm and a device product's Java jars are byte-identical) and the image is
not odexed, so PackageManagerService dexopts kktls-conscrypt.jar and kktls-sslfilter.jar into /data/dalvik-cache on the
first boot (every /system/framework jar off the boot class path), as on a device.

    python3 -I emu_layer_d.py --emu-a DIR --layer-d DIR --out DIR [--debugfs PATH] [--e2fsck PATH]

--emu-a: system.img (raw ext4) + ramdisk.img of the layer-A aosp_arm build; --layer-d: a device build's layer-D artefact folder
(framework/, lib/, product-init.environ.rc). Writes OUT/{system.img,ramdisk.img,SHA256SUMS,inputs.txt}; reads every
written file back and runs e2fsck -fn. Deterministic: E2FSPROGS_FAKE_TIME. debugfs/e2fsck default
to Homebrew's e2fsprogs (keg-only, not on PATH); --debugfs/--e2fsck take a path or a name looked up on PATH. Exit 1 with a message on any error (bad input, debugfs failing, a read-back difference).
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python3 -I leaves the script directory off sys.path
from kktlsfmt import CONSCRYPT_SO, environ_bcp, ramdisk_cpio, sha256_file as sha  # noqa: E402

FILES = [("framework/kktls-conscrypt.jar", "/framework/kktls-conscrypt.jar"),
         ("framework/kktls-sslfilter.jar", "/framework/kktls-sslfilter.jar"),
         (CONSCRYPT_SO, "/" + CONSCRYPT_SO)]
FAKE_TIME = "1791547200"  # 2026-10-09T12:00:00Z
DEBUGFS = "/opt/homebrew/opt/e2fsprogs/sbin/debugfs"
E2FSCK = "/opt/homebrew/opt/e2fsprogs/sbin/e2fsck"


WRAPPER_DESC = b"Lio/github/hsw/kktls/KktlsDefaultSSLSocketFactory;"


def check_ramdisk(src, product_environ, dst):
    """Copy the layer-A ramdisk unchanged after checking its BOOTCLASSPATH: = the D build's, no kktls-* jar."""
    members = ramdisk_cpio(src)
    with open(product_environ, encoding="utf-8") as f:
        _, prod = environ_bcp(f.read())
    idx = [i for i, m in enumerate(members) if m[1] == "init.environ.rc"]
    if len(idx) != 1:
        raise SystemExit("ramdisk has %d init.environ.rc" % len(idx))
    _, emu = environ_bcp(members[idx[0]][2].decode())
    bad = [j for j in prod + emu if os.path.basename(j).startswith("kktls-")]
    if bad:
        raise SystemExit("a kktls-* jar on BOOTCLASSPATH (layer D has no boot jar): %s" % sorted(set(bad)))
    if emu != prod:
        raise SystemExit("emulator BOOTCLASSPATH %s != the D build's %s (%s)" % (emu, prod, product_environ))
    shutil.copyfile(src, dst)
    return len(emu)


def debugfs(img, cmds, debugfs_bin, write=False):
    """stdout + stderr of debugfs running cmds on img. debugfs 1.47 exits 0 even when it cannot open the image (it then
    prints "Filesystem not open" for every command) and when one command fails (e.g. `rm` of a file the image does not
    have yet), so a non-zero exit or an image that did not open stops here with debugfs's own message; the read-back
    in make_system checks the commands' effect."""
    env = dict(os.environ, E2FSPROGS_FAKE_TIME=FAKE_TIME)
    with tempfile.NamedTemporaryFile("w", suffix=".cmds", delete=False) as t:
        t.write("\n".join(cmds) + "\n")
    try:
        r = subprocess.run([debugfs_bin] + (["-w"] if write else []) + ["-f", t.name, img], env=env,
                           capture_output=True, text=True)
    finally:
        os.unlink(t.name)
    if r.returncode != 0 or "while trying to open" in r.stderr or "Filesystem not open" in r.stderr:
        raise SystemExit("%s could not run on %s (rc=%d):\n%s" % (debugfs_bin, img, r.returncode,
                                                                   "\n".join((r.stdout + r.stderr).splitlines()[:6])))
    return r.stdout + r.stderr


def make_system(src, dfiles, dst, debugfs_bin, e2fsck_bin, td):
    shutil.copyfile(src, dst)
    core = os.path.join(td, "core.jar")
    debugfs(dst, ["dump /framework/core.jar %s" % core], debugfs_bin)
    try:
        with zipfile.ZipFile(core) as z:
            has_factory = WRAPPER_DESC in z.read("classes.dex")
    except (OSError, KeyError, zipfile.BadZipFile) as e:
        raise SystemExit("cannot read classes.dex of /framework/core.jar in %s: %s" % (src, e))
    if not has_factory:
        raise SystemExit("/framework/core.jar of %s does not define %s: a layer-A image without libcore/0025 of"
                         " Task 4; rebuild it" % (src, WRAPPER_DESC[1:-1].decode().replace("/", ".")))
    ctx = debugfs(dst, ["ea_get /framework/core.jar security.selinux"], debugfs_bin)
    if "u:object_r:system_file:s0" not in ctx:
        raise SystemExit("cannot read the SELinux label of /framework/core.jar: %s" % ctx)
    ctx_file = os.path.join(td, "selinux.ctx")
    with open(ctx_file, "wb") as f:
        f.write(b"u:object_r:system_file:s0\0")
    cmds = []
    for rel, dest in FILES:
        cmds += ["rm %s" % dest, "write %s %s" % (os.path.join(dfiles, rel), dest),
                 "sif %s mode 0100644" % dest, "sif %s uid 0" % dest, "sif %s gid 0" % dest,
                 "ea_set -f %s %s security.selinux" % (ctx_file, dest)]
        for t in ("atime", "ctime", "mtime", "crtime"):
            cmds.append("sif %s %s @%s" % (dest, t, FAKE_TIME))
    log = debugfs(dst, cmds, debugfs_bin, write=True)
    # read back: content, owner, mode, label
    for rel, dest in FILES:
        out = os.path.join(td, os.path.basename(dest))
        debugfs(dst, ["dump %s %s" % (dest, out)], debugfs_bin)
        if not os.path.isfile(out) or sha(out) != sha(os.path.join(dfiles, rel)):
            raise SystemExit("read-back of %s differs from %s\n%s" % (dest, rel, log))
        st = debugfs(dst, ["stat %s" % dest, "ea_get %s security.selinux" % dest], debugfs_bin)
        if "Mode:  0644" not in st or "User:     0   Group:     0" not in st or "system_file" not in st:
            raise SystemExit("%s: wrong mode/owner/label:\n%s" % (dest, st))
    r = subprocess.run([e2fsck_bin, "-fn", dst], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("e2fsck -fn %s: rc=%d\n%s" % (dst, r.returncode, r.stdout + r.stderr))
    return r.stdout.strip().splitlines()[-1]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--emu-a", required=True)
    ap.add_argument("--layer-d", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--debugfs", default=DEBUGFS, help="path or name on PATH (default %(default)s)")
    ap.add_argument("--e2fsck", default=E2FSCK, help="path or name on PATH (default %(default)s)")
    a = ap.parse_args()
    for opt in ("debugfs", "e2fsck"):
        tool = shutil.which(getattr(a, opt))  # a path is checked as is, a bare name is looked up on PATH
        if tool is None:
            ap.error("--%s %s: not an executable path, nor a name found on PATH" % (opt, getattr(a, opt)))
        setattr(a, opt, tool)
    os.makedirs(a.out, exist_ok=True)
    try:
        n_bcp = check_ramdisk(os.path.join(a.emu_a, "ramdisk.img"),
                              os.path.join(a.layer_d, "product-init.environ.rc"),
                              os.path.join(a.out, "ramdisk.img"))
    except (RuntimeError, OSError, UnicodeDecodeError) as e:
        raise SystemExit("ramdisk: %s: %s" % (type(e).__name__, e))
    with tempfile.TemporaryDirectory() as td:
        fsck = make_system(os.path.join(a.emu_a, "system.img"), a.layer_d, os.path.join(a.out, "system.img"),
                           a.debugfs, a.e2fsck, td)
    with open(os.path.join(a.out, "inputs.txt"), "w") as f:
        for p in [os.path.join(a.emu_a, "system.img"), os.path.join(a.emu_a, "ramdisk.img"),
                  os.path.join(a.layer_d, "product-init.environ.rc")] + [os.path.join(a.layer_d, r) for r, _ in FILES]:
            f.write("%s  %s\n" % (sha(p), p))
    with open(os.path.join(a.out, "SHA256SUMS"), "w") as f:
        for n in ("system.img", "ramdisk.img"):
            f.write("%s  %s\n" % (sha(os.path.join(a.out, n)), n))
    print("ramdisk: copied, BOOTCLASSPATH %d jars (no kktls-* jar); system: core.jar has the default factory, %d files"
          " written, read back OK; e2fsck: %s" % (n_bcp, len(FILES), fsck))
    with open(os.path.join(a.out, "SHA256SUMS")) as f:
        sys.stdout.write(f.read())
    return 0


if __name__ == "__main__":
    sys.exit(main())
