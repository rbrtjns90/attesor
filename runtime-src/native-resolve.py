#!/usr/bin/env python3
"""native-resolve.py — resolve Debian package names to .deb URLs, natively.

Replaces the translated `apt-get --print-uris` step in apt-install.sh with a
host-side resolver over the apt index already in the sysroot. Reads:

  var/lib/apt/lists/*_Packages*        (xz-compressed stanzas)
  var/lib/dpkg/status                  (installed set)
  etc/apt/sources.list*/*.sources      (suite -> mirror base URI)

Emits one '<url>' line per .deb to download (deps first), or nothing when
every requested package is already installed — same shape apt-install.sh
parses from apt-get --print-uris.

Usage: native-resolve.py <sysroot> <pkg> [<pkg>...]
"""

import lzma
import os
import re
import sys
from pathlib import Path

sysroot = Path(sys.argv[1])
wanted = sys.argv[2:]

# --- mirror bases -------------------------------------------------------------
# The apt lists filenames encode <host>_<path>_dists_<suite>_... — rebuild the
# suite -> base URI map from the sources config so Filename joins correctly.
def mirror_bases():
    bases = {}          # suite -> base URI (no trailing slash)
    etc = sysroot / "etc/apt"
    texts = []
    if (etc / "sources.list").exists():
        texts.append((etc / "sources.list").read_text(errors="replace"))
    d = etc / "sources.list.d"
    if d.is_dir():
        for f in sorted(d.iterdir()):
            texts.append(f.read_text(errors="replace"))
    uris, suites = [], []
    for text in texts:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("URIs:"):
                uris = line.split(":", 1)[1].split()
            elif line.startswith("Suites:"):
                suites = line.split(":", 1)[1].split()
                for s in suites:
                    for u in uris:
                        bases.setdefault(s, u.rstrip("/"))
                uris, suites = [], []
            elif line.startswith("deb "):
                m = re.match(r"deb\s+(?:\[[^\]]*\]\s+)?(\S+)\s+(\S+)", line)
                if m:
                    bases.setdefault(m.group(2), m.group(1).rstrip("/"))
    return bases

BASES = mirror_bases()

def base_for_lists(name):
    # e.g. deb.debian.org_debian_dists_bookworm_main_... -> suite bookworm
    m = re.search(r"_dists_([^_]+)_", name)
    if not m:
        return None
    return BASES.get(m.group(1))

# --- version compare (deb policy: alternating non-digit/digit runs) -----------
def _verpart(v):
    if not v or not v[0].isdigit():
        return 0, v
    i = 0
    while i < len(v) and v[i].isdigit():
        i += 1
    return int(v[:i]), v[i:]

def _ndigit(c):
    # order: letters < tilde < everything else per dpkg
    return ord(c) + 256 if c.isalpha() else (0 if c == "~" else (ord(c) or 0))

def vercmp(a, b):
    a = a.split("-", 1)[0].split(":", 1)[-1] if ":" in a else a.split("-", 1)[0]
    b = b.split("-", 1)[0].split(":", 1)[-1] if ":" in b else b.split("-", 1)[0]
    while a or b:
        # non-digit run
        na = nb = ""
        while a and not a[0].isdigit():
            na += a[0]; a = a[1:]
        while b and not b[0].isdigit():
            nb += b[0]; b = b[1:]
        for x, y in zip(na, nb):
            if _ndigit(x) != _ndigit(y):
                return -1 if _ndigit(x) < _ndigit(y) else 1
        if len(na) != len(nb):
            return -1 if len(na) < len(nb) else 1
        va, a = _verpart(a)
        vb, b = _verpart(b)
        if va != vb:
            return -1 if va < vb else 1
    return 0

VERS_OK = {">>": 1, ">=": 1, "=": 0, "<=": -1, "<<": -1, ">": 1, "<": -1}

def ver_satisfies(have, op, want):
    c = vercmp(have, want)
    if op in (">>", ">"):
        return c > 0
    if op == ">=":
        return c >= 0
    if op == "=":
        return c == 0
    if op == "<=":
        return c <= 0
    return c < 0

# --- index parsing -------------------------------------------------------------
def stanzas(path):
    try:
        data = lzma.open(path).read().decode("utf-8", "replace")
    except Exception:
        try:
            data = path.read_text(errors="replace")
        except Exception:
            return
    cur = {}
    key = None
    for line in data.splitlines():
        if not line:
            if "Package" in cur:
                yield cur
            cur, key = {}, None
            continue
        if line[0] in " \t" and key:
            cur[key] += "\n" + line
            continue
        if ":" in line:
            key, val = line.split(":", 1)
            cur[key] = val.strip()

index = {}     # name -> stanza (highest version wins)
provides = {}  # virtual -> [provider names]
lists_dir = sysroot / "var/lib/apt/lists"
for f in sorted(lists_dir.glob("*_Packages*")):
    base = base_for_lists(f.name)
    if not base:
        continue
    for st in stanzas(f):
        name = st["Package"]
        if name not in index or vercmp(st.get("Version", "0"),
                                       index[name].get("Version", "0")) > 0:
            st["_base"] = base
            index[name] = st
        for p in re.split(r",\s*", st.get("Provides", "") or ""):
            p = p.split()[0] if p.strip() else ""
            if p:
                provides.setdefault(p, []).append(name)

# --- installed set ---------------------------------------------------------
installed = {}  # name -> version
status = sysroot / "var/lib/dpkg/status"
if status.exists():
    cur = {}
    for line in status.read_text(errors="replace").splitlines() + [""]:
        if not line:
            if cur.get("Status", "").startswith("install ok installed"):
                installed[cur["Package"]] = cur.get("Version", "0")
            cur = {}
        elif ":" in line:
            k, v = line.split(":", 1)
            cur[k] = v.strip()

def dep_ok(dep):
    """Is one alternative (possibly versioned/arch-qualified) satisfied
    by the installed set?"""
    m = re.match(r"([^ (|]+)(?::[a-z0-9-]+)?\s*(?:\((\S+)\s*(\S+)\))?", dep.strip())
    if not m:
        return False
    name, op, ver = m.group(1), m.group(2), m.group(3)
    have = installed.get(name)
    if have is None:
        # a virtual package provided by something installed counts too
        return any(p in installed for p in provides.get(name, ()))
    return not op or ver_satisfies(have, op, ver)

def resolve_alt(dep_group):
    """Pick a package to satisfy 'a (>=v) | b | c': installed alternative
    first, else first that exists in the index (or via Provides)."""
    alts = [a.strip() for a in dep_group.split("|")]
    for a in alts:
        if dep_ok(a):
            return None
    for a in alts:
        name = re.match(r"([^ (|]+)", a).group(1)
        if name in index:
            return name
        for p in provides.get(name, ()):
            if p in index:
                return p
    return None

# --- BFS resolution ---------------------------------------------------------
seen, order, missing = set(), [], []

def add(name):
    if name in seen:
        return
    seen.add(name)
    st = index.get(name)
    if st is None:
        # virtual with a provider already picked elsewhere
        prov = [p for p in provides.get(name, ()) if p in index]
        if prov:
            add(prov[0])
        else:
            missing.append(name)
        return
    deps = st.get("Pre-Depends", "") + ", " + st.get("Depends", "")
    if os.environ.get("OAH_NO_RECOMMENDS") != "1":
        deps += ", " + st.get("Recommends", "")
    for group in re.split(r",\s*(?![^()]*\))", deps):
        group = group.strip()
        if not group:
            continue
        pick = resolve_alt(group)
        if pick:
            add(pick)
    if name not in installed:
        order.append(name)

for w in wanted:
    w = w.split(":")[0]
    if w in index:
        add(w)
    elif w in installed or any(p in installed for p in provides.get(w, ())):
        pass
    else:
        print(f"native-resolve: unable to locate package {w}", file=sys.stderr)
        sys.exit(1)

if missing:
    for m in sorted(set(missing)):
        print(f"native-resolve: no candidate for dependency {m}",
              file=sys.stderr)

for name in order:
    st = index[name]
    fn = st.get("Filename")
    if fn:
        print(f"'{st['_base']}/{fn}'")
