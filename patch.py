#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io, os, re, json, struct, sys, zlib, array

EXE = '(the) Gnorp Apologue.exe'
WORKDIR = './data'
SCALE = {'font2': 0.6, 'font5': 0.45}
NEW_SECTION_NAME = b'.rus\x00\x00\x00\x00'
ERROR_MARK = b'[ERROR: NO TEXT]'
LANG_MARKERS = [('EN', 'Welcome to'), ('PT', 'Boas-vindas'), ('FR', 'Bienvenue'),
                ('DE', 'Willkommen'), ('ES', 'bienvenida'), ('ZH', '欢迎'), ('JA', 'ようこそ')]
LANG_LABELS = ['English', '简体中文', '日本語', 'Français', 'Español', 'Português', 'Deutsch']
PNG_SIG = b'\x89PNG\r\n\x1a\n'
SFNT_TAGS = (b'\x00\x01\x00\x00', b'OTTO', b'true')
_DROP_TABLES = ('fpgm', 'prep', 'cvt ', 'hdmx', 'LTSH', 'VDMX', 'gasp', 'DSIG', 'GSUB', 'GPOS',
                'GDEF', 'kern', 'BASE', 'JSTF', 'MATH', 'vhea', 'vmtx', 'VORG', 'meta')


class PatchError(Exception): pass


def align_up(x, a): return (x + a - 1) // a * a


class Section:
    def __init__(self, name, vsize, va, rawsize, rawptr, chars):
        self.name, self.vsize, self.va = name, vsize, va
        self.rawsize, self.rawptr, self.chars = rawsize, rawptr, chars

    @property
    def is_code(self): return bool(self.chars & 0x20)


class Exe:
    def __init__(self, data):
        d = self.data = bytes(data)
        if len(d) < 0x200 or d[:2] != b'MZ':
            raise PatchError('нет сигнатуры MZ')
        self.pe = struct.unpack_from('<I', d, 0x3C)[0]
        if d[self.pe:self.pe + 4] != b'PE\x00\x00':
            raise PatchError('нет сигнатуры PE')
        self.coff = self.pe + 4
        machine, nsec, _ts, _ps, _ns, optsz, _ch = struct.unpack_from('<HHIIIHH', d, self.coff)
        self.opt = self.coff + 20
        if machine != 0x8664 or struct.unpack_from('<H', d, self.opt)[0] != 0x20B:
            raise PatchError('нужен 64-битный PE (x64)')
        self.nsec = nsec
        self.image_base = struct.unpack_from('<Q', d, self.opt + 24)[0]
        self.sec_align, self.file_align = struct.unpack_from('<II', d, self.opt + 32)
        self.checksum = struct.unpack_from('<I', d, self.opt + 64)[0]
        self.sect_tab = self.opt + optsz
        self.sections = []
        for i in range(nsec):
            h = self.sect_tab + 40 * i
            vsize, va, rawsize, rawptr = struct.unpack_from('<IIII', d, h + 8)
            chars = struct.unpack_from('<I', d, h + 36)[0]
            self.sections.append(Section(d[h:h + 8], vsize, va, rawsize, rawptr, chars))
        self._lea = None

    def va2off(self, va):
        rva = va - self.image_base
        for s in self.sections:
            if s.va <= rva < s.va + s.vsize:
                delta = rva - s.va
                return s.rawptr + delta if delta < s.rawsize else None
        return None

    def off2va(self, off):
        for s in self.sections:
            if s.rawptr <= off < s.rawptr + s.rawsize:
                return self.image_base + s.va + (off - s.rawptr)
        return None

    def data_ranges(self):
        return [(s.rawptr, s.rawptr + min(s.rawsize, s.vsize)) for s in self.sections if not s.is_code]

    def code_ranges(self):
        return [(s.rawptr, s.rawptr + min(s.rawsize, s.vsize)) for s in self.sections if s.is_code]

    def lea_targets(self):
        if self._lea is None:
            d, res = self.data, {}
            pat = re.compile(rb'(?=[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d])', re.S)
            for lo, hi in self.code_ranges():
                for m in pat.finditer(d[lo:hi]):
                    i = lo + m.start()
                    if i + 7 > hi: continue
                    tgt = self.off2va(i) + 7 + struct.unpack_from('<i', d, i + 3)[0]
                    res.setdefault(tgt, []).append(i)
            self._lea = res
        return self._lea


def pe_checksum(data, checksum_off):
    b = bytearray(data)
    b[checksum_off:checksum_off + 4] = b'\x00\x00\x00\x00'
    if len(b) % 2: b.append(0)
    words = array.array('H')
    words.frombytes(bytes(b))
    if sys.byteorder == 'big': words.byteswap()
    s = sum(words)
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (s + len(data)) & 0xFFFFFFFF


class TextTable:
    def __init__(self, exe, lens_off, starts_off, n):
        self.exe, self.lens_off, self.starts_off, self.n = exe, lens_off, starts_off, n
        self.base_va = exe.off2va(starts_off)
        self.lang = None

    def text(self, i):
        d = self.exe.data
        rel = struct.unpack_from('<i', d, self.starts_off + 4 * i)[0]
        ln = struct.unpack_from('<Q', d, self.lens_off + 8 * i)[0]
        off = self.exe.va2off(self.base_va + rel)
        return d[off:off + ln].decode('utf-8', errors='replace')

    def all_texts(self): return [self.text(i) for i in range(self.n)]


def find_text_tables(exe):
    d = exe.data
    anchors = set()
    for m in re.finditer(re.escape(ERROR_MARK), d):
        va = exe.off2va(m.start())
        if va: anchors.add(va)
    if not anchors: raise PatchError('не найден якорь текстовых таблиц')
    hits = []
    for lo, hi in exe.data_ranges():
        lo4 = lo + (-lo % 4)
        n = (hi - lo4) // 4
        arr = array.array('i')
        arr.frombytes(d[lo4:lo4 + n * 4])
        if sys.byteorder == 'big': arr.byteswap()
        va0 = exe.off2va(lo4)
        for k in range(n):
            if (va0 + 4 * k + arr[k]) in anchors: hits.append(lo4 + 4 * k)
    hits.sort()
    n = (hits[1] - hits[0] - 4) // 12
    tables = [TextTable(exe, h - 8 * n, h, n) for h in hits]
    for t in tables:
        s4 = t.text(4)
        for code, marker in LANG_MARKERS:
            if marker in s4:
                t.lang = code
                break
    langs = [t.lang for t in tables]
    if 'EN' not in langs and langs.count(None) == 1:
        tables[langs.index(None)].lang = 'EN'
    return dict((t.lang or ('L%d' % i), t) for i, t in enumerate(tables))


def game_strings(tables):
    out = list(LANG_LABELS)
    for t in tables.values(): out.extend(t.all_texts())
    return out


def sfnt_parse(b):
    if len(b) < 12 or b[:4] not in SFNT_TAGS: raise PatchError('не sfnt-шрифт')
    nt = struct.unpack_from('>H', b, 4)[0]
    tables, end = {}, 12 + 16 * nt
    for i in range(nt):
        tag, _cs, to, tl = struct.unpack_from('>4sIII', b, 12 + 16 * i)
        tables[tag] = (to, tl)
        end = max(end, to + tl)
    return tables, (end + 3) & ~3


def cmap_parse(b):
    chars = set()
    try:
        tabs, _ = sfnt_parse(b)
        if b'cmap' not in tabs: return chars
        off = tabs[b'cmap'][0]
        n = struct.unpack_from('>H', b, off + 2)[0]
        seen = set()
        for i in range(n):
            pid, eid, so = struct.unpack_from('>HHI', b, off + 4 + 8 * i)
            if not (pid == 0 or (pid == 3 and eid in (1, 10))) or so in seen: continue
            seen.add(so)
            st = off + so
            fmt = struct.unpack_from('>H', b, st)[0]
            if fmt == 4:
                sx2 = struct.unpack_from('>H', b, st + 6)[0]; seg = sx2 // 2
                ends = struct.unpack_from('>%dH' % seg, b, st + 14)
                starts = struct.unpack_from('>%dH' % seg, b, st + 16 + sx2)
                deltas = struct.unpack_from('>%dh' % seg, b, st + 16 + 2 * sx2)
                ros = struct.unpack_from('>%dH' % seg, b, st + 16 + 3 * sx2)
                for k in range(seg):
                    for c in range(starts[k], ends[k] + 1):
                        if c == 0xFFFF: continue
                        if ros[k] == 0:
                            gid = (c + deltas[k]) & 0xFFFF
                        else:
                            p = st + 16 + 3 * sx2 + 2 * k + ros[k] + 2 * (c - starts[k])
                            if p + 2 > len(b): continue
                            gid = struct.unpack_from('>H', b, p)[0]
                            if gid: gid = (gid + deltas[k]) & 0xFFFF
                        if gid: chars.add(c)
            elif fmt == 12:
                ng = struct.unpack_from('>I', b, st + 12)[0]
                for k in range(ng):
                    sc, ec, sg = struct.unpack_from('>III', b, st + 16 + 12 * k)
                    if ec - sc > 0x20000: continue
                    for c in range(sc, ec + 1):
                        if sg + (c - sc): chars.add(c)
            elif fmt == 6:
                first, cnt = struct.unpack_from('>HH', b, st + 6)
                gids = struct.unpack_from('>%dH' % cnt, b, st + 10)
                chars.update(first + k for k, gid in enumerate(gids) if gid)
            elif fmt == 0:
                chars.update(k for k, gid in enumerate(b[st + 6:st + 262]) if gid)
    except Exception:
        pass
    return chars


def blank_strings(strings, old_cmap, new_cmap):
    res = []
    for s in strings:
        vis = [ord(c) for c in s if not c.isspace()]
        if any(c in old_cmap for c in vis) and not any(c in new_cmap for c in vis):
            res.append(s)
    return res


def _has_cjk(cm):
    return any(0x2E80 <= c <= 0x9FFF or 0xAC00 <= c <= 0xD7AF or 0xFF00 <= c <= 0xFFEF for c in cm)


def pixel_grid(font):
    import math
    try:
        glyf, upem = font['glyf'], font['head'].unitsPerEm
        gcds, mins = [], []
        for n in font.getGlyphOrder():
            gl = glyf[n]
            if gl.isComposite() or gl.numberOfContours <= 0: continue
            coords, start, edges = gl.coordinates, 0, []
            for e in gl.endPtsOfContours:
                pts = coords[start:e + 1]; start = e + 1
                for k in range(len(pts)):
                    (x1, y1), (x2, y2) = pts[k], pts[(k + 1) % len(pts)]
                    if y1 == y2 and x1 != x2: edges.append(abs(x2 - x1))
                    elif x1 == x2 and y1 != y2: edges.append(abs(y2 - y1))
            if edges:
                g = 0
                for v in edges: g = math.gcd(g, v)
                gcds.append(g); mins.append(min(edges))
        if len(mins) < 10: return None

        def mode(vals, tol):
            top, top_n = None, 0
            for v in sorted(set(vals)):
                n = sum(1 for m in vals if v * (1 - tol) <= m <= v * (1 + tol))
                if n > top_n: top, top_n = v, n
            return top, top_n

        unit = None
        v, n = mode(gcds, 0)
        if v and v >= upem / 64.0 and n >= 0.4 * len(gcds): unit = float(v)
        if unit is None:
            v, n = mode(mins, 0.03)
            if v and n >= 0.4 * len(mins):
                unit = sum(m for m in mins if v * 0.97 <= m <= v * 1.03) / float(n)
        if unit is None or unit < upem / 64.0: return None
        return unit, upem / unit
    except Exception:
        return None


def fit_grid(new, old):
    from fontTools.ttLib.scaleUpem import scale_upem
    go, gn = pixel_grid(old), pixel_grid(new)
    if not go or not gn: return None
    old_upem, new_upem = old['head'].unitsPerEm, new['head'].unitsPerEm
    ratio = (go[0] / old_upem) / (gn[0] / new_upem)
    if abs(ratio - 1) < 0.02: return 1.0
    scale_upem(new, max(1, round(new_upem * ratio)))
    new['head'].unitsPerEm = new_upem
    return ratio


def avg_advance_px(font, unit):
    try:
        cm, hm = font.getBestCmap(), font['hmtx']
        v = [hm[cm[c]][0] for c in range(0x61, 0x7B) if c in cm]
        return (sum(v) / float(len(v))) / unit if v else None
    except Exception:
        return None


def tighten_font(font, delta):
    if delta <= 0: return
    glyf, hm = font['glyf'], font['hmtx']
    for name in font.getGlyphOrder():
        adv, lsb = hm.metrics[name]
        if adv <= 0: continue
        floor = delta
        try:
            gl = glyf[name]
            if gl.numberOfContours != 0:
                gl.recalcBounds(glyf)
                floor = max(gl.xMax, 1)
        except Exception:
            pass
        hm.metrics[name] = (max(adv - delta, min(adv, floor)), lsb)


def scale_glyphs(font, k):
    from fontTools.ttLib.scaleUpem import scale_upem
    upem = font['head'].unitsPerEm
    scale_upem(font, max(1, int(round(upem * k))))
    font['head'].unitsPerEm = upem


def merge_fonts(old_blob, new_blob, scale=None):
    try:
        from fontTools.ttLib import TTFont
        from fontTools.ttLib.scaleUpem import scale_upem
        from fontTools.merge import Merger, Options
    except ImportError:
        raise PatchError('нужен fontTools: pip install fonttools')
    import tempfile, logging
    logging.getLogger('fontTools').setLevel(logging.CRITICAL)
    old, new = TTFont(io.BytesIO(old_blob)), TTFont(io.BytesIO(new_blob))
    if 'glyf' not in old or 'glyf' not in new:
        raise PatchError('объединение только для TrueType (glyf)')
    if _has_cjk(set(old.getBestCmap())):
        base, extra = old, new
    else:
        base, extra = new, old
    fit_grid(new, old)
    if scale and abs(float(scale) - 1) > 1e-3:
        scale_glyphs(new, float(scale))
    gn, go = pixel_grid(new), pixel_grid(old)
    if gn:
        a_old = avg_advance_px(old, go[0]) if go else None
        a_new = avg_advance_px(new, gn[0])
        n = max(0, int(round(a_new - a_old))) if (a_old and a_new) else 0
        tighten_font(new, int(round(n * gn[0])))
    upem = base['head'].unitsPerEm
    if extra['head'].unitsPerEm != upem:
        scale_upem(extra, upem)
    for f in (base, extra):
        for t in _DROP_TABLES:
            if t in f: del f[t]
        glyf = f['glyf']
        for name in f.getGlyphOrder():
            try: glyf[name].removeHinting()
            except Exception: pass
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for i, f in enumerate((base, extra)):
            pth = os.path.join(tmp, 'f%d.ttf' % i)
            f.save(pth)
            paths.append(pth)
        merged = Merger(options=Options(drop_tables=list(_DROP_TABLES))).merge(paths)
        out = io.BytesIO()
        merged.save(out)
        blob = out.getvalue()
    sfnt_parse(blob)
    if not cmap_parse(blob): raise PatchError('шрифт без cmap')
    return blob


def prepare_font(exe, tables, a, new_blob, stem):
    old_blob = a.bytes(exe)
    try:
        new_blob = merge_fonts(old_blob, new_blob, SCALE.get(stem))
    except Exception:
        pass
    if blank_strings(game_strings(tables), cmap_parse(old_blob), cmap_parse(new_blob)):
        return None
    return new_blob


def png_ok(b):
    if b[:8] != PNG_SIG: return False
    pos = 8
    while pos + 12 <= len(b):
        ln = struct.unpack_from('>I', b, pos)[0]
        if pos + 12 + ln > len(b): return False
        typ, data = b[pos + 4:pos + 8], b[pos + 8:pos + 8 + ln]
        if zlib.crc32(typ + data) & 0xFFFFFFFF != struct.unpack_from('>I', b, pos + 8 + ln)[0]:
            return False
        if typ == b'IEND': return True
        pos += 12 + ln
    return False


class Asset:
    def __init__(self, kind, off, length, va):
        self.kind, self.off, self.length, self.va = kind, off, length, va
        self.sites = []

    def bytes(self, exe): return exe.data[self.off:self.off + self.length]


def _find_len_imm(d, lea_off, length):
    win = d[lea_off + 7:lea_off + 7 + 48]
    for m in re.finditer(rb'\x41?[\xb8-\xbf]', win, re.S):
        p = m.end()
        if p + 4 <= len(win) and struct.unpack_from('<I', win, p)[0] == length:
            return lea_off + 7 + p
    return None


def find_assets(exe):
    d = exe.data
    cands = []
    for lo, hi in exe.data_ranges():
        blob = d[lo:hi]
        for m in re.finditer(rb'(?=\x00\x01\x00\x00|OTTO|true)', blob):
            off = lo + m.start()
            try:
                _t, ln = sfnt_parse(d[off:off + 4 * 1024 * 1024])
                if off + ln > len(d): continue
                tabs = sfnt_parse(d[off:off + ln])[0]
                if b'head' in tabs or b'CFF ' in tabs:
                    cands.append(Asset('font', off, ln, exe.off2va(off)))
            except Exception:
                continue
        for m in re.finditer(re.escape(PNG_SIG), blob):
            off = lo + m.start()
            if d[off + 12:off + 16] != b'IHDR': continue
            e = d.find(b'IEND', off)
            if e < 0: continue
            cands.append(Asset('png', off, e + 8 - off, exe.off2va(off)))
    leas = exe.lea_targets()
    res = []
    for a in cands:
        if a.va is None or a.va not in leas: continue
        for lea in leas[a.va]:
            imm = _find_len_imm(d, lea, a.length)
            if imm: a.sites.append((lea, imm))
        if a.sites: res.append(a)
    return res


def build(exe, en, plan_text, plan_assets, assets):
    d = bytearray(exe.data)
    sec = bytearray()

    def add(blob, align):
        while len(sec) % align: sec.append(0)
        off = len(sec)
        sec.extend(blob)
        return off

    placed_assets = {off: add(blob, 16) for off, blob in sorted(plan_assets.items())}
    placed_text = {i: add(s.encode('utf-8'), 1) for i, s in sorted(plan_text.items())}
    hdr_pos = exe.sect_tab + 40 * exe.nsec
    new_rva = align_up(max(s.va + s.vsize for s in exe.sections), exe.sec_align)
    raw_ptr = align_up(len(d), exe.file_align)
    raw_size = align_up(len(sec), exe.file_align)
    new_va = exe.image_base + new_rva
    d.extend(bytes(raw_ptr - len(d)))
    d.extend(sec)
    d.extend(bytes(raw_size - len(sec)))
    d[hdr_pos:hdr_pos + 40] = NEW_SECTION_NAME + struct.pack('<IIIIIIHHI',
        len(sec), new_rva, raw_size, raw_ptr, 0, 0, 0, 0, 0x40000040)
    struct.pack_into('<H', d, exe.coff + 2, exe.nsec + 1)
    soi = struct.unpack_from('<I', d, exe.opt + 8)[0]
    struct.pack_into('<I', d, exe.opt + 8, soi + raw_size)
    struct.pack_into('<I', d, exe.opt + 56, align_up(new_rva + len(sec), exe.sec_align))
    for i, off in placed_text.items():
        rel = (new_va + off) - en.base_va
        struct.pack_into('<i', d, en.starts_off + 4 * i, rel)
        struct.pack_into('<Q', d, en.lens_off + 8 * i, len(plan_text[i].encode('utf-8')))
    for off, newoff in placed_assets.items():
        a, blob = assets[off], plan_assets[off]
        for lea, imm in a.sites:
            disp = (new_va + newoff) - (exe.off2va(lea) + 7)
            struct.pack_into('<i', d, lea + 3, disp)
            struct.pack_into('<I', d, imm, len(blob))
    if exe.checksum:
        struct.pack_into('<I', d, exe.opt + 64, pe_checksum(bytes(d), exe.opt + 64))
    return bytes(d)


def main():
    exe = Exe(open(EXE, 'rb').read())
    tables = find_text_tables(exe)
    en = tables['EN']
    orig_texts = en.all_texts()
    with open(os.path.join(WORKDIR, 'texts.json'), encoding='utf-8') as f:
        texts_data = json.load(f)
    plan_text = {}
    for i, item in enumerate(texts_data):
        if i >= len(orig_texts): break
        ru = item.get('ru', '')
        if ru and ru != orig_texts[i]: plan_text[i] = ru
    with open(os.path.join(WORKDIR, 'manifest.json'), encoding='utf-8') as f:
        man = json.load(f)
    assets = dict((a.off, a) for a in find_assets(exe))
    plan_assets = {}
    for m in man['assets']:
        a = assets.get(m['offset'])
        if not a or not a.sites: continue
        p = os.path.join(WORKDIR, m['file'])
        if not os.path.exists(p): continue
        blob = open(p, 'rb').read()
        if not blob or blob == a.bytes(exe): continue
        try:
            if a.kind == 'png':
                if not png_ok(blob): continue
            else:
                sfnt_parse(blob)
        except PatchError:
            continue
        if a.kind == 'font':
            blob = prepare_font(exe, tables, a, blob,
                                os.path.splitext(os.path.basename(m['file']))[0])
            if blob is None: continue
        plan_assets[a.off] = blob
    if not plan_text and not plan_assets: return
    base, ext = os.path.splitext(EXE)
    with open(base + '_patched' + ext, 'wb') as f:
        f.write(build(exe, en, plan_text, plan_assets, assets))


if __name__ == '__main__':
    main()