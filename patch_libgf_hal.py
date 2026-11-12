#!/usr/bin/env python3
"""
Patcher libgf_hal.so (Goodix FOD, Transsion MTK, arm64) untuk ROM custom/port.

Tiga patch (semua dicari lewat simbol ELF + pola instruksi, bukan offset mati):
  1. goodix::tran_uevent_handle(const char*, int)
       -> usleep(DELAY_US); return 1;   (tidak lagi menunggu uevent netlink kernel)
  2. goodix::CustomizedFingerprintCore::gfHbmEventDetectingThread(void*)
       -> NOP gate  `ldr w,[x,#0x1b4]; cmp w,#1; b.ne`  (uiReadyStatus)
  3. goodix::Device::enable()
       -> `cbz w0,ok` setelah ioctl GF_IOC_INIT menjadi `b ok`

Keamanan: setiap patch memverifikasi instruksi asli sebelum menulis. Jika ada
yang tidak cocok, tidak ada yang ditulis sama sekali. Aman dijalankan ulang
(idempotent) dan bisa dipakai untuk mengganti nilai --delay-us.

Pemakaian:
  python3 patch_libgf_hal.py libgf_hal.so                 # jeda 30 ms (default, = skrip lama)
  python3 patch_libgf_hal.py libgf_hal.so --delay-us 8000 # lebih cepat
  python3 patch_libgf_hal.py libgf_hal.so --check         # dry-run, tidak menulis
  python3 patch_libgf_hal.py libgf_hal.so -o out.so --strict
"""
import argparse
import hashlib
import struct
import sys

SYM_UEVENT = "_ZN6goodix18tran_uevent_handleEPKci"
SYM_HBM_THREAD = "_ZN6goodix25CustomizedFingerprintCore25gfHbmEventDetectingThreadEPv"
SYM_ENABLE = "_ZN6goodix6Device6enableEv"
UI_READY_OFF = 0x1B4
NOP = 0xD503201F

# build yang sudah diuji manual
KNOWN_BUILDS = {
    "789c228681e5f5c66bcf84bde58591f6e45ec2c4afbea8944dcd48b6eecf74af": "libgf_hal.so (Transsion KJ7 build yang dianalisis)",
}


class PatchError(Exception):
    pass


# ---------------------------------------------------------------- ELF helpers
class Elf:
    def __init__(self, data: bytearray):
        self.d = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[18:20] != struct.pack("<H", 183):
            raise PatchError("bukan ELF64 AArch64")
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        phoff, = struct.unpack_from("<Q", data, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
        self.secs = []
        for i in range(shnum):
            (name, typ, flags, addr, off, size, link, info, align, entsize) = struct.unpack_from(
                "<IIQQQQIIQQ", data, shoff + i * shentsize)
            self.secs.append(dict(name=name, type=typ, addr=addr, off=off, size=size, link=link, entsize=entsize))
        shstr = self.secs[shstrndx]
        for s in self.secs:
            s["sname"] = self._cstr(shstr["off"] + s["name"])
        self.loads = []
        for i in range(phnum):
            p_type, _fl, p_off, p_va, _pa, p_fsz, _msz, _al = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
            if p_type == 1:
                self.loads.append((p_va, p_off, p_fsz))
        self.syms = self._dynsyms()

    def _cstr(self, off):
        end = self.d.index(b"\0", off)
        return self.d[off:end].decode("latin1")

    def sec(self, name):
        for s in self.secs:
            if s["sname"] == name:
                return s
        raise PatchError(f"section {name} tidak ada")

    def _dynsyms(self):
        ds = self.sec(".dynsym")
        strtab = self.secs[ds["link"]]
        out = {}
        for i in range(ds["size"] // 24):
            name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.d, ds["off"] + i * 24)
            if shndx == 0 or not value:
                continue
            out[self._cstr(strtab["off"] + name)] = (value, size)
        return out

    def va2off(self, va):
        for p_va, p_off, p_fsz in self.loads:
            if p_va <= va < p_va + p_fsz:
                return va - p_va + p_off
        raise PatchError(f"vma 0x{va:x} tidak dipetakan")

    def u32(self, va):
        return struct.unpack_from("<I", self.d, self.va2off(va))[0]

    def put32(self, va, val):
        struct.pack_into("<I", self.d, self.va2off(va), val)

    def symbol(self, name):
        if name not in self.syms:
            raise PatchError(f"simbol {name} tidak ditemukan")
        return self.syms[name]

    def plt_stub(self, func):
        """alamat stub PLT untuk fungsi impor `func` (lewat .rela.plt + decode adrp/ldr)."""
        ds = self.sec(".dynsym")
        strtab = self.secs[ds["link"]]
        rp = self.sec(".rela.plt")
        got = None
        for i in range(rp["size"] // 24):
            r_off, r_info, _ = struct.unpack_from("<QQq", self.d, rp["off"] + i * 24)
            si = r_info >> 32
            name, *_ = struct.unpack_from("<IBBHQQ", self.d, ds["off"] + si * 24)
            if self._cstr(strtab["off"] + name) == func:
                got = r_off
                break
        if got is None:
            raise PatchError(f"relokasi PLT untuk {func} tidak ada")
        plt = self.sec(".plt")
        for va in range(plt["addr"], plt["addr"] + plt["size"] - 8, 4):
            w0, w1 = self.u32(va), self.u32(va + 4)
            if (w0 & 0x9F00001F) == 0x90000010 and (w1 & 0xFFC003FF) == 0xF9400211:
                immlo, immhi = (w0 >> 29) & 3, (w0 >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= 1 << 21
                page = (va & ~0xFFF) + (imm << 12)
                if page + ((w1 >> 10) & 0xFFF) * 8 == got:
                    return va
        raise PatchError(f"stub PLT {func} tidak ditemukan")


def enc_bl(src, dst):
    off = (dst - src) >> 2
    if not -(1 << 25) <= off < (1 << 25):
        raise PatchError("target BL di luar jangkauan")
    return 0x94000000 | (off & 0x3FFFFFF)


def enc_movw(rd, imm16):
    return 0x52800000 | (imm16 << 5) | rd


def is_bl_to(w, pc, target):
    return (w & 0xFC000000) == 0x94000000 and enc_bl(pc, target) == w


# -------------------------------------------------------------- patch planners
# setiap planner mengembalikan (deskripsi, [(va, nilai_baru), ...]) atau
# (deskripsi, []) jika sudah ter-patch dengan nilai yang sama.

def plan_uevent(elf, delay_us):
    va, size = elf.symbol(SYM_UEVENT)
    if size < 24:
        raise PatchError("tran_uevent_handle terlalu pendek (<24 byte)")
    usleep = elf.plt_stub("usleep")
    new = [0xA9BF7BFD, enc_movw(0, delay_us), enc_bl(va + 8, usleep),
           enc_movw(0, 1), 0xA8C17BFD, 0xD65F03C0]
    cur = [elf.u32(va + 4 * i) for i in range(6)]
    already = cur[0] == new[0] and (cur[1] & 0xFFE0001F) == 0x52800000 \
        and is_bl_to(cur[2], va + 8, usleep) and cur[3:] == new[3:]
    if not already and (cur[0] & 0xFFC07FFF) != 0xA9807BFD:
        raise PatchError(f"prolog tran_uevent_handle tak dikenal: {cur[0]:08x}")
    desc = f"tran_uevent_handle @0x{va:x}: usleep({delay_us}) + return 1 (usleep@plt=0x{usleep:x})"
    return desc, [(va + 4 * i, w) for i, w in enumerate(new) if cur[i] != w]


def plan_uiready(elf):
    va, size = elf.symbol(SYM_HBM_THREAD)
    hits = []
    for pc in range(va, va + size - 8, 4):
        a, b, c = elf.u32(pc), elf.u32(pc + 4), elf.u32(pc + 8)
        if (a & 0xFFC00000) == 0xB9400000 and ((a >> 10) & 0xFFF) * 4 == UI_READY_OFF \
                and (b & 0xFFFFFC1F) == 0x7100041F and ((b >> 5) & 0x1F) == (a & 0x1F) \
                and (c & 0xFF00001F) == 0x54000001:
            hits.append(pc)
    if len(hits) == 1:
        pc = hits[0]
        return f"gate uiReadyStatus @0x{pc:x}: ldr/cmp/b.ne -> 3x NOP", [(pc, NOP), (pc + 4, NOP), (pc + 8, NOP)]
    if len(hits) > 1:
        raise PatchError("pola gate uiReady ambigu (>1 kecocokan)")
    for pc in range(va, va + size - 8, 4):
        if elf.u32(pc) == elf.u32(pc + 4) == elf.u32(pc + 8) == NOP:
            return f"gate uiReadyStatus @0x{pc:x}: sudah ter-patch", []
    raise PatchError("gate uiReadyStatus tidak ditemukan di gfHbmEventDetectingThread")


def plan_init(elf):
    va, size = elf.symbol(SYM_ENABLE)
    ioctl = elf.plt_stub("ioctl")
    for pc in range(va, va + size - 4, 4):
        if not is_bl_to(elf.u32(pc), pc, ioctl):
            continue
        nxt = elf.u32(pc + 4)
        if (nxt & 0xFF00001F) == 0x34000000:  # cbz w0, target
            imm = (nxt >> 5) & 0x7FFFF
            if imm & (1 << 18):
                imm -= 1 << 19
            tgt = pc + 4 + imm * 4
            # sanity: ioctl request harus 0x8001xxxx (movk w1,#0x8001,lsl16) tepat sebelum bl
            warn = ""
            if not any((elf.u32(p) & 0xFFFFFFE1) == 0x72B00021 for p in range(pc - 24, pc, 4)):
                warn = " (PERINGATAN: konstanta ioctl 0x8001xxxx tidak terlihat)"
            new = 0x14000000 | (((tgt - (pc + 4)) >> 2) & 0x3FFFFFF)
            return f"Device::enable ioctl init @0x{pc + 4:x}: cbz w0 -> b 0x{tgt:x}{warn}", [(pc + 4, new)]
        if (nxt & 0xFC000000) == 0x14000000:
            return f"Device::enable ioctl init @0x{pc + 4:x}: sudah ter-patch", []
    raise PatchError("bl ioctl + cbz w0 tidak ditemukan di Device::enable")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("lib")
    ap.add_argument("-o", "--output", help="default: <lib>.patched")
    ap.add_argument("--delay-us", type=int, default=30000,
                    help="jeda pengganti uevent (mikrodetik, 1..65535). default 30000 = perilaku skrip lama. "
                         "Lebih kecil = deteksi FOD lebih cepat tetapi loop lebih sering berputar.")
    ap.add_argument("--check", action="store_true", help="dry-run: hanya verifikasi dan tampilkan rencana")
    ap.add_argument("--strict", action="store_true", help="tolak build yang hash-nya belum dikenal")
    a = ap.parse_args()

    if not 1 <= a.delay_us <= 0xFFFF:
        sys.exit("--delay-us harus 1..65535")
    raw = open(a.lib, "rb").read()
    sha = hashlib.sha256(raw).hexdigest()
    if sha in KNOWN_BUILDS:
        print(f"[ok] build dikenal: {KNOWN_BUILDS[sha]}")
    else:
        msg = f"build belum dikenal (sha256 {sha})"
        if a.strict:
            sys.exit("[tolak] " + msg)
        print("[peringatan] " + msg + "; lanjut karena pola instruksi diverifikasi satu per satu")

    data = bytearray(raw)
    try:
        elf = Elf(data)
        plans = [plan_uevent(elf, a.delay_us), plan_uiready(elf), plan_init(elf)]
    except (PatchError, struct.error, ValueError, IndexError) as e:
        sys.exit(f"[gagal] {e}\nTidak ada file yang ditulis.")

    changed = 0
    for desc, writes in plans:
        print(("[patch] " if writes else "[skip ] ") + desc)
        for va, val in writes:
            elf.put32(va, val)
            changed += 1
    if a.check:
        print(f"[check] {changed} instruksi akan diubah; tidak menulis file.")
        return
    out = a.output or a.lib + ".patched"
    open(out, "wb").write(data)
    print(f"[selesai] {changed} instruksi diubah -> {out}")
    print(f"          sha256 hasil: {hashlib.sha256(bytes(data)).hexdigest()}")


if __name__ == "__main__":
    main()
