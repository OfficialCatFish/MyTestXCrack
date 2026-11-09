from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_32
except ImportError:  # pragma: no cover - handled in main()
    Ks = None


"""Generic MyTestX 10.x test-EXE patcher (PE32/x86).

The patcher is signature-based.  It does not rely on one fixed set of
addresses, so it can process other self-contained test EXEs produced by the
same MyTestX engine family.

What it changes
---------------
1. Every ordinary answer-evaluation branch in the answer dispatcher is forced
   to the "correct" result flag.  The dedicated dl==0 skip branch keeps its
   original flag.
2. The test finalizer is hooked.  Before the original completion-threshold
   check runs, the hook walks the per-question result records and:
     * marks a record with a non-empty answer as correct (state 4);
     * marks a record without an answer as wrong (state 3);
     * normalizes total/completed/correct/wrong/skipped counters;
     * recomputes the earned-points double from the records and zeroes the
       points of unanswered records.
   This removes skipped questions from the report and prevents the finalizer
   from resetting records when the test was finished early.
3. The two finish-handler calls to the answer dispatcher with DL=0 are NOPed,
   so they cannot erase the current question's answer string or increment the
   skipped counter right before the finalizer runs.

The patch refuses to modify a file when an expected signature is missing or
ambiguous.  The source file is never overwritten.
"""

MACHINE_I386 = 0x014C
PE32_MAGIC = 0x010B

# Answer dispatcher and result flags.
EVAL_START = bytes.fromhex("55 8B EC B9 41 00 00 00 6A 00 6A 00")
EVAL_NEXT_SEARCH = 0x8000
FAIL_FLAG = bytes.fromhex("C6 45 B7 00")
TRUE_FLAG = bytes.fromhex("C6 45 B7 01")
SKIP_HEAD = bytes.fromhex("C6 45 B7 00 8D 45 F8 E8")
EXPECTED_FLAG_WRITES = 11
EXPECTED_FLAG_PATCHES = 10

# Finalizer discovery.
FINALIZER_PROLOGUE = bytes.fromhex("55 8B EC B9 06 00 00 00")
FINALIZER_COMPLETION = bytes.fromhex(
    "6B 46 64 64 89 45 D8 DB 45 D8 DB 46 60 DE F9"
)
FINALIZER_SEARCH_BACK = 0x300

# Helper functions used by the injected stub (located dynamically).
GET_RECORD_PATTERN = bytes.fromhex(
    "53 56 57 8B F2 8B D8 8B 7B 04 8B 47 08 85 C0"
)
GET_RECORD_COUNT_PATTERN = bytes.fromhex("8B 40 04 8B 40 08 C3")
HELPER_MAX_DISTANCE = 0x800

# Finish handlers call the dispatcher with DL=0 in this pattern:
#   xor edx, edx
#   mov eax, ebx
#   call answer_dispatcher
DL0_PREFIX = bytes.fromhex("33 D2 8B C3")
FINALIZER_LOOKAHEAD = 0x60
EXPECTED_FINISH_CALLS = 2

# Offsets inside the statistics object at [test + 0xB94].
STATS_TOTAL = 0x60
STATS_COMPLETED = 0x64
STATS_CORRECT = 0x68
STATS_WRONG = 0x6C
STATS_SKIPPED = 0x70
STATS_EARNED = 0x80

# Offsets inside one per-question result record.
REC_STATE = 0x04
REC_POINTS = 0x18
REC_ANSWER = 0x20

NOP5 = b"\x90" * 5

# The full stub is byte-for-byte the variant that was verified at runtime.
STUB_TEMPLATE_FULL = """
    pushfd
    pushad
    sub esp, 24
    mov dword ptr [esp], 0
    mov dword ptr [esp + 4], 0
    mov dword ptr [esp + 8], 0
    mov dword ptr [esp + 12], 0
    mov esi, dword ptr [eax + 0xB94]
    test esi, esi
    jz done
    mov eax, esi
    call {get_count}
    mov ebx, eax
    test ebx, ebx
    jle counters
    xor edi, edi
loop_start:
    cmp edi, ebx
    jge counters
    mov eax, esi
    mov edx, edi
    call {get_record}
    test eax, eax
    jz next
    mov edx, dword ptr [eax + 0x20]
    test edx, edx
    jz unanswered
    cmp dword ptr [edx - 4], 0
    je unanswered
    mov dword ptr [eax + 4], 4
    inc dword ptr [esp]
    fld qword ptr [eax + 0x18]
    fadd qword ptr [esp + 8]
    fstp qword ptr [esp + 8]
    jmp next
unanswered:
    mov dword ptr [eax + 4], 3
    inc dword ptr [esp + 4]
    mov dword ptr [eax + 0x18], 0
    mov dword ptr [eax + 0x1C], 0
next:
    inc edi
    jmp loop_start
counters:
    mov eax, dword ptr [esi + 0x60]
    mov dword ptr [esi + 0x64], eax
    mov ecx, dword ptr [esp]
    mov dword ptr [esi + 0x68], ecx
    mov edx, eax
    sub edx, ecx
    jns store_wrong
    xor edx, edx
store_wrong:
    mov dword ptr [esi + 0x6C], edx
    mov dword ptr [esi + 0x70], 0
    fld qword ptr [esp + 8]
    fstp qword ptr [esi + 0x80]
done:
    add esp, 24
    popad
    popfd
    push ebp
    mov ebp, esp
    mov ecx, 6
    jmp {resume}
"""

# Smaller equivalent stub, used only if the full variant does not fit into a
# zero-filled code cave.  It drops the unused wrong-answer local counter.
STUB_TEMPLATE_COMPACT = """
    pushfd
    pushad
    push 0
    push 0
    push 0
    mov ebp, dword ptr [eax + 0xB94]
    test ebp, ebp
    jz done
    mov eax, ebp
    call {get_count}
    mov ebx, eax
    test ebx, ebx
    jle counters
    xor edi, edi
loop_start:
    cmp edi, ebx
    jge counters
    mov eax, ebp
    mov edx, edi
    call {get_record}
    test eax, eax
    jz next
    mov edx, dword ptr [eax + 0x20]
    test edx, edx
    jz unanswered
    cmp dword ptr [edx - 4], 0
    je unanswered
    mov dword ptr [eax + 4], 4
    inc dword ptr [esp]
    fld qword ptr [eax + 0x18]
    fadd qword ptr [esp + 4]
    fstp qword ptr [esp + 4]
    jmp next
unanswered:
    mov dword ptr [eax + 4], 3
    xor edx, edx
    mov dword ptr [eax + 0x18], edx
    mov dword ptr [eax + 0x1C], edx
next:
    inc edi
    jmp loop_start
counters:
    mov eax, dword ptr [ebp + 0x60]
    mov dword ptr [ebp + 0x64], eax
    mov ecx, dword ptr [esp]
    mov dword ptr [ebp + 0x68], ecx
    mov edx, eax
    sub edx, ecx
    jns store_wrong
    xor edx, edx
store_wrong:
    mov dword ptr [ebp + 0x6C], edx
    mov dword ptr [ebp + 0x70], 0
    fld qword ptr [esp + 4]
    fstp qword ptr [ebp + 0x80]
done:
    add esp, 12
    popad
    popfd
    push ebp
    mov ebp, esp
    mov ecx, 6
    jmp {resume}
"""


class AlreadyPatched(Exception):
    pass


class UnsupportedBuild(Exception):
    pass


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError(f"bad alignment: {alignment}")
    return (value + alignment - 1) & ~(alignment - 1)


def parse_pe(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise UnsupportedBuild("not a PE file: MZ signature missing")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
        raise UnsupportedBuild("PE signature missing")

    machine, section_count = struct.unpack_from("<HH", data, pe_off + 4)
    optional_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    if machine != MACHINE_I386:
        raise UnsupportedBuild(f"expected I386, got Machine=0x{machine:04X}")

    opt_off = pe_off + 24
    if optional_size < 96 or opt_off + optional_size > len(data):
        raise UnsupportedBuild("bad Optional Header")
    if struct.unpack_from("<H", data, opt_off)[0] != PE32_MAGIC:
        raise UnsupportedBuild("expected PE32")

    image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
    section_align = struct.unpack_from("<I", data, opt_off + 32)[0]
    checksum_off = opt_off + 64
    section_table = opt_off + optional_size

    sections = []
    for i in range(section_count):
        h = section_table + i * 40
        if h + 40 > len(data):
            raise UnsupportedBuild("section table is outside the file")
        name = data[h:h + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, h + 8
        )
        characteristics = struct.unpack_from("<I", data, h + 36)[0]
        sections.append({
            "name": name,
            "header_off": h,
            "virtual_size": virtual_size,
            "va": virtual_address,
            "raw_size": raw_size,
            "raw_ptr": raw_ptr,
            "characteristics": characteristics,
        })

    return {
        "pe_off": pe_off,
        "opt_off": opt_off,
        "image_base": image_base,
        "section_align": section_align,
        "checksum_off": checksum_off,
        "sections": sections,
    }


def find_text_section(pe: dict) -> dict:
    text = next((s for s in pe["sections"] if s["name"] == ".text"), None)
    if text is None:
        raise UnsupportedBuild(".text section not found")
    if not (text["characteristics"] & 0x20000000):
        raise UnsupportedBuild(".text section is not executable")
    if text["raw_size"] <= 0:
        raise UnsupportedBuild("unexpected .text raw layout")
    return text


def positions_in_range(data: bytes, start: int, end: int, needle: bytes) -> list[int]:
    out = []
    pos = data.find(needle, start, end)
    while pos >= 0:
        out.append(pos)
        pos = data.find(needle, pos + 1, end)
    return out


def require_one_in_text(data: bytes, text: dict, needle: bytes, label: str) -> int:
    start = text["raw_ptr"]
    end = start + text["raw_size"]
    found = positions_in_range(data, start, end, needle)
    if len(found) != 1:
        raise UnsupportedBuild(
            f"signature '{label}' must occur once in .text, found {len(found)}"
        )
    return found[0]


def off_to_va(off: int, text: dict, image_base: int) -> int:
    return image_base + text["va"] + (off - text["raw_ptr"])


def va_to_text_off(va: int, text: dict, image_base: int) -> int:
    off = text["raw_ptr"] + (va - image_base - text["va"])
    if not (text["raw_ptr"] <= off < text["raw_ptr"] + text["raw_size"]):
        raise UnsupportedBuild(f"VA 0x{va:08X} is outside .text raw data")
    return off


def rel32(opcode: int, source_va: int, target_va: int) -> bytes:
    disp = target_va - (source_va + 5)
    if not -(1 << 31) <= disp < (1 << 31):
        raise UnsupportedBuild("rel32 target out of range")
    return bytes([opcode]) + struct.pack("<i", disp)


def pe_checksum(data: bytes, checksum_offset: int) -> int:
    buf = bytearray(data)
    buf[checksum_offset:checksum_offset + 4] = b"\0\0\0\0"
    total = 0
    length = len(buf)
    for i in range(0, length - (length % 2), 2):
        word = buf[i] | (buf[i + 1] << 8)
        total = (total & 0xFFFF) + word + (total >> 16)
        total = (total & 0xFFFF) + (total >> 16)
    if length & 1:
        total += buf[-1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + length
    return total & 0xFFFFFFFF


def find_eval_region(data: bytes, text: dict) -> tuple[int, int]:
    start = require_one_in_text(data, text, EVAL_START, "answer evaluation dispatcher")
    end = data.find(
        b"\x55\x8B\xEC",
        start + len(EVAL_START),
        min(start + EVAL_NEXT_SEARCH, text["raw_ptr"] + text["raw_size"]),
    )
    if end < 0:
        raise UnsupportedBuild("could not find the end of the answer evaluation dispatcher")
    return start, end


def patch_result_flags(data: bytearray, start: int, end: int) -> int:
    region = bytes(data[start:end])
    skip_hits = positions_in_range(region, 0, len(region), SKIP_HEAD)
    if len(skip_hits) != 1:
        raise UnsupportedBuild(
            f"expected one dl==0 skip branch, found {len(skip_hits)}"
        )
    skip_rel = skip_hits[0]
    flag_sites = positions_in_range(region, 0, len(region), FAIL_FLAG)
    if len(flag_sites) != EXPECTED_FLAG_WRITES:
        raise UnsupportedBuild(
            f"expected {EXPECTED_FLAG_WRITES} result-flag writes, found {len(flag_sites)}"
        )
    if skip_rel not in flag_sites:
        raise UnsupportedBuild("the skip branch is not among the result-flag writes")

    changed = 0
    for pos in flag_sites:
        if pos == skip_rel:
            continue
        data[start + pos:start + pos + len(FAIL_FLAG)] = TRUE_FLAG
        changed += 1
    if changed != EXPECTED_FLAG_PATCHES:
        raise AssertionError("unexpected number of patched result flags")

    remaining = bytes(data[start:end]).count(FAIL_FLAG)
    if remaining != 1:
        raise UnsupportedBuild(
            f"post-check: {remaining} result-flag writes remain instead of 1"
        )
    if bytes(data[start:end]).find(FAIL_FLAG) != skip_rel:
        raise UnsupportedBuild("post-check: the remaining flag is not the skip branch")
    return changed


def find_finalizer(data: bytes, text: dict, image_base: int) -> tuple[int, int]:
    """Return (finalizer file offset, resume VA)."""
    completion_off = require_one_in_text(
        data, text, FINALIZER_COMPLETION, "finalizer completion check"
    )
    lower = max(text["raw_ptr"], completion_off - FINALIZER_SEARCH_BACK)
    for off in range(completion_off, lower - 1, -1):
        if data[off:off + len(FINALIZER_PROLOGUE)] == FINALIZER_PROLOGUE:
            finalizer_va = off_to_va(off, text, image_base)
            resume_va = finalizer_va + len(FINALIZER_PROLOGUE)
            return off, resume_va
    raise UnsupportedBuild(
        "finalizer prologue not found before the completion check "
        "(file is already patched or comes from a different build)"
    )


def find_helpers(data: bytes, text: dict, image_base: int) -> tuple[int, int]:
    """Return (get_record_count VA, get_record VA)."""
    start = text["raw_ptr"]
    end = start + text["raw_size"]

    get_hits = positions_in_range(data, start, end, GET_RECORD_PATTERN)
    if len(get_hits) != 1:
        raise UnsupportedBuild(
            f"get-record helper signature must occur once, found {len(get_hits)}"
        )
    get_off = get_hits[0]

    count_hits = [
        p for p in positions_in_range(data, start, end, GET_RECORD_COUNT_PATTERN)
        if p < get_off
    ]
    if not count_hits:
        raise UnsupportedBuild("get-record-count helper signature not found")
    count_off = max(count_hits)
    if get_off - count_off > HELPER_MAX_DISTANCE:
        raise UnsupportedBuild(
            "get-record-count helper is too far from the get-record helper"
        )

    count_va = off_to_va(count_off, text, image_base)
    get_va = off_to_va(get_off, text, image_base)
    return count_va, get_va


def find_eval_callers(
    data: bytes, text: dict, image_base: int, eval_va: int, finalizer_va: int
) -> list[tuple[int, int]]:
    """Find direct calls to the dispatcher and classify their DL argument."""
    start = text["raw_ptr"]
    end = start + text["raw_size"] - 5
    calls: list[tuple[int, int]] = []
    pos = data.find(b"\xE8", start, end)
    while pos >= 0:
        disp = struct.unpack_from("<i", data, pos + 1)[0]
        call_va = off_to_va(pos, text, image_base)
        if call_va + 5 + disp == eval_va:
            calls.append((pos, call_va))
        pos = data.find(b"\xE8", pos + 1, end)

    finish_calls: list[tuple[int, int]] = []
    for off, call_va in calls:
        prefix = bytes(data[off - len(DL0_PREFIX):off])
        if prefix != DL0_PREFIX:
            continue

        look_end = min(off + 5 + FINALIZER_LOOKAHEAD, end)
        j = data.find(b"\xE8", off + 5, look_end)
        found_finalizer = False
        while j >= 0:
            disp = struct.unpack_from("<i", data, j + 1)[0]
            target_va = off_to_va(j, text, image_base) + 5 + disp
            if target_va == finalizer_va:
                found_finalizer = True
                break
            j = data.find(b"\xE8", j + 1, look_end)
        if found_finalizer:
            finish_calls.append((off, call_va))

    if len(finish_calls) != EXPECTED_FINISH_CALLS:
        found = ", ".join(f"0x{va:08X}" for _, va in finish_calls) or "none"
        raise UnsupportedBuild(
            "expected exactly two finish-handler DL=0 dispatcher calls, "
            f"found {len(finish_calls)} ({found})"
        )
    return finish_calls


def patch_finish_calls(data: bytearray, finish_calls: list[tuple[int, int]]) -> list[int]:
    patched: list[int] = []
    for off, call_va in finish_calls:
        actual = bytes(data[off:off + 5])
        if len(actual) != 5 or actual[0] != 0xE8:
            raise UnsupportedBuild(f"unexpected call bytes at 0x{call_va:08X}")
        data[off:off + 5] = NOP5
        patched.append(call_va)
    for off, call_va in finish_calls:
        if bytes(data[off:off + 5]) != NOP5:
            raise UnsupportedBuild(f"post-check: call at 0x{call_va:08X} was not NOPed")
    return patched


def assemble_stub(
    cave_va: int, get_count_va: int, get_record_va: int, resume_va: int, compact: bool
) -> bytes:
    template = STUB_TEMPLATE_COMPACT if compact else STUB_TEMPLATE_FULL
    source = template.format(
        get_count=f"0x{get_count_va:08X}",
        get_record=f"0x{get_record_va:08X}",
        resume=f"0x{resume_va:08X}",
    )
    if Ks is None:
        raise UnsupportedBuild("keystone-engine is not installed")
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(source, addr=cave_va)
    code = bytes(encoding)
    if count < 40 or len(code) < 100:
        raise AssertionError("stub assembly looks wrong")
    if code[:2] != b"\x9C\x60":
        raise AssertionError("stub does not start with pushfd/pushad")
    if code[-5] != 0xE9:
        raise AssertionError("stub does not end with a rel32 jump")
    disp = struct.unpack_from("<i", code, len(code) - 4)[0]
    if cave_va + len(code) + disp != resume_va:
        raise AssertionError("stub jump-back target is wrong")
    return code


def cave_candidates(data: bytes, text: dict, min_len: int) -> list[int]:
    """Return candidate file offsets in preference order."""
    raw_start = text["raw_ptr"]
    raw_end = raw_start + text["raw_size"]
    vs = text["virtual_size"]
    candidates: list[int] = []

    # Prefer the zero-filled tail after VirtualSize.  Try a 16-byte aligned
    # start first, then 4-byte, then the exact end of VirtualSize.
    for alignment in (0x10, 4, 1):
        off = raw_start + align_up(vs, alignment)
        if off < raw_end and off not in candidates:
            candidates.append(off)

    # Then look for zero runs inside .text.  Runs fully inside VirtualSize are
    # preferred because they do not require a VirtualSize change.
    runs: list[tuple[int, int]] = []
    run_start = None
    for i in range(raw_start, raw_end):
        if data[i] == 0:
            if run_start is None:
                run_start = i
        else:
            if run_start is not None:
                if i - run_start >= min_len:
                    runs.append((run_start, i))
                run_start = None
    if run_start is not None and raw_end - run_start >= min_len:
        runs.append((run_start, raw_end))

    vs_end = raw_start + vs
    inner: list[tuple[bool, int]] = []
    for a, b in runs:
        start = align_up(a, 0x10)
        if start + min_len > b:
            start = a
        inside = start + min_len <= vs_end
        inner.append((inside, start))
    inner.sort(key=lambda item: (not item[0], -item[1]))
    for _, off in inner:
        if off not in candidates:
            candidates.append(off)

    return candidates


def choose_cave_and_stub(
    data: bytes,
    text: dict,
    image_base: int,
    finalizer_va: int,
    resume_va: int,
    get_count_va: int,
    get_record_va: int,
) -> tuple[int, bytes, bool]:
    raw_start = text["raw_ptr"]
    raw_end = raw_start + text["raw_size"]
    vs_end_off = raw_start + text["virtual_size"]

    # Try the full stub everywhere first, then the compact fallback.
    for compact in (False, True):
        # Build once at a provisional address to get a lower bound on length.
        probe_va = image_base + text["va"] + 0x1000
        probe = assemble_stub(probe_va, get_count_va, get_record_va, resume_va, compact)
        candidates = cave_candidates(data, text, len(probe))
        for off in candidates:
            if off + len(probe) > raw_end:
                continue
            if off > vs_end_off and any(data[vs_end_off:off]):
                continue
            if any(data[off:off + len(probe)]):
                continue
            cave_va = off_to_va(off, text, image_base)
            stub = assemble_stub(
                cave_va, get_count_va, get_record_va, resume_va, compact
            )
            if off + len(stub) > raw_end:
                continue
            if any(data[off:off + len(stub)]):
                continue
            # Do not overwrite the dispatcher or the finalizer.
            return off, stub, compact
    raise UnsupportedBuild("no suitable zero-filled code cave found in .text")


def patch_one(src: Path, dst: Path) -> dict[str, str | int]:
    data = bytearray(src.read_bytes())
    pe = parse_pe(data)
    text = find_text_section(pe)
    if text["raw_ptr"] + text["raw_size"] > len(data):
        raise UnsupportedBuild(".text raw data is outside the file")
    if text["virtual_size"] > text["raw_size"]:
        raise UnsupportedBuild(".text VirtualSize is larger than its raw data")
    image_base = pe["image_base"]

    eval_start, eval_end = find_eval_region(data, text)
    all_flags = positions_in_range(data, eval_start, eval_end, FAIL_FLAG)
    if len(all_flags) == 1:
        raise AlreadyPatched(
            "only the skip flag remains: the file looks already patched"
        )
    if len(all_flags) != EXPECTED_FLAG_WRITES:
        raise UnsupportedBuild(
            f"expected {EXPECTED_FLAG_WRITES} result-flag writes, "
            f"found {len(all_flags)}"
        )

    finalizer_off, resume_va = find_finalizer(data, text, image_base)
    finalizer_va = off_to_va(finalizer_off, text, image_base)
    get_count_va, get_record_va = find_helpers(data, text, image_base)
    eval_va = off_to_va(eval_start, text, image_base)

    finish_calls = find_eval_callers(
        data, text, image_base, eval_va, finalizer_va
    )

    flag_patches = patch_result_flags(data, eval_start, eval_end)
    finish_patched = patch_finish_calls(data, finish_calls)

    cave_off, stub, compact = choose_cave_and_stub(
        data, text, image_base, finalizer_va, resume_va,
        get_count_va, get_record_va,
    )
    cave_va = off_to_va(cave_off, text, image_base)
    cave_section_off = cave_off - text["raw_ptr"]
    cave_end_section = cave_section_off + len(stub)

    new_virtual_size = max(text["virtual_size"], cave_end_section)
    following = [s["va"] for s in pe["sections"] if s["va"] > text["va"]]
    if following:
        next_rva = min(following)
        if text["va"] + align_up(new_virtual_size, pe["section_align"]) > next_rva:
            raise UnsupportedBuild(
                "expanded .text would overlap the next PE section"
            )

    hook = rel32(0xE9, finalizer_va, cave_va) + b"\x90" * (
        len(FINALIZER_PROLOGUE) - 5
    )
    if len(hook) != len(FINALIZER_PROLOGUE):
        raise AssertionError("hook length differs from displaced prologue")
    if data[finalizer_off:finalizer_off + len(FINALIZER_PROLOGUE)] != FINALIZER_PROLOGUE:
        raise UnsupportedBuild("finalizer prologue changed unexpectedly")

    data[finalizer_off:finalizer_off + len(hook)] = hook
    data[cave_off:cave_off + len(stub)] = stub
    struct.pack_into("<I", data, text["header_off"] + 8, new_virtual_size)

    checksum = pe_checksum(data, pe["checksum_off"])
    struct.pack_into("<I", data, pe["checksum_off"], checksum)

    # Static post-conditions.
    if bytes(data[finalizer_off:finalizer_off + len(hook)]) != hook:
        raise AssertionError("post-check: hook bytes were not written")
    if bytes(data[cave_off:cave_off + len(stub)]) != stub:
        raise AssertionError("post-check: stub bytes were not written")
    if struct.unpack_from("<I", data, text["header_off"] + 8)[0] != new_virtual_size:
        raise AssertionError("post-check: VirtualSize was not updated")
    flags_after = positions_in_range(data, eval_start, eval_end, FAIL_FLAG)
    if len(flags_after) != 1:
        raise AssertionError("post-check: result-flag state is inconsistent")
    if data.find(SKIP_HEAD, eval_start, eval_end) != flags_after[0]:
        raise AssertionError("post-check: the remaining flag is not the skip branch")
    for off, call_va in finish_calls:
        if bytes(data[off:off + 5]) != NOP5:
            raise AssertionError(f"post-check: call at 0x{call_va:08X} is not NOPed")

    dst.write_bytes(data)
    return {
        "eval_va": f"0x{eval_va:08X}",
        "finalizer_va": f"0x{finalizer_va:08X}",
        "flags_patched": flag_patches,
        "finish_calls_noped": " ".join(f"0x{va:08X}" for va in finish_patched),
        "cave_va": f"0x{cave_va:08X}",
        "cave_size": len(stub),
        "stub": "compact" if compact else "full",
        "virtual_size": f"0x{new_virtual_size:X}",
        "checksum": f"0x{checksum:08X}",
    }


def collect_inputs(paths: list[str], recursive: bool, include_runner: bool) -> list[Path]:
    result: list[Path] = []
    seen: set[Path] = set()

    def add(p: Path) -> None:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            result.append(p)

    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            iterator = p.rglob("*.exe") if recursive else p.iterdir()
            for f in iterator:
                if not f.is_file() or f.suffix.lower() != ".exe":
                    continue
                name = f.name.lower()
                stem = f.stem.lower()
                if stem.endswith(("_final", "_patched", "_summary_v5")):
                    continue
                if not include_runner and name in {"myteststudent.exe", "mytestx.exe"}:
                    continue
                add(f)
        elif p.is_file():
            add(p)
        else:
            print(f"[!] path not found: {p}", file=sys.stderr)
    return result


def output_path_for(src: Path, out_dir: Path | None, suffix: str) -> Path:
    parent = out_dir if out_dir is not None else src.parent
    return parent / (src.stem + suffix + src.suffix)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Patch MyTestX 10.x self-contained test EXEs: answered questions "
            "count as correct, unanswered questions are reported as wrong."
        )
    )
    ap.add_argument(
        "paths", nargs="*", help="test EXE files and/or folders with test EXEs"
    )
    ap.add_argument(
        "-o", "--output-dir", help="write patched files to this folder"
    )
    ap.add_argument(
        "--suffix", default="_final", help="output name suffix (default: _final)"
    )
    ap.add_argument(
        "--recursive", action="store_true", help="scan folders recursively"
    )
    ap.add_argument(
        "--overwrite", action="store_true", help="overwrite existing output files"
    )
    ap.add_argument(
        "--include-runner", action="store_true",
        help="when scanning a folder, also process MyTestStudent.exe",
    )
    args = ap.parse_args()

    if Ks is None:
        print(
            "[!] keystone-engine is required. Install it with:\n"
            "    python -m pip install keystone-engine",
            file=sys.stderr,
        )
        return 2

    if not args.paths:
        ap.print_help()
        return 2

    inputs = collect_inputs(args.paths, args.recursive, args.include_runner)
    if not inputs:
        print("[!] no input EXE files found", file=sys.stderr)
        return 1

    out_dir = Path(args.output_dir) if args.output_dir else None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)

    ok = 0
    skipped = 0
    failed = 0
    for src in inputs:
        dst = output_path_for(src, out_dir, args.suffix)
        if src.resolve() == dst.resolve():
            print(f"[skip] {src}: output path equals input path")
            skipped += 1
            continue
        if dst.exists() and not args.overwrite:
            print(f"[skip] {src}: output exists (use --overwrite): {dst}")
            skipped += 1
            continue

        try:
            info = patch_one(src, dst)
        except AlreadyPatched as exc:
            print(f"[skip] {src}: {exc}")
            skipped += 1
        except (OSError, ValueError, UnsupportedBuild, struct.error) as exc:
            print(f"[!] {src}: {exc}", file=sys.stderr)
            failed += 1
        else:
            ok += 1
            details = ", ".join(f"{k}={v}" for k, v in info.items())
            print(f"[ok] {src.name} -> {dst.name}")
            print(f"     {details}")

    print()
    print(f"Done: patched={ok}, skipped={skipped}, failed={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
