#!/usr/bin/env python3
"""
patch_binary.py

Usage:
    python3 patch_binary.py <binary> <output> <xorkey>

Requires:
    - radare2 (r2) installed and in PATH
    - r2pipe Python package (pip install r2pipe)

What it does:
    - runs r2 analysis
    - collects symbol table and relocations (to resolve call targets)
    - enumerates functions (aflj)
    - for each function, disassembles (pdfj) and finds calls to __cyg_profile_func_enter / __cyg_profile_func_exit
      * if disasm contains no symbol name, it resolves the call target via op.jump or parsing and looks up the symbol/reloc
    - computes the range between the last enter-call and the first exit-call (start after enter instr, end at start of exit instr)
    - writes JSON results and prints human-readable output
    - xors and modifies .data section of binary
"""
import sys
import json
import argparse
import r2pipe
import re
import os
import struct
from shutil import copyfile

class PatchFile:
    SENTINEL = (0xdead, 0xbeef, 0xcafebabe, 0x78)

    def load_ranges(json_path):
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
        except TypeError:
            # This exception is just in case we pass the actual parsed JSON as a string already
            data = json_path
        except Exception as e:
            print("Error getting JSON to load_ranges: ", e)
        ranges = []
        for entry in data:
            er = entry.get("encrypt_region", {})
            start = er.get("start", None)
            end   = er.get("end", None)
            if start is None or end is None:
                continue
            ranges.append((int(start), int(end), int(entry.get("func_addr"))))
        return ranges

    def locate_and_patch_data_section(data_bin, new_table_bytes, output_file):
        # Load the existing .data section
        with open(data_bin, "rb") as f:
            data = bytearray(f.read())

        # Convert sentinel tuple to bytes
        sentinel_bytes = b"".join(struct.pack("<Q", s) for s in PatchFile.SENTINEL)
        print(sentinel_bytes)

        # Search for sentinel
        offset = data.find(sentinel_bytes)
        if offset == -1:
            print(f"Sentinel [{PatchFile.SENTINEL}] not found in .data")
            import pdb
            pdb.set_trace()
            sys.exit(1)
        print(f"Found sentinel at offset 0x{offset:x}")

        # Overwrite with new enc_table
        if offset + len(new_table_bytes) > len(data):
            print("Error: new table too large for .data section!")
            sys.exit(1)

        data[offset:offset+len(new_table_bytes)] = new_table_bytes

        # Write patched .data section
        with open(output_file, "wb") as f:
            f.write(data)

        print(f"Patched .data written to {output_file}")

    def patch_file(binpath, ranges, key_byte, output_path=None):
        filesize = os.path.getsize(binpath)
        # validate ranges, this SHOULD already be done but just in case
        for s,e,faddr in ranges:
            if s < 0 or e < 0 or s >= filesize or e > filesize or s >= e:
                raise ValueError(f"Invalid range in 0x{s:x}-0x{e:x} for file size {filesize}")

        print(f"File: {binpath}  size: {filesize} bytes")
        print("Planned XOR patches:")
        for s,e,faddr in ranges:
            print(f"  0x{s:x} .. 0x{e:x}  (len {e-s}) [in function: {faddr:x}]")

        print(f"Writing patched file to {output_path}")
        copyfile(binpath, output_path)

        # read original
        with open(output_path, "rb") as f:
            data = bytearray(f.read())

        packed_data = b""
        for s,e,faddr in ranges:
            # super-dependent on how your .data section got compiled.
            # If you use __attribute__((packed)) should only be <QQQB.
            # Just look at the .data section to make sure this is correct
            packed_data += struct.pack("<QQQB7x", s, e, faddr, key_byte)
            for i in range(s, e):
                data[i] ^= key_byte

        # Dont need to do this unless we completely erase data section.
        # pad to the full table size (512 entries)
        #total_size = 512 * 16
        #if len(packed_data) < total_size:
        #    packed_data += b"\x00" * (total_size - len(packed_data))
        
        with open(output_path, "wb") as f:
            f.write(data)
        
        #with open(output_path+".datapatch.bin", "wb") as f:
        #    f.write(packed_data)
        return packed_data


# This function collection is vibe-coded. Maybe its nonsense, maybe its not
# I fixed it up till it worked, and ignored the stuff that wasnt breaking
class R2Analyze:
    ENTER_SYM = "__cyg_profile_func_enter"
    EXIT_SYM = "__cyg_profile_func_exit"

    @staticmethod
    def build_symbol_map(r2):
        """
        Build maps:
        - addr_to_sym: exact address -> symbol name
        - name_to_addrs: symbol name -> list of addresses
        Also includes relocations (irj) and imported symbols.
        """
        addr_to_sym = {}
        name_to_addrs = {}
        # symbols
        try:
            syms = r2.cmdj("isj") or []
        except Exception:
            syms = []
        for s in syms:
            v = s.get("vaddr")
            name = s.get("name")
            if v is None or not name:
                continue
            addr_to_sym[v] = name
            name_to_addrs.setdefault(name, []).append(v)

        # relocations (import table / plt entries)
        try:
            rels = r2.cmdj("irj") or []
        except Exception:
            rels = []
        for r in rels:
            v = r.get("vaddr")
            name = r.get("name")
            if v is None or not name:
                continue
            # prefer reloc name if symbol at same addr not present
            if v not in addr_to_sym:
                addr_to_sym[v] = name
            name_to_addrs.setdefault(name, []).append(v)

        # also add entries from 'aflj' functions that have 'name' as plt stubs etc.
        # (some PLT pseudo-funcs have addresses)
        try:
            funcs = r2.cmdj("aflj") or []
            #print(funcs)
        except Exception:
            funcs = []
        for f in funcs:
            # Another spot that could be offset, vaddr, or minaddr?
            v = f.get("addr")
            name = f.get("name")
            if v is None or not name:
                continue
            if v not in addr_to_sym:
                addr_to_sym[v] = name
            name_to_addrs.setdefault(name, []).append(v)

        #print(addr_to_sym, name_to_addrs)
        return addr_to_sym, name_to_addrs

    @staticmethod
    def resolve_call_target_sym(r2, op, addr_to_sym):
        """
        Given an instruction json op (from pdfj), attempt to resolve the symbol name of the call target.
        Strategy:
        - if op contains 'disasm' with a known symbol string, return that
        - if op has 'jump' use addr_to_sym mapping
        - if op has 'ptr' or 'val' fields, try those
        - as a fallback parse hex number from disasm and look up
        """
        disasm = (op.get("disasm") or "").lower()
        # if name already present in disasm text
        if R2Analyze.ENTER_SYM in disasm:
            return R2Analyze.ENTER_SYM
        if R2Analyze.EXIT_SYM in disasm:
            return R2Analyze.EXIT_SYM

        # try op.jump
        jump = op.get("jump")
        if jump:
            name = addr_to_sym.get(jump)
            if name:
                return name
        # try op.get('ptr') or op.get('val') fields
        ptr = op.get("ptr") or op.get("val")
        if ptr:
            name = addr_to_sym.get(ptr)
            if name:
                return name

        # try to parse immediate address from disasm like 'call 0x400abc'
        m = re.search(r"0x[0-9a-fA-F]+", op.get("disasm") or "")
        if m:
            try:
                v = int(m.group(0), 16)
                name = addr_to_sym.get(v)
                if name:
                    return name
            except Exception:
                pass

        # no resolution
        return None

    @staticmethod
    def analyze(binary_path):
        r2 = r2pipe.open(binary_path, flags=['-2'])
        # perform analysis
        r2.cmd("aa")
        # build symbol map once
        addr_to_sym, name_to_addrs = R2Analyze.build_symbol_map(r2)

        funcs_json = r2.cmd("aflj")
        try:
            funcs = json.loads(funcs_json)
        except Exception as e:
            print("ERROR: failed to parse aflj JSON:", e, file=sys.stderr)
            r2.quit()
            sys.exit(1)

        results = []
        #print(funcs)
        print("Filtering on 'addr' in json. If r2 versions change this could be vaddr, offset, or minaddr")
        funcs = [f for f in funcs if f.get("addr") is not None]
        #print(funcs)
        for f in funcs:
            faddr = f.get("addr")
            fname = f.get("name", f"sub_{faddr:x}")
            fsize = f.get("size", 0)

            pdfj = r2.cmd(f"pdfj @ {faddr}")
            try:
                pdf = json.loads(pdfj)
            except Exception:
                continue
            ops = pdf.get("ops") or []
            enter_calls = []
            exit_calls = []
            for op in ops:
                if op.get("type") not in ["call", "jmp"]:
                    continue
                disasm = op.get("disasm") or ""
                print("current disasm:", disasm)
                # direct textual check first
                if R2Analyze.ENTER_SYM in disasm:
                    enter_calls.append(op)
                    continue
                if R2Analyze.EXIT_SYM in disasm:
                    exit_calls.append(op)
                    continue
                # try resolve via symbol/reloc map
                target_name = R2Analyze.resolve_call_target_sym(r2, op, addr_to_sym)
                if target_name:
                    print("resolve_call_target_sym:", target_name)
                    if R2Analyze.ENTER_SYM in target_name:
                        enter_calls.append(op)
                        continue
                    if R2Analyze.EXIT_SYM in target_name:
                        exit_calls.append(op)
                        continue

            if not enter_calls and not exit_calls:
                continue

            print(enter_calls, exit_calls)
            # Another offset/addr/vaddr/minaddr point
            # highest is actually lower address, lowest is actually higher address
            highest_enter = min(enter_calls, key=lambda o: o.get("addr", 0)) if enter_calls else None
            lowest_exit = max(exit_calls, key=lambda o: o.get("addr", 1<<62)) if exit_calls else None

            encrypt_start = None
            encrypt_end = None
            note = ""
            if highest_enter and lowest_exit:
                enter_end = highest_enter["addr"] + highest_enter.get("size", 1)
                exit_start = lowest_exit["addr"]
                if enter_end <= exit_start:
                    encrypt_start = enter_end
                    encrypt_end = exit_start
                else:
                    note = "enter instruction ends after exit instruction start (no valid between-region)"
            else:
                if highest_enter and not lowest_exit:
                    note = "enter found but no exit found in function"
                elif lowest_exit and not highest_enter:
                    note = "exit found but no enter found in function"
                else:
                    note = "no enter/exit calls found"

            res = {
                "func_name": fname,
                "func_addr": faddr,
                "func_size": fsize,
                "enter_calls": [
                    {"offset": op.get("addr"), "size": op.get("size"), "disasm": op.get("disasm")}
                    for op in enter_calls
                ],
                "exit_calls": [
                    {"offset": op.get("addr"), "size": op.get("size"), "disasm": op.get("disasm")}
                    for op in exit_calls
                ],
                "highest_enter": {
                    "offset": highest_enter["addr"], "size": highest_enter.get("size"), "disasm": highest_enter.get("disasm")
                } if highest_enter else None,
                "lowest_exit": {
                    "offset": lowest_exit["addr"], "size": lowest_exit.get("size"), "disasm": lowest_exit.get("disasm")
                } if lowest_exit else None,
                "encrypt_region": {
                    "start": encrypt_start,
                    "end": encrypt_end,
                    "length": (encrypt_end - encrypt_start) if (encrypt_start is not None and encrypt_end is not None) else None
                },
                "note": note
            }
            results.append(res)

        r2.quit()
        return results

def main():
    p = argparse.ArgumentParser(description="Find ranges between __cyg_profile_func_enter and __cyg_profile_func_exit, xors them on disk, patches .data section for runtime success")
    p.add_argument("binary", help="path to binary")
    p.add_argument("output", help="path for patched binary to be saved")
    p.add_argument("xorkey", help="xor key byte (ie 0xAA)")
    args = p.parse_args()

    jsonanalysis = R2Analyze.analyze(args.binary)
    for r in jsonanalysis:
        print("="*60)
        print(f"Function {r['func_name']} @ 0x{r['func_addr']:x} (size {r['func_size']})")
        if r['highest_enter']:
            he = r['highest_enter']
            print(f"  Highest enter call: 0x{he['offset']:x} (size {he['size']})    '{he['disasm']}'")
        if r['lowest_exit']:
            le = r['lowest_exit']
            print(f"  Lowest exit call:  0x{le['offset']:x} (size {le['size']})    '{le['disasm']}'")
        enc = r['encrypt_region']
        if enc and enc['start'] is not None:
            print(f"  Encrypt range: 0x{enc['start']:x} .. 0x{enc['end']:x}  (len {enc['length']})")
        else:
            print("  No valid encrypt range. Note:", r.get("note"))

    key_byte = int(args.xorkey, 16) & 0xFF

    merged_ranges = PatchFile.load_ranges(jsonanalysis)
    if not merged_ranges:
        print("No ranges found in JSON. Nothing to do.")
        return

    try:
        packed_data = PatchFile.patch_file(args.binary, merged_ranges, key_byte, output_path=args.output)
        PatchFile.locate_and_patch_data_section(args.output, packed_data, args.output)
    except Exception as e:
        print("Error patching file:", e)
        sys.exit(1)

    # Sometimes its nice to inspect the JSON that glues analyze -> patchfile
    # with open("json.dump", "w") as f:
    #     json.dump(jsonanalysis, f, indent=2)
    # print(f"\nWrote JSON to json.dump")

if __name__ == "__main__":
    main()
