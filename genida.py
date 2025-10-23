# single-file GenIda: ELF parser (pyelftools) + Capstone disassembler + decompiler + C generator
# Requires: pip install capstone pyelftools
import sys
import os
import re
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import StringTableSection
from capstone import *

class ELFHelper:
    def __init__(self, path):
        self.path = path
        self.f = open(path, 'rb')
        self.elffile = ELFFile(self.f)
        self.arch = self.elffile.get_machine_arch()
        self.bitness = self.elffile.elfclass
        self.text_section = self.elffile.get_section_by_name('.text')
        if self.text_section:
            self.text_addr = self.text_section['sh_addr']
            self.text_size = self.text_section['sh_size']
        else:
            self.text_addr = 0
            self.text_size = 0

    def get_text_section(self):
        if not self.text_section:
            return b''
        return self.text_section.data()

    def read_bytes(self, addr, size):
        if not self.text_section:
            return b''
        base = self.text_section['sh_addr']
        off = addr - base
        data = self.text_section.data()[off:off + size]
        return data

    def list_functions(self):
        out = []
        seen = set()
        for s in self.elffile.iter_sections():
            if getattr(s, 'name', None) in ('.symtab', '.dynsym'):
                for sym in s.iter_symbols():
                    if sym['st_info']['type'] == 'STT_FUNC' and sym['st_shndx'] != 'SHN_UNDEF':
                        addr = sym['st_value']
                        if addr in seen:
                            continue
                        seen.add(addr)
                        name = sym.name if sym.name else 'sub_%08x' % addr
                        size = sym['st_size'] if sym['st_size'] > 0 else self.text_size
                        out.append((name, addr, size))
        return out

    def find_functions_heuristic(self):
        data = self.get_text_section()
        res = []
        if not data:
            return res
        prologs = [b'\x55\x48\x89\xe5', b'\x55\x89\xe5', b'\xf0\xb5', b'\xed\x2f', b'\x10\xb5']
        base = self.text_addr
        for p in prologs:
            i = 0
            while True:
                i = data.find(p, i)
                if i == -1:
                    break
                addr = base + i
                res.append(('sub_%08x' % addr, addr, self.text_size))
                i += 1
        return res

    def rodata_strings(self, min_len=4):
        out = {}
        for s in self.elffile.iter_sections():
            if isinstance(s, StringTableSection) or getattr(s, 'name', '') == '.rodata':
                try:
                    data = s.data()
                except Exception:
                    continue
                cur = bytearray()
                base = s['sh_addr'] if 'sh_addr' in s.header else 0
                for i in range(len(data)):
                    b = data[i]
                    if b == 0:
                        if len(cur) >= min_len:
                            addr = base + i - len(cur)
                            try:
                                out[addr] = cur.decode('utf-8', 'ignore')
                            except:
                                out[addr] = cur.decode('latin1', 'ignore')
                        cur = bytearray()
                    else:
                        cur.append(b)
        return out

    def symbols_map(self):
        out = {}
        for s in self.elffile.iter_sections():
            if getattr(s, 'name', None) in ('.symtab', '.dynsym'):
                for sym in s.iter_symbols():
                    if sym['st_shndx'] != 'SHN_UNDEF' and sym['st_value']:
                        out[sym['st_value']] = sym.name
        return out

class Disassembler:
    def __init__(self, arch, bitness):
        self.arch = arch or ''
        self.bitness = bitness
        a = self.arch.lower()
        if 'arm' in a and '64' in a:
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self.tag = 'arm64'
            self.arg_regs = ['x0', 'x1', 'x2', 'x3']
            self.sp_regs = ['sp']
        elif 'arm' in a:
            self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            self.tag = 'arm'
            self.arg_regs = ['r0', 'r1', 'r2', 'r3']
            self.sp_regs = ['sp']
        elif 'x86' in a and ('64' in a or bitness == 64):
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.tag = 'x86_64'
            self.arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
            self.sp_regs = ['rsp', 'esp']
        else:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.tag = 'x86'
            self.arg_regs = ['eax', 'edx', 'ecx']
            self.sp_regs = ['esp']
        self.cs.detail = True
        self.re_reg = re.compile(r'([a-z]{1,4}\d*|sp|lr|pc)', re.I)

    def disasm(self, code, addr):
        out = []
        try:
            for i in self.cs.disasm(code, addr):
                out.append(i)
        except Exception:
            pass
        return out

    def regs_used_before_def(self, insns):
        reads = set()
        defs = set()
        for i in insns:
            if hasattr(i, 'regs_read'):
                for r in i.regs_read:
                    try:
                        n = self.cs.reg_name(r)
                    except:
                        n = None
                    if n and n not in defs:
                        reads.add(n)
            if hasattr(i, 'regs_write'):
                for r in i.regs_write:
                    try:
                        n = self.cs.reg_name(r)
                    except:
                        n = None
                    if n:
                        defs.add(n)
        return reads

    def infer_arg_registers(self, insns):
        reads = self.regs_used_before_def(insns[:12])
        args = []
        for r in self.arg_regs:
            if r in reads:
                args.append(r)
        return args

class DecompilerCore:
    def __init__(self, dis, elfhelper):
        self.dis = dis
        self.elf = elfhelper
        self.strings = self.elf.rodata_strings()
        self.symbols = self.elf.symbols_map()
        self.known_libc = set(['printf', 'sprintf', 'snprintf', 'strcmp', 'strncmp', 'memcpy', 'memset', 'malloc', 'free', 'strlen', 'strcpy', 'strncpy'])

    def addr_to_name(self, a):
        return self.symbols.get(a, None)

    def replace_addr_literals(self, text):
        if not text:
            return text
        for m in re.finditer(r'0x[0-9a-fA-F]+', text):
            s = m.group(0)
            try:
                v = int(s, 0)
            except:
                continue
            if v in self.strings:
                text = text.replace(s, '"%s"' % self.strings[v].replace('"', '\"'))
            elif v in self.symbols:
                text = text.replace(s, self.symbols[v])
        return text

    def split_basic_blocks(self, insns):
        if not insns:
            return []
        cuts = set([insns[0].address])
        for i in insns:
            m = i.mnemonic.lower()
            next_addr = i.address + i.size
            if m.startswith('b') or m in ('jmp', 'ret', 'bx'):
                ops = i.op_str.split(',')[0].strip()
                try:
                    t = int(ops, 0)
                    cuts.add(t)
                except:
                    pass
                cuts.add(next_addr)
            else:
                cuts.add(next_addr)
        pts = sorted(cuts)
        addr_to_block = {}
        blocks = []
        for p in pts:
            b = {'start': p, 'insns': [], 'succ': []}
            blocks.append(b)
            addr_to_block[p] = b
        cur = None
        for i in insns:
            if i.address in addr_to_block:
                cur = addr_to_block[i.address]
            if cur is not None:
                cur['insns'].append(i)
        for b in blocks:
            if not b['insns']:
                continue
            last = b['insns'][-1]
            m = last.mnemonic.lower()
            if m.startswith('b') or m in ('jmp', 'ret', 'bx'):
                ops = last.op_str.split(',')[0].strip()
                try:
                    t = int(ops, 0)
                    if t in addr_to_block:
                        b['succ'].append(addr_to_block[t]['start'])
                except:
                    pass
            else:
                na = last.address + last.size
                if na in addr_to_block:
                    b['succ'].append(na)
        return blocks

    def insn_to_expr(self, i):
        m = i.mnemonic.lower()
        ops = i.op_str
        ops = self.replace_addr_literals(ops)
        if m in ('mov', 'movs', 'ldr', 'ldrb', 'ldrh', 'ldrsw'):
            p = [x.strip() for x in ops.split(',')]
            if len(p) >= 2:
                return '%s = %s' % (p[0], p[1])
        if m in ('str', 'strb', 'strh'):
            p = [x.strip() for x in ops.split(',')]
            if len(p) >= 2:
                return '%s = %s' % (p[1], p[0])
        if m in ('lea',):
            return '%s = &%s' % tuple(x.strip() for x in ops.split(',')[:2])
        if m in ('add', 'adds', 'adc'):
            p = [x.strip() for x in ops.split(',')]
            if len(p) >= 2:
                return '%s = %s + %s' % (p[0], p[0], p[1])
        if m in ('sub', 'subs', 'sbb'):
            p = [x.strip() for x in ops.split(',')]
            if len(p) >= 2:
                return '%s = %s - %s' % (p[0], p[0], p[1])
        if m in ('mul', 'muls', 'imul'):
            p = [x.strip() for x in ops.split(',')]
            if len(p) >= 2:
                return '%s = %s * %s' % (p[0], p[0], p[1])
        if m in ('div', 'idiv'):
            p = [x.strip() for x in ops.split(',')]
            if len(p) >= 2:
                return '%s = %s / %s' % (p[0], p[0], p[1])
        if m in ('and', 'ands'):
            p = [x.strip() for x in ops.split(',')]
            return '%s = %s & %s' % (p[0], p[0], p[1] if len(p) > 1 else '1')
        if m in ('or', 'orr'):
            p = [x.strip() for x in ops.split(',')]
            return '%s = %s | %s' % (p[0], p[0], p[1] if len(p) > 1 else '0')
        if m in ('xor', 'eor'):
            p = [x.strip() for x in ops.split(',')]
            return '%s = %s ^ %s' % (p[0], p[0], p[1] if len(p) > 1 else '0')
        if m in ('shl', 'sal', 'lsl'):
            p = [x.strip() for x in ops.split(',')]
            return '%s = %s << %s' % (p[0], p[0], p[1] if len(p) > 1 else '1')
        if m in ('shr', 'sar', 'lsr'):
            p = [x.strip() for x in ops.split(',')]
            return '%s = %s >> %s' % (p[0], p[0], p[1] if len(p) > 1 else '1')
        if m in ('inc',):
            p = ops.strip()
            return '%s = %s + 1' % (p, p)
        if m in ('dec',):
            p = ops.strip()
            return '%s = %s - 1' % (p, p)
        if m in ('neg', 'not'):
            p = ops.strip()
            return '%s = -%s' % (p, p)
        if m in ('cmp', 'cmn', 'tst', 'teq'):
            p = [x.strip() for x in ops.split(',')]
            if len(p) >= 2:
                return 'cmp %s,%s' % (p[0], p[1])
        if m.startswith('j') or m in ('b', 'bl', 'bx'):
            return '%s %s' % (m, ops)
        if m in ('call', 'bl', 'blx'):
            tgt = ops.split(',')[0].strip()
            try:
                if tgt.startswith('0x'):
                    a = int(tgt, 0)
                    if a in self.symbols:
                        name = self.symbols[a]
                        if name in self.known_libc:
                            return 'call %s()' % name
                        return 'call %s()' % name
            except:
                pass
            return 'call %s' % ops
        if m in ('ret', 'bx lr'):
            return 'return' 
        return '%s %s' % (m, ops) if ops else m

    def structure_if(self, blocks):
        out = []
        for b in blocks:
            out.append(('bb', b['start']))
            if not b['insns']:
                continue
            for idx, i in enumerate(b['insns']):
                s = self.insn_to_expr(i)
                out.append((i.address, s))
                if s.startswith('cmp '):
                    if idx + 1 < len(b['insns']):
                        n = b['insns'][idx + 1]
                        if n.mnemonic.lower().startswith('j') and n.mnemonic.lower() not in ('call',):
                            tgt = n.op_str.split(',')[0].strip()
                            out.append(('if', tgt))
        return out

    def decompile_function(self, name, addr, insns):
        if not insns:
            return {'name': name, 'addr': addr, 'stmts': []}
        arg_regs = self.dis.infer_arg_registers(insns)
        blocks = self.split_basic_blocks(insns)
        stmts = self.structure_if(blocks)
        return {'name': name, 'addr': addr, 'stmts': stmts, 'args': arg_regs}

class CGenerator:
    def __init__(self, inline_strings=True):
        self.inline_strings = inline_strings

    def generate(self, results, elf):
        out = []
        strings = elf.rodata_strings()
        for (name, addr), ast in results.items():
            args = ast.get('args', [])
            proto_args = ', '.join('int %s' % r for r in args) if args else 'void'
            proto = 'void %s(%s)' % (name, proto_args)
            out.append(proto + ' {')
            for t, v in ast['stmts']:
                if t == 'bb':
                    continue
                elif t == 'if':
                    cond = v
                    out.append('  if(%s) {' % self._cond_to_c(cond))
                    out.append('  }')
                else:
                    expr = self._cleanup_expr(v, strings)
                    out.append('  %s;' % expr)
            out.append('}
')
        return '\n'.join(out)

    def _cond_to_c(self, cond):
        cond = cond.strip()
        if cond.startswith('0x'):
            return '/*branch %s*/0' % cond
        return cond

    def _cleanup_expr(self, expr, strings):
        if not expr:
            return ''
        for m in re.finditer(r'0x[0-9a-fA-F]+', expr):
            s = m.group(0)
            try:
                v = int(s, 0)
            except:
                continue
            if v in strings:
                expr = expr.replace(s, '"%s"' % strings[v].replace('"', '\"'))
        expr = expr.replace('cmp ', '')
        return expr

def ensure_paths(so_path):
    so_dir = os.path.dirname(os.path.abspath(so_path)) or '.'
    base = os.path.splitext(os.path.basename(so_path))[0]
    out_c = os.path.join(so_dir, base + '_genida.c')
    asm_path = os.path.join(so_dir, base + '_genida.asm')
    return out_c, asm_path

def interactive_path():
    sys.stdout.write('Path to .so: ')
    sys.stdout.flush()
    return sys.stdin.readline().strip()

def main(argv):
    if len(argv) > 1:
        so = argv[1]
    else:
        so = interactive_path()
    if not so or not os.path.isfile(so):
        print('File not found:', so)
        return
    elf = ELFHelper(so)
    dis = Disassembler(elf.arch, elf.bitness)
    decomp = DecompilerCore(dis, elf)
    funcs = elf.list_functions()
    heur = elf.find_functions_heuristic()
    for h in heur:
        if h not in funcs:
            funcs.append(h)
    results = {}
    if not funcs:
        code = elf.get_text_section()
        addr = elf.text_addr
        insns = dis.disasm(code, addr)
        ast = decomp.decompile_function('sub_%08x' % addr, addr, insns)
        results[('sub_%08x' % addr, addr)] = ast
    else:
        for name, addr, size in funcs:
            code = elf.read_bytes(addr, size)
            insns = dis.disasm(code, addr)
            ast = decomp.decompile_function(name, addr, insns)
            results[(name, addr)] = ast
    out_c, asm_path = ensure_paths(so)
    gen = CGenerator()
    outc = gen.generate(results, elf)
    with open(out_c, 'w', encoding='utf-8') as f:
        f.write(outc)
    with open(asm_path, 'w', encoding='utf-8') as f:
        for (name, addr), ast in results.items():
            f.write('function %s 0x%x\n' % (name, addr))
            for t, v in ast['stmts']:
                if t == 'bb':
                    f.write('BB 0x%x\n' % v)
                elif t == 'if':
                    f.write('IF -> %s\n' % v)
                else:
                    f.write('0x%x: %s\n' % (t, v))
    print('Wrote:', out_c)
    print('Wrote:', asm_path)

if __name__ == '__main__':
    main(sys.argv)
