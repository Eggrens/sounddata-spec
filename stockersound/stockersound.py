#!/usr/bin/env python3
"""Export Sims 2, Urbz and Spyro Shadow Legacy DS music to IT or render original ARM9 audio."""
from dataclasses import dataclass
import argparse
import hashlib
import json
import struct
import tempfile
import sys
import wave
from pathlib import Path

try:
    from ndspy.code import MainCodeFile
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ
    from unicorn.arm_const import (
        UC_ARM_REG_R0,
        UC_ARM_REG_R1,
        UC_ARM_REG_R2,
        UC_ARM_REG_R3,
        UC_ARM_REG_R4,
        UC_ARM_REG_R7,
        UC_ARM_REG_R12,
        UC_ARM_REG_SP,
        UC_ARM_REG_LR,
        UC_ARM_REG_PC,
    )
except ImportError:
    raise SystemExit(
        "Run setup.py with your cartridge dump first, then use the .venv Python."
    )
BANK_SHA256 = 'abd69c8c410ff84f5d7712f0299bb77950837971dad138ccd785a1f46701c2d4'


ARM9_SHA256 = 'f73d945c0acc8fc5839de45791b1e26260194d13e5b479d34e98d9ed75b71bac'


@dataclass(frozen=True)
class RuntimeProfile:
    name: str
    game_code: str
    code_delta: int
    data_delta: int
    allocator: int
    runtime: str = 'sims2'
    bank_sha256: str = BANK_SHA256
    sdk_delta: int = 0

    def code(self, usa_address):
        if self.runtime == 'spyro':
            if usa_address == 0x0207ff70:
                return self.allocator
            return usa_address+(self.sdk_delta if usa_address >= 0x02070000 else self.code_delta)
        if self.runtime == 'urbz':
            if usa_address == 0x0204e518:
                return self.allocator
            return usa_address+(self.sdk_delta if usa_address >= 0x020b0000 else self.code_delta)
        return self.allocator if usa_address == 0x02046580 else usa_address+self.code_delta

    def data(self, usa_address):
        return usa_address+self.data_delta


PROFILES = {
    ARM9_SHA256: RuntimeProfile('The Sims 2 USA', 'ASJE', 0, 0, 0x02046580),
    '119953cbfa26ced167850a86490f5c3b1ad79cf90654987e8ac9229f78a0e8c0':
        RuntimeProfile('The Sims 2 Europe', 'ASJP', 0x13c, 0x140, 0x020465f8),
    '00c14bce3a75569b47ae8cb9fbb93936a53343b77b72eef98e8dd589fcdc9389':
        RuntimeProfile('The Sims 2 Japan', 'ASJJ', -0x3d8, -0x3a0, 0x0204660c),
    'f4aa380377884ef053df48548dc4047cd81a187b6102387f60f28403312e6c30':
        RuntimeProfile('The Urbz USA', 'ASIE', 0, 0, 0x0204e518, 'urbz',
                       '02a7a5b61f500227bfd5a2a8d52bd6fc539df74832d614038cbdf9b7df4cfb26', 0),
    '83f8a0a51a0a435d2e3c5d5b93854d11eb040d21477bd3da7789cbd6f327b7c4':
        RuntimeProfile('The Urbz Europe', 'ASIP', 0x128c, 0, 0x0204f2a8, 'urbz',
                       '02a7a5b61f500227bfd5a2a8d52bd6fc539df74832d614038cbdf9b7df4cfb26', 0x13b0),
    '3f6df28cd9aad060c817434b7557b7331f912001f6e59aff66c8990fb36b0640':
        RuntimeProfile('The Urbz Japan', 'ASIJ', 0x3cc, 0, 0x0204e894, 'urbz',
                       '02a7a5b61f500227bfd5a2a8d52bd6fc539df74832d614038cbdf9b7df4cfb26', 0x39c),
    '046d140174853e2c24220408693b30afc5886613908dde8759ea202e4a1ca794':
        RuntimeProfile('Spyro Shadow Legacy USA', 'ASSE', 0, 0, 0x0207ff70, 'spyro',
                       '47794e7544ecf505340f568f51dff1b10e54eaaad4a79ce1dbefa75f8d77e1da', 0),
    '5d322f6229ec062c7aec9cb5e89bbc7b6a452b8e6e7cd85bebefc31440e1c2c7':
        RuntimeProfile('Spyro Shadow Legacy Europe', 'ASSP', 0xd8, 0, 0x020803cc, 'spyro',
                       '47794e7544ecf505340f568f51dff1b10e54eaaad4a79ce1dbefa75f8d77e1da', 0x45c),
}


def profile_for(code):
    digest = hashlib.sha256(code).hexdigest()
    if digest not in PROFILES:
        raise ValueError('Unsupported ARM9 runtime; recover and verify its address map first')
    return PROFILES[digest]


BASE = 0x02000000


STATE = 0x02200000


ORDERS = 0x02201000


PATTERNS = 0x02202000


STACK = 0x023FF000


RETURN = 0x023FE000


BLOB = 0x03000000


SEEK = 0x020D4100


READ_ROW = 0x020D2864


def word(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


class RuntimePatterns:
    def __new__(cls, code, bank, *args, **kwargs):
        if cls is RuntimePatterns and profile_for(code).runtime == 'urbz':
            # The standalone build includes this class in the same script.
            if 'UrbzPatterns' in globals():
                adapter = globals()['UrbzPatterns']
            else:
                from analysis.urbz_runtime import UrbzPatterns
                adapter = UrbzPatterns
            if not issubclass(adapter, cls):
                return adapter(code, bank, *args, **kwargs)
            return object.__new__(adapter)
        if cls is RuntimePatterns and profile_for(code).runtime == 'spyro':
            if 'SpyroPatterns' in globals():
                adapter = globals()['SpyroPatterns']
            else:
                from analysis.spyro_runtime import SpyroPatterns
                adapter = SpyroPatterns
            if not issubclass(adapter, cls):
                return adapter(code, bank, *args, **kwargs)
            return object.__new__(adapter)
        return object.__new__(cls)

    def __init__(self, code, bank):
        self.code, self.bank = code, bank
        # Guard the exact routines this harness instruments. No guessed offsets.
        self.code_hash = hashlib.sha256(code).hexdigest()
        self.profile = profile_for(code)
        self.banks = struct.unpack_from('<10I', bank)
        count = (self.banks[4] - self.banks[3]) // 4
        self.pattern_ptrs = struct.unpack_from(f'<{count}I', bank, self.banks[3])
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.mem_map(BASE, 0x400000)
        self.uc.mem_write(BASE, code)
        self.uc.mem_map(BLOB, 0x10000)
        self.slots = word(code, 0xD42A8+self.profile.code_delta)
        self.active = word(code, 0xD42AC+self.profile.code_delta)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read, begin=BLOB, end=BLOB+0xFFFF)
        self.uc.hook_add(UC_HOOK_CODE, self._seek_row, begin=self.profile.code(0x020D4158), end=self.profile.code(0x020D4158))
        self.uc.hook_add(UC_HOOK_CODE, self._packet_start, begin=self.profile.code(0x020D289C), end=self.profile.code(0x020D289C))
        self.uc.hook_add(UC_HOOK_CODE, self._fields, begin=self.profile.code(0x020D2986), end=self.profile.code(0x020D2986))
        self.uc.hook_add(UC_HOOK_CODE, self._skip_application, begin=self.profile.code(0x020D2A4C), end=self.profile.code(0x020D2A4C))
        self.uc.hook_add(UC_HOOK_CODE, self._packet_end, begin=self.profile.code(0x020D2A80), end=self.profile.code(0x020D2A80))
        self.row_starts, self.events, self.max_read = [], [], 0

    def _u32(self, address):
        return struct.unpack('<I', self.uc.mem_read(address, 4))[0]

    def _read(self, uc, access, address, size, value, context):
        self.max_read = max(self.max_read, address + size - BLOB)
        if address + size > BLOB + self.payload_length:
            raise ValueError(f'Runtime read outside pattern at {address:#x}')

    def _seek_row(self, uc, address, size, context):
        self.row_starts.append(self._u32(STATE+0x14)-BLOB)

    def _packet_start(self, uc, address, size, context):
        self.event_start = self._u32(STATE+0x14)-BLOB

    def _fields(self, uc, address, size, context):
        sp = uc.reg_read(UC_ARM_REG_SP)
        channel = self._u32(sp+12)
        values = dict(note=uc.reg_read(UC_ARM_REG_R4),
                      instrument=self._u32(sp+4),
                      volume=uc.reg_read(UC_ARM_REG_R3),
                      command=uc.reg_read(UC_ARM_REG_R2),
                      parameter=self._u32(sp+8))
        end = self._u32(STATE+0x14)-BLOB
        self.pending = dict(offset=self.event_start, end=end, channel=channel,
                            raw=self.payload[self.event_start:end].hex(),
                            fields={k: v for k, v in values.items() if v != 255})
        # The parameter is written with the command; 0xff is a real argument,
        # unlike the note/instrument/volume/command absence sentinel.
        if values['command'] != 255:
            self.pending['fields']['parameter'] = values['parameter']

    def _skip_application(self, uc, address, size, context):
        # Decode/state writes and the SDx delay gate have already executed.
        # Skip all three musical application calls, preserving packet traversal.
        uc.reg_write(UC_ARM_REG_PC, self.profile.code(0x020D2A80) | 1)

    def _packet_end(self, uc, address, size, context):
        ch = self.pending['channel']
        state = bytes(uc.mem_read(STATE+60+36*ch, 36))
        self.pending['channel_fields'] = list(state[:5])
        self.pending['channel_flags'] = state[34]
        self.events.append(self.pending)

    def _call(self, address, args=()):
        self.uc.reg_write(UC_ARM_REG_SP, STACK)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN)
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2), args):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(address, RETURN, count=2_000_000)
        if self.uc.reg_read(UC_ARM_REG_PC) != RETURN:
            raise RuntimeError('Runtime instruction limit exceeded')

    def pattern(self, pid, active_channels=64):
        if not 0 <= pid < len(self.pattern_ptrs):
            raise ValueError('Pattern index outside bank')
        if not 1 <= active_channels <= 64:
            raise ValueError('Channel count must be between 1 and 64')
        ptr = self.pattern_ptrs[pid]
        length = word(self.bank, ptr)
        self.payload = self.bank[ptr+4:ptr+4+length+1]
        self.payload_length = len(self.payload)
        if self.payload_length != length+1 or self.payload_length > 0x10000:
            raise ValueError('Invalid pattern length')
        self.uc.mem_write(STATE, bytes(0x1000))
        self.uc.mem_write(STATE+8, struct.pack('<II', ORDERS, PATTERNS))
        self.uc.mem_write(STATE+38, bytes([active_channels]))
        self.uc.mem_write(ORDERS, b'\0')
        self.uc.mem_write(PATTERNS, struct.pack('<I', BLOB))
        self.uc.mem_write(self.slots, struct.pack('<I', STATE))
        self.uc.mem_write(self.active, struct.pack('<I', STATE))
        self.uc.mem_write(BLOB, self.payload+bytes(0x10000-self.payload_length))
        self.row_starts, self.max_read = [], 0
        rows = self.payload[0]+1
        self._call(self.profile.code(SEEK), (0, 0, rows))
        seek_end = self._u32(STATE+0x14)-BLOB
        self.uc.mem_write(STATE+0x14, struct.pack('<I', BLOB+1))
        decoded = []
        for row in range(rows):
            start = self._u32(STATE+0x14)-BLOB
            if start != self.row_starts[row]:
                raise AssertionError(f'Row reader/seek disagreement: pattern {pid}, row {row}')
            self.events = []
            self._call(self.profile.code(READ_ROW) | 1)
            decoded.append(dict(row=row, start=start,
                                end=self._u32(STATE+0x14)-BLOB, events=self.events))
        reader_end = self._u32(STATE+0x14)-BLOB
        if reader_end != seek_end or reader_end != self.payload_length:
            raise AssertionError(f'Pattern {pid} was not consumed exactly')
        return dict(pattern=pid, source_offset=ptr, payload_length=self.payload_length,
                    rows=decoded)

    def module_patterns(self, index):
        modules = struct.unpack_from(f'<{(self.banks[1]-self.banks[0])//4}I', self.bank, self.banks[0])
        if not 0 <= index < len(modules):
            raise ValueError('Module index outside bank')
        ptr = modules[index]
        orders, instruments, samples, patterns = self.bank[ptr+4:ptr+8]
        channels = self.bank[ptr+10]
        offset = ptr+12+2*channels
        order_list = list(self.bank[offset:offset+orders])
        offset += orders+2*instruments+2*samples
        ids = struct.unpack_from(f'<{patterns}H', self.bank, offset)
        return channels, order_list, ids


BASE, STACK, RETURN = 0x02000000, 0x023ff000, 0x023fe000


HEAP, HEAP_SIZE = 0x02400000, 0x01000000


ACTIVE, SLOTS, ENGINE, MIX_CHANNELS = 0x02142394, 0x021423a0, 0x02142708, 0x02142408


FILE = 0x02204000


class SongMachine:
    def __new__(cls, code, bank, *args, **kwargs):
        if cls is SongMachine and profile_for(code).runtime == 'urbz':
            # The standalone build includes this class in the same script.
            if 'UrbzSongMachine' in globals():
                adapter = globals()['UrbzSongMachine']
            else:
                from analysis.urbz_runtime import UrbzSongMachine
                adapter = UrbzSongMachine
            if not issubclass(adapter, cls):
                return adapter(code, bank, *args, **kwargs)
            return object.__new__(adapter)
        if cls is SongMachine and profile_for(code).runtime == 'spyro':
            if 'SpyroSongMachine' in globals():
                adapter = globals()['SpyroSongMachine']
            else:
                from analysis.spyro_runtime import SpyroSongMachine
                adapter = SpyroSongMachine
            if not issubclass(adapter, cls):
                return adapter(code, bank, *args, **kwargs)
            return object.__new__(adapter)
        return object.__new__(cls)

    def __init__(self, code, bank, trace_ticks=False):
        self.profile = profile_for(code)
        self.sample_rate = 32768
        self.engine = self.profile.data(ENGINE)
        self.active = self.profile.data(ACTIVE)
        self.slots = self.profile.data(SLOTS)
        self.mix_channels = self.profile.data(MIX_CHANNELS)
        self.bank = bank
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.mem_map(BASE, 0x400000)
        self.uc.mem_write(BASE, code)
        self.uc.mem_map(HEAP, HEAP_SIZE)
        self.uc.mem_map(0x01ff8000, 0x8000)
        # Reproduce the ARM9 startup copy table, including its real ITCM mixer.
        for section in MainCodeFile(code, BASE).sections:
            self.uc.mem_write(section.ramAddress, bytes(section.data))
        self.uc.mem_map(0x04000000, 0x10000)
        self.heap_next = HEAP
        self.file_pos = 0
        self.allocations = []
        self.rows = []
        self.tick = 0
        self.state = None
        self.active_row = None
        self.frame_total = 0
        self.rendering = False
        self.render_start = 0
        self.ticks = []
        if trace_ticks:
            self.uc.hook_add(UC_HOOK_CODE, self._tick_exit, begin=self.profile.code(0x020d3d20), end=self.profile.code(0x020d3d20))
        self.uc.hook_add(UC_HOOK_CODE, self._tick_entry, begin=self.profile.code(0x020d3b7c), end=self.profile.code(0x020d3b7c))
        self.uc.hook_add(UC_HOOK_CODE, self._platform, begin=self.profile.code(0x020ff61c), end=self.profile.code(0x020ff61c))
        self.uc.hook_add(UC_HOOK_CODE, self._platform, begin=self.profile.code(0x020ff688), end=self.profile.code(0x020ff688))
        self.uc.hook_add(UC_HOOK_CODE, self._platform, begin=self.profile.code(0x02046580), end=self.profile.code(0x02046580))
        self.uc.hook_add(UC_HOOK_CODE, self._platform, begin=self.profile.code(0x020fad58), end=self.profile.code(0x020fad58))
        self.uc.hook_add(UC_HOOK_CODE, self._platform, begin=self.profile.code(0x020fd2d4), end=self.profile.code(0x020fd2d4))
        self.uc.hook_add(UC_HOOK_MEM_READ, self._division, begin=0x040002a0, end=0x040002af)
        self.uc.hook_add(UC_HOOK_CODE, self._row_entry, begin=self.profile.code(0x020d2864), end=self.profile.code(0x020d2864))
        self.uc.hook_add(UC_HOOK_CODE, self._row_exit, begin=self.profile.code(0x020d2a94), end=self.profile.code(0x020d2a94))
        # File handle address is held directly in the loader's literal pool.
        # Original loaders use the handle structure at 0x21423c4. File adapters
        # update its cursor fields at +32/+40 as the original callers expect.
        # Execute the engine's allocation, dither-table generation, and defaults
        # initialization block. Stop before Nintendo's device/FIFO setup calls.
        self.uc.reg_write(UC_ARM_REG_SP, STACK)
        self.uc.emu_start(self.profile.code(0x020d8f80), self.profile.code(0x020d9054), count=100000)
        if self.uc.reg_read(UC_ARM_REG_PC) != self.profile.code(0x020d9054):
            raise RuntimeError('Engine initialization did not finish')
        # Copy the real mixer dispatch table (the game does this immediately
        # after its platform-device setup).
        self.uc.emu_start(self.profile.code(0x020d9080), self.profile.code(0x020d9090), count=10000)
        # Engine sample rate is needed by the original tempo calculation.
        self.uc.mem_write(self.engine+0x12, struct.pack('<H', 32768))

    def module_header(self):
        return bytes(self.uc.mem_read(self.state, 60))

    def channel_address(self, channel):
        return self.state+60+36*channel

    def u32(self, address):
        return struct.unpack('<I', self.uc.mem_read(address, 4))[0]

    def _return(self, value=0):
        self.uc.reg_write(UC_ARM_REG_R0, value & 0xffffffff)
        self.uc.reg_write(UC_ARM_REG_PC, self.uc.reg_read(UC_ARM_REG_LR))

    def _platform(self, uc, address, size, context):
        a, b, c = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        if address == self.profile.code(0x02046580):
            size = (a+3)&~3
            ptr = self.heap_next
            self.heap_next += size
            if self.heap_next > 0x027e0000:
                raise MemoryError('Harness heap exhausted')
            self.allocations.append(dict(address=ptr, size=a))
            self._return(ptr)
        elif address == self.profile.code(0x020ff61c):
            signed = b if b < 0x80000000 else b-0x100000000
            origin = (0, self.file_pos, len(self.bank))[c]
            self.file_pos = origin+signed
            if not 0 <= self.file_pos <= len(self.bank):
                raise ValueError('File seek outside bank')
            uc.mem_write(a+32, struct.pack('<I', 0))
            uc.mem_write(a+40, struct.pack('<I', self.file_pos))
            self._return(1)
        elif address == self.profile.code(0x020ff688):
            data = self.bank[self.file_pos:self.file_pos+c]
            if len(data) != c:
                raise ValueError('File read past bank')
            uc.mem_write(b, data)
            self.file_pos += c
            uc.mem_write(a+40, struct.pack('<I', self.file_pos))
            self._return(c)
        else:
            # Cache publication and starting ARM7 output have no host devices.
            self._return(0)

    def _division(self, uc, access, address, size, value, context):
        mode = self.u32(0x04000280)&3
        def signed(raw, bits):
            raw &= (1 << bits)-1
            return raw-(1 << bits) if raw&(1 << (bits-1)) else raw
        num = struct.unpack('<Q', uc.mem_read(0x04000290, 8))[0]
        den = struct.unpack('<Q', uc.mem_read(0x04000298, 8))[0]
        num = signed(num, 32 if mode == 0 else 64)
        raw_den = den
        den = signed(den, 64 if mode == 2 else 32)
        bits = 32 if mode == 0 else 64
        overflow = den == 0 or (num == -(1 << (bits-1)) and den == -1)
        if den == 0:
            # DS divider returns a result even for duplicate envelope ticks.
            quotient, remainder = (1 if num < 0 else -1), num
        elif overflow:
            quotient, remainder = num, 0
        else:
            quotient = abs(num)//abs(den)
            if (num < 0) != (den < 0):
                quotient = -quotient
            remainder = num-quotient*den
        raw_quotient = quotient&0xffffffffffffffff
        if mode == 0 and overflow:
            raw_quotient ^= 0xffffffff00000000
        uc.mem_write(0x040002a0, struct.pack('<QQ', raw_quotient, remainder&0xffffffffffffffff))
        control = self.u32(0x04000280)&~0xc000
        uc.mem_write(0x04000280,struct.pack('<I',control|(0x4000 if raw_den == 0 else 0)))

    def _row_entry(self, uc, address, size, context):
        state = self.u32(self.active)
        order = bytes(uc.mem_read(state+43, 1))[0]
        orders = self.u32(state+8)
        pattern = bytes(uc.mem_read(orders+order, 1))[0]
        ptr = self.u32(self.u32(state+12)+4*pattern)
        remaining = struct.unpack('<H', uc.mem_read(state+34, 2))[0]
        row = bytes(uc.mem_read(ptr, 1))[0]-remaining
        self.active_row = dict(tick=self.tick, order=order, pattern=pattern, row=row,
                               cursor_start=self.u32(state+20)-ptr)
        if self.rendering:
            self.active_row['frame'] = self.frame_total+(self.u32(self.engine+4)-self.render_start)%2048

    def _tick_entry(self, uc, address, size, context):
        if self.rendering:
            self.tick += 1

    def _row_exit(self, uc, address, size, context):
        state = self.u32(self.active)
        channels = bytes(uc.mem_read(state+38, 1))[0]
        self.active_row['channels'] = [list(uc.mem_read(state+60+36*i, 36)) for i in range(channels)]
        self.active_row['voices'] = [list(uc.mem_read(state+0x93c+32*i, 32)) for i in range(32)]
        self.active_row['speed'] = bytes(uc.mem_read(state+46, 1))[0]
        self.active_row['tempo'] = bytes(uc.mem_read(state+45, 1))[0]
        self.rows.append(self.active_row)

    def _tick_exit(self, uc, address, size, context):
        state = self.u32(self.active)
        if not self.rendering or state != self.state:
            return
        channels = bytes(uc.mem_read(state+38, 1))[0]
        voice_count = bytes(uc.mem_read(self.engine+16, 1))[0]
        slot = bytes(uc.mem_read(state+59, 1))[0]
        owners = bytes(uc.mem_read(self.engine+1588, voice_count))
        mixer = [list(uc.mem_read(self.mix_channels+24*i, 24)) for i in range(voice_count)]
        self.ticks.append(dict(tick=self.tick,
                               frame=self.frame_total+(self.u32(self.engine+4)-self.render_start)%2048,
                               row_index=len(self.rows)-1,
                               global_volume=bytes(uc.mem_read(state+44, 1))[0],
                               channels=[list(uc.mem_read(state+60+36*i, 36)) for i in range(channels)],
                               voices=[list(uc.mem_read(state+0x93c+32*i, 32)) for i in range(voice_count)],
                               mixer=mixer,
                               active_voices=sum(owner == slot and any(entry[:4])
                                                 for owner, entry in zip(owners, mixer)),
                               mixing_voices=sum(owner == slot and any(entry[:4]) and any(entry[12:16])
                                                 for owner, entry in zip(owners, mixer))))

    def call(self, address, args=(), limit=20_000_000):
        self.uc.reg_write(UC_ARM_REG_SP, STACK)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN)
        for reg, val in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2), args):
            self.uc.reg_write(reg, val)
        try:
            self.uc.emu_start(address, RETURN, count=limit)
        except Exception as exc:
            raise RuntimeError(f'Original routine {address:#x} failed at PC {self.uc.reg_read(UC_ARM_REG_PC):#x}: {exc}') from exc
        if self.uc.reg_read(UC_ARM_REG_PC) != RETURN:
            raise RuntimeError(f'Instruction limit at {self.uc.reg_read(UC_ARM_REG_PC):#x}')
        return self.uc.reg_read(UC_ARM_REG_R0)

    def load(self, module):
        banks = struct.unpack_from('<10I', self.bank)
        if not 0 <= module < (banks[1]-banks[0])//4:
            raise ValueError('Module index outside bank')
        # Slot 2 follows the same sequencer while avoiding slot-0 device setup.
        self.call(self.profile.code(0x020d4850), (2, module, 0))
        self.state = self.u32(self.slots+8)
        return self.state

    def run(self, ticks):
        if self.state is None or ticks < 1:
            raise ValueError('Load a song and provide a positive tick count')
        for tick in range(ticks):
            self.tick = tick
            self.call(self.profile.code(0x020d3b7c), (2,))
            if bytes(self.uc.mem_read(self.state+40, 1))[0] == 0:
                break
        return self.rows

    def render(self, seconds, path, chunk_frames=2048):
        """Execute the real scheduler and ITCM mixer into its stereo ring."""
        if seconds <= 0 or not 4 <= chunk_frames <= 2048 or chunk_frames%4:
            raise ValueError('Positive duration and a chunk size divisible by four (4..2048) required')
        if self.state is None:
            raise ValueError('Load a song before rendering')
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.rendering = True
        self.tick = -1
        frames = int(seconds*32768)
        frames = (frames+3)&~3
        with wave.open(str(path), 'wb') as out:
            out.setnchannels(2)
            out.setsampwidth(2)
            out.setframerate(32768)
            while self.frame_total < frames:
                count = min(chunk_frames, frames-self.frame_total)
                start = self.u32(self.engine+4)
                self.render_start = start
                # Use the original scheduler's forced-count path. Bit 8 only
                # controls host/device scheduling; bit 4 enables stereo mixing.
                flags = self.u32(self.engine+12)
                self.uc.mem_write(self.engine+12, struct.pack('<I', (flags&~4)|8|0x10))
                self.uc.mem_write(self.profile.data(0x02142d08)+0x60, struct.pack('<H', count))
                self.call(self.profile.code(0x020d8934))
                ring = self.u32(self.engine)
                left = bytes(self.uc.mem_read(ring, 4096))
                right = bytes(self.uc.mem_read(ring+4096, 4096))
                stereo = bytearray(count*4)
                for i in range(count):
                    pos = ((start+i)%2048)*2
                    stereo[i*4:i*4+2] = left[pos:pos+2]
                    stereo[i*4+2:i*4+4] = right[pos:pos+2]
                out.writeframesraw(stereo)
                self.frame_total += count
        self.rendering = False
        return self.rows


class UrbzSongMachine(SongMachine):
    def __init__(self, code, bank, trace_ticks=False):
        self.profile = profile_for(code)
        self.bank = bytes(bank)
        if hashlib.sha256(self.bank).hexdigest() != self.profile.bank_sha256:
            raise ValueError('Music bank does not match the selected runtime')
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.mem_map(BASE, 0x400000)
        self.uc.mem_write(BASE, code)
        self.uc.mem_map(HEAP, HEAP_SIZE)
        self.uc.mem_map(0x01ff8000, 0x8000)
        for section in MainCodeFile(code, BASE).sections:
            self.uc.mem_write(section.ramAddress, bytes(section.data))
        self.uc.mem_map(0x04000000, 0x10000)
        self.state = struct.unpack_from('<I', code, self.addr(0x020953b8)-BASE)[0]
        self.engine = struct.unpack_from('<I', code, self.addr(0x020953bc)-BASE)[0]
        self.mix_channels = struct.unpack_from('<I', code, self.addr(0x020953c0)-BASE)[0]
        self.voice_base = struct.unpack_from('<I', code, self.addr(0x020953c4)-BASE)[0]
        self.sound_state = struct.unpack_from('<I', code, self.addr(0x020953c8)-BASE)[0]
        self.heap_next, self.file_pos = HEAP, 0
        self.allocations, self.rows, self.ticks = [], [], []
        self.tick, self.frame_total = 0, 0
        self.rendering, self.render_start = False, 0
        self.active_row = None
        # Ordinary host allocation, FS operations and output-device calls only.
        self.platform_addresses = [0x0204e518, 0x020bad50, 0x020bad94,
                                   0x020baf70, 0x020badfc, 0x020bae68, 0x020baf24,
                                   0x020b8a24, 0x020b89f0, 0x020b8b60,
                                   0x020b8bd0, 0x020b8c40]
        for address in self.platform_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._urbz_platform,
                             begin=self.addr(address), end=self.addr(address))
        self.uc.hook_add(UC_HOOK_MEM_READ, self._division, begin=0x040002a0, end=0x040002af)
        self.uc.hook_add(UC_HOOK_CODE, self._tick_entry, begin=self.addr(0x02094cac), end=self.addr(0x02094cac))
        self.uc.hook_add(UC_HOOK_CODE, self._urbz_row_entry, begin=self.addr(0x02094f18), end=self.addr(0x02094f18))
        self.uc.hook_add(UC_HOOK_CODE, self._urbz_row_exit, begin=self.addr(0x0209519c), end=self.addr(0x0209519c))
        if trace_ticks:
            self.uc.hook_add(UC_HOOK_CODE, self._urbz_tick_exit, begin=self.addr(0x020953ac), end=self.addr(0x020953ac))
        self.call(self.addr(0x02098488))
        # Select full host output volume through the original public setters.
        # EUR initialization restores saved-game volume preferences, which are
        # absent in this isolated harness; USA/JPN initialize these to 127.
        self.call(self.addr(0x02097bcc), (127,))
        self.call(self.addr(0x02097ba0), (127,))
        self.sample_rate = self.u32(self.engine+8)

    def addr(self, address):
        return self.profile.code(address)

    def _urbz_platform(self, uc, address, size, context):
        a, b, c = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        original = self.platform_addresses[[self.addr(x) for x in self.platform_addresses].index(address)]
        if original == 0x0204e518:
            ptr = self.heap_next
            self.heap_next += (a+31)&~31
            if self.heap_next > 0x027c0000:
                raise MemoryError('Harness heap exhausted')
            self.allocations.append(dict(address=ptr, size=a))
            self._return(ptr)
        elif original == 0x020bad94:
            uc.mem_write(b, struct.pack('<4I', 1, 1, 0, len(self.bank)))
            self._return(1)
        elif original == 0x020badfc:
            signed = b if b < 0x80000000 else b-0x100000000
            self.file_pos = (0, self.file_pos, len(self.bank))[c]+signed
            if not 0 <= self.file_pos <= len(self.bank):
                raise ValueError('File seek outside bank')
            uc.mem_write(a+32, struct.pack('<I', 0))
            uc.mem_write(a+40, struct.pack('<I', self.file_pos))
            self._return(1)
        elif original == 0x020bae68:
            data = self.bank[self.file_pos:self.file_pos+c]
            if len(data) != c:
                raise ValueError('File read past bank')
            uc.mem_write(b, data)
            self.file_pos += c
            uc.mem_write(a+40, struct.pack('<I', self.file_pos))
            self._return(c)
        elif original in (0x020bad50, 0x020baf70, 0x020baf24):
            self._return(1)
        else:
            self._return(0)

    def channel_address(self, channel):
        return self.state+44+36*channel

    def module_header(self):
        # Present loader fields to the common structural IT writer. This copy
        # never changes the state consumed by cartridge instructions.
        native = bytes(self.uc.mem_read(self.state, 44))
        header = bytearray(60)
        header[:16] = native[:16]
        header[38], header[40] = native[26], native[28]
        header[43] = native[31]
        header[44:52] = native[32:40]
        return bytes(header)

    def load(self, module):
        banks = struct.unpack_from('<10I', self.bank)
        if not 0 <= module < (banks[1]-banks[0])//4:
            raise ValueError('Module index outside bank')
        self.call(self.addr(0x02095a30), (module, 2))
        self.sample_rate = self.u32(self.engine+8)
        return self.state

    def _urbz_row_entry(self, uc, address, size, context):
        order = bytes(uc.mem_read(self.state+31, 1))[0]
        pattern = bytes(uc.mem_read(self.u32(self.state+8)+order, 1))[0]
        ptr = self.u32(self.u32(self.state+12)+4*pattern)
        remaining = struct.unpack('<H', uc.mem_read(self.state+22, 2))[0]
        row = bytes(uc.mem_read(ptr, 1))[0]-remaining
        self.active_row = dict(tick=self.tick, order=order, pattern=pattern, row=row,
                               cursor_start=self.u32(self.state+16)-ptr)
        if self.rendering:
            self.active_row['frame'] = self.frame_total+self.render_offset()

    def _urbz_row_exit(self, uc, address, size, context):
        header = self.module_header()
        self.active_row.update(channels=[list(uc.mem_read(self.channel_address(i),36)) for i in range(header[38])],
                               voices=[list(uc.mem_read(self.voice_base+32*i,32)) for i in range(32)],
                               speed=header[46], tempo=header[45])
        self.rows.append(self.active_row)

    def _urbz_tick_exit(self, uc, address, size, context):
        if not self.rendering:
            return
        header = self.module_header()
        count = bytes(uc.mem_read(self.engine+34, 1))[0]
        mixer = [list(uc.mem_read(self.mix_channels+24*i,24)) for i in range(count)]
        reserved = self.u32(self.sound_state+596)
        self.ticks.append(dict(tick=self.tick, frame=self.frame_total+self.render_offset(),
                               row_index=len(self.rows)-1, global_volume=header[44],
                               channels=[list(uc.mem_read(self.channel_address(i),36)) for i in range(header[38])],
                               voices=[list(uc.mem_read(self.voice_base+32*i,32)) for i in range(count)],
                               mixer=mixer, active_voices=sum(not(reserved&(1<<i)) and any(m[:4]) for i,m in enumerate(mixer)),
                               mixing_voices=sum(not(reserved&(1<<i)) and any(m[:4]) and any(m[12:16]) for i,m in enumerate(mixer))))

    def run(self, ticks):
        if ticks < 1:
            raise ValueError('Positive tick count required')
        for tick in range(ticks):
            self.tick = tick
            self.call(self.addr(0x02094cac))
            if bytes(self.uc.mem_read(self.state+28,1))[0] == 0:
                break
        return self.rows

    def render_offset(self):
        ring = self.u32(self.engine+4)
        return ((self.u32(self.engine)-ring)//2-self.render_start)%2048

    def render(self, seconds, path, chunk_frames=2048):
        if seconds <= 0 or not 4 <= chunk_frames <= 2048 or chunk_frames%4:
            raise ValueError('Positive duration and chunk size divisible by four (4..2048) required')
        path = Path(path)
        path.parent.mkdir(parents=True,exist_ok=True)
        self.rendering, self.tick = True, -1
        frames = (int(seconds*self.sample_rate)+3)&~3
        with wave.open(str(path),'wb') as out:
            out.setnchannels(2); out.setsampwidth(2); out.setframerate(self.sample_rate)
            while self.frame_total < frames:
                count = min(chunk_frames,frames-self.frame_total)
                ring = self.u32(self.engine+4)
                start = (self.u32(self.engine)-ring)//2
                self.render_start = start
                # Original software scheduler: set its pending sample count.
                # Clear device restart flag to avoid ARM7/FIFO setup.
                flags = self.u32(self.engine+20)
                status = bytes(self.uc.mem_read(self.state+28,1))[0]
                self.uc.mem_write(self.state+28,bytes([status&0x7f]))
                self.uc.mem_write(self.engine+20,struct.pack('<I',(flags&~(4|8))|1|2))
                self.uc.mem_write(self.engine+28,struct.pack('<H',count))
                self.call(self.addr(0x02097ec0))
                left = bytes(self.uc.mem_read(ring,4096))
                right = bytes(self.uc.mem_read(ring+4096,4096))
                stereo = bytearray(count*4)
                for i in range(count):
                    pos = ((start+i)%2048)*2
                    stereo[i*4:i*4+2] = left[pos:pos+2]
                    stereo[i*4+2:i*4+4] = right[pos:pos+2]
                out.writeframesraw(stereo)
                self.frame_total += count
        self.rendering = False
        return self.rows


class UrbzPatterns(RuntimePatterns):
    def __init__(self, code, bank):
        self.code, self.bank = code, bytes(bank)
        self.code_hash = hashlib.sha256(code).hexdigest()
        self.profile = profile_for(code)
        if hashlib.sha256(self.bank).hexdigest() != self.profile.bank_sha256:
            raise ValueError('Music bank does not match the selected runtime')
        self.banks = struct.unpack_from('<10I', bank)
        count = (self.banks[4]-self.banks[3])//4
        self.pattern_ptrs = struct.unpack_from(f'<{count}I', bank, self.banks[3])
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.mem_map(BASE,0x400000)
        self.uc.mem_write(BASE,code)
        self.uc.mem_map(BLOB,0x10000)
        self.state = struct.unpack_from('<I',code,self.addr(0x020953b8)-BASE)[0]
        self.orders, self.pattern_table = 0x02201000,0x02202000
        for address, callback in [(0x020955d0,self._urbz_seek_row),
                                  (0x02094f64,self._urbz_packet_start),
                                  (0x0209505c,self._urbz_fields),
                                  (0x02095144,self._urbz_skip),
                                  (0x0209518c,self._urbz_packet_end)]:
            self.uc.hook_add(UC_HOOK_CODE,callback,begin=self.addr(address),end=self.addr(address))
        self.uc.hook_add(UC_HOOK_MEM_READ,self._read,begin=BLOB,end=BLOB+0xffff)

    def addr(self,address):
        return self.profile.code(address)

    def _urbz_seek_row(self,uc,address,size,context):
        self.row_starts.append(self._u32(self.state+16)-BLOB)

    def _urbz_packet_start(self,uc,address,size,context):
        self.event_start = self._u32(self.state+16)-BLOB

    def _urbz_fields(self,uc,address,size,context):
        values = dict(note=uc.reg_read(UC_ARM_REG_R7),instrument=uc.reg_read(UC_ARM_REG_LR),
                      volume=uc.reg_read(UC_ARM_REG_R12),command=uc.reg_read(UC_ARM_REG_R3),
                      parameter=uc.reg_read(UC_ARM_REG_R2))
        end = self._u32(self.state+16)-BLOB
        self.pending = dict(offset=self.event_start,end=end,channel=uc.reg_read(UC_ARM_REG_R4),
                            raw=self.payload[self.event_start:end].hex(),
                            fields={k:v for k,v in values.items() if v != 255})
        if values['command'] != 255:
            self.pending['fields']['parameter'] = values['parameter']

    def _urbz_skip(self,uc,address,size,context):
        uc.reg_write(UC_ARM_REG_PC,self.addr(0x0209518c))

    def _urbz_packet_end(self,uc,address,size,context):
        state = bytes(uc.mem_read(self.state+44+36*self.pending['channel'],36))
        self.pending['channel_fields'] = list(state[:5])
        self.pending['channel_flags'] = state[34]
        self.events.append(self.pending)

    def pattern(self,pid,active_channels=64):
        if not 0 <= pid < len(self.pattern_ptrs) or not 1 <= active_channels <= 64:
            raise ValueError('Pattern index or channel count outside range')
        ptr = self.pattern_ptrs[pid]
        length = struct.unpack_from('<I',self.bank,ptr)[0]
        self.payload = self.bank[ptr+4:ptr+5+length]
        self.payload_length = len(self.payload)
        if self.payload_length != length+1 or self.payload_length > 0x10000:
            raise ValueError('Invalid pattern length')
        self.uc.mem_write(self.state,bytes(0x1000))
        self.uc.mem_write(self.state+8,struct.pack('<II',self.orders,self.pattern_table))
        self.uc.mem_write(self.state+26,bytes([active_channels]))
        self.uc.mem_write(self.orders,b'\0')
        self.uc.mem_write(self.pattern_table,struct.pack('<I',BLOB))
        self.uc.mem_write(BLOB,self.payload+bytes(0x10000-self.payload_length))
        rows = self.payload[0]+1
        self.row_starts,self.max_read = [],0
        self._call(self.addr(0x020954c8),(0,rows))
        seek_end = self.row_starts.pop()
        self.uc.mem_write(self.state+16,struct.pack('<I',BLOB+1))
        decoded = []
        for row in range(rows):
            start = self._u32(self.state+16)-BLOB
            if start != self.row_starts[row]:
                raise AssertionError(f'Row reader/seek disagreement: pattern {pid}, row {row}')
            self.events = []
            self.uc.reg_write(UC_ARM_REG_SP,STACK)
            self.uc.emu_start(self.addr(0x02094f18),self.addr(0x0209519c),count=2_000_000)
            if self.uc.reg_read(UC_ARM_REG_PC) != self.addr(0x0209519c):
                raise RuntimeError('Original Urbz row reader instruction limit')
            self.uc.emu_start(self.addr(0x020951b0),self.addr(0x020951c0),count=10)
            decoded.append(dict(row=row,start=start,end=self._u32(self.state+16)-BLOB,events=self.events))
        if self._u32(self.state+16)-BLOB != seek_end or seek_end != self.payload_length:
            raise AssertionError(f'Pattern {pid} was not consumed exactly')
        return dict(pattern=pid,source_offset=ptr,payload_length=self.payload_length,rows=decoded)


class SpyroSongMachine(SongMachine):
    def __init__(self, code, bank, trace_ticks=False, repair_runtime=True):
        self.profile = profile_for(code)
        self.bank = bytes(bank)
        if hashlib.sha256(self.bank).hexdigest() != self.profile.bank_sha256:
            raise ValueError('Music bank does not match the selected runtime')
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.mem_map(BASE,0x400000)
        self.uc.mem_write(BASE,code)
        self.uc.mem_map(HEAP,HEAP_SIZE)
        self.uc.mem_map(0x01ff8000,0x8000)
        for section in MainCodeFile(code,BASE).sections:
            self.uc.mem_write(section.ramAddress,bytes(section.data))
        self.repair_runtime = repair_runtime
        self.runtime_adjustments = []
        if repair_runtime:
            # Reserve enough stack for every possible unsigned-byte sample count.
            for source_address,expected,replacement in ((0x0202693c,0xe24ddf45,0xe24ddc03),
                                                        (0x02026cb4,0xe28ddf45,0xe28ddc03)):
                address = self.addr(source_address)
                if struct.unpack('<I',self.uc.mem_read(address,4))[0] != expected:
                    raise ValueError('Unexpected original Spyro sample-loader stack instruction')
                self.uc.mem_write(address,struct.pack('<I',replacement))
                self.runtime_adjustments.append(dict(kind='loader_stack_capacity',address=address,
                                                    original=expected,replacement=replacement,
                                                    original_frame_bytes=0x114,frame_bytes=0x300))
            # The third envelope is pitch OR filter; filter DSP is unsupported.
            # Check at pitch evaluation, so S7 envelope-enable commands cannot
            # reintroduce the bug. All original envelope/tick state still advances.
            guard = 0x023fd000
            address = self.addr(0x02023c30)
            expected = 0xe2100020  # ANDS r0,r0,#32
            if struct.unpack('<I',self.uc.mem_read(address,4))[0] != expected:
                raise ValueError('Unexpected original Spyro pitch-envelope instruction')
            instructions = (0xe2100020,  # ANDS r0,r0,#32 (pitch envelope active)
                            0x012fff1e,  # BXEQ lr
                            0xe5d62005,  # LDRB r2,[r6,#5] (instrument)
                            0xe591c004,  # LDR ip,[r1,#4] (instrument table)
                            0xe08cc282,  # ADD ip,ip,r2,LSL #5
                            0xe59cc01c,  # LDR ip,[ip,#28] (third envelope)
                            0xe5dcc008,  # LDRB ip,[ip,#8] (envelope flags)
                            0xe31c0080,  # TST ip,#128 (filter)
                            0x13a00000,  # MOVNE r0,#0
                            0xe2100020,  # ANDS r0,r0,#32
                            0xe12fff1e)  # BX lr
            self.uc.mem_write(guard,struct.pack('<11I',*instructions))
            branch = 0xeb000000|(((guard-address-8)//4)&0xffffff)
            self.uc.mem_write(address,struct.pack('<I',branch))
            self.runtime_adjustments.append(dict(kind='filter_envelope_pitch_guard',address=address,
                                                original=expected,replacement=branch,guard_address=guard,
                                                detail='Unsupported filter envelopes are ignored by rendering, not applied to pitch; source IT filter data remains intact'))
            # Pitch envelopes are semitone offsets even in Amiga-slide songs.
            # Apply them separately through the cartridge's own linear helper;
            # regular slides/vibrato retain the original module-mode path.
            site = self.addr(0x02023c9c)
            original = struct.unpack('<I',self.uc.mem_read(site,4))[0]
            if original != 0xe0844440:  # ADD r4,r4,r0,ASR #8
                raise ValueError('Unexpected original Spyro pitch-envelope accumulation')
            wrapper = 0x023fd100
            active = struct.unpack_from('<I',code,self.addr(0x020265c4)-BASE)[0]
            words = [0xe92d404f,  # PUSH {r0-r3,r6,lr}
                     0xe1a01440,  # ASR r1,r0,#8 (envelope slide)
                     0xe1a00005,  # MOV r0,r5 (base frequency)
                     0xe59f2028,  # LDR r2,active literal
                     0xe5922000,  # LDR r2,[r2] (song)
                     0xe5d2302f,  # LDRB r3,[r2,#47]
                     0xe3836008,  # ORR r6,r3,#8 (linear helper)
                     0xe5c2602f,  # STRB r6,[r2,#47]
                     0xe92d000c]  # PUSH {r2,r3}
            address = wrapper+len(words)*4
            words += [0xeb000000|(((self.addr(0x02023040)-address-8)//4)&0xffffff),
                      0xe8bd000c,  # POP {r2,r3}
                      0xe5c2302f,  # STRB r3,[r2,#47] (restore mode)
                      0xe1a05000,  # MOV r5,r0 (transposed frequency)
                      0xe8bd404f,  # POP {r0-r3,r6,lr}
                      0xe12fff1e,  # BX lr
                      active]
            self.uc.mem_write(wrapper,struct.pack('<16I',*words))
            replacement = 0xeb000000|(((wrapper-site-8)//4)&0xffffff)
            self.uc.mem_write(site,struct.pack('<I',replacement))
            self.runtime_adjustments.append(dict(kind='linear_pitch_envelope',address=site,
                                                original=original,replacement=replacement,
                                                guard_address=wrapper,
                                                detail='Apply semitone pitch envelopes through original linear-slide helper independently of ordinary slide mode'))
        self.uc.mem_map(0x04000000,0x10000)
        self.active = struct.unpack_from('<I',code,self.addr(0x020265c4)-BASE)[0]
        self.slots = struct.unpack_from('<I',code,self.addr(0x02027ebc)-BASE)[0]
        self.engine = struct.unpack_from('<I',code,self.addr(0x02022eb4)-BASE)[0]
        self.mix_channels = struct.unpack_from('<I',code,self.addr(0x02022eb8)-BASE)[0]
        self.control = struct.unpack_from('<I',code,self.addr(0x02022a54)-BASE)[0]
        self.heap_next,self.file_pos = HEAP,0
        self.allocations,self.rows,self.ticks = [],[],[]
        self.tick,self.frame_total = 0,0
        self.state,self.active_row = None,None
        self.rendering,self.render_start = False,0
        self.platform_addresses = [0x0207ff70,0x020804ac,0x02080458,0x020803ac,0x020803d0,0x02080418,
                                   0x0209396c,0x02095930,0x020953a8,0x02095374,
                                   0x020954e4,0x020956a0,0x02095610]
        for address in self.platform_addresses:
            self.uc.hook_add(UC_HOOK_CODE,self._spyro_platform,begin=self.addr(address),end=self.addr(address))
        self.uc.hook_add(UC_HOOK_MEM_READ,self._division,begin=0x040002a0,end=0x040002af)
        self.uc.hook_add(UC_HOOK_CODE,self._tick_entry,begin=self.addr(0x02027974),end=self.addr(0x02027974))
        self.uc.hook_add(UC_HOOK_CODE,self._row_entry,begin=self.addr(0x0202627c),end=self.addr(0x0202627c))
        self.uc.hook_add(UC_HOOK_CODE,self._row_exit,begin=self.addr(0x020265b8),end=self.addr(0x020265b8))
        if trace_ticks:
            self.uc.hook_add(UC_HOOK_CODE,self._spyro_tick_exit,begin=self.addr(0x02027ab8),end=self.addr(0x02027ab8))
        self.call(self.addr(0x02022d94))
        self.sample_rate = struct.unpack('<H',self.uc.mem_read(self.engine+18,2))[0]

    def addr(self,address):
        return self.profile.code(address)

    def _spyro_platform(self,uc,address,size,context):
        a,b,c,d = [uc.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
        original = self.platform_addresses[[self.addr(x) for x in self.platform_addresses].index(address)]
        if original == 0x0207ff70:
            ptr = self.heap_next
            self.heap_next += (a+31)&~31
            if self.heap_next > 0x027c0000:
                raise MemoryError('Harness heap exhausted')
            self.allocations.append(dict(address=ptr,size=a))
            self._return(ptr)
        elif original == 0x020803ac:
            self._return(self.file_pos)
        elif original == 0x020803d0:
            signed = b if b < 0x80000000 else b-0x100000000
            self.file_pos = (0,self.file_pos,len(self.bank))[c]+signed
            if not 0 <= self.file_pos <= len(self.bank):
                raise ValueError('File seek outside bank')
            uc.mem_write(a+40,struct.pack('<I',self.file_pos))
            self._return(0)
        elif original == 0x02080418:
            count = b*c
            data = self.bank[self.file_pos:self.file_pos+count]
            if len(data) != count:
                raise ValueError('File read past bank')
            uc.mem_write(a,data)
            self.file_pos += count
            uc.mem_write(d+40,struct.pack('<I',self.file_pos))
            self._return(c)
        elif original == 0x020804ac:
            self.file_pos = 0
            uc.mem_write(a,bytes(72))
            self._return(1)
        else:
            self._return(0)

    def load(self,module):
        banks = struct.unpack_from('<10I',self.bank)
        if not 0 <= module < (banks[1]-banks[0])//4:
            raise ValueError('Module index outside bank')
        if not self.repair_runtime:
            pointer = struct.unpack_from('<I',self.bank,banks[0]+module*4)[0]
            count = self.bank[pointer+6]
            if count > 100:
                raise ValueError(f'Unmodified Spyro loader has a 100-entry stack sample list; module declares {count}')
        self.call(self.addr(0x02028438),(2,module,0))
        self.state = self.u32(self.slots+8)
        return self.state

    def run(self,ticks):
        if self.state is None or ticks < 1:
            raise ValueError('Load a song and provide positive ticks')
        for tick in range(ticks):
            self.tick = tick
            self.call(self.addr(0x02027974),(2,))
            if bytes(self.uc.mem_read(self.state+40,1))[0] == 0:
                break
        return self.rows

    def _spyro_tick_exit(self,uc,address,size,context):
        if not self.rendering or self.u32(self.active) != self.state:
            return
        channels = self.module_header()[38]
        count = bytes(uc.mem_read(self.engine+16,1))[0]
        slot = bytes(uc.mem_read(self.state+59,1))[0]
        owners = bytes(uc.mem_read(self.engine+1372,count))
        mixer = [list(uc.mem_read(self.mix_channels+24*i,24)) for i in range(count)]
        self.ticks.append(dict(tick=self.tick,frame=self.frame_total+(self.u32(self.engine+4)-self.render_start)%2048,
                               row_index=len(self.rows)-1,global_volume=self.module_header()[44],
                               channels=[list(uc.mem_read(self.channel_address(i),36)) for i in range(channels)],
                               voices=[list(uc.mem_read(self.state+0x93c+32*i,32)) for i in range(count)],mixer=mixer,
                               active_voices=sum(o==slot and any(m[:4]) for o,m in zip(owners,mixer)),
                               mixing_voices=sum(o==slot and any(m[:4]) and any(m[12:16]) for o,m in zip(owners,mixer))))

    def render(self,seconds,path,chunk_frames=2048):
        path = Path(path)
        path.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent,suffix='.wav',delete=False) as handle:
            temporary = Path(handle.name)
        try:
            result = self._render_to_file(seconds,temporary,chunk_frames)
            temporary.replace(path)
            return result
        finally:
            self.rendering = False
            temporary.unlink(missing_ok=True)

    def _render_to_file(self,seconds,path,chunk_frames):
        if self.state is None or seconds <= 0 or not 4 <= chunk_frames <= 2048 or chunk_frames%4:
            raise ValueError('Load a song; positive duration and chunk size divisible by four required')
        path = Path(path)
        path.parent.mkdir(parents=True,exist_ok=True)
        self.rendering,self.tick = True,-1
        frames = (int(seconds*self.sample_rate)+3)&~3
        with wave.open(str(path),'wb') as out:
            out.setnchannels(2);out.setsampwidth(2);out.setframerate(self.sample_rate)
            while self.frame_total < frames:
                count = min(chunk_frames,frames-self.frame_total)
                start = self.u32(self.engine+4)
                self.render_start = start
                # Original timer scheduler forced-count path consumes bytes/2.
                # Bit 8 selects it; bit 4 enables software stereo mixing.
                flags = self.u32(self.engine+12)
                self.uc.mem_write(self.engine+12,struct.pack('<I',(flags&~4)|8|0x10))
                self.uc.mem_write(self.control+136,struct.pack('<H',count*2))
                self.call(self.addr(0x0202286c))
                ring = self.u32(self.engine)
                left,right = bytes(self.uc.mem_read(ring,4096)),bytes(self.uc.mem_read(ring+4096,4096))
                stereo = bytearray(count*4)
                for i in range(count):
                    pos = ((start+i)%2048)*2
                    stereo[i*4:i*4+2] = left[pos:pos+2]
                    stereo[i*4+2:i*4+4] = right[pos:pos+2]
                out.writeframesraw(stereo)
                self.frame_total += count
        self.rendering = False
        return self.rows


class SpyroPatterns(RuntimePatterns):
    def __init__(self,code,bank):
        self.code,self.bank = code,bytes(bank)
        self.profile = profile_for(code)
        self.code_hash = hashlib.sha256(code).hexdigest()
        if hashlib.sha256(self.bank).hexdigest() != self.profile.bank_sha256:
            raise ValueError('Music bank does not match the selected runtime')
        self.banks = struct.unpack_from('<10I',bank)
        count = (self.banks[4]-self.banks[3])//4
        self.pattern_ptrs = struct.unpack_from(f'<{count}I',bank,self.banks[3])
        self.uc = Uc(UC_ARCH_ARM,UC_MODE_ARM)
        self.uc.mem_map(BASE,0x400000)
        self.uc.mem_write(BASE,code)
        self.uc.mem_map(BLOB,0x10000)
        self.slots = struct.unpack_from('<I',code,self.addr(0x02027ebc)-BASE)[0]
        self.active = struct.unpack_from('<I',code,self.addr(0x02027ec0)-BASE)[0]
        for address,callback in [(0x02027e70,self._seek_row),(0x020262e4,self._packet_start),
                                  (0x02026468,self._spyro_fields),(0x02026554,self._spyro_skip),
                                  (0x02026598,self._packet_end)]:
            self.uc.hook_add(UC_HOOK_CODE,callback,begin=self.addr(address),end=self.addr(address))
        self.uc.hook_add(UC_HOOK_MEM_READ,self._read,begin=BLOB,end=BLOB+0xffff)

    def addr(self,address):
        return self.profile.code(address)

    def _spyro_fields(self,uc,address,size,context):
        values = dict(note=uc.reg_read(UC_ARM_REG_R7),instrument=uc.reg_read(UC_ARM_REG_LR),
                      volume=uc.reg_read(UC_ARM_REG_R12),command=uc.reg_read(UC_ARM_REG_R3),
                      parameter=uc.reg_read(UC_ARM_REG_R2))
        end = self._u32(STATE+20)-BLOB
        self.pending = dict(offset=self.event_start,end=end,channel=uc.reg_read(UC_ARM_REG_R4),
                            raw=self.payload[self.event_start:end].hex(),
                            fields={k:v for k,v in values.items() if v != 255})
        if values['command'] != 255:
            self.pending['fields']['parameter'] = values['parameter']&255

    def _spyro_skip(self,uc,address,size,context):
        uc.reg_write(UC_ARM_REG_PC,self.addr(0x02026598))

    def pattern(self,pid,active_channels=64):
        if not 0 <= pid < len(self.pattern_ptrs) or not 1 <= active_channels <= 64:
            raise ValueError('Pattern index or channel count outside range')
        ptr = self.pattern_ptrs[pid]
        length = struct.unpack_from('<I',self.bank,ptr)[0]
        self.payload = self.bank[ptr+4:ptr+5+length]
        self.payload_length = len(self.payload)
        if self.payload_length != length+1 or self.payload_length > 0x10000:
            raise ValueError('Invalid pattern length')
        self.uc.mem_write(STATE,bytes(0x1000))
        self.uc.mem_write(STATE+8,struct.pack('<II',ORDERS,PATTERNS))
        self.uc.mem_write(STATE+38,bytes([active_channels]))
        self.uc.mem_write(ORDERS,b'\0')
        self.uc.mem_write(PATTERNS,struct.pack('<I',BLOB))
        self.uc.mem_write(self.slots,struct.pack('<I',STATE))
        self.uc.mem_write(self.active,struct.pack('<I',STATE))
        self.uc.mem_write(BLOB,self.payload+bytes(0x10000-self.payload_length))
        rows = self.payload[0]+1
        self.row_starts,self.max_read = [],0
        self._call(self.addr(0x02027cec),(0,0,rows))
        seek_end = self.row_starts.pop()
        self.uc.mem_write(STATE+20,struct.pack('<I',BLOB+1))
        decoded = []
        for row in range(rows):
            start = self._u32(STATE+20)-BLOB
            if start != self.row_starts[row]:
                raise AssertionError(f'Row reader/seek disagreement: pattern {pid}, row {row}')
            self.events = []
            self._call(self.addr(0x0202627c))
            decoded.append(dict(row=row,start=start,end=self._u32(STATE+20)-BLOB,events=self.events))
        if self._u32(STATE+20)-BLOB != seek_end or seek_end != self.payload_length:
            raise AssertionError(f'Pattern {pid} was not consumed exactly')
        return dict(pattern=pid,source_offset=ptr,payload_length=self.payload_length,rows=decoded)


ROOT = Path(__file__).resolve().parent


def envelope(machine, pointer):
    block = bytearray(82)
    if not pointer:
        return bytes(block)
    header = bytes(machine.uc.mem_read(pointer+8, 6))
    count = header[1]
    if not 1 <= count <= 25:
        raise ValueError(f'Envelope has {count} points; IT supports at most 25')
    block[:6] = header
    ticks = bytes(machine.uc.mem_read(machine.u32(pointer), 2*count))
    values = bytes(machine.uc.mem_read(machine.u32(pointer+4), count))
    for i in range(count):
        block[6+3*i] = values[i]
        block[7+3*i:9+3*i] = ticks[2*i:2*i+2]
    return bytes(block)


def instruments(machine, count, warnings):
    table = machine.u32(machine.state+4)
    result = []
    for slot in range(1, count+1):
        address = table+32*slot
        native = bytes(machine.uc.mem_read(address, 32))
        header = bytearray(554)
        header[:4] = b'IMPI'
        # Runtime +0=NNA, +1=duplicate-check type, +2=duplicate-check action.
        # +3 is loader ownership flags, not the source's byte 3.
        header[0x11:0x14] = native[:3]
        header[0x14:0x1c] = native[4:12]
        struct.pack_into('<H', header, 0x1c, 0x0214)
        notes = bytes(machine.uc.mem_read(machine.u32(address+12), 120))
        samples = bytes(machine.uc.mem_read(machine.u32(address+16), 120))
        if any(s > count_samples(machine) for s in samples):
            warnings.append(dict(kind='sample_map', instrument=slot,
                                 references=sorted({s for s in samples if s > count_samples(machine)}),
                                 detail='Native mapping refers outside the loaded sample table; preserved without repair'))
        header[0x1e] = len(set(samples)-{0})
        for i in range(120):
            header[0x40+2*i:0x42+2*i] = bytes((notes[i], samples[i]))
        for i, offset in enumerate((0x130, 0x182, 0x1d4)):
            header[offset:offset+82] = envelope(machine, machine.u32(address+20+4*i))
        if machine.profile.runtime == 'spyro' and header[0x1d4] & 0x80:
            warnings.append(dict(kind='native_filter_envelope',instrument=slot,
                                 detail='Filter envelope flag preserved in IT; Repaired Spyro renderer ignores unsupported filter envelopes rather than applying them to pitch. IT retains the filter, so timbre can differ.'))
        result.append(header)
    return result


def count_samples(machine):
    return machine.module_header()[50]


def samples(machine, count, warnings):
    table = machine.u32(machine.state)
    headers, blobs = [], []
    for slot in range(1, count+1):
        native = bytes(machine.uc.mem_read(table+36*slot, 36))
        encoded, = struct.unpack_from('<I', native)
        header = bytearray(80)
        header[:4] = b'IMPS'
        header[0x11:0x14] = native[4:7]
        header[0x2e] = 1  # The native mixer reads signed PCM.
        header[0x30:0x48] = native[8:32]
        header[0x4c:0x50] = native[32:36]
        length, = struct.unpack_from('<I', native, 8)
        flags = native[5]
        if flags & (4 | 8):
            warnings.append(dict(kind='sample_flags', sample=slot, flags=flags,
                                 detail='DS loader/mixer behavior needs comparison for stereo or compression flags'))
        if flags & 0xc0:
            warnings.append(dict(kind='native_forward_loop', sample=slot, source_flags=flags,
                                 detail='Removed ping-pong bits: native sample setup supplies forward loop endpoints/length only'))
        # The native loader reads raw data even if the source compression bit
        # is set. Export the loaded bytes as ordinary PCM, never IT compression.
        header[0x12] &= ~(8 | 0xc0)
        unit = 2 if flags & 2 else 1
        pointer = (encoded & 0x7fffffff)*2 if flags & 2 else encoded
        if length and not pointer:
            raise ValueError(f'Sample {slot} has length but no loaded PCM')
        blobs.append(bytes(machine.uc.mem_read(pointer, unit*length)) if length else b'')
        headers.append(header)
    return headers, blobs


def pack_pattern(pattern, instrument_count, warnings):
    packed = bytearray()
    for row in pattern['rows']:
        seen = set()
        for event in row['events']:
            channel, fields = event['channel'], event['fields']
            if channel in seen:
                raise ValueError(f'Pattern {pattern["pattern"]} row {row["row"]}: multiple packets on channel {channel}; cannot collapse their applications into one IT cell')
            seen.add(channel)
            if not fields:
                raise ValueError('Cached class-0 packet needs live state; refusing a guessed export')
            mask, payload = 0, bytearray()
            if 'note' in fields:
                note = fields['note']
                if note >= 120 and note not in (126, 127):
                    raise ValueError(f'Unhandled native note {note}')
                mask |= 1
                payload.append({126: 254, 127: 255}.get(note, note))
            if 'instrument' in fields:
                instrument = fields['instrument']
                if not 1 <= instrument <= instrument_count:
                    raise ValueError(f'Instrument {instrument} needs explicit runtime semantics')
                mask |= 2
                payload.append(instrument)
            if 'volume' in fields:
                mask |= 4
                payload.append(fields['volume'])
            if 'command' in fields:
                command = fields['command']
                if command > 26:
                    raise ValueError(f'Unhandled effect {command}')
                if command == 25:
                    warnings.append(dict(kind='native_noop', pattern=pattern['pattern'], row=row['row'],
                                         channel=channel, command=command,
                                         detail='Omitted: native row handler returns without enabling ticks; IT Yxx would add panbrello'))
                else:
                    mask |= 8
                    parameter = fields['parameter']
                    if command == 24 and parameter&3:
                        warnings.append(dict(kind='native_pan_quantization', pattern=pattern['pattern'], row=row['row'],
                                             channel=channel, source_parameter=parameter, it_parameter=parameter&~3,
                                             detail='Native Xxx truncates to whole pan steps; IT preserves quarter steps'))
                        parameter &= ~3
                    payload.extend((command, parameter))
                if command == 26:
                    warnings.append(dict(kind='effect', pattern=pattern['pattern'], row=row['row'],
                                         channel=channel, command=command,
                                         detail='Preserved numeric command; DS/IT equivalence is not established'))
            if mask:
                packed.extend(((channel+1)|128, mask))
                packed.extend(payload)
        packed.append(0)
    if len(packed) > 65527:
        raise ValueError('Packed pattern exceeds IT size limit')
    return struct.pack('<HHI', len(packed), len(pattern['rows']), 0)+packed


def export(code, bank, module, output):
    decoder = RuntimePatterns(code, bank)
    channels, orders, ids = decoder.module_patterns(module)
    machine = SongMachine(code, bank)
    state = machine.load(module)
    native = machine.module_header()
    warnings = []
    instrument_headers = instruments(machine, native[49], warnings)
    sample_headers, pcm = samples(machine, native[50], warnings)
    patterns = [decoder.pattern(pid, channels) for pid in ids]
    packed = [pack_pattern(p, len(instrument_headers), warnings) for p in patterns]
    out = bytearray(0xc0)
    out[:4] = b'IMPM'
    title = f'SoundData {module:02d} native decode'.encode('ascii')
    out[4:4+min(26, len(title))] = title[:26]
    struct.pack_into('<9H', out, 0x1e, 0x1004, len(orders), len(instrument_headers),
                     len(sample_headers), len(packed), 0x0214, 0x0214,
                     native[47]&0x3f, 0)
    # Source byte 3 is flags, not mixing volume. Native code explicitly checks
    # bit 3 in the pitch-slide routine and bit 4 in vibrato/tick handling.
    out[0x30:0x36] = bytes((native[44], 128, native[46], native[45], 128, 0))
    out[0x40:0x80] = bytes([128])*64
    for channel in range(channels):
        values = bytes(machine.uc.mem_read(machine.channel_address(channel)+6, 2))
        out[0x80+channel], out[0x40+channel] = values
    out.extend(bytes(orders))
    table = len(out)
    entries = len(instrument_headers)+len(sample_headers)+len(packed)
    out.extend(bytes(entries*4))
    offsets = []
    for blob in instrument_headers+sample_headers+packed:
        offsets.append(len(out))
        out.extend(blob)
    for i, pointer in enumerate(offsets):
        struct.pack_into('<I', out, table+4*i, pointer)
    for i, blob in enumerate(pcm):
        sample_header = offsets[len(instrument_headers)+i]
        struct.pack_into('<I', out, sample_header+0x48, len(out) if blob else 0)
        out.extend(blob)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(out)
    report = dict(module=module, bytes=len(out), sha256=hashlib.sha256(out).hexdigest(),
                  source_sha256=hashlib.sha256(bank).hexdigest(), arm9_sha256=decoder.code_hash,
                  patterns=[dict(local=i, global_id=p['pattern'], rows=len(p['rows']),
                                 source_offset=p['source_offset']) for i, p in enumerate(patterns)],
                  source_flags=native[47]&0x7f,
                  runtime_adjustments=getattr(machine,'runtime_adjustments',[]),
                  warnings=[item for item in warnings if item['kind'] not in ('native_noop', 'native_forward_loop', 'native_pan_quantization')],
                  adaptations=[item for item in warnings if item['kind'] in ('native_noop', 'native_forward_loop', 'native_pan_quantization')],
                  status='Structural reconstruction from cartridge loader/decoder; runtime adjustments recorded; IT playback equivalence unverified',
                  limitations=['DS mixer, voice limits, envelopes and effect memory may differ from IT players',
                               'IT mixing volume is set to 128; source engine gain has no established IT equivalent',
                               'Patterns are decoded in isolation; cross-pattern SD0 delay memory is left to the IT player'])
    output.with_suffix('.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir", type=Path, default=ROOT / "data", help="Prepared ROM inputs"
    )
    commands = parser.add_subparsers(dest="mode", required=True)
    exporter = commands.add_parser(
        "export", help="Reconstruct editable IT files (all modules by default)"
    )
    selection = exporter.add_mutually_exclusive_group()
    selection.add_argument("--module", type=int, help="One zero-based bank module")
    selection.add_argument(
        "--all", action="store_true", help="Export the entire bank (default)"
    )
    exporter.add_argument("--output-dir", type=Path, default=ROOT / "output/it")
    renderer = commands.add_parser(
        "render", help="Render original ARM9 sequencer and mixer to WAV"
    )
    renderer.add_argument(
        "--module", type=int, required=True, help="Zero-based bank module"
    )
    renderer.add_argument(
        "--seconds", type=float, default=60, help="Output duration, default 60 seconds"
    )
    renderer.add_argument(
        "--output", type=Path, help="WAV path, default output/moduleNN.wav"
    )
    renderer.add_argument("--unmodified-runtime",action="store_true",
                          help="Spyro: disable documented ARM runtime repairs for original-behavior investigation")
    renderer.add_argument(
        "--trace", type=Path, help="Optional native row/tick JSON for investigation"
    )
    args = parser.parse_args()
    try:
        code = (args.data_dir / "arm9.bin").read_bytes()
        bank = (args.data_dir / "SoundData.rom").read_bytes()
        if (
            hashlib.sha256(bank).hexdigest()
            != profile_for(code).bank_sha256
        ):
            raise ValueError(
                "Unsupported SoundData bank; rerun setup with the supported cartridge dump"
            )
        if args.mode == "export":
            banks = struct.unpack_from("<10I", bank)
            count = (banks[1] - banks[0]) // 4
            modules = [args.module] if args.module is not None else range(count)
            failures = []
            for module in modules:
                output = args.output_dir / f"module{module:02d}.it"
                try:
                    report = export(code, bank, module, output)
                except (ValueError,RuntimeError) as exc:
                    if args.module is not None:
                        raise
                    failures.append(module)
                    print(f'Module {module} failed: {exc}',file=sys.stderr,flush=True)
                    continue
                print(
                    f'{output}: {report["bytes"]} bytes, {len(report["warnings"])} warnings',
                    flush=True,
                )
            if failures:
                parser.exit(1,f'Exported {count-len(failures)}/{count} modules; failed modules: {failures}. No replacement exports were created for failures.\n')
        else:
            output = args.output or ROOT / "output" / f"module{args.module:02d}.wav"
            options = dict(trace_ticks=bool(args.trace))
            if profile_for(code).runtime == 'spyro':
                options['repair_runtime'] = not args.unmodified_runtime
            elif args.unmodified_runtime:
                raise ValueError('--unmodified-runtime is only needed for Spyro')
            machine = SongMachine(code, bank, **options)
            machine.load(args.module)
            print(
                f"Rendering module {args.module}: {args.seconds:g} seconds through original DS code",
                flush=True,
            )
            machine.render(args.seconds, output)
            if args.trace:
                args.trace.parent.mkdir(parents=True, exist_ok=True)
                args.trace.write_text(
                    json.dumps(
                        dict(
                            module=args.module,
                            rows=machine.rows,
                            ticks=machine.ticks,
                            allocations=machine.allocations,
                            mixed_frames=machine.frame_total,
                            sample_rate=machine.sample_rate,
                            runtime_adjustments=getattr(machine,"runtime_adjustments",[]),
                            scope="Original ARM9 loader, sequencer and mixer; host platform adapters",
                        ),
                        indent=2,
                    )
                    + "\n"
                )
            print(f"{output}: {machine.frame_total} stereo frames at {machine.sample_rate} Hz")
    except FileNotFoundError as exc:
        parser.exit(
            1,
            f"Missing file: {exc.filename}. Run setup.py with your cartridge dump first.\n",
        )
    except (ValueError, RuntimeError, OSError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
