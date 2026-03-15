from typing import Callable

from keystone import *
from capstone import *
from btrace.ProjectInfo import ProjectInfo
from abc import ABC, abstractmethod
from btrace.core.asm.AsmInstr import AsmInstr


# For Abstract Arch 
def get_endian_modes(endian: str):
    cs_endian = {
        "le": CS_MODE_LITTLE_ENDIAN,
        "be": CS_MODE_BIG_ENDIAN
    }[endian]
    ks_endian = {
        "le": KS_MODE_LITTLE_ENDIAN,
        "be": KS_MODE_BIG_ENDIAN
    }[endian]
    return cs_endian, ks_endian

# capstone, keystone pair
class AsmMode:
    def __init__(self, cs_arch: int, cs_mode: int, ks_arch: int, ks_mode: int,
                 jmp_size: int, gcc_flags: list[str] = []):
        self.cs = Cs(cs_arch, cs_mode)
        self.cs.detail = True
        self.ks        = Ks(ks_arch, ks_mode)
        self.jmp_size = jmp_size
        self.gcc_flags = gcc_flags

    def assemble(self, asm: str, addr: int = 0) -> bytes:
        encoding, _ = self.ks.asm(asm, addr)
        return bytes(encoding)

    def disassemble(self, raw: bytes | str, addr: int = 0):
        if isinstance(raw, str):
            raw = bytes.fromhex(raw)
        return list(self.cs.disasm(raw, addr))

## CS : CapStone
## KS : KeyStone
class AArch:
    CS_ARCH: int
    KS_ARCH: int
    DEFAULT_MODE: str
    BASE_MODES: dict[str, tuple[int, int, int, list[str]]]
    SUB_MODES:  dict[str, tuple[int, int, int, list[str]]] = {}

    def __init__(self, project_info: ProjectInfo):
        cs_endian, ks_endian = get_endian_modes(project_info.endianness)

        cs_flags, ks_flags, jmp_size, gcc_flags = self.BASE_MODES[self.DEFAULT_MODE]
        self._default = AsmMode(
            self.CS_ARCH, cs_flags | cs_endian,
            self.KS_ARCH, ks_flags | ks_endian,
            jmp_size, gcc_flags,
        )
        self._sub_modes: dict[str, AsmMode] = {
            name: AsmMode(
                self.CS_ARCH, cs_f | cs_endian,
                self.KS_ARCH, ks_f | ks_endian,
                jmp_sz, gcc_f,
            )
            for name, (cs_f, ks_f, jmp_sz, gcc_f) in self.SUB_MODES.items()
        }

    def _get_mode(self, mode: bool | str) -> AsmMode:
        if not mode:
            return self._default
        if mode not in self._sub_modes:
            raise ValueError(f"Unknown sub-mode '{mode}' for {type(self).__name__}.")
        return self._sub_modes[mode]

    @abstractmethod
    def gcc_flags(self, mode: bool | str = False) -> list[str] | None:
        pass

    def assemble(self, asm: str, addr: int = 0, mode: bool | str = False) -> bytes:
        return self._get_mode(mode).assemble(asm, addr)

    def disassemble(self, raw: bytes | str, addr: int = 0, mode: bool | str = False):
        return self._get_mode(mode).disassemble(raw, addr)

    def jmp(self, pc_offset: int, mode: bool | str = False) -> bytes:
        return self._get_mode(mode).assemble(self._jmp_instr(pc_offset))

    def jmp_size(self, mode: bool | str = False) -> int:
        return self._get_mode(mode).jmp_size

    @abstractmethod
    def save_context(self, mode: bool | str = False) -> bytes:
        pass

    @abstractmethod
    def restore_context(self, mode: bool | str = False) -> bytes:
        pass

    @abstractmethod
    def _jmp_instr(self, pc_offset: int) -> str:
        pass

    @abstractmethod
    def is_pc_relative(self, instr : AsmInstr) -> bool:
        pass

    @abstractmethod
    def get_relocator(self, instr : AsmInstr) -> Callable | None:
        pass

    @abstractmethod
    def relocate_instr(self, instr : AsmInstr):
        pass