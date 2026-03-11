from keystone import *
from capstone import *
from btrace.ProjectInfo import ProjectInfo
from abc import ABC, abstractmethod

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
    def __init__(self, cs_arch: int, cs_mode: int, ks_arch: int, ks_mode: int, call_size: int):
        self.cs = Cs(cs_arch, cs_mode)
        self.cs.detail = True
        self.ks = Ks(ks_arch, ks_mode)
        self.call_size = call_size 

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
    SUB_MODES: dict[str, tuple[int, int, int]] = {}  # (cs_flags, ks_flags, call_size)

    def __init__(self, project_info: ProjectInfo):
        cs_endian, ks_endian = get_endian_modes(project_info.endianness)

        cs_flags, ks_flags, call_size = self.BASE_MODES[self.DEFAULT_MODE]
        self._default = AsmMode(
            self.CS_ARCH, cs_flags | cs_endian,
            self.KS_ARCH, ks_flags | ks_endian,
            call_size,
        )
        self._sub_modes: dict[str, AsmMode] = {
            name: AsmMode(
                self.CS_ARCH, cs_f | cs_endian,
                self.KS_ARCH, ks_f | ks_endian,
                call_sz,
            )
            for name, (cs_f, ks_f, call_sz) in self.SUB_MODES.items()
        }

    def _get_mode(self, mode: bool | str) -> AsmMode:
        if not mode:
            return self._default
        if mode not in self._sub_modes:
            raise ValueError(f"Unknown sub-mode '{mode}' for {type(self).__name__}.")
        return self._sub_modes[mode]

    def assemble(self, asm: str, addr: int = 0, mode: bool | str = False) -> bytes:
        return self._get_mode(mode).assemble(asm, addr)

    def disassemble(self, raw: bytes | str, addr: int = 0, mode: bool | str = False):
        return self._get_mode(mode).disassemble(raw, addr)

    def call(self, pc_offset: int, mode: bool | str = False) -> bytes:
        return self._get_mode(mode).assemble(self._call_instr(pc_offset))

    def call_size(self, mode: bool | str = False) -> int:
        return self._get_mode(mode).call_size

    @abstractmethod
    def _call_instr(self, pc_offset: int) -> str:
        pass

class Arm(AArch):
    CS_ARCH = CS_ARCH_ARM
    KS_ARCH = KS_ARCH_ARM
    DEFAULT_MODE = "arm"
    BASE_MODES = {
        "arm":   (CS_MODE_ARM,   KS_MODE_ARM,   4),
    }
    SUB_MODES = {
        "thumb": (CS_MODE_THUMB, KS_MODE_THUMB, 4),
    }

    def _call_instr(self, pc_offset: int) -> str:
        return f"bl {pc_offset}"


_ARCH_MAP: dict[str, type[AArch]] = {
    "arm":   Arm,
}


class AsmEngine:
    _instance = None

    def __new__(cls, project_info: ProjectInfo):
        if cls._instance is not None:
            raise RuntimeError("AsmEngine already initialized")

        obj = super().__new__(cls)
        cls._instance = obj
        return obj

    def __init__(self, project_info: ProjectInfo):
        arch = project_info.arch.lower()

        cls = _ARCH_MAP.get(arch)
        if cls is None:
            raise ValueError(f"unsupported arch: {arch}")

        self.arch: AArch = cls(project_info)

    @classmethod
    def get(cls):
        if cls._instance is None:
            raise RuntimeError("AsmEngine not initialized")
        return cls._instance