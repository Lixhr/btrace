from keystone import *
from capstone import *
from btrace.ProjectInfo import ProjectInfo


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

## CS : CapStone
## KS : KeyStone
class AArch:
    CS_ARCH: int
    CS_BASE_MODE: int
    special_cs: Cs | None

    KS_ARCH: int
    KS_BASE_MODE: int
    special_ks: Ks | None

    def __init__(self, project_info: ProjectInfo):
        cs_endian, ks_endian = get_endian_modes(project_info.endianness)

        self.CS_MODE = self.CS_BASE_MODE | cs_endian
        self.cs = Cs(self.CS_ARCH, self.CS_MODE)
        self.special_cs = None
        self.cs.detail = True

        self.KS_MODE = self.KS_BASE_MODE | ks_endian
        self.ks = Ks(self.KS_ARCH, self.KS_MODE)
        self.special_ks = None

    def assemble(self, asm: str, addr: int = 0, special: bool = False) -> bytes:
        if special:
            encoding, _ = self.special_ks.asm(asm, addr)
        else:
            encoding, _ = self.ks.asm(asm, addr)

        return bytes(encoding)
    
    def disassemble(self, raw: bytes, addr: int = 0, special: bool | str = False):
        if isinstance(raw, str):
            raw = bytes.fromhex(raw)

        if special:
            return list(self.special_cs.disasm(raw, addr))
        else:
            return list(self.cs.disasm(raw, addr))

class Arm(AArch):
    CS_ARCH = CS_ARCH_ARM
    KS_ARCH = KS_ARCH_ARM
    CS_BASE_MODE = CS_MODE_ARM
    KS_BASE_MODE = KS_MODE_ARM

    def __init__(self, project_info: ProjectInfo):
        super().__init__(project_info)
        self.special_cs = Cs(self.CS_ARCH, CS_MODE_THUMB)
        self.special_ks = Ks(self.KS_ARCH, KS_MODE_THUMB)
        self.special_cs.detail = True


_ARCH_MAP = {
    "arm": Arm
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