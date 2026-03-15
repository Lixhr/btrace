
from capstone import CsInsn
from capstone.arm import ARM_OP_REG, ARM_OP_MEM, ARM_REG_PC

class AsmInstr:
    pc_relative : bool = False

    def __init__(self, cs_instr: CsInsn, mode: str | None = None, patched: bool = False):
        self._instr   = cs_instr
        self.mode     = mode
        self.patched  = patched


    @property
    def ea(self):
        return self._instr.address

    @property
    def raw(self) -> str:
        return self._instr.bytes.hex()

    @property
    def raw_bytes(self) -> bytes:
        return bytes(self._instr.bytes)

    @property
    def mnemonic(self):
        return self._instr.mnemonic

    @property
    def op_str(self):
        return self._instr.op_str

    def __getattr__(self, name):
        return getattr(self._instr, name)

    def __str__(self):
        return f"{self.mnemonic} {self.op_str}"
    
    def to_dict(self):
        return {
            "ea": self.ea,
            "raw": self.raw,
            "mode": self.mode
        }

    def _test_print(self):
        print(self.mnemonic, self.op_str)

        regs_read = set()
        regs_write = set()

        for op in self.operands:
            if op.type == ARM_OP_REG:
                regs_read.add(self.reg_name(op.reg))

            elif op.type == ARM_OP_MEM:
                if op.mem.base:
                    regs_read.add(self.reg_name(op.mem.base))
                if op.mem.index:
                    regs_read.add(self.reg_name(op.mem.index))

        print("read:", regs_read)
        print("write:", regs_write)