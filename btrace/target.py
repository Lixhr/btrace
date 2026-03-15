from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit import print_formatted_text
from btrace.ProjectInfo import ProjectInfo
from btrace.core.asm.AsmEngine import AsmEngine
from btrace.core.asm.AsmInstr import AsmInstr
import os

class Target:
    c_filename: str = ""
    asm_ctx: AsmInstr

    def __init__(self, obj: dict, pinfo: ProjectInfo, *, _skip_setup=False):
        self.name    = obj.get("name")
        self.ea      = obj.get("ea")
        self.func_end  = obj.get("end_ea")
        self.asm     = AsmEngine.get()
        self.asm_ctx = self._build_ctx(obj.get("context", []))
        if not _skip_setup:
            self._check_bounds()
            self._create_handler(pinfo.btrace_workdir)
        self._check_relocations()

    @classmethod
    def from_dict(cls, data: dict, info: ProjectInfo) -> "Target":
        return cls(data, info, _skip_setup=True)

    def to_dict(self):
        return {
            "name": self.name,
            "ea": self.ea,
            "context": [i.to_dict() for i in self.asm_ctx]
        }

    def _build_ctx(self, raw_ctx: list[dict]) -> list[AsmInstr]:
        if not raw_ctx:
            return []

        result = []
        for entry in raw_ctx:
            instrs = self.asm.arch.disassemble(entry["raw"], entry["ea"], entry.get("mode"))

            for cs_instr in instrs:
                instr = AsmInstr(cs_instr, entry.get("mode"))
                instr.patched = self.ea <= instr.ea < self.ea + self.asm.arch.jmp_size(instr.mode)
                result.append(instr)

        return result

    def get_target_instructions(self) -> list[AsmInstr]:
        return [i for i in self.asm_ctx if i.patched]

    def _check_relocations(self):
        for instr in self.get_target_instructions():
            if self.asm.arch.is_pc_relative(instr):
                self.asm.arch.get_relocator(instr) # throws if unimplemented
                instr.pc_relative = True

    def _check_bounds(self) -> None:
        if self.ea is None or self.func_end is None:
            raise Exception(f"{self.name}: missing ea or func_end ??")
        if self.ea + self.asm.arch.jmp_size() >= self.func_end:
            raise Exception(f"can't add {hex(self.ea)}: end of function")

    def _create_handler(self, btrace_workdir: str):
        c_name = self.name.replace("+", "_")
        self.c_filename = f"{btrace_workdir}/trace/{c_name}.c"
        try:
            if not os.path.isfile(self.c_filename):
                print(self.c_filename)
                with open(self.c_filename, "w") as f:
                    f.write(self._get_cfile_content(c_name))
                print(f"Handler created: {os.path.basename(self.c_filename)}")
        except OSError as e:
            raise Exception(f"{e.strerror} {e.filename}")

    def _get_ret_addr(self) -> int:
        instr = next((i for i in reversed(self.asm_ctx) if i.patched), None)
        if instr is None:
            raise Exception("No patched instruction found")
        return instr.ea + instr.size

    def _get_cfile_content(self, func_name: str) -> str:
        return f"""\
void {func_name}(void) {{
}}
"""

    ## display

    def _instr_colors(self, instr: AsmInstr) -> tuple[str, str, str]:
        if instr.patched:
            return ("ansicyan bold", "ansigreen bold", "")
        return ("ansiblack", "ansiblack", "ansiblack")

    def _print_instr(self, instr: AsmInstr):
        c0, c1, c2 = self._instr_colors(instr)
        print_formatted_text(FormattedText([
            (c0, f"  {hex(instr.ea)}  "),
            (c1, f"{instr.raw:<10}"),
            (c2, f"  {instr}"),
        ]))

    def print_line(self, i: int):
        print_formatted_text(FormattedText([
            ("ansiyellow bold", f"\n [{i}] "),
            ("bold",            f"{self.name}  "),
            ("ansigray",        f"{hex(self.ea)}    "),
            ("ansiblack",       f"{os.path.basename(self.c_filename)}"),
        ]))
        print_formatted_text(FormattedText([
            ("ansigray", "  " + "─" * 58),
        ]))
        for instr in self.asm_ctx:
            self._print_instr(instr)