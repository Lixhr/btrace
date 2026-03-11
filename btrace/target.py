from prompt_toolkit.formatted_text import FormattedText 
from prompt_toolkit import print_formatted_text
from btrace.ProjectInfo import ProjectInfo
from btrace.core.asm.AsmEngine import AsmEngine
import os

class TracePoint:
    c_filename : str  =""

    def __init__(self, obj: dict, pinfo: ProjectInfo, *, _skip_setup=False):
        self.name    = obj.get("name")
        self.ea      = obj.get("ea")
        self.end_ea  = obj.get("end_ea")
        self.asm_ctx = obj.get("context")
        self.asm     = AsmEngine.get()
        if not _skip_setup:
            self.check_bounds(obj)
            self.create_handler(pinfo.btrace_workdir)

    @classmethod
    def from_dict(cls, data: dict, info: ProjectInfo) -> "TracePoint":
        return cls(data, info, _skip_setup=True)
    
    def check_bounds(self, obj) -> None:
        callsize = self.asm.arch.call_size()

        if self.ea + callsize > self.end_ea:
            raise Exception(f"Patched tracepoint {self.name} \
                            overlaps with another function (call size {hex(callsize)})")


    def get_cfile_content(self, func_name: str):
        return f"""\
#include "btrace.h"

void {func_name}(void) {{
        
}}

REGISTER_HANDLER(
    {func_name},
    {hex(self.asm_ctx[-1]['ea'])}
);
"""

    def create_handler(self, btrace_workdir: str):
        c_name = self.name.replace("+", "_")

        self.c_filename = f"{btrace_workdir}/handlers/{c_name}.c"
        try:
            if not os.path.isfile(self.c_filename):
                with open(self.c_filename, "w") as file:
                    file.write(self.get_cfile_content(c_name))
                    print(f"Handler created: {os.path.basename(self.c_filename)}")

        except OSError as e:
            raise Exception(f"{e.strerror} {e.filename}")

    def _is_patched(self, instr: dict) -> bool:
        return self.ea <= instr["ea"] < self.ea + self.asm.arch.call_size(instr["mode"])

    def _instr_colors(self, instr: dict) -> tuple[str, str, str]:
        if self._is_patched(instr):
            return ("ansicyan bold", "ansigreen bold", "")
        return ("ansiblack", "ansiblack", "ansiblack")

    def _format_disasm(self, instr: dict) -> str:
        disasm = self.asm.arch.disassemble(instr["raw"], instr["ea"], instr["mode"])
        return " ; ".join(f"{i.mnemonic} {i.op_str}" for i in disasm)

    def _print_instr(self, instr: dict):
        addr, raw, disasm = hex(instr["ea"]), instr["raw"], self._format_disasm(instr)
        c0, c1, c2 = self._instr_colors(instr)
        print_formatted_text(FormattedText([
            (c0, f"  {addr}  "),
            (c1, f"{raw:<10}"),
            (c2, f"  {disasm}"),
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