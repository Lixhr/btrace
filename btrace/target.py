from prompt_toolkit.formatted_text import FormattedText 
from prompt_toolkit import print_formatted_text
from btrace.ProjectInfo import ProjectInfo
from btrace.core.asm.AsmEngine import AsmEngine
import os

class TracePoint():
    def __init__(self, obj, pinfo: ProjectInfo):
        self.name = obj.get("name")
        self.ea = obj.get("ea")
        self.asm_ctx = obj.get("context")
        self.create_handler(pinfo.btrace_workdir)


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

    def print_line(self, i: int):
        print_formatted_text(FormattedText([
            ("ansiyellow bold", f"\n [{i}] "),
            ("bold",            f"{self.name}  "),
            ("ansigray",        f"{hex(self.ea)}    "),
            ("ansiblack",        f"{os.path.basename(self.c_filename)}"),
        ]))
        print_formatted_text(FormattedText([
            ("ansigray", "  " + "─" * 58),
        ]))
        for i, instr in enumerate(self.asm_ctx):
            if (instr["ea"] < self.ea or instr == self.asm_ctx[-1]): # context: before / after teh target
                colors = ["ansiblack", "ansiblack", "ansiblack"]
            else:
                colors = ["ansicyan bold", "ansigreen bold", ""] # patched instruction

            asm = AsmEngine.get()
            disasm_list = asm.arch.disassemble(instr["raw"], instr["ea"], instr["special"])
            disasm_str = " ; ".join(f"{i.mnemonic} {i.op_str}" for i in disasm_list)

            print_formatted_text(FormattedText([
                (colors[0],  f"  {hex(instr['ea'])}  "),
                (colors[1], f"{instr['raw']:<10}"),
                (colors[2],          f"  {disasm_str}"),
            ]))
