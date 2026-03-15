import subprocess
import tempfile
import os
from btrace.ProjectInfo import ProjectInfo
from btrace.target import Target
from btrace.ProjectInfo import Segment
from btrace.core.asm import AsmInstr
from prompt_toolkit import prompt
from pathlib import Path
from btrace.core.asm.AsmEngine import AsmEngine
from btrace.context import BTraceContext
from elftools.elf.elffile import ELFFile

class Img:
    raw_bytes: bytearray
    base_segment: Segment
    cursor: int = 0

    def __init__(self, pinfo: ProjectInfo, patch_base: int):
        self.raw_bytes = self._get_image(pinfo.bin_path)
        self.base_segment = pinfo.get_image_segment()
        self.cursor = patch_base

    def _get_image(self, infile: str):
        try:
            with open(infile, "rb") as img:
                return bytearray(img.read())
        except OSError as e:
            raise Exception(f"{e.filename}: {e.strerror}")

    def addr_to_offset(self, addr: int):
        return addr - self.base_segment.start

    def offset_to_addr(self, offset: int):
        print(self.base_segment.start)
        print(offset)
        return self.base_segment.start + offset

    ## Write assumes the destination is in the 'mapped' range
    def write(self, addr: int, data: bytes):
        offset = self.addr_to_offset(addr)
        end = offset + len(data)
        self.raw_bytes[offset:end] = data

    ## Appends in the patching area
    def append(self, data: bytes):
        end = self.cursor + len(data)

        if end > len(self.raw_bytes):
            self.raw_bytes.extend(b"\x00" * (end - len(self.raw_bytes)))

        self.raw_bytes[self.cursor:end] = data
        self.cursor = end

    def seek(self, addr: int):
        self.cursor = self.addr_to_offset(addr)

    def tell(self):
        return self.offset_to_addr(self.cursor)


def make_cfiles(target_dir: str, workdir: Path, asm: AsmEngine):
    src_path = workdir / target_dir
    bin_path = src_path / "build" / "payload.bin"
    elf_path = src_path / "build" / "payload.elf"

    makeflags = ["make", "-C", str(workdir), f"MODE={target_dir}"]
    arch_flags = asm.arch.gcc_flags()
    if arch_flags:
        joined = " ".join(arch_flags)
        makeflags.append(f"CPU_SPECIFIC={joined}")

    subprocess.run(
        makeflags,
        check=True,
        close_fds=False,
    )
    return bin_path, elf_path    

class ELF(ELFFile):
    def __init__(self, path: str):
        self._file = open(path, "rb")
        super().__init__(self._file)

    def close(self):
        self._file.close()

class AInstrumentationMode:
    pinfo: ProjectInfo
    targets: list[Target]
    img: Img
    patch_base: int
    bin_path: str
    elf_path: str

    def __init__(self, pinfo : ProjectInfo, targets: list[Target], asm: AsmEngine):
        self.pinfo = pinfo
        self.patch_base = self._ask_patch_address()
        self.img = Img(self.pinfo, self.patch_base)
        self._check_base_segment(targets)

        self.targets = targets
        self.asm = asm

    def get_patched_bin(self) ->bytes:
        with open(self.bin_path, "rb") as file:
            return file.read()

    def _ask_patch_address(self) -> int:
        if self.pinfo.patch_base is not None:
            while True:
                print(f"Current patch base: {hex(self.pinfo.patch_base)}. Use it ? [y/n]")
                resp = prompt(" > ")
                if resp == "y": 
                    return self.pinfo.patch_base
                elif resp == "n":
                    break

        print("Please select the patch's base address (hex, e.g. 0x123DD8):")
        base = int(prompt(" > "), 16)

        aligned_base = (base + 0xF) & ~0xF
        if aligned_base != base:
            print(f"Aligned patch base: {hex(aligned_base)}")

        self.pinfo.patch_base = aligned_base
        return aligned_base

    def _check_base_segment(self, targets: list[Target]):
        for i, t in enumerate(targets):
            if i == 3: ##  enough ?
                break
            for instr in t.asm_ctx:
                offset = self.img.addr_to_offset(instr.ea)
                img_slice = self.img.raw_bytes[offset: offset + instr.size]

                if (img_slice != instr.raw_bytes):
                    raise Exception(f"Ida / infile mismatch at address {hex(instr.ea)}. You may have chosen the wrong base segment")

class CoverageMode(AInstrumentationMode):
    pass

class BinTraceMode(AInstrumentationMode):
    elf : ELF | None = None

    def __init__(self, pinfo : ProjectInfo, asm: AsmEngine, targets: list[Target]):
        super().__init__(pinfo, targets, asm)
        self.bin_path, self.elf_path = make_cfiles("trace", pinfo.btrace_workdir, asm)

        self.append_ofiles()
        self.redirect_flow()

        with open("/tmp/out", "wb") as file:
            from btrace.CLI.utils import DEV_LOG
            file.write(self.img.raw_bytes)
            DEV_LOG(f"File written at /tmp/out")

    def append_ofiles(self): # append the compiled cfiles at patch_base
        self.img.append(self.get_patched_bin())

    def redirect_flow(self):
        for t in self.targets:
            # todo : one instruction sample -> can't handle the transition between cpu modes.
            target_instr = t.get_target_instructions()[0] 

            src_ea = target_instr.ea

            # replaces the targets to jump on our handler 
            jmp = self.asm.arch.assemble(
                self.asm.arch._jmp_instr(self.img.tell()),
                addr=src_ea,
                mode=target_instr.mode
            )
            self.img.write(src_ea, jmp)
            

            self.img.append(self.asm.arch.save_context(target_instr.mode))
            for instr in t.asm_ctx:
                if instr.patched: 
                    if instr.pc_relative:
                        from btrace.CLI.utils import DEV_LOG
                        DEV_LOG("PC RELATIVE")
                        self.asm.arch.relocate_instr(instr)
                        # new_addr = self.img.tell()
                        # relocated = self.asm.arch.assemble(instr.asm_str, addr=new_addr, mode=instr.mode)
                        # self.img.append(relocated)
                    else:
                        DEV_LOG("NOT PC RELATIVE")
                        # self.img.append(instr.raw_bytes)



            self.img.append(self.asm.arch.restore_context(target_instr.mode))
            
            


    def close(self):
        if self.elf is not None:
            self.elf.close()
