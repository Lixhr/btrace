from btrace.CLI.errors import IdaError
from btrace.CLI.utils import DEV_LOG
from prompt_toolkit.formatted_text import FormattedText 
from prompt_toolkit import print_formatted_text
from prompt_toolkit import prompt
import os
import shutil
from pathlib import Path
import shutil
import os

class Segment:
    start: int
    end: int
    name: str
    is_image : bool = False

    def __init__(self, obj):
        self.start = int(obj.get("start"), 16)
        self.end   = int(obj.get("end"), 16)
        self.name = obj.get("name")

    def print(self, i: int):
        print_formatted_text(FormattedText([
            ("ansiblue bold", f"[{i}] "),
            ("bold",            f"{self.name:<10}"),
            ("ansigray",        f"{hex(self.start):<14}"),
            ("ansigray",        f"- {hex(self.end)}"),
        ]))

class ProjectInfo:
    endianness: str
    arch: str
    bin_path: str
    bits: int
    btrace_workdir: str
    conf: str
    segments : list[Segment]
    base_addr : int

    def __init__(self, srv):
        try:
            info = self._fetch(srv)

            self.bin_path = info.get("bin_path")
            self.arch = info.get("arch")
            self.endianness = info.get("endianness")
            self.bits = info.get("bits")
            self.segments = [Segment(s) for s in info.get("segments", [])]
            self._setup_project()
            DEV_LOG(info)

        except IdaError as e:
            print(f"ProjectInfo error: {e}")


    def get_image_segment(self) -> Segment:
        img_seg = next((s for s in self.segments if s.is_image), None)

        if img_seg is None:
            print(f"Please select the segment that contains the firmware image: [0-{len(self.segments) - 1}]")
            for i, seg in enumerate(self.segments):
                    seg.print(i)
            seg_i = int(prompt(" > "))
            img_seg = self.segments[seg_i]
            img_seg.is_image = True
        return img_seg
    

    def fill_from_json(self, obj):
        if not obj:
            return
        seg_start = obj.get("project", {}).get("img_base")
        if seg_start is None:
            return
        img_seg = next((s for s in self.segments if s.start == seg_start), None)
        if img_seg:
            img_seg.is_image = True


    def _setup_project(self):
        if not self.bin_path:
            raise IdaError("bin_path is not defined")

        bin_path = Path(self.bin_path)
        proj_name = bin_path.name
        ida_workdir = bin_path.parent

        self.btrace_workdir = ida_workdir / f"__btrace_{proj_name}"
        self.conf = self.btrace_workdir / ".btrace"

        if not self.btrace_workdir.exists(): ## first opened
            self._init_project()

        print(f"Workdir: {self.btrace_workdir}")


    def _init_project(self):
        self.btrace_workdir.mkdir(parents=True, exist_ok=True)


        handlers_dir = self.btrace_workdir / "handlers"
        core_dest = self.btrace_workdir / "core"

        handlers_dir.mkdir(parents=True, exist_ok=True)
        core_dest.mkdir(parents=True, exist_ok=True)

        self._copy_core_files(core_dest)

    def _copy_core_files(self, dest):
        core_src = Path(os.getcwd()) / "btrace" / "core" / "c_files"

        if not core_src.exists():
            print(f"Core source not found: {core_src}")
            return

        for item in core_src.iterdir():
            if item.is_file():
                shutil.copy(item, dest / item.name)

    def _get_btrace_workdir(self):
        proj_name = os.path.basename(self.bin_path)
        ida_workdir = os.path.dirname(self.bin_path)

        self.btrace_workdir = ida_workdir / "__btrace_" + proj_name
        if not os.path.isdir(self.btrace_workdir):
            self.init_project()


        print(f"Workdir: {self.btrace_workdir}")

    def _fetch(self, srv) -> dict | None:
        resp = srv.send({"action": "info"})
        if resp:
            body = resp.get("body")
            if (not resp.get("ok")):
                raise IdaError(body)
            return (body)
        else:
            raise IdaError("failed to query db")
            