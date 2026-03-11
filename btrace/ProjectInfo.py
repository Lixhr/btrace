from btrace.CLI.errors import IdaError
from btrace.CLI.utils import DEV_LOG
import os
import shutil


from pathlib import Path
import shutil
import os


class ProjectInfo:
    endianness: str
    arch: str
    bin_path: str
    bits: int
    btrace_workdir: str

    def __init__(self, srv):
        try:
            info = self._fetch(srv)

            self.bin_path = info.get("bin_path")
            self.arch = info.get("arch")
            self.endianness = info.get("endianness")
            self.bits = info.get("bits")

            self._setup_workdir()
            DEV_LOG(info)

        except IdaError as e:
            print(f"ProjectInfo error: {e}")

    def _setup_workdir(self):
        if not self.bin_path:
            raise IdaError("bin_path is not defined")

        bin_path = Path(self.bin_path)
        proj_name = bin_path.name
        ida_workdir = bin_path.parent

        self.btrace_workdir = ida_workdir / f"__btrace_{proj_name}"

        if not self.btrace_workdir.exists():
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

    def get_btrace_workdir(self):
        proj_name = os.path.basename(self.bin_path)
        ida_workdir = os.path.dirname(self.bin_path)

        self.btrace_workdir = ida_workdir + "/__btrace_" + proj_name
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
            