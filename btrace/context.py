from __future__ import annotations
from btrace.CLI.idaserver import IdaIPC
from btrace.ProjectInfo import ProjectInfo
from btrace.target import TracePoint
import json
import os
from btrace.core.asm.AsmEngine import AsmEngine

class BTraceContext:
    _instance = None
    traced : list[TracePoint] = []
    srv: IdaIPC = None
    info : ProjectInfo = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized"):
            return
        self.srv = IdaIPC()
        self.srv.connect()

        self.info = ProjectInfo(self.srv)
        self.asm = AsmEngine(self.info)


        data = self.load_json(f"{self.info.btrace_workdir}/.btrace")
        self.info.fill_from_json(data) # proj_info
        self.fill_from_json(data) # context / breakpoints


        self._initialized = True

    def trace(self, obj):
        new = TracePoint(obj, self.info)

        for i, func in enumerate(self.traced):
            if new.ea == func.ea: 
                return

            if new.ea < func.ea:
                self.traced.insert(i, new)
                return True

        self.traced.append(new)
        return True

    def untrace(self, name: str) -> bool:
        ea = None
        try:
            ea = int(name, 16)
        except ValueError:
            pass

        for func in self.traced:
            if func.name == name or (ea is not None and ea == func.ea):
                self.traced.remove(func)
                return True

        return False
    
    def export_json(self, path: str) -> None:
        img_seg = self.info.get_image_segment()
        if img_seg is None:
            raise Exception("No image segment selected")
        data = {
            "project": {
                "img_base": img_seg.start
            },
            "traced": [
                {
                    "name":    tp.name,
                    "ea":      tp.ea,
                    "context": tp.asm_ctx,
                }
                for tp in self.traced
            ]
        }
        if not data["traced"]:
            raise Exception("nothing to save")
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def load_json(self, path: str):
        try:
            with open(path, "r") as f:
                data = json.load(f)
                return (data)
        except FileNotFoundError:
            pass
        except OSError as e:
            print(f"Failed to load {path}: {e.strerror}")

    def fill_from_json(self, data: dict | None):
        if not data:
            return
        for tp_data in data.get("traced", []):
            tp = TracePoint.from_dict(tp_data, self.info)
            self.traced.append(tp)