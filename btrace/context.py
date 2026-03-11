from __future__ import annotations
from btrace.CLI.idaserver import IdaIPC
from btrace.ProjectInfo import ProjectInfo
from btrace.target import TracePoint
import json
import os
from btrace.core.asm.AsmEngine import AsmEngine

class BTraceContext:
    _instance = None
    traced = None
    srv = None
    info = None

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
        self.traced = []
        self.import_json(f"{self.info.bin_path}.btrace")
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
        data = []

        for tp in self.traced:
            data.append({
                "name": tp.name,
                "ea": tp.ea,
                "context": tp.asm_ctx
            })
        if (not len(data)):
            raise Exception("nothing to save")
        with open(path, "w") as file:
            json.dump(data, file, indent=2)

    def import_json(self, path: str) -> None:
        try:
            with open(path, "r") as f:
                data = json.load(f)

            for obj in data:
                self.trace(obj)

        except FileNotFoundError:
            pass
        except OSError as e:
            print(f"Failed to load {path}: {e.strerror}")
