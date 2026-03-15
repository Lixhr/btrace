from keystone import *
from capstone import *
from btrace.ProjectInfo import ProjectInfo
from abc import ABC, abstractmethod
from btrace.core.asm.AsmInstr import AsmInstr
from btrace.core.asm.arm.arm import Arm
from btrace.core.asm.AArch import AArch


_ARCH_MAP: dict[str, type[AArch]] = {
    "arm":   Arm,
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