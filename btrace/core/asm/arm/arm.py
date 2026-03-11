from btrace.core.asm.Arch import Arch
from keystone import *

class Arm(Arch):
    def __init__(self):
        super().__init__()
        self.ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
