import idaapi
import idc
import ida_kernwin
from ida_btrace import server
import time

class BinTrace:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized"):
            return
        self._initialized  = True
        self.server = server.Server()
        self.server.start()
        print("BinTrace init")


    def traceFunc(self, obj) -> bool:
        if not obj.cur_func:
            print("[BinTrace] No function under cursor")
            return False
        
        ea   = obj.cur_func.start_ea
        name = idaapi.get_func_name(ea) or hex(ea)
        if ea in self._tracepoints:
            print(f"[BinTrace] Already traced: {ea}")
            return False
        print(f"{ea} traced")
        return True
    
    def term(self):
        self.server.stop()
        print("BinTrace killed")
