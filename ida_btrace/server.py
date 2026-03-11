import threading
import zmq
import idaapi
import ida_funcs
from abc import ABC, abstractmethod
import idautils
import ida_xref
import idc
import ida_bytes
import ida_idp

SOCKET_ADDR = "ipc:///tmp/btrace.ipc"

class IDAException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

def get_func_by_name(name: str):
    ea = idaapi.get_name_ea(idaapi.BADADDR, name)
    if ea == idaapi.BADADDR:
        return None
    return ida_funcs.get_func(ea)

def get_func_by_address(ea: int):
    return (idaapi.get_func(ea))

def get_mode_context(ea: int) -> str | None:
    arch = ida_idp.get_idp_name().lower()

    match arch:
        case "arm":
            return ("thumb" if idc.get_sreg(ea, "T") else None)
    return (None)

def get_instruction(ea: int):
    insn = idaapi.insn_t()

    if idaapi.decode_insn(insn, int(ea)) == 0:
        raise RuntimeError(f"failed to decode instruction at {hex(ea)}")

    raw = ida_bytes.get_bytes(ea, insn.size)
    if raw is None:
        raise RuntimeError(f"failed to read bytes at {hex(ea)}")

    return {
        "ea": ea,
        "raw": raw.hex(),
        "size": insn.size, 
        "mode": get_mode_context(ea)
    }

## Get instructions before / after target 
## Ensure the context is large enough to hande x86 6 bytes longjmp
def get_asm_context(func, ea: int):
    before = []
    target = []
    after  = []

    prev_ea = idc.prev_head(ea, func.start_ea)
    if prev_ea != idaapi.BADADDR:
        before.append(get_instruction(prev_ea))

    target_instr = get_instruction(ea)
    target.append(target_instr)
    collected = target_instr["size"]

    cur_ea = int(ea + target_instr["size"])
    first_after = True
    while first_after or collected < 10:
        print(collected)
        if cur_ea >= func.end_ea:
            break
        if ida_bytes.is_data(ida_bytes.get_full_flags(cur_ea)):
            break
        instr = get_instruction(cur_ea)
        after.append(instr)
        collected += instr["size"]
        cur_ea += instr["size"]
        first_after = False

    return before + target + after

class AIPCCommand(ABC):
    action: str

    @abstractmethod
    def handle(self, msg: dict) -> dict: ...

class IPCAdd(AIPCCommand):
    action = "add"

    def handle(self, body: list[str]) -> dict:
        body_rsp = []
        for target in body:
            if target.startswith("0x"): # hex instr address
                addr = int(target, 16)
                func = get_func_by_address(addr)
                if func is None:
                    raise IDAException(f"{target} does not exist")
                target = f"{func.name}+{addr - func.start_ea}"

            else:
                func = get_func_by_name(target)
                if func is None:
                    raise IDAException(f"{target} does not exist")
                addr = func.start_ea

            if func is None:
                raise IDAException(f"no function at {target}")

            body_rsp.append({
                "name":    target,
                "ea":      addr,
                "end_ea": func.end_ea,
                "context": get_asm_context(func, addr),
            })
        print(body_rsp)
        return {"ok": True, "body": body_rsp}

class IPCProjectInfo(AIPCCommand):
    action = "info"

    def handle(self, body):
        body_rsp = {
            "bin_path": idaapi.get_input_file_path(),
            "arch": ida_idp.get_idp_name().lower(),
            "endianness": "be" if idaapi.inf_is_be() else "le",
            "bits": 64 if idaapi.inf_is_64bit() else 32
        }
        return {"ok": True, "body": body_rsp}

class Server(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._stop = threading.Event()
        self._ctx  = zmq.Context()
        self._commands = {cmd.action: cmd for cmd in [
            IPCAdd(),
            IPCProjectInfo(),
        ]}
    def stop(self):
        self._stop.set()
        self._ctx.term()

    def run(self):
        sock = self._ctx.socket(zmq.PAIR)
        sock.bind(SOCKET_ADDR)
        sock.setsockopt(zmq.RCVTIMEO, 500)

        print("[btrace] server started")

        while not self._stop.is_set():
            try:
                msg = sock.recv_json()
                print(f"[btrace] recv: {msg}")

                response = {}
                idaapi.execute_sync(
                    lambda: response.update(self._dispatch(msg)),
                    idaapi.MFF_READ
                )
                sock.send_json(response)
            except zmq.Again:
                continue
            except zmq.ZMQError as e:
                print(f"[btrace] ZMQError: {e}")
                break
            except Exception as e:
                print(f"[btrace] error: {e}")

        sock.close()
        print("[btrace] server stopped")


    def _dispatch(self, msg: dict) -> dict:
        action = msg.get("action")
        body   = msg.get("body")

        try:
            cmd = self._commands.get(action)
            if not cmd:
                raise IDAException(f"unknown action: {action}")

            return cmd.handle(body)
        except IDAException as e:
            return {"ok": False, "body": e.message}
        except Exception as e:
            return {"ok": False, "body": str(e)}
