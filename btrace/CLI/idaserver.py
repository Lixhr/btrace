import zmq
import threading
from btrace.CLI.utils import DEV_LOG

SOCKET_ADDR = "ipc:///tmp/btrace.ipc"

class IdaIPC(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._stop     = threading.Event()
        self._ctx      = zmq.Context()
        self._sock     = self._ctx.socket(zmq.PAIR)
        self._sock.setsockopt(zmq.RCVTIMEO, 500)
        self._lock     = threading.Lock()
        self._pending  = threading.Event()
        self._response = None

    def connect(self):
        self._sock.connect(SOCKET_ADDR)
        self.start()

    def send(self, msg: dict) -> dict | None:
        with self._lock:
            self._pending.clear()
            self._response = None
            self._sock.send_json(msg)
            self._pending.wait(timeout=2.0)
            return self._response

    def stop(self):
        self._stop.set()
        self._ctx.term()

    def run(self):
        DEV_LOG("[server] ready")
        while not self._stop.is_set():
            try:
                msg = self._sock.recv_json()
                if self._pending.is_set() is False:
                    self._response = msg
                    self._pending.set()
                else:
                    print(f"[btrace] event: {msg}") ## For future ida refresh updates 
            except zmq.Again:
                continue
            except zmq.ZMQError:
                break
            except Exception as e:
                raise
        print("[server] finished")