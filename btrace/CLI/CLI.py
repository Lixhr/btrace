from __future__ import annotations
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.styles import Style
from btrace.CLI.commands import *
from btrace.CLI.errors import IdaError, InvalidArg

class BTraceCompleter(Completer):
    def __init__(self, commands: dict[str, ACommand]):
        self._commands = commands

    def get_completions(self, document, complete_event):
        text  = document.text_before_cursor
        words = text.strip().split()
        trailing = text.endswith(" ")

        if not words or (len(words) == 1 and not trailing):
            prefix = words[0] if words else ""
            for name in self._commands:
                if name.startswith(prefix):
                    yield Completion(name, start_position=-len(prefix))
            return

        cmd = self._commands.get(words[0])
        if not cmd:
            return

        args   = words[1:] if trailing else words[1:-1]
        prefix = "" if trailing else words[-1]

        for suggestion in cmd.complete(args):
            if suggestion.startswith(prefix):
                yield Completion(suggestion, start_position=-len(prefix))

class BTraceCLI:
    STYLE = Style.from_dict({"prompt": "ansicyan bold"})

    def __init__(self, commands: list[ACommand]):
        self._commands = {cmd.name: cmd for cmd in commands}
        self._session  = PromptSession(
            completer=BTraceCompleter(self._commands),
            style=self.STYLE,
            complete_while_typing=True,
        )

    def run(self):
        print("\n  btrace — IDA firmware tracer")
        print("  type 'help' for commands\n")
        while True:
            try:
                line = self._session.prompt([("class:prompt", "btrace> ")]).strip()
                if line:
                    self._dispatch(line)
            except KeyboardInterrupt:
                continue
            except EOFError:
                print("bye!")
                break

    def test(self):
        print("\n  btrace — IDA firmware tracer")
        print("   TESTS MODE\n\n")

        lines = [
            "add sub_131C24",
            "add ipc_rx_evt",
            "add 0x0013702A",
            "add 0x00137086", 
            "list",
        ]
        for line in lines:
            self._dispatch(line)


    def _dispatch(self, line: str) -> bool:
        parts = line.split()
        cmd = self._commands.get(parts[0])
        try:
            if cmd:
                cmd.execute(parts[1:])
                return (True)
            else:
                raise Exception(f"unknown command")
        except IdaError as e:
            print(f"IdaError: {e}")
        except EOFError:
            raise
        except Exception as e:
            print(f"Error: {parts[0]}: {e}")

