from btrace.CLI.args import Arg
from abc import ABC, abstractmethod
from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import FormattedText
from btrace.CLI.args import Arg, ParsedArgs, parse_args
from btrace.CLI.errors import InvalidArg, IdaError
from btrace.CLI.utils import DEV_LOG

## Abstract Command Classes ##

class ACommand(ABC):
    name:    str
    desc:    str  = ""
    args_spec: list[Arg] = []

    def __init__(self):
        from btrace.context import BTraceContext
        self.ctx = BTraceContext()

    @abstractmethod
    def execute(self, args: list[str]) -> None: ...

    def parse(self, argv: list[str]) -> ParsedArgs:
        try:
            return parse_args(argv, self.args_spec)
        except ValueError as e:
            raise InvalidArg(f"{e}")

    def check_ida(self, resp: dict) -> None:
        if not resp.get("ok"):
            raise IdaError(resp.get("error", resp.get("body")))

    def complete(self, args: list[str]) -> list[str]:
        flags = [f"--{a.name}" for a in self.args_spec if a.flag]
        if args and args[-1].startswith("--"):
            return [f for f in flags if f.startswith(args[-1])]
        return flags

    def usage(self) -> str:
        parts = []
        for a in self.args_spec:
            if a.flag:
                parts.append(f"[--{a.name}]")
            elif a.required:
                parts.append(f"<{a.name}>")
            else:
                parts.append(f"[{a.name}]")
        return " ".join(parts)

    def help(self) -> None:
        print_formatted_text(FormattedText([
            ("ansicyan", f"  {self.name:<10}"),
            ("",         f"  {self.usage():<24}  {self.desc}"),
        ]))

class AGroupCommand(ACommand):
    subcommands: dict[str, ACommand] = {}

    def __init__(self):
        super().__init__()

    def execute(self, argv: list[str]) -> None:
        if not argv or argv[0] == "help":
            self.help()
            return

        sub = self.subcommands.get(argv[0])
        if not sub:
            raise InvalidArg(f"unknown subcommand: {argv[0]}")

        try:
            sub.execute(argv[1:])
        except InvalidArg as e:
            raise InvalidArg(f"{e.message}")

    def complete(self, args: list[str]) -> list[str]:
        if not args:
            return list(self.subcommands.keys())

        sub = self.subcommands.get(args[0])

        if not sub:
            return [s for s in self.subcommands if s.startswith(args[0])]

        return sub.complete(args[1:])

    def help(self) -> None:
        print_formatted_text(FormattedText([
            ("ansicyan", f"  {self.name}"),
            ("",     f"  —  {self.desc}"),
        ]))
        for sub in self.subcommands.values():
            print_formatted_text(FormattedText([
                ("",         "           "),
                ("ansicyan", f"{sub.name:<10}"),
                ("",         f"  {sub.usage():<24}  {sub.desc}"),
            ]))
        print()

##

## Commands implementation

class HelpCommand(ACommand):
    name = "help"
    desc = "Display this help message"

    def __init__(self, commands: dict):
        super().__init__()
        self._commands = commands

    def execute(self, args: list[str]) -> None:
        if args:
            cmd = self._commands.get(args[0])
            if not cmd:
                print(f"  unknown command: {args[0]}")
                return
            cmd.help()
            return

        for cmd in self._commands.values():
            if isinstance(cmd, AGroupCommand):
                print()
            cmd.help()

    def complete(self, args: list[str]) -> list[str]:
        prefix = args[-1] if args else ""
        return [n for n in self._commands if n.startswith(prefix)]


class ExitCommand(ACommand):
    name = "exit"
    desc = "Quit btrace"

    def execute(self, args: list[str]) -> None:
        raise EOFError()


class AddCommand(ACommand):
    name      = "add"
    desc      = "Trace targets"
    args_spec = [
        Arg("targets", "function name(s)", required=True),
    ]

    def execute(self, argv: list[str]) -> None:
        parsed = self.parse(argv)
        resp   = self.ctx.srv.send({"action": "add", "body": parsed.positional})
        self.check_ida(resp)
        DEV_LOG(resp)
        for f in resp.get("body", []):
            self.ctx.trace(f)

class DelCommand(ACommand):
    name      = "del"
    desc      = "Untrace targets"
    args_spec = [
        Arg("targets", "function name(s)", required=True),
    ]

    def execute(self, argv: list[str]) -> None:
        parsed = self.parse(argv)
        for name in parsed.positional:
            self.ctx.untrace(name)

class ListCommand(ACommand):
    name      = "list"
    desc      = "List traced targets"
    args_spec = [
    ]

    def execute(self, argv: list[str]) -> None:
        for i, func in enumerate(self.ctx.traced):
            func.print_line(i)

class SaveCommand(ACommand):
    name = "save"
    desc = "Save configuration"

    def execute(self, argv: list[str]) -> None:
        out_file = f"{self.ctx.info.bin_path}.btrace"

        try:
            out_file = f"{self.ctx.info.bin_path}.btrace"
            self.ctx.export_json(out_file)
            print(f"configuration saved at {out_file}")
        except OSError as e:
            raise Exception(f"{e.strerror}: {out_file}")


class PatchCommand(ACommand):
    name = "patch"
    desc = "Patch the targets"

    def execute(self, argv: list[str]) -> None:
        for target in self.ctx.traced:
            print(target.ea)