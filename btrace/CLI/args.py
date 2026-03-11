
from dataclasses import dataclass, field


@dataclass
class Arg:
    name:     str
    desc:     str
    required: bool  = False
    flag:     bool  = False
    default:  object = None


@dataclass
class ParsedArgs:
    positional: list[str]        = field(default_factory=list)
    flags:      dict[str, object] = field(default_factory=dict)

    def get(self, name: str, default=None):
        return self.flags.get(name, default)

    def has(self, name: str) -> bool:
        return name in self.flags


def parse_args(argv: list[str], spec: list[Arg]) -> ParsedArgs:
    parsed     = ParsedArgs()
    flags_spec = {f"--{a.name}": a for a in spec if a.flag}
    pos_spec   = [a for a in spec if not a.flag]
    i          = 0

    while i < len(argv):
        token = argv[i]
        if token.startswith("--"):
            arg = flags_spec.get(token)
            if not arg:
                raise ValueError(f"unknown flag: {token}")
            if arg.flag:
                parsed.flags[arg.name] = True
            else:
                i += 1
                parsed.flags[arg.name] = argv[i]
        else:
            parsed.positional.append(token)
        i += 1

    # check required
    for arg in spec:
        if arg.required and not arg.flag and len(parsed.positional) < 1:
            raise ValueError(f"missing required argument: <{arg.name}>")
        if arg.required and arg.flag and arg.name not in parsed.flags:
            raise ValueError(f"missing required flag: --{arg.name}")

    return parsed