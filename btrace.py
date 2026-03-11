from btrace.CLI.CLI import BTraceCLI
from btrace.context import BTraceContext
from btrace.CLI.commands import *
import sys

if __name__ == "__main__":
    try:
        ctx = BTraceContext()

        commands = [
            AddCommand(),
            DelCommand(),
            ListCommand(),
            SaveCommand(),
            ExitCommand(),
            PatchCommand(),
        ]
        commands.append(HelpCommand({cmd.name: cmd for cmd in commands}))
        
        if (len(sys.argv) > 1 and sys.argv[1] == "test"): ## TMP
            BTraceCLI(commands).test() ## TMP
        else:
            BTraceCLI(commands).run()
    except OSError as e:
        print(f"Error: {e.strerror}")
    except Exception as e:
        print(f"Error: {e}")