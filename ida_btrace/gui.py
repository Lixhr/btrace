import idaapi
import idc
import ida_kernwin

class TraceFunctionAction(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, obj):
        if obj.cur_func:
            from ida_btrace.core import BinTrace
            BinTrace().traceFunc(obj)
        return 1

    def update(self, obj):
        return idaapi.AST_ENABLE if obj.cur_func else idaapi.AST_DISABLE


class GUITracerHook(idaapi.UI_Hooks):
    ACTION_ID = "BinTrace:trace"

    def __init__(self):
        super().__init__()
        self.loaded = False
        self.action = None
        self.hook()

    def ready_to_run(self):
        self.init_action()

    def init_action(self):
        if self.loaded:
            return
        self.action = idaapi.action_desc_t(
            self.ACTION_ID,
            "Trace function",
            TraceFunctionAction(),
            "Shift+B",
            "Adds the function to the BinTrace list",
            -1,
        )
        idaapi.register_action(self.action)
        self.loaded = True

    def finish_populating_widget_popup(self, widget, popup, ctx):
        idaapi.attach_action_to_popup(widget, popup, self.ACTION_ID)

    def term(self):
        if self.action:
            idaapi.unregister_action(self.ACTION_ID)
            self.unhook()

