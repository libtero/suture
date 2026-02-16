from rulesets import ClassRuleSet, StackRuleSet
import ida_kernwin
import ida_hexrays
import ida_typeinf
import ida_idaapi
import common
import utils

ACTION_NAME = "suture:create_update_struct"


class Suture(ida_kernwin.action_handler_t):
	def __init__(self):
		super().__init__()
		self.vdui: ida_hexrays.vdui_t
		self.lvar: ida_hexrays.lvar_t
		self.lvar_name: str
		self.lvar_type: ida_typeinf.tinfo_t
		self.lvar_type_new: ida_typeinf.tinfo_t | None
		self.is_stk_lvar: bool
		self.added: bool

	def activate(self, ctx):
		self.vdui = utils.get_current_vdui()
		if not utils.can_process_lvar(self.vdui):
			return
		self.added = False
		self.init_attrs()
		self.process()
		lt = self.lvar_type_new if self.added else self.lvar_type
		self.set_lvar_type(lt)

	def update(self, ctx):
		return ida_kernwin.AST_ENABLE_FOR_WIDGET

	def set_lvar_type(self, t: ida_typeinf.tinfo_t | str):
		if isinstance(t, str):
			t = ida_typeinf.tinfo_t(t)
		for lvar in self.vdui.cfunc.get_lvars():
			if lvar.name == self.lvar_name:
				self.vdui.set_lvar_type(lvar, t)
				break

	def init_attrs(self):
		lvar = utils.get_cursor_lvar(self.vdui)
		self.lvar_name = lvar.name
		self.lvar_type = ida_typeinf.tinfo_t(str(lvar.tif))
		self.lvar_type_new = None
		self.is_stk_lvar = lvar.is_stk_var()

	def process(self):
		new_struct_name = str()

		if self.is_stk_lvar:
			rs = StackRuleSet()
		else:
			rs = ClassRuleSet()
			self.set_lvar_type("__int64")

		matcher = common.Matcher(self.vdui.cfunc, rs)
		matches = matcher.match()

		filtered, extracted = common.Extractor(self.lvar_name, self.vdui.cfunc, matches).data

		if common.DEBUG:
			print("\n------ MATCHES ------")
			print("\n".join([str(i) for i in matches]))
			print("\n------ FILTERED ------")
			print("\n".join([str(i) for i in filtered]))

		if not filtered:
			print("No struct access found")
			return

		ask = False

		if self.is_stk_lvar and not self.lvar_type.is_struct():
			ask = True
		elif not self.lvar_type.is_ptr() or not utils.is_struct_ptr(self.lvar_type):
			ask = True

		if ask:
			if not (new_struct_name := utils.ask_struct_name()):
				return

		if new_struct_name:
			struct_tif = utils.add_struct(new_struct_name)
		else:
			struct_tif = self.lvar_type

		common.Populator(struct_tif, extracted)

		if self.is_stk_lvar:
			self.lvar_type_new = struct_tif
		else:
			self.lvar_type_new = struct_tif if struct_tif.is_ptr() else ida_hexrays.make_pointer(struct_tif)

		self.added = True


class ContextHook(ida_kernwin.UI_Hooks):
	def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
		if not ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE \
				or not utils.can_process_lvar(ida_hexrays.get_widget_vdui(widget)):
			ida_kernwin.detach_action_from_popup(widget, ACTION_NAME)
		else:
			ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_NAME)


def run_tests():
	from pathlib import Path
	import pytest

	test_dir = Path(__file__).parent / "tests"

	targets = [
		test_dir / "test_parser.py",
		test_dir / "test_slice.py",
		test_dir / "test_ruleset.py",
		test_dir / "test_populator.py",
	]

	pytest.main([str(t) for t in targets])


class SuturePlugin(ida_idaapi.plugin_t):
	wanted_name = "Suture"
	flags = ida_idaapi.PLUGIN_HIDE

	def init(self):
		if common.DEBUG:
			run_tests()
		if not ida_hexrays.init_hexrays_plugin():
			return ida_idaapi.PLUGIN_SKIP
		if not ida_kernwin.register_action(ida_kernwin.action_desc_t(
				ACTION_NAME, "Create/Update struct members", Suture(), shortcut="Shift-F")
		):
			return ida_idaapi.PLUGIN_SKIP
		self.hook = ContextHook()
		self.hook.hook()
		return ida_idaapi.PLUGIN_KEEP


def PLUGIN_ENTRY():
	return SuturePlugin()
