import common
import ida_typeinf
import ida_kernwin
import ida_hexrays
import idc


def is_struct_ptr(tif: ida_typeinf.tinfo_t) -> bool:
	if tif.is_ptr():
		return tif.get_pointed_object().is_struct()
	return False


def can_fit_member(struct_tif: ida_typeinf.tinfo_t,
                   off: int,
                   size: int
                   ) -> tuple[bool, int]:
	tid = struct_tif.get_tid()
	for i in range(size):
		name = idc.get_member_name(tid, off + i)

		if common.DEBUG:
			print(f"Member Name: {struct_tif} @ 0x{off + i:02X} -> {name}")

		if name is not None and not name.startswith("gap"):
			return False, off + i

		udm = struct_tif.get_udm_by_offset(off * 8 + i)[1]
		if udm and not udm.is_gap():
			return False, off + i

	return True, 0


def get_member_type(struct_tif, off: int) -> ida_typeinf.tinfo_t | None:
	if r := struct_tif.get_udm_by_offset(off * 8)[1]:
		if common.DEBUG:
			print(f"Member Type: {struct_tif} @ 0x{off:02X} -> {r.type}")
		if not r.is_gap():
			return r.type
	return None


def add_struct(name: str) -> ida_typeinf.tinfo_t:
	sid = idc.add_struc(-1, name, 0)
	tif = ida_typeinf.tinfo_t()
	tif.get_type_by_tid(sid)
	if common.DEBUG:
		print(f"Adding Struct: {tif}")
	assert len(str(tif)), "Failed to create new struct"
	return tif


def add_member(struct_tif: ida_typeinf.tinfo_t,
               name: str,
               member_type: ida_typeinf.tinfo_t,
               off: int,
               force: bool = False
               ):
	size = struct_tif.get_size()
	flags = ida_typeinf.ETF_FORCENAME
	flags = ida_typeinf.ETF_MAY_DESTROY | flags if force else flags

	if common.DEBUG:
		print(f"Adding Member: {struct_tif} @ 0x{off:02X} -> {member_type}")

	if off > size:
		struct_tif.add_udm(name, member_type, size * 8, flags)
		idc.expand_struc(struct_tif.get_tid(), size, off - size)
	else:
		struct_tif.add_udm(name, member_type, off * 8, flags)


def struct_exists(name: str) -> bool:
	return idc.get_struc_id(name) != idc.BADADDR


def struct_with_name_exists(name: str) -> bool:
	return idc.get_struc_id(name) != idc.BADADDR


def new_tmpstruct_name() -> str:
	i = 1
	while True:
		name = "tmpstru_{}".format(i)
		if not struct_exists(name):
			return name
		i += 1


def ask_struct_name() -> str | None:
	while True:
		if not (name := ida_kernwin.ask_str(new_tmpstruct_name(), 0, "New struct name")):
			return None

		if struct_with_name_exists(name):
			ida_kernwin.warning("Struct name already taken")
			continue

		return name


def get_current_vdui() -> ida_hexrays.vdui_t:
	widget = ida_kernwin.get_current_widget()
	return ida_hexrays.get_widget_vdui(widget)


def get_cursor_lvar(vdui) -> ida_hexrays.lvar_t | None:
	try:
		cit = vdui.item.it
		lvars = vdui.cfunc.get_lvars()
		idx = cit.cexpr.get_v().idx
		return lvars[idx]

	except (KeyError, AttributeError):
		pass

	return None


def can_process_lvar(vdui: ida_hexrays.vdui_t) -> bool:
	if not vdui:
		return False

	if vdui.get_current_item(ida_hexrays.USE_KEYBOARD):
		lvar = get_cursor_lvar(vdui)
		if lvar:
			return True

	return False


def log_struct_action(struct_tif: ida_typeinf.tinfo_t,
                      off: int,
                      added: bool):
	t = "Added" if added else "Conflict"
	print("{} {} @ 0x{:X} for {}".format(
		t,
		get_member_type(struct_tif, off),
		off,
		str(struct_tif))
	)


def get_ptr_shift(t: ida_typeinf.tinfo_t) -> int:
	if not t.is_ptr():
		return 0
	info = ida_typeinf.ptr_type_data_t()
	t.get_ptr_details(info)
	if info.is_shifted():
		return info.delta
	return 0


def get_proc_ptr_size() -> int:
	return 8 if idc.__EA64__ else 4
