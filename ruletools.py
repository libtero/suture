import ida_hexrays
import common
from typing import Callable
from re import search


def CotToStr(cot: int) -> str:
	if not hasattr(CotToStr, '_keys'):
		CotToStr._keys = {val: name for name, val in ida_hexrays.__dict__.items() if name.startswith("cot_")}
	return CotToStr._keys.get(cot, f"unknown_{cot}")


def PrintItem(e: ida_hexrays.cexpr_t):
	t = e.type
	op = e.op
	op_name = CotToStr(op)

	if op == ida_hexrays.cot_num:
		val = f" {e.numval()}"
	else:
		val = ""
	if op == ida_hexrays.cot_call:
		t = e.x.type

	print(f"  {op_name + val:<15}{t}")


def DebugItems(func):
	def wrapper(self, items):
		if common.DEBUG:
			print(f"\n{str(self)}")
			for i in items:
				PrintItem(i)
		return func(self, items)

	return wrapper


def ParsePattern(chain_str: str,
                 predicate: Callable[[ida_hexrays.cexpr_t], bool] | None = None
                 ) -> common.Slice:
	lines = chain_str.strip().split('\n')
	nodes = {}
	args_map = {}

	for line in lines:
		match = search(
			r'i\.?([xyza0-9\[\].]*)\.op\s+(?:is|==)\s+((?:(?:idaapi|common)\.)?\w+(?:\s+or\s+(?:(?:idaapi|common)\.)?\w+)*)',
			line)
		if match:
			path, op_names = match.groups()
			op_parts = [p.strip().replace('idaapi.', '').replace('common.', '') for p in op_names.split(' or ')]
			op_values = []

			for op_name in op_parts:
				if not (op_val := getattr(ida_hexrays, op_name, None)):
					op_val = getattr(common, op_name, None)
				assert op_val is not None, f"{op_name} not found"
				op_values.append(op_val)

			final_op = tuple(op_values) if len(op_values) > 1 else op_values[0]
			arg_m = search(r'(.*?)\.?a\[(\d+)]', path)

			if arg_m:
				parent_path, idx = arg_m.groups()
				parent_path = parent_path.rstrip('.')
				if parent_path not in args_map: args_map[parent_path] = {}
				args_map[parent_path][int(idx)] = common.Slice(final_op) if isinstance(final_op, int) else final_op
			else:
				nodes[path.rstrip('.')] = final_op

	def build(current_path):
		base_op = nodes.get(current_path)
		x_p, y_p, z_p = [f"{current_path}.{c}" if current_path else c for c in "xyz"]
		s = common.Slice(
			base_op,
			x=build(x_p) if any(k.startswith(x_p) for k in nodes) else None,
			y=build(y_p) if any(k.startswith(y_p) for k in nodes) else None,
			z=build(z_p) if any(k.startswith(z_p) for k in nodes) else None,
			a=args_map.get(current_path)
		)
		if not current_path and predicate:
			s.predicate = predicate
		return s

	return build("")
