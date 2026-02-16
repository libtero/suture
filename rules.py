import ida_typeinf
from ida_hexrays import cexpr_t, cot_call, cot_add, cot_var, cot_num, cot_ptr, cot_cast
from common import RuleExtractResult, AccessInfo, Slice, Rule
from ruletools import ParsePattern, DebugItems, PrintItem


# -------------------------------------- HEAP RULESET --------------------------------------
class InterfaceDispatch(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_call and
			i.x.op is idaapi.cot_ptr and
			i.x.x.op is idaapi.cot_ptr and
			i.x.x.x.op is idaapi.cot_cast and
			i.x.x.x.x.op is idaapi.cot_var and
			i.a[0].op is idaapi.cot_var
			""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult | None:
		r1 = AccessInfo(0,
		                AccessInfo(0, items[1].type))
		return RuleExtractResult(r1, self)


class FieldAccess1(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_ptr and
			i.x.op is idaapi.cot_cast and
			i.x.x.op is idaapi.cot_add and
			i.x.x.x.op is idaapi.cot_var and
			i.x.x.y.op is idaapi.cot_num
			""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[4].numval(), items[0].type)
		return RuleExtractResult(r1, self)


class FunctionalField(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_ptr and
			i.x.op is idaapi.cot_cast and
			i.x.x.op is idaapi.cot_add and
			i.x.x.x.op is idaapi.cot_var and
			i.x.x.y.op is idaapi.cot_num
			""",
		                    predicate=lambda x: x.type.is_funcptr())

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[4].numval(), items[0].type)
		return RuleExtractResult(r1, self)


class VirtualDispatch(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_ptr and
			i.x.op is idaapi.cot_cast and
			i.x.x.op is idaapi.cot_add and
			i.x.x.x.op is idaapi.cot_ptr and
			i.x.x.x.x.op is idaapi.cot_cast and
			i.x.x.x.x.x.op is idaapi.cot_var and
			i.x.x.y.op is idaapi.cot_num
			""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(0,
		                AccessInfo(items[6].numval(), items[0].type))
		return RuleExtractResult(r1, self)


class IndirectionPath1(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_ptr and
			i.x.op is idaapi.cot_cast and
			i.x.x.op is idaapi.cot_add and
			i.x.x.x.op is idaapi.cot_ptr and
			i.x.x.x.x.op is idaapi.cot_ptr and
			i.x.x.x.x.x.op is idaapi.cot_cast and
			i.x.x.x.x.x.x.op is idaapi.cot_add and
			i.x.x.x.x.x.x.x.op is idaapi.cot_var and
			i.x.x.x.x.x.x.y.op is idaapi.cot_num and
			i.x.x.y.op is idaapi.cot_num
			""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[8].numval(),
		                AccessInfo(0,
		                           AccessInfo(items[9].numval(), items[0].type)))
		return RuleExtractResult(r1, self)


class IndirectionPath2(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_ptr and
			i.x.op is idaapi.cot_cast and
			i.x.x.op is idaapi.cot_add and
			i.x.x.x.op is idaapi.cot_ptr and
			i.x.x.x.x.op is idaapi.cot_ptr and
			i.x.x.x.x.x.op is idaapi.cot_cast and
			i.x.x.x.x.x.x.op is idaapi.cot_var and
			i.x.x.y.op is idaapi.cot_num
			""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(0,
		                AccessInfo(0,
		                           AccessInfo(items[7].numval(), items[0].type)))
		return RuleExtractResult(r1, self)


class DataAssignment1(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_asg and
			i.x.op is idaapi.cot_ptr and
			i.x.x.op is idaapi.cot_cast and
			i.x.x.x.op is idaapi.cot_var and
			i.y.op is idaapi.cot_ref and
			i.y.x.op is idaapi.cot_obj
			""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(0, items[4].type)
		return RuleExtractResult(r1, self)


class DataAssignment2(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_asg and
			i.x.op is idaapi.cot_ptr and
			i.x.x.op is idaapi.cot_cast and
			i.x.x.x.op is idaapi.cot_var and
			i.y.op is idaapi.cot_obj
			""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(0, items[4].type)
		return RuleExtractResult(r1, self)


class DataAssignment3(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_asg and
			i.x.op is idaapi.cot_ptr and
			i.x.x.op is idaapi.cot_cast and
			i.x.x.x.op is idaapi.cot_add and
			i.x.x.x.x.op is idaapi.cot_var and
			i.x.x.x.y.op is idaapi.cot_num and
			i.y.op is idaapi.cot_obj
			""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[5].numval(), items[6].type)
		return RuleExtractResult(r1, self)


class FunctionArgument1(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_cast and
			i.x.op is idaapi.cot_add and
			i.x.x.op is idaapi.cot_var and
			i.x.y.op is idaapi.cot_num
			""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[3].numval(), ida_typeinf.remove_pointer(items[0].type))
		return RuleExtractResult(r1, self)


class FieldAccess2(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_ptr and
			i.x.op is idaapi.cot_cast and
			i.x.x.op is idaapi.cot_var
			""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(0, items[0].type)
		return RuleExtractResult(r1, self)


class FunctionArgument3(Rule):
	@property
	def pattern(self) -> Slice:
		return Slice(cot_call, a=Slice(cot_add, x=cot_var, y=cot_num))

	@DebugItems
	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[3].numval(), items[2].type)
		return RuleExtractResult(r1, self)


class FunctionArgument4(Rule):
	@property
	def pattern(self) -> Slice:
		return Slice(cot_call,
		             a=Slice(cot_ptr,
		                     x=Slice(cot_cast,
		                             x=Slice(cot_add,
		                                     x=cot_var,
		                                     y=cot_num)
		                             )
		                     )
		             )

	@DebugItems
	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[5].numval(), items[1].type)
		return RuleExtractResult(r1, self)


class FunctionArgument5(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
		i.op is idaapi.cot_add and
		i.x.op is idaapi.cot_ptr and
		i.x.x.op is idaapi.cot_cast and
		i.x.x.x.op is idaapi.cot_add and
		i.x.x.x.x.op is idaapi.cot_var and
		i.x.x.x.y.op is idaapi.cot_num and
		i.y.op is idaapi.cot_num""")

	@DebugItems
	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[5].numval(), AccessInfo(items[6].numval(), items[1].type))
		return RuleExtractResult(r1, self)


class NestedRootVtableCall(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
		i.op is idaapi.cot_ptr and
		i.x.op is idaapi.cot_ptr and
		i.x.x.op is idaapi.cot_cast and
		i.x.x.x.op is idaapi.cot_var""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(0, AccessInfo(0, items[0].type))
		return RuleExtractResult(r1, self)


class DoubleNestedRootVtableCall1(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
		i.op is idaapi.cot_call and
		i.x.op is idaapi.cot_ptr and
		i.x.x.op is idaapi.cot_ptr and
		i.x.x.x.op is idaapi.cot_ptr and
		i.x.x.x.x.op is idaapi.cot_cast and
		i.x.x.x.x.x.op is idaapi.cot_var""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(0, AccessInfo(0, AccessInfo(0, items[1].type)))
		return RuleExtractResult(r1, self)


class DoubleNestedRootVtableCall2(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
		i.op is idaapi.cot_call and
		i.x.op is idaapi.cot_ptr and
		i.x.x.op is idaapi.cot_ptr and
		i.x.x.x.op is idaapi.cot_cast and
		i.x.x.x.x.op is idaapi.cot_var""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(0, AccessInfo(0, items[1].type))
		return RuleExtractResult(r1, self)


class TripleNestedVtableCall(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
		i.op is idaapi.cot_ptr and
		i.x.op is idaapi.cot_ptr and
		i.x.x.op is idaapi.cot_ptr and
		i.x.x.x.op is idaapi.cot_cast and
		i.x.x.x.x.op is idaapi.cot_add and
		i.x.x.x.x.x.op is idaapi.cot_ptr and
		i.x.x.x.x.x.x.op is idaapi.cot_cast and
		i.x.x.x.x.x.x.x.op is idaapi.cot_add and
		i.x.x.x.x.x.x.x.x.op is idaapi.cot_var and
		i.x.x.x.x.x.x.x.y.op is idaapi.cot_num and
		i.x.x.x.x.y.op is idaapi.cot_num""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[9].numval(), AccessInfo(items[10].numval(), AccessInfo(0, AccessInfo(0, items[0].type))))
		return RuleExtractResult(r1, self)


class DoubleNestedRootVtableCallWithOffset1(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
		i.op is idaapi.cot_call and
		i.x.op is idaapi.cot_ptr and
		i.x.x.op is idaapi.cot_ptr and
		i.x.x.x.op is idaapi.cot_ptr and
		i.x.x.x.x.op is idaapi.cot_cast and
		i.x.x.x.x.x.op is idaapi.cot_add and
		i.x.x.x.x.x.x.op is idaapi.cot_var and
		i.x.x.x.x.x.y.op is idaapi.cot_num""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[7].numval(), AccessInfo(0, AccessInfo(0, items[1].type)))
		return RuleExtractResult(r1, self)


class DoubleNestedRootVtableCallWithOffset2(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
		i.op is idaapi.cot_ptr and
		i.x.op is idaapi.cot_cast and
		i.x.x.op is idaapi.cot_add and
		i.x.x.x.op is idaapi.cot_ptr and
		i.x.x.x.x.op is idaapi.cot_cast and
		i.x.x.x.x.x.op is idaapi.cot_add and
		i.x.x.x.x.x.x.op is idaapi.cot_ptr and
		i.x.x.x.x.x.x.x.op is idaapi.cot_cast and
		i.x.x.x.x.x.x.x.x.op is idaapi.cot_var and
		i.x.x.x.x.x.y.op is idaapi.cot_num and
		i.x.x.y.op is idaapi.cot_num""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(0, AccessInfo(items[9].numval(), AccessInfo(items[10].numval(), items[0].type)))
		return RuleExtractResult(r1, self)

	@property
	def elevated(self):
		return True


# -------------------------------------- STACK RULESET --------------------------------------

class IdxAssignment1(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
		i.op is idaapi.cot_asg and
		i.x.op is idaapi.cot_idx and
		i.x.x.op is idaapi.cot_var and
		i.x.y.op is idaapi.cot_num and
		i.y.op is idaapi.cot_var or idaapi.cot_num or idaapi.cot_ptr""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[1].type.get_size() * items[3].numval(), items[0].type)
		return RuleExtractResult(r1, self)


class DirectAssignmentFromFunction(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
		i.op is idaapi.cot_asg and
		i.x.op is idaapi.cot_ptr and
		i.x.x.op is idaapi.cot_var and
		i.y.op is idaapi.cot_call""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(0, items[2].type)
		return RuleExtractResult(r1, self)


class IdxAssignment2(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
		i.op is idaapi.cot_ptr and
		i.x.op is idaapi.cot_cast and
		i.x.x.op is idaapi.cot_ref and
		i.x.x.x.op is idaapi.cot_idx and
		i.x.x.x.x.op is idaapi.cot_var and
		i.x.x.x.y.op is idaapi.cot_num""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[5].numval() * items[3].type.get_size(), items[0].type)
		return RuleExtractResult(r1, self)


class IdxAssignment3(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_asg and
			i.x.op is idaapi.cot_ptr and
			i.y.op is idaapi.cot_idx and
			i.y.x.op is idaapi.cot_var and
			i.y.y.op is idaapi.cot_num
		""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[4].numval() * items[2].type.get_size(), items[0].type)
		return RuleExtractResult(r1, self)


class IdxAssignment4(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
		i.op is idaapi.cot_asg and
		i.x.op is idaapi.cot_idx and
		i.x.x.op is idaapi.cot_var and
		i.x.y.op is idaapi.cot_num""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(items[1].type.get_size() * items[3].numval(), items[0].type)
		return RuleExtractResult(r1, self)


class DirectAssignment(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
		i.op is idaapi.cot_asg and
		i.x.op is idaapi.cot_ptr and
		i.x.x.op is idaapi.cot_cast and
		i.x.x.x.op is idaapi.cot_var and
		i.y.op is idaapi.cot_num""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(0, items[0].type)
		return RuleExtractResult(r1, self)
