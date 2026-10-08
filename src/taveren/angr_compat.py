"""
Compatibility layer between Ta'veren and upstream angr.

Ta'veren used to depend on patched forks of angr and claripy (pulled in as git
submodules). This module re-applies those patches on top of the stock angr
release so that the forks are no longer needed:

* ``div`` and ``fmod`` libc SimProcedures.
* PPC64: set ``r12`` to the callee address in call states (ELFv2 global entry
  points derive the TOC pointer from ``r12``).
* ARM: lift THUMB blocks with some look-back bytes so that VEX can tell whether
  an instruction sits inside an IT block.
* claripy: a handful of extra canonicalization rules for constraints. Since
  angr 10, claripy is implemented in Rust and its simplifiers cannot be
  extended from Python, so the rules are applied to every constraint that is
  added to a state's solver instead.

It also restores pure-Python claripy behavior that angr 10 changed:

* ``SimSolver.min()``/``max()`` with ``signed=True`` return negative values
  instead of unsigned bit patterns.

It also provides ``make_like()``, which replaces ``claripy.ast.Base.make_like()``
that no longer exists.

The patches are applied when this module is imported (``taveren/__init__.py``
does that).
"""

from __future__ import annotations

import contextvars
import functools
import inspect
import operator

import angr
import archinfo
from angr import claripy
from angr.engines.vex.lifter import VEXLifter
from angr.simos.simos import SimOS
from angr.state_plugins.sim_action_object import _raw_ast
from angr.state_plugins.solver import SimSolver

#
# claripy helpers
#

_OPERATORS = {
    "__add__": operator.add,
    "__sub__": operator.sub,
    "__mul__": operator.mul,
    "__floordiv__": operator.floordiv,
    "__mod__": operator.mod,
    "__and__": operator.and_,
    "__or__": operator.or_,
    "__xor__": operator.xor,
    "__lshift__": operator.lshift,
    "__rshift__": operator.rshift,
    "__eq__": operator.eq,
    "__ne__": operator.ne,
}


def make_like(op: str, args) -> claripy.ast.Base:
    """
    Build an AST of operation ``op`` from ``args``.

    Replacement for ``claripy.ast.Base.make_like()`` from pure-Python claripy.
    Note that the argument layout of some operations differs from pure-Python
    claripy (e.g., ``fpMul`` takes ``(lhs, rhs, rm)``), so ``args`` must follow
    the layout of ``ast.args`` in the current claripy.
    """
    if op in _OPERATORS:
        return functools.reduce(_OPERATORS[op], args)
    if op in ("fpAdd", "fpSub", "fpMul", "fpDiv"):
        lhs, rhs, rm = args
        return getattr(claripy, op)(rm, lhs, rhs)
    return getattr(claripy, op)(*args)


def leaf_asts(expr):
    """
    Yield the unique leaf ASTs of ``expr``.

    Replacement for ``claripy.ast.Base.leaf_asts()`` from pure-Python claripy.
    """
    seen = set()
    stack = [expr]
    while stack:
        node = stack.pop()
        if node.hash() in seen:
            continue
        seen.add(node.hash())
        if node.is_leaf():
            yield node
        else:
            stack.extend(reversed(_children(node)))


def _children(expr):
    return [arg for arg in expr.args if isinstance(arg, claripy.ast.Base)]


def _canonicalize_node(expr):
    """
    Rules ported from Ta'veren's claripy fork, plus simplifications that
    pure-Python claripy did but angr 10's claripy does not. Returns None if no
    rule applies.
    """
    op = expr.op
    if op in ("__add__", "__sub__"):
        # expr + 0 -> expr, expr - 0 -> expr
        args = [
            arg
            for i, arg in enumerate(expr.args)
            if not (
                arg.op == "BVV"
                and arg.concrete_value == 0
                and (op == "__add__" or i > 0)
            )
        ]
        if len(args) == 1:
            return args[0]
        if len(args) < len(expr.args):
            return make_like(op, args)
    elif op == "__ne__":
        # c1 - expr != c2  ->  expr != c1 - c2
        a, b = expr.args
        if (
            a.op == "__sub__"
            and len(a.args) == 2
            and a.args[0].op == "BVV"
            and b.op == "BVV"
        ):
            return a.args[1] != a.args[0] - b
    elif op == "UGE":
        # c >= expr  ->  expr <= c
        a, b = expr.args
        if a.op == "BVV" and b.op != "BVV":
            return claripy.ULE(b, a)
    elif op == "__and__" and len(expr.args) == 2:
        # If(cond, iftrue, iffalse) & c  ->  If(cond, iftrue & c, iffalse & c)
        a, b = expr.args
        if a.op == "BVV" and b.op == "If":
            a, b = b, a
        if a.op == "If" and b.op == "BVV":
            cond, iftrue, iffalse = a.args
            if iftrue.op == "BVV" or iffalse.op == "BVV":
                return claripy.If(cond, iftrue & b, iffalse & b)
    return None


def canonicalize(expr, _max_rounds: int = 8):
    """
    Apply the canonicalization rules of Ta'veren's claripy fork to every node
    of ``expr``.
    """
    if not isinstance(expr, claripy.ast.Base) or expr.is_leaf():
        return expr
    for _ in range(_max_rounds):
        # find the first (post-order) node that can be rewritten
        seen = set()
        stack = [(expr, False)]
        found = None
        while stack and found is None:
            node, expanded = stack.pop()
            if expanded:
                new = _canonicalize_node(node)
                if new is not None and not new.identical(node):
                    found = node, new
                continue
            if node.hash() in seen:
                continue
            seen.add(node.hash())
            stack.append((node, True))
            stack.extend(
                (child, False) for child in _children(node) if not child.is_leaf()
            )
        if found is None:
            break
        expr = expr.replace(*found)
    return expr


_orig_solver_add = SimSolver.add
_orig_solver_simplify = SimSolver.simplify


@functools.wraps(_orig_solver_add)
def _solver_add(self, *constraints):
    return _orig_solver_add(self, *(canonicalize(c) for c in constraints))


@functools.wraps(_orig_solver_simplify)
def _solver_simplify(self, e=None):
    r = _orig_solver_simplify(self, e)
    if e is None:
        return r
    return canonicalize(r)


def _to_signed(value, bits):
    if value >= 1 << (bits - 1):
        return value - (1 << bits)
    return value


_orig_solver_min = SimSolver.min
_orig_solver_max = SimSolver.max


# angr 10's claripy solves min/max with signed=True correctly but returns the
# result as an unsigned bit pattern; pure-Python claripy returned a Python int
# with the sign applied.
@functools.wraps(_orig_solver_min)
def _solver_min(self, e, *args, signed=False, **kwargs):
    r = _orig_solver_min(self, e, *args, signed=signed, **kwargs)
    return _to_signed(r, e.size()) if signed else r


@functools.wraps(_orig_solver_max)
def _solver_max(self, e, *args, signed=False, **kwargs):
    r = _orig_solver_max(self, e, *args, signed=signed, **kwargs)
    return _to_signed(r, e.size()) if signed else r


#
# SimProcedures
#


class div(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, x, y):
        if archinfo.arch_arm.is_arm_arch(self.arch):
            # on ARM, div_t is returned in memory; the result pointer is passed in r0, so the operands are shifted by
            # one register
            ptr = _raw_ast(x)
            x = _raw_ast(y)
            y = _raw_ast(self.state.regs.r2)
            x = x[31:0]
            y = y[31:0]
            quotient = x / y
            remainder = x % y
            self.state.memory.store(ptr, quotient, endness=self.arch.memory_endness)
            self.state.memory.store(
                ptr + 4, remainder, endness=self.arch.memory_endness
            )
            return ptr
        x = _raw_ast(x)
        y = _raw_ast(y)
        x = x[31:0]
        y = y[31:0]
        quotient = x / y
        remainder = x % y
        return claripy.Concat(quotient, remainder)


class fmod(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, x, y):
        val_len = self.arch.bytes * self.arch.byte_width
        # both x and y are double
        x = _raw_ast(x)
        y = _raw_ast(y)
        rm = claripy.fp.RM.RM_TowardsZero

        if x.size() != val_len or y.size() != val_len:
            # we need to truncate x or y
            if isinstance(x, claripy.ast.FP):
                x = claripy.fpToSBV(rm, x, val_len)
            if isinstance(y, claripy.ast.FP):
                y = claripy.fpToSBV(rm, y, val_len)
            if self.arch.memory_endness == "Iend_LE":
                x = x[63 : 64 - val_len]
                y = y[63 : 64 - val_len]
            else:
                x = x[63:0]
                y = y[63:0]

        # ensure both x and y are FPs
        x = x.raw_to_fp()
        y = y.raw_to_fp()

        r = x / y
        quotient = claripy.fpToSBV(rm, r, val_len)
        remainder = x - y * quotient.val_to_fp(None)
        return remainder


def _register_libc_procedures():
    for proc in (div, fmod):
        name = proc.__name__
        angr.SIM_PROCEDURES["libc"][name] = proc
        for lib in angr.SIM_LIBRARIES.get("libc.so.6", []):
            lib.add(name, proc)


#
# PPC64 call states
#

_orig_state_call = SimOS.state_call


@functools.wraps(_orig_state_call)
def _state_call(self, addr, *args, **kwargs):
    state = _orig_state_call(self, addr, *args, **kwargs)
    if state.arch.name == "PPC64":
        state.regs.r12 = addr
    return state


#
# THUMB look-back
#

# VEX looks at up to 18 bytes before a THUMB instruction to find a preceding IT instruction
THUMB_LOOKBACK = 20

_lifting_thumb = contextvars.ContextVar("_lifting_thumb", default=False)

_orig_lift_vex = VEXLifter.lift_vex
_orig_load_bytes = VEXLifter._load_bytes
_LIFT_VEX_SIGNATURE = inspect.signature(_orig_lift_vex)


def _is_thumb_lift(args) -> bool:
    arch = args.get("arch")
    state = args.get("state")
    clemory = args.get("clemory")
    if arch is None:
        arch = clemory._arch if clemory else state.arch if state is not None else None
    if not isinstance(arch, archinfo.ArchARM):
        return False
    if args.get("thumb"):
        return True
    addr = args.get("addr")
    if addr is None and state is not None:
        addr = state.solver.eval(state._ip)
    return addr is not None and addr % 2 == 1


@functools.wraps(_orig_lift_vex)
def _lift_vex(self, *args, **kwargs):
    try:
        thumb = _is_thumb_lift(
            _LIFT_VEX_SIGNATURE.bind(self, *args, **kwargs).arguments
        )
    except Exception:  # pylint:disable=broad-except
        # let the original method report bad arguments
        thumb = False
    token = _lifting_thumb.set(thumb)
    try:
        return _orig_lift_vex(self, *args, **kwargs)
    finally:
        _lifting_thumb.reset(token)


@functools.wraps(_orig_load_bytes)
def _load_bytes(self, addr, max_size, state=None, clemory=None):
    buff, size, offset = _orig_load_bytes(self, addr, max_size, state, clemory)
    if not _lifting_thumb.get() or offset >= THUMB_LOOKBACK or addr < THUMB_LOOKBACK:
        # the buffer already holds enough bytes before addr, or there are none to load
        return buff, size, offset
    lb_buff, lb_size, lb_offset = _orig_load_bytes(
        self, addr - THUMB_LOOKBACK, max_size + THUMB_LOOKBACK, state, clemory
    )
    if lb_size <= THUMB_LOOKBACK:
        # the bytes before addr are not contiguous with the block
        return buff, size, offset
    return lb_buff, min(max_size, lb_size - THUMB_LOOKBACK), lb_offset + THUMB_LOOKBACK


def _apply():
    _register_libc_procedures()
    SimOS.state_call = _state_call
    VEXLifter.lift_vex = _lift_vex
    VEXLifter._load_bytes = _load_bytes
    SimSolver.add = _solver_add
    SimSolver.simplify = _solver_simplify
    SimSolver.min = _solver_min
    SimSolver.max = _solver_max


_apply()
