"""APIs for diagnosing and altering a state graph inside a binary.

When a safety policy is violated, :class:`taveren.RootCauseAnalysis` traces the violation back to
*root causes* in the binary (subclasses of :class:`CauseBase`). A root cause can then be mitigated
with a *patch* (:class:`EditDataPatch` and friends), either on an angr state, to re-run recovery
and check the fix, or on the running PLC process.

Patches subclass Patcherex's ``Patch`` when Patcherex is installed; Patcherex is optional, since
applying a patch does not use it.

Examples:
    Fix a timer constant that a root cause pointed at, and check the fix on an angr state:

    >>> import angr
    >>> from angr import claripy
    >>> proj = angr.load_shellcode(b"\\xc3", arch="amd64")
    >>> state = proj.factory.blank_state()
    >>> state.memory.store(0x2000, claripy.BVV(20000, 32), endness="Iend_LE")
    >>> cause = DataItemCause(0x2000, "int", 4, name="TIMEOUT")
    >>> patch = EditDataPatch(cause.addr, (15).to_bytes(4, "little"))
    >>> apply_patch_on_state(patch, state)
    >>> state.solver.eval(state.memory.load(0x2000, 4, endness="Iend_LE"))
    15
"""

import struct
from typing import List, Optional, Iterable, TYPE_CHECKING
import logging

if TYPE_CHECKING:
    import angr

_l = logging.getLogger(name=__name__)

try:
    from patcherex.patches import Patch
except ImportError:
    # dummy patch base class
    class Patch:
        """Stand-in for ``patcherex.patches.Patch`` when Patcherex is not installed."""

        def __init__(self, name):
            self.name = name


from .abstract_state import AbstractState

#
# Patches
#


class AddStatePatch(Patch):
    """
    Add a new state and its corresponding logic (implemented as assembly code for now) to the state graph inside the
    binary.

    This patch is implemented as a combination of lower-level Patcherex patches. Applying it is not supported yet.

    Args:
        pred_states: Predecessor states of this new abstract state.
        succ_states: Successor states of this new abstract state.
        asm_code: The assembly code that implements the logic of this new abstract state.
        name: An optional name for the patch.

    Examples:
        >>> from taveren import AbstractStateFields
        >>> from taveren.abstract_state import AbstractState
        >>> fields = AbstractStateFields({"VALVE": (0x1000, "bool", 1)})
        >>> idle = AbstractState(fields, {"VALVE": 0})
        >>> AddStatePatch([idle], asm_code="mov byte ptr [0x1000], 0")
        AddStatePatch
    """

    def __init__(
        self,
        pred_states: Iterable[AbstractState],
        succ_states: Optional[Iterable[AbstractState]] = None,
        asm_code: Optional[str] = None,
        name: Optional[str] = None,
    ):

        super().__init__(name)

        self.pred_states = pred_states
        self.succ_states = succ_states
        self.asm_code = asm_code

    def __repr__(self):
        return "AddStatePatch"


class EditDataPatch(Patch):
    """
    Edit an existing constant value in the binary. Note that the constant value to be edited may or may not be in a
    data section. In other words, you may use EditDataPatch to directly edit bytes anywhere in the binary.

    If old_data is specified, it will be used to check against existing data before applying this patch. The patch will
    not be applied if existing data does not match old_data.

    ``data`` is written byte for byte, so encode multi-byte values in the target's endianness.

    Args:
        addr: The address of the first byte to overwrite.
        data: The new bytes.
        old_data: The bytes expected at ``addr`` before patching.
        name: An optional name for the patch.

    Examples:
        Change the 4-byte chunk at ``0x83200`` from ``04 00 00 00`` to ``13 37 00 00``:

        >>> p = EditDataPatch(0x83200, b"\\x13\\x37\\x00\\x00", old_data=b"\\x04\\x00\\x00\\x00")
        >>> hex(p.addr), p.data.hex(" ")
        ('0x83200', '13 37 00 00')

        See :func:`apply_patch_on_state` and :func:`apply_patch` for applying it.
    """

    def __init__(
        self,
        addr: int,
        data: bytes,
        old_data: Optional[bytes] = None,
        name: Optional[str] = None,
    ):
        super().__init__(name)
        self.addr = addr
        self.data = data
        self.old_data = old_data


class EditInstrPatch(Patch):
    """
    Edit an existing instruction in the binary. Note that this patch is not always applicable.

    For now, the following edits are supported.

    - Changing comparison operators: (signed to unsigned, unsigned to signed, less than to greater than, less than or
      equal to to greater than or equal to, etc.)
    - Nopping instructions.

    Applying it is not supported yet.

    Args:
        addr: The address of the instruction to edit.
        new_instr: The replacement instruction, in assembly.
        name: An optional name for the patch.

    Examples:
        Make a signed comparison unsigned:

        >>> p = EditInstrPatch(0x401A2C, "jae 0x401a40")
        >>> hex(p.addr), p.new_instr
        ('0x401a2c', 'jae 0x401a40')
    """

    def __init__(self, addr: int, new_instr: str, name: Optional[str] = None):
        super().__init__(name)
        self.addr = addr
        self.new_instr = new_instr


#
# Root cause diagnosis
#


class CauseBase:
    """
    This is the base class for all possible root causes.

    A root cause is a location in the binary (a data item, an instruction operand or an instruction opcode) that
    decides how the program behaves in a policy violation. Causes are hashable and compare by value, so duplicates
    can be removed with a ``set``.

    Examples:
        >>> causes = [InstrOpcodeCause(0x401000, "cmp"), InstrOpcodeCause(0x401000, "cmp")]
        >>> len(set(causes))
        1
        >>> all(isinstance(c, CauseBase) for c in causes)
        True
    """

    pass


class DataItemCause(CauseBase):
    """
    Describes root causes that only involve a single data item in the original binary.

    For example, in the following piece of program::

        int a = 20000;  // line 1
        sleep(a);  // line 2

    The root cause of "sleeping for *20,000* seconds" is the integer 20,000 that is involved at line 1. For
    architectures like ARM and MIPS, large integers are almost always directly loaded from memory. In these scenarios,
    it can be captured by a DataItemCause instance.

    Args:
        addr: The address of the data item.
        data_type: Its type: ``"int"``, ``"float"`` or ``"double"``.
        data_size: Its size in bytes.
        name: The variable name, if known (e.g. a configuration variable from the environment model).

    Examples:
        >>> DataItemCause(0x83200, "int", 4)
        <DataItemCause: int@0x83200[4 bytes]>
        >>> DataItemCause(0x83200, "int", 4, name="TIMEOUT")
        <DataItemCause: int@0x83200[4 bytes]TIMEOUT>
    """

    def __init__(
        self, addr: int, data_type: str, data_size: int, name: Optional[str] = None
    ):
        self.addr = addr
        self.data_type = data_type
        self.data_size = data_size
        self.name = name

    def __repr__(self):
        return (
            f"<DataItemCause: {self.data_type}@{self.addr:#x}[{self.data_size} bytes]%s>"
            % (self.name if self.name else "")
        )

    def __eq__(self, other):
        if not isinstance(other, DataItemCause):
            return False
        return (
            self.addr == other.addr
            and self.data_type == other.data_type
            and self.data_size == other.data_size
            and self.name == other.name
        )

    def __hash__(self):
        return hash((self.addr, self.data_type, self.data_size, self.name))


class InstrOperandCause(CauseBase):
    """
    Describes root causes that only involve an instruction operand.

    For example, in the following piece of program::

        int a = 2; // line 1
        sleep(a); // line 2

    The root cause of "sleeping for *2* seconds" is the integer 2 that is involved at line 1. If this integer is
    directly used in an instruction, the cause can be captured by an InstrOperandCause instance.

    Args:
        addr: The address of the instruction.
        operand_idx: The index of the operand within the instruction.
        old_value: The current value of the operand.

    Examples:
        For ``mov edi, 2`` at ``0x401000``, the constant is operand 1:

        >>> InstrOperandCause(0x401000, 1, 2)
        <InstrOperandCause 0x401000 operand 1:2>
    """

    def __init__(self, addr: int, operand_idx: int, old_value: int):
        self.addr = addr
        self.operand_idx = operand_idx
        self.old_value = old_value

    def __repr__(self):
        return f"<InstrOperandCause {self.addr:#x} operand {self.operand_idx}:{self.old_value}>"

    def __eq__(self, other):
        if not isinstance(other, InstrOperandCause):
            return False
        return (
            self.addr == other.addr
            and self.operand_idx == other.operand_idx
            and self.old_value == other.old_value
        )

    def __hash__(self):
        return hash((self.addr, self.operand_idx, self.old_value))


class InstrOpcodeCause(CauseBase):
    """
    Describes root causes that only involve an instruction opcode or operator.

    For example, in the following piece of program::

        int a = b + 2; // line 1
        sleep(a); // line 2

    The root cause of "sleeping for *b + 2* seconds" involves the add operator. If this addition operation is
    implemented as an instruction, such as ``add r0, r0, 2``, then InstrOpcodeCause will be able to capture it.

    Args:
        addr: The address of the instruction.
        operator: The instruction mnemonic, e.g. ``"add"`` or ``"cmp"``.

    Examples:
        >>> InstrOpcodeCause(0x10A4C, "add")
        <InstrOpcodeCause 0x10a4c opcode add>
    """

    def __init__(self, addr: int, operator):
        self.addr = addr
        self.operator = operator

    def __repr__(self):
        return f"<InstrOpcodeCause {self.addr:#x} opcode {self.operator}>"

    def __eq__(self, other):
        if not isinstance(other, InstrOpcodeCause):
            return False
        return self.addr == other.addr and self.operator == other.operator

    def __hash__(self):
        return hash((self.addr, self.operator))


#
# Interaction
#


def generate_patch(arch, causes: List[CauseBase]) -> Optional[Patch]:
    """
    Interactively build a patch that mitigates one of ``causes``.

    Asks on standard input which cause to mitigate and, for a :class:`DataItemCause`, its new value, which is
    encoded according to the cause's data type and ``arch``'s endianness. Other cause types are not supported yet.

    Args:
        arch: The architecture of the binary (``proj.arch``).
        causes: The root causes to choose from, as listed to the user.

    Returns:
        An :class:`EditDataPatch`, or ``None`` if the input is invalid or the chosen cause cannot be patched.

    Raises:
        RuntimeError: If the chosen cause has an unsupported data type.

    Examples:
        With the answers ``0`` (the first cause) and ``15`` (its new value):

        >>> import archinfo
        >>> from unittest import mock
        >>> causes = [DataItemCause(0x83200, "int", 4, name="TIMEOUT")]
        >>> with mock.patch("builtins.input", side_effect=["0", "15"]):
        ...     patch = generate_patch(archinfo.ArchAMD64(), causes)
        >>> hex(patch.addr), patch.data
        ('0x83200', b'\\x0f\\x00\\x00\\x00')
    """
    # patches
    idx = input(
        "[?] Which root cause do you want to mitigate? (%d - %d) "
        % (0, len(causes) - 1)
    )
    try:
        idx = int(idx)
    except (ValueError, TypeError):
        print("[-] Invalid ID. Continue.")
        return
    if 0 <= idx < len(causes):
        cause = causes[idx]
        # Generate patch based on user input and cause type
        if isinstance(cause, DataItemCause):
            new_value = input("[?] New value:")
            endness_prefix = "<" if arch.memory_endness == "Iend_LE" else ">"

            # encode the value as required
            if cause.data_type == "int":
                new_data = struct.pack(f"{endness_prefix}I", int(new_value))
            elif cause.data_type == "float":
                new_data = struct.pack(f"{endness_prefix}f", float(new_value))
            elif cause.data_type == "double":
                new_data = struct.pack(f"{endness_prefix}d", float(new_value))
            else:
                raise RuntimeError(f"Unsupported data type {cause.data_type}")

            patch = EditDataPatch(cause.addr, new_data)
            return patch

    return None


def apply_patch_on_state(patch: Patch, state: "angr.SimState"):
    """
    Apply ``patch`` to the memory of an angr state.

    Use this to re-run state graph recovery on a patched program and check that a violation is gone.

    Args:
        patch: The patch to apply. Only :class:`EditDataPatch` is supported.
        state: The state to modify in place.

    Raises:
        NotImplementedError: For any other patch type.

    Examples:
        >>> import angr
        >>> proj = angr.load_shellcode(b"\\xc3", arch="amd64")
        >>> state = proj.factory.blank_state()
        >>> apply_patch_on_state(EditDataPatch(0x2000, b"\\x13\\x37"), state)
        >>> hex(state.solver.eval(state.memory.load(0x2000, 2)))
        '0x1337'
    """
    if isinstance(patch, EditDataPatch):
        state.memory.store(patch.addr, patch.data, endness="Iend_BE")
    else:
        raise NotImplementedError("Do not support other types of patches yet.")


def apply_patch(
    patch: Patch,
    file_path: str,
    output_path: str,
    proj: "angr.Project",
    start_addr: int,
) -> None:
    """
    Write a script that applies ``patch`` to a running PLC process.

    The generated Python script takes a process ID as its only argument, finds where the PLC library is mapped in
    that process (any mapping whose path contains ``/tmp/``, where the Beremiz runtime loads it), and overwrites the
    patched bytes with ``python-ptrace``. Patches other than :class:`EditDataPatch` are ignored.

    Args:
        patch: The patch to apply.
        file_path: The path of the binary. Unused.
        output_path: Where to write the script.
        proj: The angr project of the binary, used to turn ``patch.addr`` into an offset from the load address.
        start_addr: Unused.

    Examples:
        >>> import angr, os, tempfile
        >>> proj = angr.load_shellcode(b"\\xc3", arch="amd64")
        >>> out = os.path.join(tempfile.mkdtemp(), "fix.py")
        >>> apply_patch(EditDataPatch(0x10, b"\\x0f"), "plc.so", out, proj, 0)
        >>> print(open(out).read())
        <BLANKLINE>
        import sys
        import ptrace.debugger
        ...
        process.writeBytes(lib_base_addr + 0x10, b"\\x0f")
        ...

        Then, on the PLC host: ``python3 fix.py <pid>``.
    """
    if isinstance(patch, EditDataPatch):
        # create a patch that uses ptrace to overwrite the target address in memory
        prolog = """
import sys
import ptrace.debugger

def get_library_base(pid: int, library_name: str):
    with open(f"/proc/{pid}/maps", "r") as f:
        lines = f.read().split("\\n")
        for line in lines:
            if library_name in line:
                items = line.split(" ")
                base_addr = items[0][:items[0].index("-")]
                base_addr = int(base_addr, 16)
                return base_addr
    return None


pid = int(sys.argv[1])
library_name = "/tmp/"

lib_base_addr = get_library_base(pid, library_name)
debugger = ptrace.debugger.PtraceDebugger()
process = debugger.addProcess(pid, False)
"""
        epilog = """
process.detach()
        """
        overwrite_one_byte = 'process.writeBytes(lib_base_addr + %#x, b"\\x%02x")'

        py_code = prolog + "\n"
        for pos, byt in enumerate(patch.data):
            py_code += overwrite_one_byte % (
                patch.addr - proj.loader.main_object.mapped_base + pos,
                byt,
            )
            py_code += "\n"
        py_code += epilog + "\n"

        with open(output_path, "w") as f:
            f.write(py_code)

        return

    return None
