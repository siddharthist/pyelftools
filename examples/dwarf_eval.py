#-------------------------------------------------------------------------------
# elftools example: dwarf_eval.py
#
# Evaluate (some) DWARFv4 expressions. Requires Python 3.7.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import print_function
import sys
from typing import NamedTuple, Optional

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class, describe_DWARF_expr
from elftools.dwarf.dwarf_expr import GenericExprVisitor


class RegisterOffset(NamedTuple):
    """A register plus a signed offset"""

    register: Optional[str]
    offset: int


class Eval(GenericExprVisitor):
    """An implementation of the DWARF stack machine

    NB: This is not standards compliant, the arithmetic operations are all
    supposed to happen mod some number depending on the largest representable
    address on the machine that the binary is compiled for.
    """

    def __init__(self, structs, arch="x64"):
        super(Eval, self).__init__(structs)
        self._stack = []
        self._arch = arch

    def pop(self):
        return self._pop()

    def _pop(self):
        return self._stack.pop()

    def _push(self, x):
        self._stack.append(x)

    def _after_visit(self, opcode, opcode_name, args):
        # print(f"Visiting {opcode_name} (args={args}) (stack={self._stack})")

        # 2.5.1.1 Literal encodings
        if opcode_name.startswith("DW_OP_lit"):
            i = int(opcode_name[8:])
            assert 0 <= i <= 31
            self._push(i)
        elif opcode_name == "DW_OP_addr":
            assert len(args) == 1
            self._push(args[0])
        elif opcode_name.startswith("DW_OP_const"):
            assert len(args) == 1
            self._push(args[0])

        # 2.5.1.2 Register Based Addressing
        elif opcode_name.startswith("DW_OP_fbreg"):
            assert len(args) == 1
            self._push(RegisterOffset(opcode_name, args[0]))
        elif opcode_name.startswith("DW_OP_breg"):
            assert len(args) == 1
            i = int(opcode_name[10:])
            assert 0 <= i <= 31
            self._push(RegisterOffset(opcode_name, args[0]))
        # elif opcode_name == "DW_OP_bregx":

        # 2.5.1.3 Stack Operations
        elif opcode_name == "DW_OP_dup":
            assert len(args) == 0
            self._push(self._stack[-1])
        elif opcode_name == "DW_OP_drop":
            assert len(args) == 0
            self._pop()
        elif opcode_name == "DW_OP_pick":
            assert len(args) == 1
            self._push(self._stack[-args[0]])
        elif opcode_name == "DW_OP_over":
            assert len(args) == 0
            self._push(self._stack[-2])
        elif opcode_name == "DW_OP_swap":
            assert len(args) == 0
            top = self._pop()
            snd = self._pop()
            self._push(top)
            self._push(snd)
        # elif opcode_name == "DW_OP_rot":
        # elif opcode_name == "DW_OP_deref":
        # elif opcode_name == "DW_OP_deref_size":
        # elif opcode_name == "DW_OP_xderef":
        # elif opcode_name == "DW_OP_xderef_size":
        # elif opcode_name == "DW_OP_push_object_address":
        # elif opcode_name == "DW_OP_form_tls_address":
        # elif opcode_name == "DW_OP_call_frame_cfa":

        # 2.5.1.4 Arithmetic and Logical Operations
        elif opcode_name == "DW_OP_abs":
            self._push(abs(self._pop()))
        elif opcode_name == "DW_OP_and":
            self._push(self._pop() & self._pop())
        elif opcode_name == "DW_OP_div":
            divisor = self._pop()
            dividend = self._pop()
            self.push(
                dividend // divisor)  # TODO: is this appropriately signed?
        elif opcode_name == "DW_OP_minus":
            subtrahend = self._pop()
            minuend = self._pop()
            self.push(minuend - subtrahend)
        elif opcode_name == "DW_OP_mod":
            subtrahend = self._pop()
            minuend = self._pop()
            self.push(minuend % subtrahend)
        elif opcode_name == "DW_OP_mul":
            self._push(self._pop() * self._pop())
        elif opcode_name == "DW_OP_neg":
            self._push(-self._pop())
        elif opcode_name == "DW_OP_not":
            self._push(~self._pop())
        elif opcode_name == "DW_OP_or":
            self._push(self._pop() | self._pop())
        elif opcode_name == "DW_OP_plus":
            self._push(self._pop() + self._pop())
        # elif opcode_name == "DW_OP_plus_uconst":
        # elif opcode_name == "DW_OP_shl":
        # elif opcode_name == "DW_OP_shr":
        # elif opcode_name == "DW_OP_shra":
        elif opcode_name == "DW_OP_xor":
            self._push(self._pop() ^ self._pop())

        # 2.5.1.4 Control Flow Operations
        # elif opcode_name == "DW_OP_le":
        # elif opcode_name == "DW_OP_ge":
        # elif opcode_name == "DW_OP_eq":
        # elif opcode_name == "DW_OP_lt":
        # elif opcode_name == "DW_OP_gt":
        # elif opcode_name == "DW_OP_ne":
        # elif opcode_name == "DW_OP_skip":
        # elif opcode_name == "DW_OP_bra":
        # elif opcode_name == "DW_OP_call2":
        # elif opcode_name == "DW_OP_call4":
        # elif opcode_name == "DW_OP_call_ref":

        elif opcode_name == "DW_OP_nop":
            pass

        # 2.6.1.1.2 Register Location Descriptions
        elif opcode_name.startswith("DW_OP_reg"):
            i = int(opcode_name[9:])
            assert 0 <= i <= 31
            self._push(RegisterOffset(opcode_name, 0))
        # elif opcode_name == "DW_OP_regx":
        elif opcode_name == "DW_OP_stack_value":
            pass

        else:
            raise NotImplementedError(opcode_name)

    def process_expr(self, expr):
        # print(f"Processing {describe_DWARF_expr(expr, self.structs)}")
        self._stack = []
        super(Eval, self).process_expr(expr)


def process_child(die, location_lists, structs):
    # If this DIE has a location attribute, evaluate it.
    loc = die.attributes.get("DW_AT_location")
    if loc is not None:
        visitor = Eval(structs)
        if loc.form == "DW_FORM_sec_offset":
            # Some locations are entries in the location lists, look them up
            # and process them individually
            loc_list = location_lists.get_location_list_at_offset(loc.value)
            for location_entry in loc_list:
                visitor.process_expr(location_entry.loc_expr)
                print("Decoded:", visitor.pop())
        elif loc.form == "DW_form_exprloc" or loc.form == "DW_FORM_exprloc":
            visitor.process_expr(loc.value)
            print("Decoded:", visitor.pop())


def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()
        location_lists = dwarfinfo.location_lists()

        # Iterate over compile units and subprograms, visiting DWARF expressions
        # contained in the location information
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_subprogram":
                    for child in die.iter_children():
                        process_child(child, location_lists, dwarfinfo.structs)


if __name__ == '__main__':
    if sys.argv[1] == '--test':
        for filename in sys.argv[2:]:
            process_file(filename)
