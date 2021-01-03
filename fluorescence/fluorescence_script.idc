// (c) 2021 Ladislav Baco
// Twitter: @ladislav_b
// https://github.com/laciKE/IDA_scripts
//
// This IDC script is inspired by Fluorescence IDA Python plugin:
// https://github.com/tacnetsol/ida/blob/master/plugins/fluorescence/fluorescence.py
//
// This code is licensed under MIT license (see LICENSE for details)

#include <idc.idc>

static is_call(addr) {
    extern calls, pushrets;
    // call instructions
    auto insn = DecodeInstruction(addr);
    auto feature = 0;
    if (insn != 0) {
	feature = insn.feature;
    }
    if ((feature & CF_CALL) || (GetMnem(addr) == "call")) {
        calls++;
        return 1;
    }

    // push + retn instructions
    if ((GetMnem(addr) == "retn") && (GetMnem(FindCode(addr, SEARCH_UP | SEARCH_NEXT)) == "push")) {
        pushrets++;
        return 1;
    }
}

static main() {
    Message("\n===== Fluorescence Call Highlighter =====\n\n");

    auto COLOR;
    COLOR = 0xFF99FF;
    extern calls, pushrets;
    calls = 0;
    pushrets = 0;

    auto addr;
    addr = 0;
    while (addr != BADADDR) {
        if (is_call(addr)) {
            Message("call at %08lx\t%s\n", addr, GetDisasm(addr));
            if (GetColor(addr, CIC_ITEM) == DEFCOLOR) {
                SetColor(addr, CIC_ITEM, COLOR);
            } else if (GetColor(addr, CIC_ITEM) == COLOR) {
                SetColor(addr, CIC_ITEM, DEFCOLOR);
            }
        }
        addr = FindCode(addr, SEARCH_DOWN | SEARCH_NEXT);
    }

    Message("\n===== Fluorescence Call Highlighter =====\n\n");
    Message("\tFound %d call instructions\n", calls);
    Message("\tFound %d push+retn instructions\n", pushrets);
}
