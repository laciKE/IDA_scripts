// (c) 2021 Ladislav Baco
// Twitter: @ladislav_b
// https://github.com/laciKE/IDA_scripts
//
// This IDC plugin is inspired by Fluorescence IDA Python plugin:
// https://github.com/tacnetsol/ida/blob/master/plugins/fluorescence/fluorescence.py
//
// This code is licensed under MIT license (see LICENSE for details)

#include <idc.idc>


class CallHighlighterPlugin_t {
    CallHighlighterPlugin_t() {
        this.flags = 0;
        this.comment = "Highlights Call-like instructions\nCurrently supported calls and and push+rets highlighting";
        this.help = "Run Fluorescence plugin for un/highlight call instructions";
        this.wanted_name = "Fluorescence";
        this.wanted_hotkey = "";

	this.COLOR = 0xFF99FF;
	this.calls = 0;
	this.pushrets = 0;
    }

    init() {
        //Message("%s::init() has been called\n", this.wanted_name);
        return PLUGIN_OK;
    }
    
    run(args) {
        //Message("%s::run() has been called\n", this.wanted_name);
	this.highlight();
    }

    term() {
        //Message("%s::term() has been called\n", this.wanted_name);
    }

    is_call(addr) {
        // call instructions
        if (GetMnem(addr) == "call") {
            this.calls++;
            return 1;
        }
    
        // push + retn instructions
        if ((GetMnem(addr) == "retn") && (GetMnem(FindCode(addr, SEARCH_UP | SEARCH_NEXT)) == "push")) {
            this.pushrets++;
            return 1;
        }
    }
    
    highlight() {
        Message("\n===== Fluorescence Call Highlighter =====\n\n");
        
        auto addr;
        addr = 0;
        this.calls = 0;
        this.pushrets = 0;
        while (addr != BADADDR) {
            if (this.is_call(addr)) {
                Message("call at %08lx\t%s\n", addr, GetDisasm(addr));
                if (get_color(addr, CIC_ITEM) == DEFCOLOR) {
                    set_color(addr, CIC_ITEM, this.COLOR);
                } else if (get_color(addr, CIC_ITEM) == this.COLOR) {
                    set_color(addr, CIC_ITEM, DEFCOLOR);
                }
            }
            addr = FindCode(addr, SEARCH_DOWN | SEARCH_NEXT);
        }
    
        Message("\n===== Fluorescence Call Highlighter =====\n\n");
        Message("\tFound %d call instructions\n", this.calls);
        Message("\tFound %d push+retn instructions\n", this.pushrets);
    }

}

static PLUGIN_ENTRY() {
    return CallHighlighterPlugin_t();
}

