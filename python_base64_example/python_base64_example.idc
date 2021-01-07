// (c) 2021 Ladislav Baco
// Twitter: @ladislav_b
// https://github.com/laciKE/IDA_scripts
//
// This code is licensed under MIT license (see LICENSE for details)

#include <idc.idc>

static main() {
    msg("===== Base64 decoder with external Python (PoC) =====\n");

    auto ea = get_screen_ea();
    auto flags = get_flags(ea);
    auto addr = BADADDR;
    if (is_strlit(flags)) {
        addr = ea; //cursor is on the string
    } else if (is_code(flags)) {
        addr = get_first_dref_from(ea); //get data reference from the instruction
    }
    if (addr == BADADDR) {
        msg("No string or reference to the string found\n");
        return;
    }
    
    auto base64_str = get_strlit_contents(addr, -1, get_str_type(addr));
    auto output = "ida_output_" + ltoa(addr, 16);
    /*if (idadir()[0] == "/") {
        output = "/tmp/" + output; //Linux/Unix-like temp path
    } else {
        output = "%TEMP%\\" + output; //Windows-like temp path // %TEMP% don't work
    }*/

    call_system("python -c \"from base64 import b64decode; print(b64decode('" + base64_str +"').decode('utf-8'))\" > " + output);

    auto handle = fopen(output, "rb");
    auto decoded_str = substr(readstr(handle), 0, -2); //skip trailing newline character
    fclose(handle);
    unlink(output);

    msg("Base64 string: %s\nDecoded string: %s\n", base64_str, decoded_str);
    set_cmt(addr, decoded_str, 1);
    if (ea != addr ) {
        refresh_idaview_anyway(); //if we have curson on instruction, refresh idaview to display repeatable comment added to the string
    }
}
