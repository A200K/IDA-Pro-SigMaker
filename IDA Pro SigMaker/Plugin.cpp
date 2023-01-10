#include "Plugin.h"

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Signature Maker for IDA Pro by A200K",
    "Select location in disassembly and press CTRL+ALT+S to open menu",
    "Signature Maker",
    "Ctrl-Alt-S"
};
