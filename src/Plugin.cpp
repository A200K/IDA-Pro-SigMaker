#include "Plugin.h"
#include "Version.h"

plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION,
	PLUGIN_MULTI,
	init,
	nullptr,
	nullptr,
	PLUGIN_NAME " v" PLUGIN_VERSION " for IDA Pro by A200K",
	"Select location in disassembly and press CTRL+ALT+S to open menu",
	PLUGIN_NAME,
	"Ctrl-Alt-S"
};
