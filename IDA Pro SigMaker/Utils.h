#pragma once
#include <Windows.h>
#include <vector>
#include <regex>
#include <string_view>

// Generic utility functions

bool SetClipboardText(std::string_view text);
bool GetRegexMatches(std::string string, std::regex regex, std::vector<std::string>& matches);