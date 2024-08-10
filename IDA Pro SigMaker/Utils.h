#pragma once

// To fix regex_error(error_stack) for longer signatures
#define _REGEX_MAX_STACK_COUNT 20000

#include <Windows.h>
#include <vector>
#include <regex>
#include <string_view>

// Generic utility functions

bool GetRegexMatches( std::string string, std::regex regex, std::vector<std::string>& matches );
constexpr auto BIT( uint32_t x ) {
    return 1LLU << x;
}
