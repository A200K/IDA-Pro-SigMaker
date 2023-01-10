#pragma once
#include <Windows.h>
#include <optional>
#include <string>
#include <sstream>
#include <format>
#include <vector>

#include "Plugin.h"

// Signature types and structures
enum class SignatureType : uint32_t {
    IDA = 0,
    x64Dbg,
    Signature_Mask,
    SignatureByteArray_Bitmask
};

typedef struct {
    uint8_t value;
    bool isWildcard;
} SignatureByte;

using Signature = std::vector<SignatureByte>;