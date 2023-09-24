#include "Main.h"

bool IS_ARM = false;

void AddByteToSignature( Signature &signature, ea_t address, bool wildcard ) {
    SignatureByte byte = {};
    byte.isWildcard = wildcard;
    byte.value = get_byte( address );
    signature.push_back( byte );
}

void AddBytesToSignature( Signature &signature, ea_t address, size_t ulSize, bool wildcard ) {
    for( size_t i = 0; i < ulSize; i++ ) {
        AddByteToSignature( signature, address + i, wildcard );
    }
}

bool GetOperandOffsetARM( const insn_t &instruction, uint8_t *operandOffset, uint8_t *operandLength ) {

    // Iterate all operands
    for( int i = 0; i < UA_MAXOP; i++ ) {
        auto &op = instruction.ops[i];

        // For ARM, we have to filter a bit though, only wildcard those operand types
        switch( op.type ) {
        case o_mem:
        case o_far:
        case o_near:
        case o_phrase:
        case o_displ:
        case o_imm:
            break;
        default:
            continue;
        }

        *operandOffset = op.offb;

        // This is somewhat of a hack because IDA api does not provide more info 
        // I always assume the operand is 3 bytes long with 1 byte operator
        if( instruction.size == 4 ) {
            *operandLength = 3;
        }
        // I saw some ADRL instruction having 8 bytes
        if( instruction.size == 8 ) {
            *operandLength = 7;
        }
        return true;
    }
    return false;
}

bool GetOperand( const insn_t &instruction, uint8_t *operandOffset, uint8_t *operandLength ) {

    // Handle ARM
    if( IS_ARM ) {
        return GetOperandOffsetARM( instruction, operandOffset, operandLength );
    }

    // Handle metapc x86/64

    // Iterate all operands
    for( int i = 0; i < UA_MAXOP; i++ ) {
        auto &op = instruction.ops[i];
        // Skip if we have no operand
        if( op.type == o_void ) {
            continue;
        }
        // offb = 0 means unknown
        if( op.offb == 0 ) {
            continue;
        }
        *operandOffset = op.offb;
        *operandLength = instruction.size - op.offb;
        return true;
    }
    return false;
}

bool IsSignatureUnique( std::string_view signature ) {
    auto ulLastOccurence = inf.min_ea;

    // Convert signature string to searchable struct
    compiled_binpat_vec_t binaryPattern;
    parse_binpat_str( &binaryPattern, inf.min_ea, signature.data(), 16 );

    // Search for occurences
    auto ulOccurence = bin_search2( ulLastOccurence, inf.max_ea, binaryPattern, BIN_SEARCH_NOCASE | BIN_SEARCH_FORWARD );

    // Signature not found
    if( ulOccurence == BADADDR )
        return false;

    // Check if it matches anywhere else
    ulLastOccurence = ulOccurence + 1;
    ulOccurence = bin_search2( ulLastOccurence, inf.max_ea, binaryPattern, BIN_SEARCH_NOCASE | BIN_SEARCH_FORWARD );

    // Signature matched only once
    if( ulOccurence == BADADDR )
        return true;

    return false;
}

// Trim wildcards at end
void TrimSignature( Signature &signature ) {
    auto ri = signature.rbegin();
    while( ri != signature.rend() ) {
        if( ri->isWildcard == true ) {
            ri = decltype( ri )( signature.erase( std::next( ri ).base() ) );
        }
        else {
            break;
        }
    }
}

// Signature to string 
std::string GenerateSignatureString( const Signature &signature, bool doubleQM = false ) {
    std::ostringstream result;
    // Build hex pattern
    for( const auto &byte : signature ) {
        if( byte.isWildcard ) {
            result << ( doubleQM ? "??" : "?" );
        }
        else {
            result << std::format( "{:02X}", byte.value );
        }
        result << " ";
    }
    auto str = result.str();
    // Remove whitespace
    if( !str.empty() )
        str.pop_back();
    return str;
}

std::string GenerateCodeSignatureString( const Signature &signature ) {
    std::ostringstream pattern;
    std::ostringstream mask;
    // Build hex pattern
    for( const auto &byte : signature ) {
        pattern << "\\x" << std::format( "{:02X}", ( byte.isWildcard ? 0 : byte.value ) );
        mask << ( byte.isWildcard ? "?" : "x" );
    }
    auto str = pattern.str() + " " + mask.str();
    return str;
}

std::string GenerateByteArrayWithBitMaskSignatureString( const Signature &signature ) {
    std::ostringstream pattern;
    std::ostringstream mask;
    // Build hex pattern
    for( const auto &byte : signature ) {
        pattern << "0x" << std::format( "{:02X}", ( byte.isWildcard ? 0 : byte.value ) ) << ", ";
        mask << ( byte.isWildcard ? "0" : "1" );
    }
    auto patternStr = pattern.str();
    auto maskStr = mask.str();

    // Reverse bitmask
    std::reverse( maskStr.begin(), maskStr.end() );

    // Remove separators
    if( !patternStr.empty() ) {
        patternStr.pop_back();
        patternStr.pop_back();
    }

    auto str = patternStr + " " + " 0b" + maskStr;
    return str;
}

bool SetClipboard( std::string_view text ) {
    bool result = false;
    if( text.empty() ) {
        return result;
    }

    if( OpenClipboard( NULL ) == false ) {
        msg( "[Error] Failed to open clipboard" );
        return result;
    }

    if( EmptyClipboard() == false ) {
        msg( "[Error] Failed to empty clipboard" );
    }

    auto memoryHandle = GlobalAlloc( GMEM_MOVEABLE | GMEM_ZEROINIT, text.size() + 1 );
    if( memoryHandle == nullptr ) {
        msg( "[Error] Failed to allocate clipboard memory" );
        CloseClipboard();
        return result;
    }

    auto textMem = reinterpret_cast< char * >( GlobalLock( memoryHandle ) );
    if( textMem == nullptr ) {
        msg( "[Error] Failed to lock clipboard memory" );
        GlobalFree( memoryHandle );
        CloseClipboard();
        return result;
    }

    memcpy( textMem, text.data(), text.size() );
    GlobalUnlock( memoryHandle );
    result = SetClipboardData( CF_TEXT, memoryHandle ) != NULL;
    GlobalFree( memoryHandle );
    CloseClipboard();

    if( result ) {
        msg( "[Error] SetClipboardData failed" );
    }
    return result;
}

std::optional<Signature> GenerateSignatureForEA( ea_t ea, bool wildcardOperands, size_t maxSignatureLength = 1000, bool askLongerSignature = true ) {
    if( ea == BADADDR ) {
        msg( "Invalid address\n" );
        return std::nullopt;
    }

    if( !is_code( get_flags( ea ) ) ) {
        msg( "Can not create code signature for data\n" );
        return std::nullopt;
    }

    Signature signature;
    uint32_t sigPartLength = 0;

    auto ulCurrentAddress = ea;
    while( true ) {
        insn_t instruction;
        auto iCurrentInstructionLength = decode_insn( &instruction, ulCurrentAddress );
        if( iCurrentInstructionLength <= 0 ) {
            if( signature.empty() ) {
                msg( "Can't decode @ %I64X, is this actually code?\n", ulCurrentAddress );
                break;
            }

            msg( "Signature reached end of function @ %I64X\n", ulCurrentAddress );
            auto signatureString = GenerateSignatureString( signature );
            msg( "NOT UNIQUE Signature for %I64X: %s\n", ea, signatureString.c_str() );
            break;
        }

        // Length check in case the signature becomes too long
        if( sigPartLength > maxSignatureLength ) {
            if( askLongerSignature ) {
                auto result = ask_yn( 1, "Signature is already at %llu bytes. Continue?", signature.size() );
                if( result == 1 ) { // Yes 
                    sigPartLength = 0;
                }
                else if( result == 0 ) { // No
                    // Print the signature we have so far, even though its not unique
                    auto signatureString = GenerateSignatureString( signature );
                    msg( "NOT UNIQUE Signature for %I64X: %s\n", ea, signatureString.c_str() );
                    break;
                }
                else { // Cancel
                    break;
                }
            }
            else {
                return std::nullopt;
            }
        }
        sigPartLength += iCurrentInstructionLength;

        uint8_t operandOffset = 0, operandLength = 0;
        if( wildcardOperands && GetOperand( instruction, &operandOffset, &operandLength ) && operandLength > 0 ) {
            // Add opcodes
            AddBytesToSignature( signature, ulCurrentAddress, operandOffset, false );
            // Wildcards for operands
            AddBytesToSignature( signature, ulCurrentAddress + operandOffset, operandLength, true );
            // If the operand is on the "left side", add the operator from the "right side"
            if( operandOffset == 0 ) {
                AddBytesToSignature( signature, ulCurrentAddress + operandLength, iCurrentInstructionLength - operandLength, false );
            }
        }
        else {
            // No operand, add all bytes
            AddBytesToSignature( signature, ulCurrentAddress, iCurrentInstructionLength, false );
        }

        auto currentSig = GenerateSignatureString( signature );
        if( IsSignatureUnique( currentSig ) ) {
            // Remove wildcards at end for output
            TrimSignature( signature );

            // Return the signature we generated
            return signature;
        }
        ulCurrentAddress += iCurrentInstructionLength;
    }
    return std::nullopt;
}

std::string FormatSignature( const Signature &signature, SignatureType type ) {
    std::string signatureStr;
    switch( type ) {
    case SignatureType::IDA:
        signatureStr = GenerateSignatureString( signature );
        break;
    case SignatureType::x64Dbg:
        signatureStr = GenerateSignatureString( signature, true );
        break;
    case SignatureType::Signature_Mask:
        signatureStr = GenerateCodeSignatureString( signature );
        break;
    case SignatureType::SignatureByteArray_Bitmask:
        signatureStr = GenerateByteArrayWithBitMaskSignatureString( signature );
        break;
    }
    return signatureStr;
}

const bool IsARM() {
    return std::string_view( "ARM" ) == inf.procname;
}

bool idaapi plugin_ctx_t::run( size_t ) {

    // Check what processor we have
    if( IsARM() ) {
        IS_ARM = true;
    }

    // Show dialog
    const char format[] =
        "STARTITEM 0\n"                                                 // TabStop
        "Signature Maker\n"                                             // Title

        "Select action:\n"                                              // Title
        "<Create Signature for current code address:R>\n"               // Radio Button 0
        "<Find shortest XREF Signature for current data or code address:R>\n"		// Radio Button 1
        "<Copy selected code:R>>\n"                                     // Radio Button 2

        "Output format:\n"                                              // Title
        "<IDA Signature:R>\n"				                            // Radio Button 0
        "<x64Dbg Signature:R>\n"			                            // Radio Button 1
        "<C Signature + String mask:R>\n"			                    // Radio Button 2
        "<C Byte Array Signature + Bitmask:R>>\n"			            // Radio Button 3

        "Options:\n"                                                    // Title
        "<Wildcards for operands:C>>\n\n";                              // Checkbox Button

    static short action = 0;
    static short outputFormat = 0;
    static short wildcardOperands = 1;
    if( ask_form( format, &action, &outputFormat, &wildcardOperands ) ) {
        switch( action ) {
        case 0:
        {
            // Find unique signature for current address
            auto ea = get_screen_ea();
            auto signature = GenerateSignatureForEA( ea, wildcardOperands );
            if( signature.has_value() ) {
                auto signatureStr = FormatSignature( signature.value(), static_cast< SignatureType >( outputFormat ) );
                msg( "Signature for %I64X: %s\n", ea, signatureStr.c_str() );
                SetClipboard( signatureStr );
            }
            break;
        }
        case 1:
        {
            // Iterate XREFs and find shortest signature
            auto ea = get_screen_ea();
            std::vector<Signature> xrefSignatures;
            xrefblk_t xref;
            for( auto xref_ok = xref.first_to( ea, XREF_FAR ); xref_ok; xref_ok = xref.next_to() ) {

                // Skip data refs, xref.iscode is not what we want though
                if( !is_code( get_flags( xref.from ) ) ) {
                    continue;
                }

                auto signature = GenerateSignatureForEA( xref.from, wildcardOperands, 250, false );
                if( !signature.has_value() ) {
                    continue;
                }

                xrefSignatures.push_back( signature.value() );
            }

            // Sort signatures by length
            std::sort( xrefSignatures.begin(), xrefSignatures.end(), []( const Signature &a, const Signature &b ) -> bool { return a.size() < b.size(); } );

            if( xrefSignatures.empty() ) {
                msg( "No XREFs have been found for your address\n" );
                break;
            }

            // Print top 3 Signatures
            auto topLength = min( 3, xrefSignatures.size() );
            msg( "Top %llu Signatures out of %llu xrefs:\n", topLength, xrefSignatures.size() );
            for( int i = 0; i < topLength; i++ ) {
                auto signature = xrefSignatures[i];
                auto signatureStr = FormatSignature( signature, static_cast< SignatureType >( outputFormat ) );
                msg( "XREF Signature for %I64X #%i: %s\n", ea, i + 1, signatureStr.c_str() );

                // Copy first signature only
                if( i == 0 ) {
                    SetClipboard( signatureStr );
                }
            }
            break;
        }
        case 2:
        {
            ea_t start, end;
            if( read_range_selection( get_current_viewer(), &start, &end ) ) {
                auto selectionSize = end - start;
                if( selectionSize > 0 ) {
                    Signature signature;
                    AddBytesToSignature( signature, start, selectionSize, false );
                    auto signatureStr = FormatSignature( signature, static_cast< SignatureType >( outputFormat ) );
                    msg( "Code for %I64X-%I64X: %s\n", start, end, signatureStr.c_str() );
                    SetClipboard( signatureStr );
                }
                else {
                    msg( "Code selection %I64X-%I64X is too small!\n", start, end );
                }
            }
            break;
        }
        default:
            break;
        }
    }
    return true;
}
