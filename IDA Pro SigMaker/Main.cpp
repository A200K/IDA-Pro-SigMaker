#include "Main.h"

bool IS_ARM = false;

static bool IsARM() {
    return std::string_view( "ARM" ) == inf.procname;
}

static void AddByteToSignature( Signature& signature, ea_t address, bool wildcard ) {
    SignatureByte byte{};
    byte.isWildcard = wildcard;
    byte.value = get_byte( address );
    signature.push_back( byte );
}

static void AddBytesToSignature( Signature& signature, ea_t address, size_t count, bool wildcard ) {
    // signature.reserve( signature.size() + count ); // Not sure if this is overhead for average signature creation
    for( size_t i = 0; i < count; i++ ) {
        AddByteToSignature( signature, address + i, wildcard );
    }
}

static bool GetOperandOffsetARM( const insn_t& instruction, uint8_t* operandOffset, uint8_t* operandLength ) {

    // Iterate all operands
    for( const auto& op : instruction.ops ) {
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

static bool GetOperand( const insn_t& instruction, uint8_t* operandOffset, uint8_t* operandLength ) {

    // Handle ARM
    if( IS_ARM ) {
        return GetOperandOffsetARM( instruction, operandOffset, operandLength );
    }

    // Handle metapc x86/64

    // Iterate all operands
    for( const auto& op : instruction.ops ) {
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

static std::vector<ea_t> FindSignatureOccurences( std::string_view idaSignature ) {
    // Convert signature string to searchable struct
    compiled_binpat_vec_t binaryPattern;
    parse_binpat_str( &binaryPattern, inf.min_ea, idaSignature.data(), 16 );

    // Search for occurences
    std::vector<ea_t> results;
    auto ea = inf.min_ea;
    while( true ) {
        auto occurence = bin_search2( ea, inf.max_ea, binaryPattern, BIN_SEARCH_NOCASE | BIN_SEARCH_FORWARD );
        // Signature not found anymore
        if( occurence == BADADDR ) {
            return results;
        }

        results.push_back( occurence );

        ea = occurence + 1;
    }
    return results;
}

static bool IsSignatureUnique( std::string_view idaSignature ) {
    return FindSignatureOccurences( idaSignature ).size() == 1;
}

// Signature to string 
static std::string BuildIDASignatureString( const Signature& signature, bool doubleQM = false ) {
    std::ostringstream result;
    // Build hex pattern
    for( const auto& byte : signature ) {
        if( byte.isWildcard ) {
            result << ( doubleQM ? "??" : "?" );
        }
        else {
            result << std::format( "{:02X}", byte.value );
        }
        result << " ";
    }
    auto str = result.str();
    // Remove whitespace at end
    if( !str.empty() ) {
        str.pop_back();
    }
    return str;
}

static std::string BuildByteArrayWithMaskSignatureString( const Signature& signature ) {
    std::ostringstream pattern;
    std::ostringstream mask;
    // Build hex pattern
    for( const auto& byte : signature ) {
        pattern << "\\x" << std::format( "{:02X}", ( byte.isWildcard ? 0 : byte.value ) );
        mask << ( byte.isWildcard ? "?" : "x" );
    }
    auto str = pattern.str() + " " + mask.str();
    return str;
}

static std::string BuildBytesWithBitmaskSignatureString( const Signature& signature ) {
    std::ostringstream pattern;
    std::ostringstream mask;
    // Build hex pattern
    for( const auto& byte : signature ) {
        pattern << "0x" << std::format( "{:02X}", ( byte.isWildcard ? 0 : byte.value ) ) << ", ";
        mask << ( byte.isWildcard ? "0" : "1" );
    }
    auto patternStr = pattern.str();
    auto maskStr = mask.str();

    // Reverse bitmask
    std::ranges::reverse( maskStr );

    // Remove separators
    if( !patternStr.empty() ) {
        patternStr.pop_back();
        patternStr.pop_back();
    }

    auto str = patternStr + " " + " 0b" + maskStr;
    return str;
}

static bool SetClipboardText( std::string_view text ) {
    if( text.empty() ) {
        msg( "[Error] Text empty" );
        return false;
    }

    if( OpenClipboard( NULL ) == false ) {
        msg( "[Error] Failed to open clipboard" );
        return false;
    }
    if( EmptyClipboard() == false ) {
        msg( "[Error] Failed to empty clipboard" );
    }

    auto memoryHandle = GlobalAlloc( GMEM_MOVEABLE | GMEM_ZEROINIT, text.size() + 1 );
    if( memoryHandle == nullptr ) {
        msg( "[Error] Failed to allocate clipboard memory" );
        CloseClipboard();
        return false;
    }

    auto textMem = reinterpret_cast< char* >( GlobalLock( memoryHandle ) );
    if( textMem == nullptr ) {
        msg( "[Error] Failed to lock clipboard memory" );
        GlobalFree( memoryHandle );
        CloseClipboard();
        return false;
    }

    memcpy( textMem, text.data(), text.size() );
    GlobalUnlock( memoryHandle );
    auto handle = SetClipboardData( CF_TEXT, memoryHandle );
    GlobalFree( memoryHandle );
    CloseClipboard();

    if( handle == nullptr ) {
        msg( "[Error] SetClipboardData failed" );
        return false;
    }
    return true;
}

// Trim wildcards at end
static void TrimSignature( Signature& signature ) {
    auto it = std::find_if( signature.rbegin(), signature.rend(), []( const auto& sb ) { return !sb.isWildcard; } );
    signature.erase( it.base(), signature.end() );
}

static std::expected<Signature, std::string> GenerateSignatureForEA( const ea_t ea, bool wildcardOperands, size_t maxSignatureLength = 1000, bool askLongerSignature = true ) {
    if( ea == BADADDR ) {
        return std::unexpected( "Invalid address" );
    }

    if( !is_code( get_flags( ea ) ) ) {
        return std::unexpected( "Can not create code signature for data" );
    }

    Signature signature;
    size_t sigPartLength = 0;

    auto currentAddress = ea;
    while( true ) {
        insn_t instruction;
        auto currentInstructionLength = decode_insn( &instruction, currentAddress );
        if( currentInstructionLength <= 0 ) {
            if( signature.empty() ) {
                return std::unexpected( "Failed to decode first instruction" );
            }

            msg( "Signature reached end of executable code @ %I64X\n", currentAddress );
            auto signatureString = BuildIDASignatureString( signature );
            msg( "NOT UNIQUE Signature for %I64X: %s\n", ea, signatureString.c_str() );
            return std::unexpected( "Signature not unique" );
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
                    auto signatureString = BuildIDASignatureString( signature );
                    msg( "NOT UNIQUE Signature for %I64X: %s\n", ea, signatureString.c_str() );
                    return std::unexpected( "Signature not unique" );
                }
                else { // Cancel
                    return std::unexpected( "Aborted" );
                }
            }
            else {
                return std::unexpected( "Signature exceeded maximum length" );
            }
        }
        sigPartLength += currentInstructionLength;

        uint8_t operandOffset = 0, operandLength = 0;
        if( wildcardOperands && GetOperand( instruction, &operandOffset, &operandLength ) && operandLength > 0 ) {
            // Add opcodes
            AddBytesToSignature( signature, currentAddress, operandOffset, false );
            // Wildcards for operands
            AddBytesToSignature( signature, currentAddress + operandOffset, operandLength, true );
            // If the operand is on the "left side", add the operator from the "right side"
            if( operandOffset == 0 ) {
                AddBytesToSignature( signature, currentAddress + operandLength, currentInstructionLength - operandLength, false );
            }
        }
        else {
            // No operand, add all bytes
            AddBytesToSignature( signature, currentAddress, currentInstructionLength, false );
        }

        auto currentSig = BuildIDASignatureString( signature );
        if( IsSignatureUnique( currentSig ) ) {
            // Remove wildcards at end for output
            TrimSignature( signature );

            // Return the signature we generated
            return signature;
        }
        currentAddress += currentInstructionLength;
    }
    return std::unexpected( "Unknown" );
}

static std::string FormatSignature( const Signature& signature, SignatureType type ) {
    using enum SignatureType;
    switch( type ) {
    case IDA:
        return BuildIDASignatureString( signature );
    case x64Dbg:
        return BuildIDASignatureString( signature, true );
    case Signature_Mask:
        return BuildByteArrayWithMaskSignatureString( signature );
    case SignatureByteArray_Bitmask:
        return BuildBytesWithBitmaskSignatureString( signature );
    }
    return {};
}

void PrintSignatureForEA( const std::expected<Signature, std::string>& signature, ea_t ea, SignatureType sigType ) {
    if( !signature.has_value() ) {
        msg( "Error: %s\n", signature.error().c_str() );
        return;
    }
    const auto signatureStr = FormatSignature( signature.value(), sigType );
    msg( "Signature for %I64X: %s\n", ea, signatureStr.c_str() );
    SetClipboardText( signatureStr );
}

static void FindXRefs( ea_t ea, bool wildcardOperands, std::vector<std::tuple<ea_t, Signature>>& xrefSignatures, size_t maxSignatureLength ) {
    xrefblk_t xref{};
    for( auto xref_ok = xref.first_to( ea, XREF_FAR ); xref_ok; xref_ok = xref.next_to() ) {

        // Skip data refs, xref.iscode is not what we want though
        if( !is_code( get_flags( xref.from ) ) ) {
            continue;
        }

        // Genreate signature for xref
        auto signature = GenerateSignatureForEA( xref.from, wildcardOperands, maxSignatureLength, false );
        if( !signature.has_value() ) {
            continue;
        }

        xrefSignatures.push_back( std::make_pair( xref.from, signature.value() ) );
    }

    // Sort signatures by length
    std::ranges::sort( xrefSignatures, []( const auto& a, const auto& b ) -> bool { return std::get<1>( a ).size() < std::get<1>( b ).size(); } );
}

static void PrintXRefSignaturesForEA( ea_t ea, const std::vector<std::tuple<ea_t, Signature>>& xrefSignatures, SignatureType sigType, size_t topCount ) {
    if( xrefSignatures.empty() ) {
        msg( "No XREFs have been found for your address\n" );
        return;
    }

    auto topLength = std::min( topCount, xrefSignatures.size() );
    msg( "Top %llu Signatures out of %llu xrefs for %I64X:\n", topLength, xrefSignatures.size(), ea );
    for( size_t i = 0; i < topLength; i++ ) {
        const auto& [originAddress, signature] = xrefSignatures[i];
        const auto signatureStr = FormatSignature( signature, sigType );
        msg( "XREF Signature #%i @ %I64X: %s\n", i + 1, originAddress, signatureStr.c_str() );

        // Copy first signature only
        if( i == 0 ) {
            SetClipboardText( signatureStr );
        }
    }
}

static void PrintSelectedCode( ea_t start, ea_t end, SignatureType sigType ) {
    const auto selectionSize = end - start;
    __assume( selectionSize > 0 );
    // Create signature from selection
    Signature signature;
    AddBytesToSignature( signature, start, selectionSize, false );

    const auto signatureStr = FormatSignature( signature, sigType );
    msg( "Code for %I64X-%I64X: %s\n", start, end, signatureStr.c_str() );
    SetClipboardText( signatureStr );
}

static bool GetRegexMatches( std::string string, std::regex regex, std::vector<std::string>& matches ) {
    std::sregex_iterator iter( string.begin(), string.end(), regex );
    std::sregex_iterator end;

    matches.clear();

    size_t i = 0;
    while( iter != end ) {
        matches.push_back( iter->str() );
        ++iter;
    }
    return !matches.empty();
}

static void SearchSignatureString( std::string input ) {
    // Try to figure out what signature type is used
    // We will convert it to IDA style
    std::string convertedSignatureString;

    std::string stringMask;

    // Try to detect a string mask like "xx????xx?xx"
    // Assume string mask always starts with x, and we don't just have one byte
    std::smatch match;
    if( std::regex_search( input, match, std::regex( R"(x(?:x|\?)+)" ) ) ) {
        stringMask = match[0].str();
    }
    // Try to find binary style bitmask like "0b101110" and convert it to a string mask
    else if( std::regex_search( input, match, std::regex( R"(0b(?:[0,1])+)" ) ) ) {
        auto bits = match[0].str().substr( 2 );
        std::string reversedBits( bits.rbegin(), bits.rend() );
        for( const auto& b : reversedBits ) {
            stringMask += ( b == '1' ? 'x' : '?' );
        }
    }

    if( !stringMask.empty() ) {
        // Since we have a mask, search for the bytes

        std::vector<std::string> rawByteStrings;
        // Search for \x00\x11\x22 type arrays
        if( GetRegexMatches( input, std::regex( R"(\\x(?:[0-9A-F]{2}))" ), rawByteStrings ) && rawByteStrings.size() == stringMask.length() ) {
            Signature convertedSignature;
            for( size_t i = 0; const auto & m : rawByteStrings ) {
                SignatureByte b{ std::stoi( m.substr( 2 ), nullptr, 16 ), stringMask[i++] == '?' };
                convertedSignature.push_back( b );
            }
            convertedSignatureString = BuildIDASignatureString( convertedSignature );
        }
        // Search for 0x00, 0x11, 0x22 type arrays
        else if( GetRegexMatches( input, std::regex( R"((?:0x(?:[0-9A-F]{2}))+)" ), rawByteStrings ) && rawByteStrings.size() == stringMask.length() ) {
            Signature convertedSignature;
            for( size_t i = 0; const auto & m : rawByteStrings ) {
                SignatureByte b{ std::stoi( m.substr( 2 ), nullptr, 16 ), stringMask[i++] == '?' };
                convertedSignature.push_back( b );
            }
            convertedSignatureString = BuildIDASignatureString( convertedSignature );
        }
        else {
            msg( "Detected mask \"%s\" but failed to match corresponding bytes\n", stringMask.c_str() );
        }
    }
    else {
        // We did not find a specific mask, so try formats with included wildcards 

        // Remove braces in case you have makers in your IDA style signature 
        input = std::regex_replace( input, std::regex( R"([\)\(\[\]]+)" ), "" );

        // Remove questionmarks and spaces at the end, and add one space for the following step
        input = std::regex_replace( input, std::regex( "[? ]+$" ), "" ) + " ";

        // Replace double question marks with single ones to convert x64Dbg style to IDA style
        // We need spaces between signature bytes, because we can not recognize if a signature uses one or two question marks per wildcard
        input = std::regex_replace( input, std::regex( R"(\?\? )" ), "? " );

        // Direct match for IDA type signature
        if( std::regex_match( input, std::regex( R"((?:(?:[A-F0-9]{2}\s+)|(?:\?\s+))+)" ) ) ) {
            // Just use it
            convertedSignatureString = input;
        }
        else {
            // Just try the other formats without wildcards

            std::vector<std::string> rawByteStrings;
            // Search for \x00\x11\x22 type arrays

            if( GetRegexMatches( input, std::regex( R"(\\x(?:[0-9A-F]{2}))" ), rawByteStrings ) && rawByteStrings.size() > 1 ) {
                Signature convertedSignature;
                for( size_t i = 0; const auto & m : rawByteStrings ) {
                    SignatureByte b{ std::stoi( m.substr( 2 ), nullptr, 16 ), false };
                    convertedSignature.push_back( b );
                }
                convertedSignatureString = BuildIDASignatureString( convertedSignature );
            }
            // Search for 0x00, 0x11, 0x22 type arrays
            else if( GetRegexMatches( input, std::regex( R"((?:0x(?:[0-9A-F]{2}))+)" ), rawByteStrings ) && rawByteStrings.size() > 1 ) {
                Signature convertedSignature;
                for( size_t i = 0; const auto & m : rawByteStrings ) {
                    SignatureByte b{ std::stoi( m.substr( 2 ), nullptr, 16 ), false };
                    convertedSignature.push_back( b );
                }
                convertedSignatureString = BuildIDASignatureString( convertedSignature );
            }
            else {
                msg( "Failed to match signature format\n" );
            }
        }
    }

    if( convertedSignatureString.empty() ) {
        msg( "Unrecognized signature type\n" );
        return;
    }

    // Print results
    msg( "Signature: %s\n", convertedSignatureString.c_str() );
    auto signatureMatches = FindSignatureOccurences( convertedSignatureString );
    if( signatureMatches.empty() ) {
        msg( "Signature does not match!\n" );
        return;
    }
    for( const auto& ea : signatureMatches ) {
        msg( "Match @ %I64X\n", ea );
    }
}

bool idaapi plugin_ctx_t::run( size_t ) {

    // Check what processor we have
    if( IsARM() ) {
        IS_ARM = true;
    }

    // Show dialog
    const char format[] =
        "STARTITEM 0\n"                                                         // TabStop
        "Signature Maker\n"                                                     // Title

        "Select action:\n"                                                      // Title
        "<Create Signature for current code address:R>\n"                       // Radio Button 0
        "<Find shortest XREF Signature for current data or code address:R>\n"	// Radio Button 1
        "<Copy selected code:R>\n"                                              // Radio Button 2
        "<Search for a signature:R>>\n"                                         // Radio Button 3

        "Output format:\n"                                                      // Title
        "<IDA Signature:R>\n"				                                    // Radio Button 0
        "<x64Dbg Signature:R>\n"			                                    // Radio Button 1
        "<C Byte Array Signature + String mask:R>\n"			                // Radio Button 2
        "<C Raw Bytes Signature + Bitmask:R>>\n"			                    // Radio Button 3

        "Options:\n"                                                            // Title
        "<Wildcards for operands:C>>\n\n";                                      // Checkbox Button

    static short action = 0;
    static short outputFormat = 0;
    static short wildcardOperands = 1;
    if( ask_form( format, &action, &outputFormat, &wildcardOperands ) ) {
        const auto sigType = static_cast< SignatureType >( outputFormat );
        switch( action ) {
        case 0:
        {
            // Find unique signature for current address
            const auto ea = get_screen_ea();
            auto signature = GenerateSignatureForEA( ea, wildcardOperands );
            PrintSignatureForEA( signature, ea, sigType );
            break;
        }
        case 1:
        {
            // Find XREFs for current selection, generate signatures up to 250 bytes length
            const auto ea = get_screen_ea();
            std::vector<std::tuple<ea_t, Signature>> xrefSignatures;
            FindXRefs( ea, wildcardOperands, xrefSignatures, 250 );

            // Print top 5 shortest signatures
            PrintXRefSignaturesForEA( ea, xrefSignatures, sigType, 5 );
            break;
        }
        case 2:
        {
            // Print selected code as signature
            ea_t start, end;
            if( read_range_selection( get_current_viewer(), &start, &end ) ) {
                PrintSelectedCode( start, end, sigType );
            }
            else {
                msg( "Select a range to copy the code\n" );
            }
            break;
        }
        case 3:
        {
            // Search for a signature
            qstring inputSignatureQstring;
            if( ask_str( &inputSignatureQstring, HIST_SRCH, "Enter a signature" ) ) {
                SearchSignatureString( inputSignatureQstring.c_str() );
            }
            break;
        }
        default:
            break;
        }
    }
    return true;
}
