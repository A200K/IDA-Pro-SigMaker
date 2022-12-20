#include <Windows.h>
#include <optional>
#include <string>
#include <sstream>
#include <format>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <search.hpp>

// Signature types and structures
enum class SignatureType : uint32_t {
    IDA = 0,
    x64Dbg,
    Signature_Mask,
    SignatureByteArray_Bitmask
};

typedef struct {
    unsigned char m_Byte;
    bool m_IsWildcard;
} SignatureByte;

typedef std::vector<SignatureByte> Signature;

void AddByteToSignature( Signature &signature, ea_t ulAddress, bool bWildcard ) {
    SignatureByte byte = {};
    byte.m_IsWildcard = bWildcard;
    byte.m_Byte = get_byte( ulAddress );
    signature.push_back( byte );
}

void AddBytesToSignature( Signature &signature, ea_t ulAddress, size_t ulSize, bool bWildcards ) {
    for ( size_t i = 0; i < ulSize; i++ ) {
        AddByteToSignature( signature, ulAddress + i, bWildcards );
    }
}

bool GetOperandOffset( const insn_t &instruction, char *pOperandOffset ) {
    for ( int i = 0; i < UA_MAXOP; i++ ) {
        if ( instruction.ops[i].offb > 0 ) {
            *pOperandOffset = instruction.ops[i].offb;
            return true;
        }
    }
    return false;
}

bool IsSignatureUnique( const std::string &signature ) {
    auto ulLastOccurence = inf.min_ea;

    // Convert signature string to searchable struct
    compiled_binpat_vec_t binaryPattern;
    parse_binpat_str( &binaryPattern, inf.min_ea, signature.c_str( ), 16 );

    // Search for occurences
    auto ulOccurence = bin_search2( ulLastOccurence, inf.max_ea, binaryPattern, BIN_SEARCH_NOCASE | BIN_SEARCH_FORWARD );

    // Signature not found
    if ( ulOccurence == BADADDR )
        return false;

    // Check if it matches anywhere else
    ulLastOccurence = ulOccurence + 1;
    ulOccurence = bin_search2( ulLastOccurence, inf.max_ea, binaryPattern, BIN_SEARCH_NOCASE | BIN_SEARCH_FORWARD );

    // Signature matched only once
    if ( ulOccurence == BADADDR )
        return true;

    return false;
}

// Trim wildcards at end
void TrimSignature( Signature &signature ) {
    auto ri = signature.rbegin( );
    while ( ri != signature.rend( ) ) {
        if ( ri->m_IsWildcard == true ) {
            ri = decltype( ri )( signature.erase( std::next( ri ).base( ) ) );
        }
        else {
            break;
        }
    }
}

// Signature to string 
std::string GenerateSignatureString( Signature &signature, bool doubleQM = false ) {
    std::ostringstream result;
    // Build hex pattern
    for ( const auto &byte : signature ) {
        if ( byte.m_IsWildcard ) {
            result << ( doubleQM ? "??" : "?" );
        }
        else {
            result << std::format( "{:02X}", byte.m_Byte );
        }
        result << " ";
    }
    auto str = result.str( );
    // Remove whitespace
    if ( !str.empty( ) )
        str.pop_back( );
    return str;
}

std::string GenerateCodeSignatureString( Signature &signature ) {
    std::ostringstream pattern;
    std::ostringstream mask;
    // Build hex pattern
    for ( const auto &byte : signature ) {
        pattern << "\\x" << std::format( "{:02X}", ( byte.m_IsWildcard ? 0 : byte.m_Byte ) );
        mask << ( byte.m_IsWildcard ? "?" : "x" );
    }
    auto str = pattern.str( ) + " " + mask.str( );
    return str;
}

std::string GenerateByteArrayWithBitMaskSignatureString( Signature &signature ) {
    std::ostringstream pattern;
    std::ostringstream mask;
    // Build hex pattern
    for ( const auto &byte : signature ) {
        pattern << "0x" << std::format( "{:02X}", ( byte.m_IsWildcard ? 0 : byte.m_Byte ) ) << ", ";
        mask << ( byte.m_IsWildcard ? "0" : "1" );
    }
    auto patternStr = pattern.str( );
    auto maskStr = mask.str( );

    // Reverse bitmask
    std::reverse( maskStr.begin( ), maskStr.end( ) );

    // Remove separators
    if ( !patternStr.empty( ) ) {
        patternStr.pop_back( );
        patternStr.pop_back( );
    }

    auto str = patternStr + " " + " 0b" + maskStr;
    return str;
}

bool SetClipboard( const std::string &text ) {
    bool result = false;
    if ( text.empty( ) )
        return result;

    if ( OpenClipboard( NULL ) ) {
        auto hTextMem = GlobalAlloc( GMEM_MOVEABLE, text.size( ) + 1 );
        if ( hTextMem ) {
            auto pTextMem = reinterpret_cast< char * >( GlobalLock( hTextMem ) );
            if ( pTextMem ) {
                memcpy( pTextMem, text.c_str( ), text.size( ) );
                GlobalUnlock( hTextMem );
                result = SetClipboardData( CF_TEXT, hTextMem ) != NULL;
            }
        }
        CloseClipboard( );
    }
    return result;
}

std::optional<Signature> GenerateSignatureForEA( ea_t ea, bool wildcardOperands ) {
    if ( ea == BADADDR ) {
        msg( "Invalid address\n" );
        return std::nullopt;
    }

    if ( !is_code( get_flags( ea ) ) ) {
        msg( "Can not create code signature for data\n" );
        return std::nullopt;
    }

    Signature signature;
    uint32_t sigPartLength = 0;

    auto ulCurrentAddress = ea;
    while ( true ) {
        insn_t instruction;
        auto iCurrentInstructionLength = decode_insn( &instruction, ulCurrentAddress );
        if ( iCurrentInstructionLength <= 0 ) {
            msg( "Can't decode @ %I64X, is this actually code?\n", ulCurrentAddress );
            break;
        }

        // Length check in case the signature becomes too long
        if ( sigPartLength >= 500 ) {
            auto result = ask_yn( 1, "Signature is already at %llu bytes. Continue?", signature.size( ) );
            if ( result == 1 ) { // Yes 
                sigPartLength = 0;
            }
            else if ( result == 0 ) { // No
                // Print the signature we have so far, even though its not unique
                auto signatureString = GenerateSignatureString( signature );
                msg( "NOT UNIQUE Signature for %I64X: %s\n", ea, signatureString.c_str( ) );
                break;
            }
            else { // Cancel
                break;
            }
        }
        sigPartLength += iCurrentInstructionLength;

        char ulOperandOffset = 0;
        if ( wildcardOperands && GetOperandOffset( instruction, &ulOperandOffset ) && ulOperandOffset > 0 ) {
            // Add opcodes
            AddBytesToSignature( signature, ulCurrentAddress, ulOperandOffset, false );
            // Wildcards for operand shit
            AddBytesToSignature( signature, ulCurrentAddress + ulOperandOffset, iCurrentInstructionLength - ulOperandOffset, true );
        }
        else {
            // No operand, add all bytes
            AddBytesToSignature( signature, ulCurrentAddress, iCurrentInstructionLength, false );
        }

        auto currentSig = GenerateSignatureString( signature );
        if ( IsSignatureUnique( currentSig ) ) {
            // Remove wildcards at end for output
            TrimSignature( signature );

            // Return the signature we generated
            return signature;
        }
        ulCurrentAddress += iCurrentInstructionLength;
    }
    return std::nullopt;
}

// Plugin specific definitions
struct plugin_ctx_t : public plugmod_t {
    ~plugin_ctx_t( )
    {
    }
    virtual bool idaapi run( size_t ) override;
};

static plugmod_t *idaapi init( ) {
    return new plugin_ctx_t;
}

std::string FormatSignature( Signature &signature, ea_t ea, SignatureType type ) {
    std::string signatureStr;
    switch ( type ) {
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

bool idaapi plugin_ctx_t::run( size_t ) {
    const char format[] =
        "STARTITEM 0\n"                                                 // TabStop
        "Signature Maker\n"                                             // Title

        "Select action:\n"                                              // Title
        "<Create Signature for current code address:R>\n"               // Radio Button 0
        "<Find shortest XREF Signature for current data or code address:R>>\n"		// Radio Button 1

        "Output format:\n"                                              // Title
        "<IDA Signature:R>\n"				                            // Radio Button 0
        "<x64Dbg Signature:R>\n"			                            // Radio Button 1
        "<C Signature + String mask:R>\n"			                            // Radio Button 2
        "<C Byte Array Signature + Bitmask:R>>\n"			            // Radio Button 3

        "Options:\n"                                                    // Title
        "<Wildcards for operands:C>>\n\n";                              // Checkbox Button

    static short action = 0;
    static short outputFormat = 0;
    static short wildcardForOperand = 1;
    if ( ask_form( format, &action, &outputFormat, &wildcardForOperand ) ) {
        switch ( action ) {
        case 0:
        {
            // Find unique signature for current address
            auto ea = get_screen_ea( );
            auto signature = GenerateSignatureForEA( ea, wildcardForOperand );
            if ( signature.has_value( ) ) {
                auto signatureStr = FormatSignature( signature.value( ), ea, static_cast< SignatureType >( outputFormat ) );
                msg( "Signature for %I64X: %s\n", ea, signatureStr.c_str( ) );
                SetClipboard( signatureStr );
            }
            break;
        }
        case 1:
        {
            // Iterate XREFs and find shortest signature
            auto ea = get_screen_ea( );
            std::vector<Signature> xrefSignatures;
            xrefblk_t xref;
            for ( auto xref_ok = xref.first_to( ea, XREF_FAR ); xref_ok; xref_ok = xref.next_to( ) ) {

                // Skip data refs, xref.iscode is not what we want though
                if ( !is_code( get_flags( xref.from ) ) ) {
                    continue;
                }

                auto signature = GenerateSignatureForEA( xref.from, wildcardForOperand );
                if ( !signature.has_value( ) ) {
                    continue;
                }

                xrefSignatures.push_back( signature.value( ) );
            }

            // Sort signatures by length
            std::sort( xrefSignatures.begin( ), xrefSignatures.end( ), []( const Signature &a, const Signature &b ) -> bool { return a.size( ) < b.size( ); } );

            if ( xrefSignatures.empty( ) ) {
                msg( "No XREFs have been found for your address\n" );
                break;
            }

            // Print top 3 Signatures
            auto topLength = min( 3, xrefSignatures.size( ) );
            msg( "Top %llu Signatures out of %llu xrefs:\n", topLength, xrefSignatures.size( ) );
            for ( int i = 0; i < topLength; i++ ) {
                auto signature = xrefSignatures[i];
                auto signatureStr = FormatSignature( signature, ea, static_cast< SignatureType >( outputFormat ) );
                msg( "XREF Signature for %I64X #%i: %s\n", ea, i + 1, signatureStr.c_str( ) );

                // Copy first signature only
                if ( i == 0 ) {
                    SetClipboard( signatureStr );
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
