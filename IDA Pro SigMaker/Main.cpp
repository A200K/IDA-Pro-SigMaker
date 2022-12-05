#include <Windows.h>
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
    Signature_Mask
};

typedef struct {
    unsigned char m_Byte;
    bool m_IsWildcard;
} SIGNATURE_BYTE;

void AddByteToSignature( std::vector<SIGNATURE_BYTE> &signature, ea_t ulAddress, bool bWildcard )
{
    SIGNATURE_BYTE byte = {};
    byte.m_IsWildcard = bWildcard;
    byte.m_Byte = get_byte( ulAddress );
    signature.push_back( byte );
}

void AddBytesToSignature( std::vector<SIGNATURE_BYTE> &signature, ea_t ulAddress, size_t ulSize, bool bWildcards )
{
    for ( size_t i = 0; i < ulSize; i++ )
    {
        AddByteToSignature( signature, ulAddress + i, bWildcards );
    }
}

bool GetOperandOffset( const insn_t &instruction, char *pOperandOffset )
{
    for ( int i = 0; i < UA_MAXOP; i++ )
    {
        if ( instruction.ops[i].offb > 0 )
        {
            *pOperandOffset = instruction.ops[i].offb;
            return true;
        }
    }
    return false;
}

bool IsSignatureUnique( const std::string &signature )
{
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
void TrimSignature( std::vector<SIGNATURE_BYTE> &signature )
{
    auto ri = signature.rbegin( );
    while ( ri != signature.rend( ) )
    {
        if ( ri->m_IsWildcard == true )
        {
            ri = decltype( ri )( signature.erase( std::next( ri ).base( ) ) );
        }
        else 
        {
            break;
        }   
    }
}

// Signature to string 
std::string GenerateSignatureString( std::vector<SIGNATURE_BYTE> &signature, bool doubleQM = false )
{
    std::ostringstream result;
    // Build hex pattern
    for ( const auto &byte : signature )
    {
        if ( byte.m_IsWildcard )
        {
            result << ( doubleQM ? "??" : "?" );
        }
        else
        {
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

std::string GenerateCodeSignatureString( std::vector<SIGNATURE_BYTE> &signature )
{
    std::ostringstream pattern;
    std::ostringstream mask;
    // Build hex pattern
    for ( const auto &byte : signature )
    {
        pattern << "\\x" << std::format( "{:02X}", ( byte.m_IsWildcard ? 0 : byte.m_Byte ) );
        mask << ( byte.m_IsWildcard ? "?" : "x" );
    }
    auto str = pattern.str( ) + " " + mask.str( );
    return str;
}

bool SetClipboard( const std::string &text )
{
    bool result = false;
    if ( text.empty( ) )
        return result;

    if ( OpenClipboard( NULL ) )
    {
        auto hTextMem = GlobalAlloc( GMEM_MOVEABLE, text.size( ) + 1 );
        if ( hTextMem )
        {
            auto pTextMem = reinterpret_cast< char * >( GlobalLock( hTextMem ) );
            if ( pTextMem )
            {
                memcpy( pTextMem, text.c_str( ), text.size( ) );
                GlobalUnlock( hTextMem );

                result = SetClipboardData( CF_TEXT, hTextMem ) != NULL;
            }
        }
        CloseClipboard( );
    }
    return result;
}

void GenerateSignature( SignatureType type, bool wildcardOperands )
{
    auto ulCurrentSelectedAddress = get_screen_ea( );
    if ( ulCurrentSelectedAddress == BADADDR )
    {
        msg( "Invalid address\n" );
        return;
    }

    std::vector<SIGNATURE_BYTE> signature;
    uint32_t sigPartLength = 0;

    auto ulCurrentAddress = ulCurrentSelectedAddress;
    while ( true )
    {
        insn_t instruction;
        auto iCurrentInstructionLength = decode_insn( &instruction, ulCurrentAddress );
        if ( iCurrentInstructionLength <= 0 )
        {
            msg( "Can't decode @ %I64X\n", ulCurrentAddress );
            break;
        }

        // Length check in case the signature becomes too long
        if ( sigPartLength > 500 )
        {
            auto result = ask_yn( 1, "Signature is already at %llu bytes. Continue?", signature.size( ) );
            if ( result == 1 ) // Yes
            {
                sigPartLength = 0;
            }
            else if ( result == 0 ) // No
            {
                // Print the signature we have so far, even though its not unique
                auto signatureString = GenerateSignatureString( signature );
                msg( "NOT UNIQUE Signature for %I64X: %s\n", ulCurrentSelectedAddress, signatureString.c_str( ) );
                break;
            }
            else // Cancel
            {
                break;
            }
        }
        sigPartLength += iCurrentInstructionLength;

        char ulOperandOffset = 0;
        if ( wildcardOperands && GetOperandOffset( instruction, &ulOperandOffset ) && ulOperandOffset > 0 )
        {
            // Add opcodes
            AddBytesToSignature( signature, ulCurrentAddress, ulOperandOffset, false );
            // Wildcards for operand shit
            AddBytesToSignature( signature, ulCurrentAddress + ulOperandOffset, iCurrentInstructionLength - ulOperandOffset, true );
        }
        else
        {
            // No operand, add all bytes
            AddBytesToSignature( signature, ulCurrentAddress, iCurrentInstructionLength, false );
        }

        auto currentSig = GenerateSignatureString( signature );
        if ( IsSignatureUnique( currentSig ) )
        {
            // Remove wildcards at end for output
            TrimSignature( signature );

            std::string signatureStr;
            switch ( type )
            {
            case SignatureType::IDA:
                signatureStr = GenerateSignatureString( signature );
                break;
            case SignatureType::x64Dbg:
                signatureStr = GenerateSignatureString( signature, true );
                break;
            case SignatureType::Signature_Mask:
                signatureStr = GenerateCodeSignatureString( signature );
                break;
            }
            msg( "Signature for %I64X: %s\n", ulCurrentSelectedAddress, signatureStr.c_str( ) );
            SetClipboard( signatureStr );
            break;
        }
        ulCurrentAddress += iCurrentInstructionLength;
    }
}

// Plugin specific definitions
struct plugin_ctx_t : public plugmod_t
{
    ~plugin_ctx_t( )
    {
        //term_hexrays_plugin( );
    }
    virtual bool idaapi run( size_t ) override;
};

static plugmod_t *idaapi init( )
{
   // if ( !init_hexrays_plugin( ) )
   //     return nullptr;
    return new plugin_ctx_t;
}

bool idaapi plugin_ctx_t::run( size_t )
{
    const char format[] =
        "STARTITEM 0\n"                      // TabStop
        "Signature Type\n"                   // Title
        "<IDA Signature:R>\n"				 // Radio Button 0
        "<x64Dbg Signature:R>\n"			 // Radio Button 1
        "<C Signature + Mask:R>>\n"			 // Radio Button 2
        "<Wildcards for operands:C>>\n\n";   // Checkbox Button

    static short signatureType = 0;
    static short wildcardForOperand = 1;
    if ( ask_form( format, &signatureType, &wildcardForOperand ) ) {
        switch ( signatureType ) {
        case 0:
            GenerateSignature( SignatureType::IDA, wildcardForOperand );
            break;
        case 1:
            GenerateSignature( SignatureType::x64Dbg, wildcardForOperand );
            break;
        case 2:
            GenerateSignature( SignatureType::Signature_Mask, wildcardForOperand );
            break;
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
