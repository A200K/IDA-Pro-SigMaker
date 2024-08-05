#include "SignatureUtils.h"

std::string BuildIDASignatureString( const Signature& signature, bool doubleQM ) {
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
	auto str = result.str( );
	// Remove whitespace at end
	if( !str.empty( ) ) {
		str.pop_back( );
	}
	return str;
}

std::string BuildByteArrayWithMaskSignatureString( const Signature& signature ) {
	std::ostringstream pattern;
	std::ostringstream mask;
	// Build hex pattern
	for( const auto& byte : signature ) {
		pattern << "\\x" << std::format( "{:02X}", ( byte.isWildcard ? 0 : byte.value ) );
		mask << ( byte.isWildcard ? "?" : "x" );
	}
	auto str = pattern.str( ) + " " + mask.str( );
	return str;
}

std::string BuildBytesWithBitmaskSignatureString( const Signature& signature ) {
	std::ostringstream pattern;
	std::ostringstream mask;
	// Build hex pattern
	for( const auto& byte : signature ) {
		pattern << "0x" << std::format( "{:02X}", ( byte.isWildcard ? 0 : byte.value ) ) << ", ";
		mask << ( byte.isWildcard ? "0" : "1" );
	}
	auto patternStr = pattern.str( );
	auto maskStr = mask.str( );

	// Reverse bitmask
	std::ranges::reverse( maskStr );

	// Remove separators
	if( !patternStr.empty( ) ) {
		patternStr.pop_back( );
		patternStr.pop_back( );
	}

	auto str = patternStr + " " + " 0b" + maskStr;
	return str;
}

std::string FormatSignature( const Signature& signature, SignatureType type ) {
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


void AddByteToSignature( Signature& signature, ea_t address, bool wildcard ) {
	SignatureByte byte{};
	byte.isWildcard = wildcard;
	byte.value = get_byte( address );
	signature.push_back( byte );
}

void AddBytesToSignature( Signature& signature, ea_t address, size_t count, bool wildcard ) {
	// signature.reserve( signature.size() + count ); // Not sure if this is overhead for average signature creation
	for( size_t i = 0; i < count; i++ ) {
		AddByteToSignature( signature, address + i, wildcard );
	}
}


// Trim wildcards at end
void TrimSignature( Signature& signature ) {
	auto it = std::find_if( signature.rbegin( ), signature.rend( ), []( const auto& sb ) { return !sb.isWildcard; } );
	signature.erase( it.base( ), signature.end( ) );
}
