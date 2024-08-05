#pragma once
#include "Main.h"

// Output functions
std::string BuildIDASignatureString( const Signature& signature, bool doubleQM = false );
std::string BuildByteArrayWithMaskSignatureString( const Signature& signature );
std::string BuildBytesWithBitmaskSignatureString( const Signature& signature );
std::string FormatSignature( const Signature& signature, SignatureType type );

// Utility functions
void AddByteToSignature( Signature& signature, ea_t address, bool wildcard );
void AddBytesToSignature( Signature& signature, ea_t address, size_t count, bool wildcard );
void TrimSignature( Signature& signature );