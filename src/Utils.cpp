#include "Utils.h"
#include <stddef.h>

bool GetRegexMatches( std::string string, std::regex regex, std::vector<std::string>& matches ) {
	std::sregex_iterator iter( string.begin( ), string.end( ), regex );
	std::sregex_iterator end;

	matches.clear( );

	size_t i = 0;
	while( iter != end ) {
		matches.push_back( iter->str( ) );
		++iter;
	}
	return !matches.empty( );
}
