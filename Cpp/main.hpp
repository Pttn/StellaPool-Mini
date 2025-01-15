// (c) 2022-present Pttn (https://riecoin.xyz/StellaPool-Mini)

#ifndef HEADER_main_hpp
#define HEADER_main_hpp

#include <fstream>
#include "tools.hpp"

using namespace std::string_literals;
using namespace std::chrono_literals;

#define versionString	"StellaPool-Mini C++ 2501"

struct Options {
	std::string poolAddress{"ric1pstellap55ue6keg3ta2qwlxr0h58g66fd7y4ea78hzkj3r4lstrsk4clvn"s};
	uint16_t poolPort{2005U};
	std::string walletHost{"127.0.0.1"s};
	uint16_t walletPort{28332U};
	std::string walletName{""s}, walletUsername{""s}, walletPassword{""s}, walletCookie{""s};
	std::string statsJsonFile{"SPM_"s + timeNowStr(true) + ".json"s}, statsHtmlFile{"SPM_"s + timeNowStr(true) + ".html"s};
	double statsUpdateInterval{30.};
};

class Configuration {
	Options _options;
	std::optional<std::pair<std::string, std::string>> _parseLine(const std::string&) const;
public:
	bool parse(const int, char**);
	Options options() const {return _options;}
};

inline Configuration configuration;

#endif
