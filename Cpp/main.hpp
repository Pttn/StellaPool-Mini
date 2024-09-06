// (c) 2022-present Pttn (https://riecoin.xyz/StellaPool-Mini)

#ifndef HEADER_main_hpp
#define HEADER_main_hpp

#include <fstream>
#include "tools.hpp"

using namespace std::string_literals;
using namespace std::chrono_literals;

#define versionString	"StellaPool-Mini C++ 24.09"

struct Options {
	std::string poolAddress;
	uint16_t poolPort;
	std::string walletHost;
	uint16_t walletPort;
	std::string walletName, walletUsername, walletPassword;
	std::string statsJsonFile, statsHtmlFile;
	double statsUpdateInterval;
	Options() :
		poolAddress("ric1qr3yxckxtl7lacvtuzhrdrtrlzvlydane2h37ja"s),
		poolPort(2005U),
		walletHost("127.0.0.1"s),
		walletPort(28332U),
		walletName(""s),
		walletUsername(""s),
		walletPassword(""s),
		statsJsonFile("SPM_"s + timeNowStr(true) + ".json"s),
		statsHtmlFile("SPM_"s + timeNowStr(true) + ".html"s),
		statsUpdateInterval(30.) {}
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
