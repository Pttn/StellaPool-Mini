// (c) 2022-present Pttn (https://riecoin.xyz/StellaPool-Mini)

#include <nlohmann/json.hpp>
#include <signal.h>

#include "main.hpp"
#include "Pool.hpp"

bool running(false);

std::optional<std::pair<std::string, std::string>> Configuration::_parseLine(const std::string &line) const {
	if (line.size() == 0)
		return std::nullopt;
	if (line[0] == '#')
		return std::nullopt;
	const auto pos(line.find('='));
	if (pos != std::string::npos) {
		std::pair<std::string, std::string> option{line.substr(0, pos), line.substr(pos + 1, line.size() - pos - 1)};
		option.first.erase(std::find_if(option.first.rbegin(), option.first.rend(), [](unsigned char c) {return !std::isspace(c);}).base(), option.first.end()); // Trim spaces before =
		option.second.erase(option.second.begin(), std::find_if(option.second.begin(), option.second.end(), [](unsigned char c) {return !std::isspace(c);})); // Trim spaces after =
		return option;
	}
	else {
		std::cout << "Cannot find the delimiter '=' for: '" << line << "'" << std::endl;
		return std::nullopt;
	}
}

bool Configuration::parse(const int argc, char** argv) {
	std::string confPath("Pool.conf");
	if (argc >= 2)
		confPath = argv[1];
	std::vector<std::string> lines;
	std::ifstream file(confPath, std::ios::in);
	if (file) {
		std::cout << "Opening configuration file " << confPath << "..." << std::endl;
		std::string line;
		while (std::getline(file, line))
			lines.push_back(line);
		file.close();
	}
	else {
		std::cout << confPath << " not found or unreadable, please configure StellaPool now or check your configuration file." << std::endl;
		return false;
	}
	
	for (const auto &line : lines) {
		const std::optional<std::pair<std::string, std::string>> option(_parseLine(line));
		if (!option.has_value())
			continue;
		const std::string key(option.value().first), value(option.value().second);
		if (key == "PoolAddress") _options.poolAddress = value;
		else if (key == "PoolPort") {
			try {_options.poolPort = std::stoi(value);}
			catch (...) {_options.poolPort = 2005U;}
		}
		else if (key == "WalletHost") _options.walletHost = value;
		else if (key == "WalletPort") {
			try {_options.walletPort = std::stoi(value);}
			catch (...) {_options.walletPort = 28332U;}
		}
		else if (key == "WalletName") _options.walletName = value;
		else if (key == "WalletUsername") _options.walletUsername = value;
		else if (key == "WalletPassword") _options.walletPassword = value;
		else if (key == "WalletCookie") _options.walletCookie = value;
		else if (key == "StatsJsonFile") _options.statsJsonFile = value;
		else if (key == "StatsHtmlFile") _options.statsHtmlFile = value;
		else if (key == "StatsUpdateInterval") {
			_options.statsUpdateInterval = std::stod(value);
			if (_options.statsUpdateInterval < 1.) _options.statsUpdateInterval = 1.;
		}
	}
	std::cout << "Pool address: " << _options.poolAddress << std::endl;
	std::vector<uint8_t> scriptPubKey(bech32ToScriptPubKey(_options.poolAddress));
	if (scriptPubKey.size() == 0) {
		std::cout << "Invalid payout address! Please check it. Note that only Bech32 addresses are supported." << std::endl;
		return false;
	}
	std::cout << "  ScriptPubKey: " << v8ToHexStr(scriptPubKey) << std::endl;
	std::cout << "Pool Port: " << _options.poolPort << std::endl;
	std::cout << "Riecoin Wallet Server: " << _options.walletHost << ":" << _options.walletPort << std::endl;
	std::cout << "Riecoin Wallet Name: " << _options.walletName << std::endl;
	if (_options.walletCookie != "")
		std::cout << "Riecoin Wallet Cookie: " << _options.walletCookie << std::endl;
	else {
		std::cout << "Riecoin Wallet Username: " << _options.walletUsername << std::endl;
		std::cout << "Riecoin Wallet Password: ..." << std::endl;
	}
	std::cout << "Stats Json File: " << _options.statsJsonFile << std::endl;
	std::cout << "Stats Html Page: " << _options.statsHtmlFile << std::endl;
	std::cout << "Stats Update Interval: " << _options.statsUpdateInterval << " s" << std::endl;
	return true;
}

void signalHandler(int signum) {
	if (Pool::pool) {
		std::cout << std::endl << "Signal " << signum << " received, stopping Pool." << std::endl;
		Pool::pool->stop();
	}
}

int main(int argc, char** argv) {
	struct sigaction SIGINTHandler;
	SIGINTHandler.sa_handler = signalHandler;
	sigemptyset(&SIGINTHandler.sa_mask);
	SIGINTHandler.sa_flags = 0;
	sigaction(SIGINT, &SIGINTHandler, NULL);
	
	std::cout << versionString << ", Riecoin Private Pool Software by Pttn" << std::endl;
	std::cout << "Project page: https://riecoin.xyz/StellaPool-Mini" << std::endl;
	std::cout << "-----------------------------------------------------------" << std::endl;
	std::cout << "G++ " << __GNUC__ << "." << __GNUC_MINOR__ << "." << __GNUC_PATCHLEVEL__ << " - https://gcc.gnu.org/" << std::endl;
	std::cout << "Curl " << LIBCURL_VERSION << " - https://curl.haxx.se/" << std::endl;
	std::cout << "GMP " << __GNU_MP_VERSION << "." << __GNU_MP_VERSION_MINOR << "." << __GNU_MP_VERSION_PATCHLEVEL << " - https://gmplib.org/" << std::endl;
	std::cout << "PicoSHA2 27fcf69 - https://github.com/okdshin/PicoSHA2"s << std::endl;
	std::cout << "NLohmann Json " << NLOHMANN_JSON_VERSION_MAJOR << "." << NLOHMANN_JSON_VERSION_MINOR << "." << NLOHMANN_JSON_VERSION_PATCH << " - https://json.nlohmann.me/" << std::endl;
	std::cout << "-----------------------------------------------------------" << std::endl;
	if (!configuration.parse(argc, argv))
		return 0;
	std::cout << "-----------------------------------------------------------" << std::endl;
	curl_global_init(CURL_GLOBAL_DEFAULT);
	Pool pool;
	pool.run();
	curl_global_cleanup();
	return 0;
}
