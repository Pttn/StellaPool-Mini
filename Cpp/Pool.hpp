// (c) 2022-present Pttn (https://riecoin.xyz/StellaPool-Mini)

#ifndef HEADER_Pool_hpp
#define HEADER_Pool_hpp

#include <curl/curl.h>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <set>
#include <sys/epoll.h>
#include <thread>

#include "main.hpp"
#include "tools.hpp"

constexpr uint16_t extraNonce1Length(4U);
constexpr uint16_t extraNonce2Length(4U);
struct Worker {
	int fileDescriptor;
	std::string ip;
	uint16_t port;
	uint32_t id;
	std::string extraNonce1;
	std::string name;
	std::chrono::time_point<std::chrono::steady_clock> latestShareTp; // Disconnection if no share since long
	enum State {UNSUBSCRIBED, SUBSCRIBED, AUTHORIZED} state;
	
	Worker() : latestShareTp(std::chrono::steady_clock::now()), state(UNSUBSCRIBED) {
		static uint32_t id0(0);
		id = id0++;
		std::ostringstream oss;
		oss << std::setfill('0') << std::setw(2U*extraNonce1Length) << std::hex << id;
		extraNonce1 = oss.str();
	}
	std::string str() const {return "Worker "s + std::to_string(id) + " from "s + ip + ":"s + std::to_string(port) + ", fd "s + std::to_string(fileDescriptor);}
};

struct StratumJob {
	uint64_t id;
	uint32_t height;
	int32_t powVersion;
	std::vector<std::vector<uint32_t>> acceptedPatterns;
	BlockHeader bh;
	std::string transactionsHex, default_witness_commitment;
	std::vector<std::array<uint8_t, 32>> txHashes;
	uint64_t coinbasevalue;
	std::vector<uint8_t> coinbase1, coinbase2;
	
	void coinbase1Gen();
	void coinbase2Gen(const std::vector<uint8_t>&);
	std::vector<uint8_t> coinBaseGen(const std::string&, const std::string&);
	std::array<uint8_t, 32> coinbaseTxId(const std::string&, const std::string&) const;
	void merkleRootGen(const std::string&, const std::string&);
};

struct Round {
	uint32_t id;
	uint32_t heightStart;
	std::optional<uint32_t> heightEnd;
	uint64_t timeStart;
	std::optional<uint64_t> timeEnd;
	int16_t confirmations;
	std::optional<std::string> blockHash;
	std::optional<double> difficulty;
	std::optional<uint64_t> reward;
	uint32_t shares;
	std::optional<std::string> finder;
};

struct Share { // Just used for recent statistics, not actual share data
	uint64_t timestamp;
	std::string finder;
	bool valid;
};

constexpr int maxEvents(16);
constexpr int maxMessageLength(32768);
constexpr double jobRefreshInterval(30.);
constexpr double maxInactivityTime(1800.);
constexpr uint64_t recentSharesTime(3600ULL);
inline const std::string poolSignature("/SPM/");
class Pool {
	const std::vector<uint8_t> _scriptPubKey;
	bool _running;
	std::map<int, std::shared_ptr<Worker>> _workers; // Indexed by File Descriptors
	std::chrono::time_point<std::chrono::steady_clock> _latestJobTp;
	std::vector<StratumJob> _currentJobs;
	uint64_t _currentJobId;
	std::vector<Round> _rounds;
	std::vector<Share> _recentShares; // For recent statistics
	std::set<std::string> _roundOffsets; // For duplicate shares detection
	std::mutex _roundUpdateMutex; // Used when a new Round is started
	std::thread _statsUpdater;
	CURL *_curlMain;
	
	nlohmann::json _sendRequestToWallet(CURL*, const std::string&, const nlohmann::json&) const; // Sends a RPC call to the Riecoin server and returns the response
	uint64_t _checkPoW(const StratumJob&, const std::vector<uint8_t>&); // Computes the Share Prime Count of a Share
	std::string _generateMiningNotify(const bool); // Generates a Stratum.Notify message
	std::pair<std::string, bool> _processMessage(const std::pair<std::shared_ptr<Worker>, std::string>&); // Processes a Stratum Message from a worker, the Bool indicates whether the worker should be disconnected
	void _startNewRound(const uint32_t); // Inserts a new round
	void _updateStats(); // Updates Stat Files
	void _fetchJob(); // Fetches work from the Riecoin server using GetBlockTemplate
public:
	inline static Pool* pool;
	Pool() : _scriptPubKey(bech32ToScriptPubKey(configuration.options().poolAddress)), _running(false) {
		assert(!pool);
		pool = this;
	}
	void run();
	void stop() {_running = false;}
};

#endif
