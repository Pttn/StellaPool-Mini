# StellaPool-Mini

StellaPool-Mini is a minimalist private Riecoin mining pool software, initially a simplified version of [StellaPool](https://github.com/Pttn/StellaPool/), intended for "large" solo miners with lots of powerful machines who may desire a way to effectively "share" a Riecoin Core node across the machines and easily monitor the status of the machines and their contributions, but who would not need most of the features of a public mining pool.

It is designed to be quickly usable and simple, so many features such as antispam measures, databases (no additional dependencies nor setup needed), Pool Fee, or withdrawals, are not implemented. If you want some of these features then you should use the "full" StellaPool instead. On the other hand, if you just have one or a few machines then you should just use the rieMiner's Solo Mining Mode and not bother with setting up a pool.

StellaPool-Mini is not meant to be a reference code, and we encourage users to modify it heavily to make it the way they want. The idea is that you just take the code, change it as you like, and forget about the present repository. Though, you may still look once a while at the commits, especially if there are changes in order to support new Riecoin Core releases. No compatibility is guaranteed, configurations may break with new code, no particular support is provided and users are expected to be knowledgeable and autonomous.

For now, it is written in C++, but there may be implementations in other languages in the future to make its use even more convenient in some cases, or it may also be integrated into Riecoin Core someday.

## Usage

Firstly, read the sections below to build and set up StellaPool-Mini. Here is a configuration template,


```bash
PoolAddress = ric1p...
PoolPort = 2005
WalletHost = 127.0.0.1
WalletPort = 28332
WalletName = SPM
WalletUsername = rpcuser
WalletPassword = rpcpassword
# StatsJsonFile = Stats.json
# StatsHtmlFile = Stats.html
StatsUpdateInterval = 30
```

Once done, run it. As a private pool, a StellaPool-Mini instance should only be reached by trusted workers just like your Riecoin Core instance (there is no particular check on the worker names, etc), so configure your firewall accordingly if needed, etc.

Then, connect your miners as if they were doing Pooled Mining, point them to your private pool. You can use any username and as you wish, for example one per machine or one per cluster... The names are used to identify your workers so if two workers have the same name then they will be considered as a single one for statistical purposes. The password is irrelevant.

StellaPool-Mini generates a Html page that is regularly updated. Open it in a Web Browser to monitor the status of your workers and latest block found.

Note that every time you restart the Pool, if you set a particular file name for the statistics, it will be **overwritten**. It is intended behavior since we assume that the user mainly cares about the *current* status of the workers, and blocks found can always be retrieved by entering the Pool Address in an Explorer. If no filename is set then them having a timestamp by default allows to retrieve previous sessions.

## Preparation

### Configure Riecoin Core

First, configure Riecoin Core using the `riecoin.conf` file. Here is a basic template:

```
daemon=1
server=1
txindex=1

rpcuser=(choose an username)
rpcpassword=(choose a password)

[main]
rpcport=28332
port=28333
rpcbind=127.0.0.1

[test]
rpcport=38332
port=38333
rpcbind=127.0.0.1
```

Once you are ready, start Riecoin Core (Mainnet, Testnet, or both, depending on your goal). If needed, create a new wallet and generate an address where block rewards will be sent before being redistributed to miners. Of course, make sure that the synchronization is done.

If you wish to support both Mainnet and Testnet, you must run two separate instances (or mod heavily the code).

## Compile the Private Pool

You must have a recent enough Linux and an appropriate compiler with C++20 support. Other and old operating systems are not supported.

### On Debian/Ubuntu

You can get the source code with Git and compile this C++ program with g++ and make, install them if needed. Then, get if needed the following dependencies:

* [Curl](https://curl.haxx.se/)
* [GMP](https://gmplib.org/)
* [NLohmann Json](https://json.nlohmann.me/)

On Debian 12, you can easily install these by doing as root:

```bash
apt install g++ make git libcurl4-openssl-dev libgmp-dev nlohmann-json3-dev
```

Then, download the source files, go/`cd` to the directory, and run `make`:

```bash
git clone https://github.com/Pttn/StellaPool-Mini.git
cd StellaPool-Mini
cd Cpp
make
```

For other Linux, executing equivalent commands (using `pacman` instead of `apt`,...) should work.

## Configure the Private Pool

StellaPool-Mini uses a text configuration file, by default a `Pool.conf` file next to the executable. It is also possible to use custom paths, examples:

```bash
./StellaPoolM config/example.txt
./StellaPoolM "config 2.conf"
./StellaPoolM /home/user/Pool/Pool.conf
```

Each option is set by a line like

```
Option = Value
```

It is case sensitive. A line starting with `#` will be ignored, as well as invalid ones. Spaces or tabs just before or after `=` are also trimmed. If an option is missing, the default value(s) will be used. If there are duplicate lines for the same option, the last one will be used.

### Settings

* `PoolAddress`: the Block Rewards are generated with this Riecoin address. You can use Bech32 "ric1" addresses (only lowercase). Default: a donation address
* `PoolPort`: the port the miners connect and send shares to. Default: 2005
* `WalletHost`: the IP of the Riecoin server. Default: 127.0.0.1
* `WalletPort`: the port of the Riecoin server (same as rpcport in riecoin.conf). Default: 28332 (default RPC port for Riecoin Core)
* `WalletName`: the name of the wallet, set this if you created multiple wallets in Riecoin Core. Default: empty
* `WalletUsername`: the username used to connect to the Riecoin server (same as rpcuser in riecoin.conf). Default: empty
* `WalletPassword`: the password used to connect to the Riecoin server (same as rpcpassword in riecoin.conf). Default: empty
* `StatsJsonFile`: the Json file where statistics (for now just Round data) are being stored. Default: SPM_YYYY-MM-DD_hhmmss.json
* `StatsHtmlFile`: the Html page where one can see an overview of the statistics. Default: SPM_YYYY-MM-DD_hhmmss.html
* `StatsUpdateInterval`: how often in s to update the stats. Default: 30

## Developers and license

* [Pttn](https://github.com/Pttn), author and maintainer. You can reach me on the [Riecoin Forum](https://riecoin.xyz/Forum).

This work is released under the MIT license.

## Contributing

You are welcomed to make Pull Requests bringing improvements that would benefit anyone using the software.

By contributing to StellaPool-Mini, you accept to place your code under the MIT license.

Donations welcome:

* Riecoin: ric1qpttn5u8u9470za84kt4y0lzz4zllzm4pyzhuge
* Bitcoin: bc1qpttn5u8u9470za84kt4y0lzz4zllzm4pwvel4c
