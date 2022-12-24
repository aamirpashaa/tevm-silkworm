/*
   Copyright 2022 The Silkworm Authors
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <iostream>
#include <string>
#include <thread>

#include <CLI/CLI.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/concurrency/signal_handler.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/stagedsync/stage.hpp>
#include <silkworm/stagedsync/stage_bodies.hpp>
#include <silkworm/stagedsync/stage_headers.hpp>
#include <silkworm/consensus/base/engine.hpp>
#include <silkworm/state/in_memory_state.hpp>
#include <silkworm/execution/processor.hpp>
#include <silkworm/trie/vector_root.hpp>
#include <silkworm/downloader/internals/body_persistence.hpp>
#include <silkworm/downloader/internals/header_persistence.hpp>
#include <silkworm/downloader/internals/header_retrieval.hpp>

#include "common.hpp"

using namespace silkworm;
using namespace silkworm::stagedsync;

bool unwind_needed(Stage::Result result) {
    return (result == Stage::Result::kWrongFork || result == Stage::Result::kInvalidBlock);
}

bool error_or_abort(Stage::Result result) {
    return (result == Stage::Result::kUnexpectedError || result == Stage::Result::kAborted);
}

// stage-loop, forwarding phase
using LastStage = size_t;
std::tuple<Stage::Result, LastStage> forward(std::vector<Stage*> stages, db::RWTxn& txn) {
    Stage::Result result{Stage::Result::kUnspecified};

    for (size_t i = 0; i < stages.size(); ++i) {
        result = stages[i]->forward(txn);
        if (unwind_needed(result)) {
            return {result, i};
        }
    }
    return {result, stages.size() - 1};
}

// stage-loop, unwinding phase
Stage::Result unwind(std::vector<Stage*> stages, LastStage last_stage, db::RWTxn& txn) {
    Stage::Result result{Stage::Result::kUnspecified};

    for (size_t i = last_stage; i <= 0; --i) {  // reverse loop
        result = stages[i]->unwind(txn);
        if (error_or_abort(result)) {
            break;
        }
    }

    return result;
}

// progress log
class ProgressLog : public ActiveComponent {
    std::vector<Stage*> stages_;

  public:
    ProgressLog(std::vector<Stage*>& stages) : stages_(stages) {}

    void execution_loop() override {  // this is only a trick to avoid using asio timers, this is only test code
        using namespace std::chrono;
        log::set_thread_name("progress-log  ");
        while (!is_stopping()) {
            std::this_thread::sleep_for(30s);
            for (auto stage : stages_) {
                auto progress = stage->get_log_progress();
                log::Message(stage->name(), progress);
            }
        }
    }
};

evmc::bytes32 CalculateReceiptsRootAndSetGasUsed(Block &block,InMemoryState &state) {
    auto engine{consensus::engine_factory(kTelosEVMMainnetConfig)};
    ExecutionProcessor processor{block, *engine, state, kTelosEVMMainnetConfig};
    std::vector<Receipt> receipts;
    receipts.resize(block.transactions.size());
    auto receipt_it{receipts.begin()};
    for (const auto& txn : block.transactions) {
        processor.execute_transaction(txn, *receipt_it);
        ++receipt_it;
    }
    static constexpr auto kEncoder = [](Bytes& to, const Receipt& r) { rlp::encode(to, r); };
    evmc::bytes32 receipt_root{trie::root_hash(receipts, kEncoder)};
    block.header.gas_used = processor.cumulative_gas_used();
    return receipt_root;
}


// Main
int main(int argc, char* argv[]) {
    using std::string, std::cout, std::cerr, std::optional, std::to_string;
    using namespace std::chrono;

    // Default values
    CLI::App app{"Downloader. Connect to p2p sentry and start header/body downloading process (stages 1 and 2)"};
    int return_value = 0;

    try {
        cmd::SilkwormCoreSettings settings;
        auto& log_settings = settings.log_settings;
        auto& node_settings = settings.node_settings;

        log_settings.log_threads = true;
        log_settings.log_file = "downloader.log";
        log_settings.log_verbosity = log::Level::kInfo;
        log_settings.log_thousands_sep = '\'';
        log::set_thread_name("main          ");

        // test & measurement only parameters [to remove]
        int requestDeadlineSeconds = 30;     // BodySequence::kRequestDeadline = std::chrono::seconds(30);
        int noPeerDelayMilliseconds = 1000;  // BodySequence::kNoPeerDelay = std::chrono::milliseconds(1000)

        app.add_option("--max_blocks_per_req", BodySequence::kMaxBlocksPerMessage,
                       "Max number of blocks requested to peers in a single request")
            ->capture_default_str();
        app.add_option("--max_requests_per_peer", BodySequence::kPerPeerMaxOutstandingRequests,
                       "Max number of pending request made to each peer")
            ->capture_default_str();
        app.add_option("--request_deadline_s", requestDeadlineSeconds,
                       "Time (secs) after which a response is considered lost and will be re-tried")
            ->capture_default_str();
        app.add_option("--no_peer_delay_ms", noPeerDelayMilliseconds,
                       "Time (msecs) to wait before making a new request when no peer accepted the last")
            ->capture_default_str();

        BodySequence::kRequestDeadline = std::chrono::seconds(requestDeadlineSeconds);
        BodySequence::kNoPeerDelay = std::chrono::milliseconds(noPeerDelayMilliseconds);
        // test & measurement only parameters end

        // Command line parsing
        cmd::parse_silkworm_command_line(app, argc, argv, settings);

        log::init(log_settings);
        log::set_thread_name("stage-loop    ");

        // Output BuildInfo
        auto build_info{silkworm_get_buildinfo()};
        log::Message("SILKWORM DOWNLOADER", {"version", std::string(build_info->git_branch) + std::string(build_info->project_version),
                                             "build", std::string(build_info->system_name) + "-" + std::string(build_info->system_processor) + " " + std::string(build_info->build_type),
                                             "compiler", std::string(build_info->compiler_id) + " " + std::string(build_info->compiler_version)});

        log::Message("BlockExchange parameter", {"--max_blocks_per_req", to_string(BodySequence::kMaxBlocksPerMessage)});
        log::Message("BlockExchange parameter", {"--max_requests_per_peer", to_string(BodySequence::kPerPeerMaxOutstandingRequests)});
        log::Message("BlockExchange parameter", {"--request_deadline_s", to_string(requestDeadlineSeconds)});
        log::Message("BlockExchange parameter", {"--no_peer_delay_ms", to_string(noPeerDelayMilliseconds)});

        // Prepare database
        cmd::run_preflight_checklist(node_settings);
        log::Message("Chain Identity", {"id", std::to_string(node_settings.chain_config->chain_id),
                                        "genesis", to_hex(node_settings.chain_config->genesis_hash.value(), true),
                                        "hard-forks", std::to_string(node_settings.chain_config->distinct_fork_numbers().size())});

        // Database access
        mdbx::env_managed db = db::open_env(node_settings.chaindata_env_config);

        // silkworm::TelosEVM tevm{};
        // tevm.push(intx::uint256{25});
        // log::Message("Stack",{"item",intx::to_string(tevm.pop())});
        // return 0;
        
        std::ifstream txdumpfile("/mnt2/TelosWorks/read-state-history/dump-short.dat");
        std::ifstream blockdumpfile("/mnt2/TelosWorks/read-state-history/dump-block.dat");
        std::ifstream accountdumpfile("/mnt2/TelosWorks/read-state-history/account_table.dat");
        
        db::RWAccess db_access(db);
        HeaderRetrieval headers(db_access);
        auto [head_hash, head_td] = headers.head_hash_and_total_difficulty();
        auto head_height = headers.head_height();
        headers.close();
        
        Hash lastblockhash = head_hash;
        std::string line,line2,line3;
        std::map<std::string,std::string> mapping;

        while (std::getline(accountdumpfile, line3))
        {
            std::string addr = line3.substr(0,line3.find(","));
            std::string acct = line3.substr(line3.find(",")+1,line3.size()-line3.find(","));
            mapping.insert(std::make_pair(acct,"0x"+addr));
        }
        while (std::getline(blockdumpfile, line))
        {
            std::string blocknum = std::to_string(stoull(line.substr(0,9))-36);
            if (blocknum > std::to_string(head_height)) {
                break;
            }
        }
        while (std::getline(txdumpfile, line2))
        {
            std::string blocknum = line2.substr(3,9);;
            if (blocknum > std::to_string(head_height)) {
                break;
            }
        }
        
        std::vector<Block> temp_blocks;
        InMemoryState state;
        do {
            std::string blocknum = std::to_string(stoull(line.substr(0,9))-36);
            std::string blockhash = line.substr(10,64);
            std::string blocktime = std::to_string(stoull(line.substr(75,10))+12600);
            uint64_t gas_limit = 0;
            // if (blocknum > "180698824") {
            //     break;
            // }
            // if (blocknum > "180840052") {
            //     break;
            // }
            if (blocknum > "180840052") {
                break;
            }
            intx::uint128 trx_index = 0;
            std::vector<silkworm::Transaction> transactions;
            if (line2.size()>0 && line2.substr(3,9) == blocknum) {
                do {
                    std::string type = line2.substr(0,3);
                    nlohmann::json trx = nlohmann::json::parse(line2.substr(12));
                    if (type == "DPS") {
                        // std::cout<<type<<" "<<blocknum<<" "<<trx["from"].get<string>()<<std::endl;
                        std::string quantity = trx["quantity"].get<string>();
                        std::string value = quantity.substr(0,quantity.find(" "));
                        std::string symbol = quantity.substr(quantity.find(" ")+1,4);
                        if (symbol != "TLOS") {
                            std::cout<<"ERROR ON PROCESSING TRANSACTION: Invalid symbol"<<std::endl;
                            throw 0;
                        }
                        if (value.at(value.size()-5) != '.') {
                            std::cout<<"ERROR ON PROCESSING TRANSACTION: Invalid decimals"<<std::endl;
                            throw 0;
                        }
                        value.replace(value.size()-5,1,"");
                        std::string to = "0x0000000000000000000000000000000000000000";
                        if (trx["memo"].get<string>() == "") {
                            if (mapping.find(trx["from"].get<string>()) != mapping.end()) {
                                to = mapping[trx["from"].get<string>()];
                            } else {
                                std::cout<<"ERROR ON PROCESSING TRANSACTION: Name not found: "<<trx["from"].get<string>()<<" "<<trx["from"].get<string>().size()<<std::endl;
                                throw 0;
                            }
                        } else {
                            if (trx["memo"].get<string>().size() == 42 && trx["memo"].get<string>().substr(0,2) == "0x") {
                                to = trx["memo"].get<string>();
                            } else {
                                if (mapping.find(trx["from"].get<string>()) != mapping.end()) {
                                    to = mapping[trx["from"].get<string>()];
                                } else {
                                    std::cout<<"ERROR ON PROCESSING TRANSACTION: Invalid memo and name not found"<<std::endl;
                                    throw 0;
                                }
                            }
                        }
                        Transaction txn{
                            Transaction::Type::kLegacy,                                                                             // type
                            0,                                                                                                      // nonce
                            intx::from_string<intx::uint256>("0x0"),                                                                // max_priority_fee_per_gas0
                            intx::from_string<intx::uint256>("0x0"),                                                                // max_fee_per_gas
                            21000,                                                                                                  // gas_limit
                            to_evmc_address(*from_hex(to)),                                                                         // to
                            intx::from_string<intx::uint256>(value)*intx::from_string<intx::uint256>("100000000000000"),            // value
                            {},                                                                                                     // data
                            true,                                                                                                   // odd_y_parity
                            3,                                                                                                      // chain_id
                            intx::from_string<intx::uint256>("0x"+blockhash) + trx_index,                                           // r
                            intx::from_string<intx::uint256>("0x0000000000000000000000000000000000000000000000000000000000000000"), // s
                            {},
                        };
                        transactions.push_back(txn);
                        gas_limit += txn.gas_limit;
                    } else if (type == "WDR") {
                        // std::cout<<type<<" "<<blocknum<<" "<<trx["to"].get<string>()<<std::endl;
                        std::string quantity = trx["quantity"].get<string>();
                        std::string value = quantity.substr(0,quantity.find(" "));
                        std::string symbol = quantity.substr(quantity.find(" ")+1,4);
                        if (symbol != "TLOS") {
                            std::cout<<"ERROR ON PROCESSING TRANSACTION: Invalid symbol"<<std::endl;
                            throw 0;
                        }
                        if (value.at(value.size()-5) != '.') {
                            std::cout<<"ERROR ON PROCESSING TRANSACTION: Invalid decimals"<<std::endl;
                            throw 0;
                        }
                        value.replace(value.size()-5,1,"");
                        std::string from = "0x0000000000000000000000000000000000000000";
                        if (mapping.find(trx["to"].get<string>()) != mapping.end()) {
                            from = mapping[trx["to"].get<string>()];
                        } else {
                            std::cout<<"ERROR ON PROCESSING TRANSACTION: Name not found: "<<trx["to"].get<string>()<<" "<<trx["to"].get<string>().size()<<std::endl;
                            throw 0;
                        }
                        std::cout<<from<<std::endl;
                        Transaction txn{
                            Transaction::Type::kLegacy,                                                                             // type
                            0,                                                                                                      // nonce
                            intx::from_string<intx::uint256>("0x0"),                                                                // max_priority_fee_per_gas0
                            intx::from_string<intx::uint256>("0x0"),                                                                // max_fee_per_gas
                            21000,                                                                                                  // gas_limit
                            0x0000000000000000000000000000000000000000_address,                                                     // to
                            intx::from_string<intx::uint256>(value)*intx::from_string<intx::uint256>("100000000000000"),            // value
                            {},                                                                                                     // data
                            true,                                                                                                   // odd_y_parity
                            3,                                                                                                      // chain_id
                            intx::from_string<intx::uint256>("0x"+blockhash) + trx_index,                                           // r
                            intx::from_string<intx::uint256>(from+"000000000000000000000000"),                                      // s
                            {},
                        };
                        transactions.push_back(txn);
                        gas_limit += txn.gas_limit;
                    } else if (type == "RAW") {
                        Transaction txn;
                        // std::cout<<type<<" "<<blocknum<<" "<<trx["tx"].get<string>()<<std::endl;
                        std::optional<Bytes> rlp{from_hex("0x"+trx["tx"].get<string>())};
                        if (rlp) {
                            ByteView view{*rlp};
                            auto res = rlp::decode_transaction(view, txn, rlp::Eip2718Wrapping::kNone);
                            // auto txn_hash{keccak256(rlp.value())};
                            // ByteView txn_hash_view{txn_hash.bytes};
                            // std::cout<<to_hex(txn_hash_view)<<std::endl;
                            if (res == DecodingResult::kOk) {
                                transactions.push_back(txn);
                                gas_limit += txn.gas_limit;
                            } else if (res == DecodingResult::kInvalidVInSignature) {
                                if (!txn.r && !txn.s && !trx["sender"].is_null()) {
                                    std::cout<<trx["sender"].get<string>()<<std::endl;
                                    txn.odd_y_parity = true;
                                    txn.chain_id = 3;
                                    txn.r = intx::from_string<intx::uint256>("0x"+blockhash) + trx_index;
                                    txn.s = intx::from_string<intx::uint256>("0x"+trx["sender"].get<string>()+"000000000000000000000000");
                                    transactions.push_back(txn);
                                    gas_limit += txn.gas_limit;
                                } else {
                                    std::cout<<"ERROR ON PROCESSING TRANSACTION: Invalid sign"<<std::endl;
                                    throw 0;
                                }
                            } else {
                                std::cout<<"ERROR ON PROCESSING TRANSACTION: Invalid result"<<std::endl;
                                throw 0;
                            }
                        } else {
                            std::cout<<"ERROR ON PROCESSING TRANSACTION: Invalid transaction encoding"<<std::endl;
                            throw 0;
                        }
                    } else {
                        std::cout<<"ERROR ON PROCESSING TRANSACTION: Invalid transaction type"<<std::endl;
                        throw 0;
                    }
                    trx_index++;
                } while (std::getline(txdumpfile, line2) && line2.substr(3,9) == blocknum);
            }
            Block block;
            block.transactions = transactions;
            block.header.parent_hash = lastblockhash;
            block.header.ommers_hash = kEmptyListHash;
            block.header.beneficiary = 0x0000000000000000000000000000000000000000_address;
            block.header.state_root = kEmptyRoot;
            block.header.transactions_root = consensus::EngineBase::compute_transaction_root(block);
            block.header.receipts_root = CalculateReceiptsRootAndSetGasUsed(block,state);
            block.header.difficulty = intx::from_string<intx::uint256>("0x0");
            block.header.number = std::stoull(blocknum, nullptr, 0);
            block.header.gas_limit = gas_limit;
            block.header.timestamp = std::stoull(blocktime, nullptr, 0);
            block.header.extra_data = *from_hex(blockhash);
            block.header.mix_hash = to_bytes32(*from_hex("0x0000000000000000000000000000000000000000000000000000000000000000"));
            endian::store_big_u64(block.header.nonce.data(), std::stoull("0x0", nullptr, 0));
            lastblockhash = block.header.hash();
            std::cout<<block.header.number<<" "<<block.header.hash()<<std::endl;
            temp_blocks.push_back(block);
            Bytes block_header_bytes;
            rlp::encode(block_header_bytes,block.header);
            if (blocknum == "180840052") {
                std::cout<<"Raw:"<<to_hex(block_header_bytes)<<std::endl;
                std::cout<<"Transaction Count:"<<block.transactions.size()<<std::endl;
                std::cout<<"parent_hash:"<<block.header.parent_hash<<std::endl;
                std::cout<<"ommers_hash:"<<block.header.ommers_hash<<std::endl;
                std::cout<<"beneficiary:"<<block.header.beneficiary<<std::endl;
                std::cout<<"state_root:"<<block.header.state_root<<std::endl;
                std::cout<<"transactions_root:"<<block.header.transactions_root<<std::endl;
                std::cout<<"receipts_root:"<<block.header.receipts_root<<std::endl;
                std::cout<<"difficulty:"<<intx::to_string(block.header.difficulty)<<std::endl;
                std::cout<<"number:"<<block.header.number<<std::endl;
                std::cout<<"gas_used:"<<block.header.gas_used<<std::endl;
                std::cout<<"gas_limit:"<<block.header.gas_limit<<std::endl;
                std::cout<<"timestamp:"<<block.header.timestamp<<std::endl;
                std::cout<<"extra_data:"<<block.header.extra_data<<std::endl;
                std::cout<<"mix_hash:"<<block.header.mix_hash<<std::endl;
                std::cout<<"nonce:"<<block.header.nonce<<std::endl;
                std::cout<<"transactions:"<<std::endl;
                for (auto &txn : block.transactions) {
                    txn.recover_sender();
                    Bytes txn_data;
                    rlp::encode(txn_data, txn, /*for_signing=*/false, /*wrap_eip2718_into_string=*/false);
                    auto txn_hash{keccak256(txn_data)};
                    ByteView txn_hash_view{txn_hash.bytes};
                    std::cout<<"######################"<<std::endl;
                    std::cout<<"- raw:"<<to_hex(txn_data)<<std::endl;
                    std::cout<<"- hash:"<<to_hex(txn_hash_view)<<std::endl;
                    std::cout<<"- nonce:"<<txn.nonce<<std::endl;
                    std::cout<<"- gas_limit:"<<txn.gas_limit<<std::endl;
                    std::cout<<"- max_fee_per_gas:"<<intx::hex(txn.max_fee_per_gas)<<std::endl;
                    std::cout<<"- max_priority_fee_per_gas:"<<intx::hex(txn.max_priority_fee_per_gas)<<std::endl;
                    std::cout<<"- from:"<<txn.from.value()<<std::endl;
                    std::cout<<"- to:"<<txn.to.value()<<std::endl;
                    std::cout<<"- value:"<<intx::hex(txn.value)<<std::endl;
                    std::cout<<"- data:"<<txn.data<<std::endl;
                    std::cout<<"- v:"<<intx::to_string(txn.v())<<std::endl;
                    std::cout<<"- r:"<<intx::hex(txn.r)<<std::endl;
                    std::cout<<"- s:"<<intx::hex(txn.s)<<std::endl;
                }
            }
            if (block.header.number%1000 == 0) {
                db::RWTxn tx1 = db_access.start_rw_tx();
                HeaderPersistence header_persistence(tx1);
                for (Block b:temp_blocks) {
                    header_persistence.persist(b.header);
                }
                header_persistence.finish();
                log::Info() << "Header persistence after height=" << header_persistence.highest_height();
                tx1.commit(false);
                db::RWTxn tx2 = db_access.start_rw_tx();
                BodyPersistence body_persistence(tx2, node_settings.chain_config.value());
                body_persistence.persist(temp_blocks);
                body_persistence.close();
                log::Info() << "Body persistence after height=" << body_persistence.highest_height();
                tx2.commit(false);
                temp_blocks.clear();
            }
        } while (std::getline(blockdumpfile, line));
        if (!temp_blocks.empty()) {
            db::RWTxn tx1 = db_access.start_rw_tx();
            HeaderPersistence header_persistence(tx1);
            for (Block b:temp_blocks) {
                header_persistence.persist(b.header);
            }
            header_persistence.finish();
            log::Info() << "Header persistence after height=" << header_persistence.highest_height();
            tx1.commit(false);
            db::RWTxn tx2 = db_access.start_rw_tx();
            BodyPersistence body_persistence(tx2, node_settings.chain_config.value());
            body_persistence.persist(temp_blocks);
            body_persistence.close();
            log::Info() << "Body persistence after height=" << body_persistence.highest_height();
            tx2.commit(false);
            temp_blocks.clear();
        }
        std::cout<<"SALAM"<<std::endl;
        return 0;

        // auto db_access = Db::ReadWriteAccess{db};
        // Block block1;
        // block1.header.parent_hash = to_bytes32(*from_hex("0x9bd7e881e0903ea4fa161c7f00096c11346f122bff30a3a5122ef5c1f9c9f80c"));
        // block1.header.ommers_hash = kEmptyListHash;
        // block1.header.beneficiary = 0x0000000000000000000000000000000000000000_address;
        // block1.header.state_root = kEmptyRoot;
        // block1.header.transactions_root = consensus::EngineBase::compute_transaction_root(block1);
        // block1.header.receipts_root = kEmptyRoot;
        // block1.header.difficulty = intx::from_string<intx::uint256>("0x0");
        // block1.header.number = 180698824;
        // block1.header.gas_limit = std::stoull("0x0", nullptr, 0);
        // block1.header.timestamp = std::stoull("0x61782354", nullptr, 0);
        // block1.header.extra_data = *from_hex("0x0ac53eeca101095f48c7b6d65d0130e566903894f7a6b9d50cf1e144ca020f38");
        // block1.header.mix_hash = to_bytes32(*from_hex("0x0000000000000000000000000000000000000000000000000000000000000000"));
        // endian::store_big_u64(block1.header.nonce.data(), std::stoull("0x0", nullptr, 0));
        
        // Transaction txn{
        //     Transaction::Type::kLegacy,                                                                             // type
        //     0,                                                                                                      // nonce
        //     intx::from_string<intx::uint256>("0x7A307EFA80"),                                                       // max_priority_fee_per_gas0
        //     intx::from_string<intx::uint256>("0x7A307EFA80"),                                                       // max_fee_per_gas
        //     21000,                                                                                                  // gas_limit
        //     0x77E5B60A7da45426Cc936Ce0cbF393D12551e57C_address,                                                     // to
        //     intx::from_string<intx::uint256>("0x5ce405be25a9b17216"),                                               // value
        //     {},                                                                                                     // data
        //     true,                                                                                                   // odd_y_parity
        //     3,                                                                                                      // chain_id
        //     intx::from_string<intx::uint256>("0x0ad587e9f199d82e9be9e47bd8dd50a9aa0b940fb964457038de8eccc0526069") + intx::uint256{0}, // r
        //     intx::from_string<intx::uint256>("0x0000000000000000000000000000000000000000000000000000000000000001"), // s
        //     {},
        // };
        // Transaction txn2;
        // std::optional<Bytes> rlp2{from_hex("0xF86D8085745EF2D63182668A94E1C0E5AC8AB0DAB88E682B9A8653BC7A943FB80F895CE3D72195B97275AC8074A0910B269AC298C331DB2A61DEC9EFB5E3D98A3FACFBE3F1FC3D8ECA7BF6EFF27AA063A0B3343CA35860B09D397506875E68F9496CBEFC06935FF715F24A4F786C03")};
        // if (rlp2) {
        //     ByteView view2{*rlp2};
        //     if (rlp::decode_transaction(view2, txn2, rlp::Eip2718Wrapping::kNone) != DecodingResult::kOk) {
        //         std::cout<<"ERROR ON PROCESSING TRANSACTION"<<std::endl;
        //     }
        // }
        // Block block2;
        // block2.transactions = std::vector<silkworm::Transaction>{txn,txn2};
        // block2.header.parent_hash = to_bytes32(*from_hex("abff8c6246671b49d8c4a6cc0e678e34a82af1c70828b621cd738c8164c39067"));
        // block2.header.ommers_hash = kEmptyListHash;
        // block2.header.beneficiary = 0x0000000000000000000000000000000000000000_address;
        // block2.header.state_root = kEmptyRoot;
        // block2.header.transactions_root = consensus::EngineBase::compute_transaction_root(block2);
        // block2.header.receipts_root = to_bytes32(*from_hex("d95b673818fa493deec414e01e610d97ee287c9421c8eff4102b1647c1a184e4"));
        // block2.header.difficulty = intx::from_string<intx::uint256>("0x0");
        // block2.header.number = 180698825;
        // block2.header.gas_used = std::stoull("0xA410", nullptr, 0);
        // block2.header.gas_limit = std::stoull("0xB892", nullptr, 0);
        // block2.header.timestamp = std::stoull("0x61782355", nullptr, 0);
        // block2.header.extra_data = *from_hex("0x0ac53eedfca4ade7cc52e356f70af7eab5aedccfad59775f2e70f421f9101a3c");
        // block2.header.mix_hash = to_bytes32(*from_hex("0x0000000000000000000000000000000000000000000000000000000000000000"));
        // endian::store_big_u64(block2.header.nonce.data(), std::stoull("0x0", nullptr, 0));

        // std::cout<<to_hex(CalculateReceiptsRoot(&block2))<<std::endl;
        
        // Db::ReadWriteAccess::Tx tx1 = db_access.start_tx();
        // HeaderPersistence header_persistence(tx1);
        // log::Info() << "Header persistence before height=" << header_persistence.initial_height();
        // header_persistence.persist(block1.header);
        // header_persistence.persist(block2.header);
        // header_persistence.close();
        // log::Info() << "Header persistence after height=" << header_persistence.highest_height();
        // tx1.commit();
        // Db::ReadWriteAccess::Tx tx2 = db_access.start_tx();
        // BodyPersistence body_persistence(tx2, chain_identity);
        // log::Info() << "Body persistence before height=" << body_persistence.initial_height();
        // body_persistence.persist(block1);
        // body_persistence.persist(block2);
        // body_persistence.close();
        // log::Info() << "Body persistence after height=" << body_persistence.highest_height();
        // tx2.commit();
        // std::cout<<"SALAM"<<std::endl;
        // return 0;

        // Sentry client - connects to sentry
        SentryClient sentry{node_settings.external_sentry_addr, db::ROAccess{db}, node_settings.chain_config.value()};
        auto message_receiving = std::thread([&sentry]() { sentry.execution_loop(); });
        auto stats_receiving = std::thread([&sentry]() { sentry.stats_receiving_loop(); });

        // BlockExchange - download headers and bodies from remote peers using the sentry
        BlockExchange block_exchange{sentry, db::ROAccess{db}, node_settings.chain_config.value()};
        auto block_downloading = std::thread([&block_exchange]() { block_exchange.execution_loop(); });

        // Stages shared state
        SyncContext shared_status;
        shared_status.is_first_cycle = true;  // = starting up silkworm

        // Stages 1 & 2 - Headers and bodies downloading - example code
        HeadersStage header_stage{&shared_status, block_exchange, &node_settings};
        BodiesStage body_stage{&shared_status, block_exchange, &node_settings};

        header_stage.set_log_prefix("[1/2 Headers]");
        body_stage.set_log_prefix("[2/2 Bodies]");

        // Trap os signals
        SignalHandler::init();
        //        SignalHandler::init([&](int) {
        //            log::Info() << "Requesting threads termination\n";
        //            header_stage.stop();
        //            body_stage.stop();
        //            block_exchange.stop();
        //            sentry.stop();
        //        });

        // Sample stage loop with 2 stages
        std::vector<Stage*> stages = {&header_stage, &body_stage};

        ProgressLog progress_log(stages);
        auto progress_displaying = std::thread([&progress_log]() {
            progress_log.execution_loop();
        });

        Stage::Result result{Stage::Result::kUnspecified};
        size_t last_stage = 0;

        do {
            db::RWTxn txn = db_access.start_rw_tx();

            std::tie(result, last_stage) = forward(stages, txn);

            if (unwind_needed(result)) {
                result = unwind(stages, last_stage, txn);
            }

            shared_status.is_first_cycle = false;
        } while (!error_or_abort(result) && !SignalHandler::signalled());

        log::Info() << "Downloader stage-loop ended\n";

        // Signal exiting
        progress_log.stop();
        header_stage.stop();
        body_stage.stop();
        block_exchange.stop();
        // Wait threads termination
        log::Info() << "Waiting threads termination\n";
        progress_displaying.join();
        block_downloading.join();
        message_receiving.join();
        stats_receiving.join();

        log::Info() << "Closing db\n";
        db.close();

        log::Info() << "Downloader terminated\n";

    } catch (const CLI::ParseError& ex) {
        return_value = app.exit(ex);
    } catch (std::exception& e) {
        cerr << "Exception (type " << typeid(e).name() << "): " << e.what() << "\n";
        return_value = 1;
    }

    return return_value;
}