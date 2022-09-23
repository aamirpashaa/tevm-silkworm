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
#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/concurrency/signal_handler.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/downloader/internals/body_sequence.hpp>
#include <silkworm/downloader/internals/header_retrieval.hpp>
#include <silkworm/downloader/stage_bodies.hpp>
#include <silkworm/downloader/stage_headers.hpp>
#include <silkworm/stagedsync/common.hpp>

#include "common.hpp"

using namespace silkworm;
using namespace silkworm::stagedsync;

// stage-loop, forwarding phase
using LastStage = size_t;
std::tuple<StageResult, LastStage> forward(std::vector<IStage*> stages, db::RWTxn& txn) {
    StageResult result{StageResult::kUnspecified};

    for (size_t i = 0; i < stages.size(); ++i) {
        result = stages[i]->forward(txn);
        // TODO (canepat) add StageResult::unwind_needed(), then if (result.unwind_needed())
        if (result == StageResult::kInvalidBlock || result == StageResult::kWrongFork) {
            return {result, i};
        }
    }
    return {result, stages.size() - 1};
}

// stage-loop, unwinding phase
StageResult unwind(std::vector<IStage*> stages, LastStage last_stage, db::RWTxn& txn) {
    StageResult result{StageResult::kUnspecified};

    for (size_t i = last_stage; i <= 0; --i) {  // reverse loop
        result = stages[i]->unwind(txn);
        // TODO (canepat) add StageResult::unwind_error(), then if (result.unwind_error())
        if (result == StageResult::kUnexpectedError || result == StageResult::kAborted) {
            break;
        }
    }

    return result;
}

// progress log
class ProgressLog : public ActiveComponent {
    std::vector<IStage*> stages_;

  public:
    ProgressLog(std::vector<IStage*>& stages) : stages_(stages) {}

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

// Main
int main(int argc, char* argv[]) {
    using std::string, std::cout, std::cerr, std::optional, std::to_string;
    using namespace std::chrono;

    // Default values
    CLI::App app{"Downloader. Connect to p2p sentry and start header/body downloading process (stages 1 and 2)"};
    int return_value = 0;

    try {
        NodeSettings node_settings{};

        log::Settings log_settings{};
        log_settings.log_threads = true;
        log_settings.log_file = "downloader.log";
        log_settings.log_verbosity = log::Level::kInfo;
        log_settings.log_thousands_sep = '\'';
        log::set_thread_name("main          ");

        // test & measurement only parameters [to remove]
        BodySequence::kMaxBlocksPerMessage = 128;
        BodySequence::kPerPeerMaxOutstandingRequests = 4;
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
        cmd::parse_silkworm_command_line(app, argc, argv, log_settings, node_settings);

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

        // Node current status
        HeaderRetrieval headers(db::ROAccess{db});
        auto [head_hash, head_td] = headers.head_hash_and_total_difficulty();
        auto head_height = headers.head_height();

        log::Message("Chain/db status", {"head hash", head_hash.to_hex()});
        log::Message("Chain/db status", {"head td", intx::to_string(head_td)});
        log::Message("Chain/db status", {"head height", to_string(head_height)});

        // Sentry client - connects to sentry
        SentryClient sentry{node_settings.external_sentry_addr};
        sentry.set_status(head_hash, head_td, node_settings.chain_config.value());
        sentry.hand_shake();
        auto message_receiving = std::thread([&sentry]() { sentry.execution_loop(); });
        auto stats_receiving = std::thread([&sentry]() { sentry.stats_receiving_loop(); });

        // BlockExchange - download headers and bodies from remote peers using the sentry
        BlockExchange block_exchange{sentry, db::ROAccess{db}, node_settings.chain_config.value()};
        auto block_downloading = std::thread([&block_exchange]() { block_exchange.execution_loop(); });

        // Stages shared state
        SyncContext shared_status;
        shared_status.is_first_cycle = true;  // = starting up silkworm
        db::RWAccess db_access(db);

        // Stages 1 & 2 - Headers and bodies downloading - example code
        HeadersStage header_stage{&shared_status, block_exchange, &node_settings};
        BodiesStage body_stage{&shared_status, block_exchange, &node_settings};

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
        std::vector<IStage*> stages = {&header_stage, &body_stage};

        ProgressLog progress_log(stages);
        auto progress_displaying = std::thread([&progress_log]() {
            progress_log.execution_loop();
        });

        StageResult result{StageResult::kUnspecified};
        size_t last_stage = 0;

        do {
            db::RWTxn txn = db_access.start_rw_tx();

            std::tie(result, last_stage) = forward(stages, txn);

            // TODO (canepat) add StageResult::unwind_needed(), then if (result.unwind_needed())
            if (result == StageResult::kInvalidBlock || result == StageResult::kWrongFork) {
                result = unwind(stages, last_stage, txn);
            }

            shared_status.is_first_cycle = false;
        } while (result != StageResult::kUnexpectedError && !SignalHandler::signalled());

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
