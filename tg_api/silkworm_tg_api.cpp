/*
   Copyright 2020 The Silkworm Authors

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

#include "silkworm_tg_api.h"

#include <cassert>
#include <gsl/gsl_util>
#include <silkworm/chain/config.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/execution/execution.hpp>

SILKWORM_EXPORT SilkwormStatusCode silkworm_execute_blocks(MDB_txn* mdb_txn, uint64_t chain_id, uint64_t start_block,
                                                           uint64_t max_block, uint64_t batch_size, bool write_receipts,
                                                           uint64_t* last_executed_block,
                                                           int* lmdb_error_code) SILKWORM_NOEXCEPT {
    assert(mdb_txn);

    using namespace silkworm;
    Logger::default_logger().set_local_timezone(true);  // for compatibility with TG logging

    const ChainConfig* config{lookup_chain_config(chain_id)};
    if (!config) {
        SILKWORM_LOG(LogError) << "Unsupported chain ID " << chain_id << std::endl;
        return kSilkwormUnknownChainId;
    }

    uint64_t block_num{start_block};

    try {
        lmdb::Transaction txn{/*parent=*/nullptr, mdb_txn, /*flags=*/0};
        auto cleanup{gsl::finally([&txn] { *txn.handle() = nullptr; })};  // avoid aborting mdb_txn

        if (write_receipts && (!db::migration_happened(txn, "receipts_cbor_encode") ||
                               !db::migration_happened(txn, "receipts_store_logs_separately"))) {
            SILKWORM_LOG(LogError) << "Legacy stored receipts are not supported\n";
            return kSilkwormIncompatibleDbFormat;
        }

        // https://github.com/ledgerwatch/turbo-geth/pull/1342
        if (!db::migration_happened(txn, "acc_change_set_dup_sort_18") ||
            !db::migration_happened(txn, "storage_change_set_dup_sort_22")) {
            SILKWORM_LOG(LogError) << "Legacy change sets are not supported\n";
            return kSilkwormIncompatibleDbFormat;
        }

        // https://github.com/ledgerwatch/turbo-geth/pull/1358
        if (db::migration_happened(txn, "tx_table_4")) {
            SILKWORM_LOG(LogError) << "Individually stored transactions are not supported yet\n";
            return kSilkwormIncompatibleDbFormat;
        }

        db::Buffer buffer{&txn};
        AnalysisCache analysis_cache;

        for (; block_num <= max_block; ++block_num) {
            std::optional<BlockWithHash> bh{db::read_block(txn, block_num, /*read_senders=*/true)};
            if (!bh) {
                return kSilkwormBlockNotFound;
            }

            std::vector<Receipt> receipts{execute_block(bh->block, buffer, *config, &analysis_cache)};

            if (write_receipts) {
                buffer.insert_receipts(block_num, receipts);
            }

            if (last_executed_block) {
                *last_executed_block = block_num;
            }

            if (block_num % 1000 == 0) {
                SILKWORM_LOG(LogInfo) << "Blocks <= " << block_num << " executed" << std::endl;
            }

            if (buffer.current_batch_size() >= batch_size) {
                buffer.write_to_db();
                return kSilkwormSuccess;
            }
        };

        buffer.write_to_db();
        return kSilkwormSuccess;

    } catch (const lmdb::exception& e) {
        if (lmdb_error_code) {
            *lmdb_error_code = e.err();
        }
        SILKWORM_LOG(LogError) << "LMDB error " << e.what() << std::endl;
        return kSilkwormLmdbError;
    } catch (const db::MissingSenders&) {
        SILKWORM_LOG(LogError) << "Missing or incorrect senders at block " << block_num << std::endl;
        return kSilkwormMissingSenders;
    } catch (const ValidationError& e) {
        SILKWORM_LOG(LogError) << "Validation error " << e.what() << " at block " << block_num << std::endl;
        return kSilkwormInvalidBlock;
    } catch (const DecodingError& e) {
        SILKWORM_LOG(LogError) << "Decoding error " << e.what() << " at block " << block_num << std::endl;
        return kSilkwormDecodingError;
    } catch (...) {
        return kSilkwormUnknownError;
    }
}
