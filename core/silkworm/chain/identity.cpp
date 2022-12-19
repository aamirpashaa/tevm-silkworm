/*
   Copyright 2021-2022 The Silkworm Authors

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

#include "identity.hpp"

namespace silkworm {

// TODO (Andrew) what about terminal total difficulty?

std::vector<BlockNum> ChainIdentity::distinct_fork_numbers() const {
    std::vector<BlockNum> forks;

    for (std::optional<uint64_t> bn : chain.evmc_fork_blocks) {
        if (bn && *bn != 0) {
            forks.push_back(*bn);
        }
    }
    if (chain.dao_block) {
        forks.push_back(*chain.dao_block);
    }
    if (chain.muir_glacier_block) {
        forks.push_back(*chain.muir_glacier_block);
    }
    if (chain.arrow_glacier_block) {
        forks.push_back(*chain.arrow_glacier_block);
    }
    if (chain.gray_glacier_block) {
        forks.push_back(*chain.gray_glacier_block);
    }

    sort(forks.begin(), forks.end());                              // block list must be ordered
    forks.erase(unique(forks.begin(), forks.end()), forks.end());  // do not repeat block if 2 forks overlap

    return forks;
}

static ChainIdentity mainnet_identity() {
    ChainIdentity id;

    id.name = "mainnet";
    id.chain = kMainnetConfig;
    id.genesis_hash = 0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3_bytes32;

    return id;
}

static ChainIdentity goerli_identity() {
    ChainIdentity id;

    id.name = "goerli";
    id.chain = kGoerliConfig;
    id.genesis_hash = 0xbf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a_bytes32;

    return id;
}

static ChainIdentity telosevmmainnet_identity() {
    ChainIdentity id;

    id.name = "telosevmmainnet";
    id.chain = kTelosEVMMainnetConfig;
    id.genesis_hash = 0x9bd7e881e0903ea4fa161c7f00096c11346f122bff30a3a5122ef5c1f9c9f80c_bytes32;

    return id;
}

static ChainIdentity telosevmtestnet_identity() {
    ChainIdentity id;

    id.name = "telosevmtestnet";
    id.chain = kTelosEVMTestnetConfig;
    id.genesis_hash = 0x3ba6f4ac4f5b74e8e62622b9d8c75d1e4ad10abb3b7e4770cbab7338a861a4f9_bytes32;

    return id;
}

ChainIdentity ChainIdentity::mainnet = mainnet_identity();
ChainIdentity ChainIdentity::goerli = goerli_identity();
ChainIdentity ChainIdentity::telosevmmainnet = telosevmmainnet_identity();
ChainIdentity ChainIdentity::telosevmtestnet = telosevmtestnet_identity();

}  // namespace silkworm
