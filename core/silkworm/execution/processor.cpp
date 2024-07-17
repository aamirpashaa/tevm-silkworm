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

#include "processor.hpp"

#include <cassert>
#include <stdio.h>

#include <silkworm/chain/dao.hpp>
#include <silkworm/chain/intrinsic_gas.hpp>
#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/trie/vector_root.hpp>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>

namespace silkworm {

class MyTracer : public EvmTracer {
    public:
    const char* istanbul_names[256] = {
        /* 0x00 */ "STOP",
        /* 0x01 */ "ADD",
        /* 0x02 */ "MUL",
        /* 0x03 */ "SUB",
        /* 0x04 */ "DIV",
        /* 0x05 */ "SDIV",
        /* 0x06 */ "MOD",
        /* 0x07 */ "SMOD",
        /* 0x08 */ "ADDMOD",
        /* 0x09 */ "MULMOD",
        /* 0x0a */ "EXP",
        /* 0x0b */ "SIGNEXTEND",
        /* 0x0c */ NULL,
        /* 0x0d */ NULL,
        /* 0x0e */ NULL,
        /* 0x0f */ NULL,
        /* 0x10 */ "LT",
        /* 0x11 */ "GT",
        /* 0x12 */ "SLT",
        /* 0x13 */ "SGT",
        /* 0x14 */ "EQ",
        /* 0x15 */ "ISZERO",
        /* 0x16 */ "AND",
        /* 0x17 */ "OR",
        /* 0x18 */ "XOR",
        /* 0x19 */ "NOT",
        /* 0x1a */ "BYTE",
        /* 0x1b */ "SHL",
        /* 0x1c */ "SHR",
        /* 0x1d */ "SAR",
        /* 0x1e */ NULL,
        /* 0x1f */ NULL,
        /* 0x20 */ "KECCAK256",
        /* 0x21 */ NULL,
        /* 0x22 */ NULL,
        /* 0x23 */ NULL,
        /* 0x24 */ NULL,
        /* 0x25 */ NULL,
        /* 0x26 */ NULL,
        /* 0x27 */ NULL,
        /* 0x28 */ NULL,
        /* 0x29 */ NULL,
        /* 0x2a */ NULL,
        /* 0x2b */ NULL,
        /* 0x2c */ NULL,
        /* 0x2d */ NULL,
        /* 0x2e */ NULL,
        /* 0x2f */ NULL,
        /* 0x30 */ "ADDRESS",
        /* 0x31 */ "BALANCE",
        /* 0x32 */ "ORIGIN",
        /* 0x33 */ "CALLER",
        /* 0x34 */ "CALLVALUE",
        /* 0x35 */ "CALLDATALOAD",
        /* 0x36 */ "CALLDATASIZE",
        /* 0x37 */ "CALLDATACOPY",
        /* 0x38 */ "CODESIZE",
        /* 0x39 */ "CODECOPY",
        /* 0x3a */ "GASPRICE",
        /* 0x3b */ "EXTCODESIZE",
        /* 0x3c */ "EXTCODECOPY",
        /* 0x3d */ "RETURNDATASIZE",
        /* 0x3e */ "RETURNDATACOPY",
        /* 0x3f */ "EXTCODEHASH",
        /* 0x40 */ "BLOCKHASH",
        /* 0x41 */ "COINBASE",
        /* 0x42 */ "TIMESTAMP",
        /* 0x43 */ "NUMBER",
        /* 0x44 */ "DIFFICULTY",
        /* 0x45 */ "GASLIMIT",
        /* 0x46 */ "CHAINID",
        /* 0x47 */ "SELFBALANCE",
        /* 0x48 */ NULL,
        /* 0x49 */ NULL,
        /* 0x4a */ NULL,
        /* 0x4b */ NULL,
        /* 0x4c */ NULL,
        /* 0x4d */ NULL,
        /* 0x4e */ NULL,
        /* 0x4f */ NULL,
        /* 0x50 */ "POP",
        /* 0x51 */ "MLOAD",
        /* 0x52 */ "MSTORE",
        /* 0x53 */ "MSTORE8",
        /* 0x54 */ "SLOAD",
        /* 0x55 */ "SSTORE",
        /* 0x56 */ "JUMP",
        /* 0x57 */ "JUMPI",
        /* 0x58 */ "PC",
        /* 0x59 */ "MSIZE",
        /* 0x5a */ "GAS",
        /* 0x5b */ "JUMPDEST",
        /* 0x5c */ NULL,
        /* 0x5d */ NULL,
        /* 0x5e */ NULL,
        /* 0x5f */ NULL,
        /* 0x60 */ "PUSH1",
        /* 0x61 */ "PUSH2",
        /* 0x62 */ "PUSH3",
        /* 0x63 */ "PUSH4",
        /* 0x64 */ "PUSH5",
        /* 0x65 */ "PUSH6",
        /* 0x66 */ "PUSH7",
        /* 0x67 */ "PUSH8",
        /* 0x68 */ "PUSH9",
        /* 0x69 */ "PUSH10",
        /* 0x6a */ "PUSH11",
        /* 0x6b */ "PUSH12",
        /* 0x6c */ "PUSH13",
        /* 0x6d */ "PUSH14",
        /* 0x6e */ "PUSH15",
        /* 0x6f */ "PUSH16",
        /* 0x70 */ "PUSH17",
        /* 0x71 */ "PUSH18",
        /* 0x72 */ "PUSH19",
        /* 0x73 */ "PUSH20",
        /* 0x74 */ "PUSH21",
        /* 0x75 */ "PUSH22",
        /* 0x76 */ "PUSH23",
        /* 0x77 */ "PUSH24",
        /* 0x78 */ "PUSH25",
        /* 0x79 */ "PUSH26",
        /* 0x7a */ "PUSH27",
        /* 0x7b */ "PUSH28",
        /* 0x7c */ "PUSH29",
        /* 0x7d */ "PUSH30",
        /* 0x7e */ "PUSH31",
        /* 0x7f */ "PUSH32",
        /* 0x80 */ "DUP1",
        /* 0x81 */ "DUP2",
        /* 0x82 */ "DUP3",
        /* 0x83 */ "DUP4",
        /* 0x84 */ "DUP5",
        /* 0x85 */ "DUP6",
        /* 0x86 */ "DUP7",
        /* 0x87 */ "DUP8",
        /* 0x88 */ "DUP9",
        /* 0x89 */ "DUP10",
        /* 0x8a */ "DUP11",
        /* 0x8b */ "DUP12",
        /* 0x8c */ "DUP13",
        /* 0x8d */ "DUP14",
        /* 0x8e */ "DUP15",
        /* 0x8f */ "DUP16",
        /* 0x90 */ "SWAP1",
        /* 0x91 */ "SWAP2",
        /* 0x92 */ "SWAP3",
        /* 0x93 */ "SWAP4",
        /* 0x94 */ "SWAP5",
        /* 0x95 */ "SWAP6",
        /* 0x96 */ "SWAP7",
        /* 0x97 */ "SWAP8",
        /* 0x98 */ "SWAP9",
        /* 0x99 */ "SWAP10",
        /* 0x9a */ "SWAP11",
        /* 0x9b */ "SWAP12",
        /* 0x9c */ "SWAP13",
        /* 0x9d */ "SWAP14",
        /* 0x9e */ "SWAP15",
        /* 0x9f */ "SWAP16",
        /* 0xa0 */ "LOG0",
        /* 0xa1 */ "LOG1",
        /* 0xa2 */ "LOG2",
        /* 0xa3 */ "LOG3",
        /* 0xa4 */ "LOG4",
        /* 0xa5 */ NULL,
        /* 0xa6 */ NULL,
        /* 0xa7 */ NULL,
        /* 0xa8 */ NULL,
        /* 0xa9 */ NULL,
        /* 0xaa */ NULL,
        /* 0xab */ NULL,
        /* 0xac */ NULL,
        /* 0xad */ NULL,
        /* 0xae */ NULL,
        /* 0xaf */ NULL,
        /* 0xb0 */ NULL,
        /* 0xb1 */ NULL,
        /* 0xb2 */ NULL,
        /* 0xb3 */ NULL,
        /* 0xb4 */ NULL,
        /* 0xb5 */ NULL,
        /* 0xb6 */ NULL,
        /* 0xb7 */ NULL,
        /* 0xb8 */ NULL,
        /* 0xb9 */ NULL,
        /* 0xba */ NULL,
        /* 0xbb */ NULL,
        /* 0xbc */ NULL,
        /* 0xbd */ NULL,
        /* 0xbe */ NULL,
        /* 0xbf */ NULL,
        /* 0xc0 */ NULL,
        /* 0xc1 */ NULL,
        /* 0xc2 */ NULL,
        /* 0xc3 */ NULL,
        /* 0xc4 */ NULL,
        /* 0xc5 */ NULL,
        /* 0xc6 */ NULL,
        /* 0xc7 */ NULL,
        /* 0xc8 */ NULL,
        /* 0xc9 */ NULL,
        /* 0xca */ NULL,
        /* 0xcb */ NULL,
        /* 0xcc */ NULL,
        /* 0xcd */ NULL,
        /* 0xce */ NULL,
        /* 0xcf */ NULL,
        /* 0xd0 */ NULL,
        /* 0xd1 */ NULL,
        /* 0xd2 */ NULL,
        /* 0xd3 */ NULL,
        /* 0xd4 */ NULL,
        /* 0xd5 */ NULL,
        /* 0xd6 */ NULL,
        /* 0xd7 */ NULL,
        /* 0xd8 */ NULL,
        /* 0xd9 */ NULL,
        /* 0xda */ NULL,
        /* 0xdb */ NULL,
        /* 0xdc */ NULL,
        /* 0xdd */ NULL,
        /* 0xde */ NULL,
        /* 0xdf */ NULL,
        /* 0xe0 */ NULL,
        /* 0xe1 */ NULL,
        /* 0xe2 */ NULL,
        /* 0xe3 */ NULL,
        /* 0xe4 */ NULL,
        /* 0xe5 */ NULL,
        /* 0xe6 */ NULL,
        /* 0xe7 */ NULL,
        /* 0xe8 */ NULL,
        /* 0xe9 */ NULL,
        /* 0xea */ NULL,
        /* 0xeb */ NULL,
        /* 0xec */ NULL,
        /* 0xed */ NULL,
        /* 0xee */ NULL,
        /* 0xef */ NULL,
        /* 0xf0 */ "CREATE",
        /* 0xf1 */ "CALL",
        /* 0xf2 */ "CALLCODE",
        /* 0xf3 */ "RETURN",
        /* 0xf4 */ "DELEGATECALL",
        /* 0xf5 */ "CREATE2",
        /* 0xf6 */ NULL,
        /* 0xf7 */ NULL,
        /* 0xf8 */ NULL,
        /* 0xf9 */ NULL,
        /* 0xfa */ "STATICCALL",
        /* 0xfb */ NULL,
        /* 0xfc */ NULL,
        /* 0xfd */ "REVERT",
        /* 0xfe */ "INVALID",
        /* 0xff */ "SELFDESTRUCT",
    };
    std::string get_opcode_name(const char* const* names, std::uint8_t opcode) {
        const auto name = names[opcode];
        return (name != nullptr) ? name : "opcode 0x" + evmc::hex(opcode) + " not defined";
    }
    void on_execution_start(evmc_revision /*rev*/, const evmc_message& /*msg*/, evmone::bytes_view /*bytecode*/) noexcept override {}
    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height,
                              const evmone::ExecutionState& state,
                              const IntraBlockState& /*intra_block_state*/) noexcept override {
        // "\"pc\":",      ctx->get_pc(), ",",
        // "\"gasLeft\":", ctx->gas_left > 0 ? intx::to_string(ctx->gas_left) : 0, ",",
        // "\"opFees\":", std::to_string(OpFees::by_code[op]), ",",
        // "\"stack\":",   ctx->s.as_array(), ",",
        // "\"depth\":",   std::to_string(get_call_depth() - 1), ",",
        // "\"opName\": \"",  opcodeToString(op), "\",",
        // "\"sm\": ",  transaction.state_modifications.size(),
        const auto opcode = state.original_code[pc];
        const auto opcode_name = get_opcode_name(istanbul_names, opcode);
        const auto stack_content = std::vector<intx::uint256>(stack_top - stack_height + 1,stack_top + 1);
        std::cout<<"{\"pc\":"<<pc<<",\"gasLeft\":"<<state.gas_left<<",\"depth\":"<<std::dec<<state.msg->depth<<",\"opName\":"<<opcode_name<<",\"stack\":[";
        for (auto elem: stack_content) {
            std::cout<<"\""<<intx::hex(elem)<<"\",";
        }
        std::cout<<"]}"<<std::endl;
    }
    void on_execution_end(const evmc_result& /*res*/, const IntraBlockState& /*intra_block_state*/) noexcept override {}

    void on_creation_completed(const evmc_result& /*result*/, const IntraBlockState& /*intra_block_state*/) noexcept override {}

    void on_precompiled_run(const evmc_result& /*result*/, int64_t /*gas*/,
                            const IntraBlockState& /*intra_block_state*/) noexcept override {}
    void on_reward_granted(const CallResult& /*result*/,
                           const IntraBlockState& /*intra_block_state*/) noexcept override {}
};

ExecutionProcessor::ExecutionProcessor(const Block& block, consensus::IEngine& consensus_engine, State& state,
                                       const ChainConfig& config)
    : state_{state}, consensus_engine_{consensus_engine}, evm_{block, state_, config} {
    evm_.beneficiary = consensus_engine.get_beneficiary(block.header);
}

ValidationResult ExecutionProcessor::validate_transaction(const Transaction& txn) const noexcept {
    assert(consensus::pre_validate_transaction(txn, evm_.block().header.number, evm_.config(),
                                               evm_.block().header.base_fee_per_gas) == ValidationResult::kOk);
    if (!txn.from.has_value()) {
        return ValidationResult::kMissingSender;
    }

    if (state_.get_code_hash(*txn.from) != kEmptyHash) {
        return ValidationResult::kSenderNoEOA;  // EIP-3607
    }

    const uint64_t nonce{state_.get_nonce(*txn.from)};
    if (nonce != txn.nonce && !(nonce == 0 && txn.nonce == 1) && !(txn.nonce == 0)) {
        std::cout<<to_hex(txn.from.value().bytes)<<" "<<txn.nonce<<" "<<nonce<<std::endl;
        return ValidationResult::kWrongNonce;
    }

    // https://github.com/ethereum/EIPs/pull/3594
    intx::uint256 charged_gas_price = txn.max_fee_per_gas;
    if (evm().block().header.number < 255838760) {
        if (txn.max_fee_per_gas > 499809179185) {
            charged_gas_price = intx::uint256{499809179185};
        }
    } else if (evm().block().header.number < 256919102) {
        if (txn.max_fee_per_gas > 503604564858) {
            charged_gas_price = intx::uint256{503604564858};
        }
    } else if (evm().block().header.number < 258567748) {
        if (txn.max_fee_per_gas > 503624212149) {
            charged_gas_price = intx::uint256{503624212149};
        }
    } else if (evm().block().header.number < 260508029) {
        if (txn.max_fee_per_gas > 503659916170) {
            charged_gas_price = intx::uint256{503659916170};
        }
    } else if (evm().block().header.number < 261916623) {
        if (txn.max_fee_per_gas > 503692840132) {
            charged_gas_price = intx::uint256{503692840132};
        }
    } else if (evm().block().header.number < 263258684) {
        if (txn.max_fee_per_gas > 503730067379) {
            charged_gas_price = intx::uint256{503730067379};
        }
    } else if (evm().block().header.number < 265110408) {
        if (txn.max_fee_per_gas > 503766558895) {
            charged_gas_price = intx::uint256{503766558895};
        }
    } else if (evm().block().header.number < 266854672) {
        if (txn.max_fee_per_gas > 503847329123) {
            charged_gas_price = intx::uint256{503847329123};
        }
    } else if (evm().block().header.number < 271693305) {
        if (txn.max_fee_per_gas > 503937085418) {
            charged_gas_price = intx::uint256{503937085418};
        }
    } else if (evm().block().header.number < 277570654) {
        if (txn.max_fee_per_gas > 504169102143) {
            charged_gas_price = intx::uint256{504169102143};
        }
    } else if (evm().block().header.number < 281052225) {
        if (txn.max_fee_per_gas > 504588007093) {
            charged_gas_price = intx::uint256{504588007093};
        }
    } else if (evm().block().header.number < 282427274) {
        if (txn.max_fee_per_gas > 504730060459) {
            charged_gas_price = intx::uint256{504730060459};
        }
    } else if (evm().block().header.number < 286905983) {
        if (txn.max_fee_per_gas > 504777487548) {
            charged_gas_price = intx::uint256{504777487548};
        }
    } else if (evm().block().header.number < 290533301) {
        if (txn.max_fee_per_gas > 504901632992) {
            charged_gas_price = intx::uint256{504901632992};
        }
    } else if (evm().block().header.number < 296069390) {
        if (txn.max_fee_per_gas > 505018605664) {
            charged_gas_price = intx::uint256{505018605664};
        }
    } else if (evm().block().header.number < 300562146) {
        if (txn.max_fee_per_gas > 505225116066) {
            charged_gas_price = intx::uint256{505225116066};
        }
    } else if (evm().block().header.number < 307967043) {
        if (txn.max_fee_per_gas > 505764887222) {
            charged_gas_price = intx::uint256{505764887222};
        }
    } else if (evm().block().header.number < 309157097) {
        if (txn.max_fee_per_gas > 507293569984) {
            charged_gas_price = intx::uint256{507293569984};
        }
    } else if (evm().block().header.number < 312517437) {
        if (txn.max_fee_per_gas > 507611802460) {
            charged_gas_price = intx::uint256{507611802460};
        }
    } else if (evm().block().header.number < 314907931) {
        if (txn.max_fee_per_gas > 508508333703) {
            charged_gas_price = intx::uint256{508508333703};
        }
    } else if (evm().block().header.number < 319569825) {
        if (txn.max_fee_per_gas > 509215569036) {
            charged_gas_price = intx::uint256{509215569036};
        }
    } else if (evm().block().header.number < 323391709) {
        if (txn.max_fee_per_gas > 510837337450) {
            charged_gas_price = intx::uint256{510837337450};
        }
    } else if (evm().block().header.number < 324360809) {
        if (txn.max_fee_per_gas > 511832996910) {
            charged_gas_price = intx::uint256{511832996910};
        }
    } else if (evm().block().header.number < 324398028) {
        if (txn.max_fee_per_gas > 512009459358) {
            charged_gas_price = intx::uint256{512009459358};
        }
    } else if (evm().block().header.number < 325597355) {
        if (txn.max_fee_per_gas > 512023715983) {
            charged_gas_price = intx::uint256{512023715983};
        }
    } else if (evm().block().header.number < 329239018) {
        if (txn.max_fee_per_gas > 512509489520) {
            charged_gas_price = intx::uint256{512509489520};
        }
    } else if (evm().block().header.number < 329714374) {
        if (txn.max_fee_per_gas > 513753813459) {
            charged_gas_price = intx::uint256{513753813459};
        }
    } else if (evm().block().header.number < 332358496) {
        if (txn.max_fee_per_gas > 513889289168) {
            charged_gas_price = intx::uint256{513889289168};
        }
    } else if (evm().block().header.number < 334211846) {
        if (txn.max_fee_per_gas > 514927973622) {
            charged_gas_price = intx::uint256{514927973622};
        }
    } else if (evm().block().header.number < 338022602) {
        if (txn.max_fee_per_gas > 515474978733) {
            charged_gas_price = intx::uint256{515474978733};
        }
    } else if (evm().block().header.number < 339221402) {
        if (txn.max_fee_per_gas > 516125417219) {
            charged_gas_price = intx::uint256{516125417219};
        }
    } else if (evm().block().header.number < 344908827) {
        if (txn.max_fee_per_gas > 516282803626) {
            charged_gas_price = intx::uint256{516282803626};
        }
    } else {
        if (txn.max_fee_per_gas > 516900477336) {
            charged_gas_price = intx::uint256{516900477336};
        }
    }
    const intx::uint512 max_gas_cost{intx::umul(intx::uint256{txn.gas_limit}, charged_gas_price)};
    // See YP, Eq (57) in Section 6.2 "Execution"
    const intx::uint512 v0{max_gas_cost + txn.value};
    std::cout<<to_hex(*txn.from)<<" "<<to_hex(*txn.to)<<" "<<intx::hex((state_.get_balance(*txn.from)))<<" "<<intx::hex((state_.get_balance(*txn.to)))<<" "<<intx::hex((state_.get_balance(0x0000000000000000000000000000000000000000_address)))<<" "<<intx::hex(v0)<<" "<<intx::hex(max_gas_cost)<<" "<<intx::hex(txn.value)<<std::endl;
    if (state_.get_balance(*txn.from) < v0 && *txn.from != 0x0000000000000000000000000000000000000000_address) {
        return ValidationResult::kInsufficientFunds;
    }

    if (available_gas() < txn.gas_limit) {
        // Corresponds to the final condition of Eq (58) in Yellow Paper Section 6.2 "Execution".
        // The sum of the transaction’s gas limit and the gas utilized in this block prior
        // must be no greater than the block’s gas limit.
        return ValidationResult::kBlockGasLimitExceeded;
    }

    return ValidationResult::kOk;
}

void ExecutionProcessor::execute_transaction(const Transaction& txn, Receipt& receipt) noexcept {
    assert(validate_transaction(txn) == ValidationResult::kOk);

    // Optimization: since receipt.logs might have some capacity, let's reuse it.
    std::swap(receipt.logs, state_.logs());

    state_.clear_journal_and_substate();

    assert(txn.from.has_value());
    state_.access_account(*txn.from);

    if (txn.to.has_value()) {
        state_.access_account(*txn.to);
        // EVM itself increments the nonce for contract creation
        if (!(*txn.from == 0x0000000000000000000000000000000000000000_address || (*txn.to == 0x0000000000000000000000000000000000000000_address && txn.v() == intx::uint256{42}))) {
            state_.set_nonce(*txn.from, txn.nonce + 1);
        }
    }

    for (const AccessListEntry& ae : txn.access_list) {
        state_.access_account(ae.account);
        for (const evmc::bytes32& key : ae.storage_keys) {
            state_.access_storage(ae.account, key);
        }
    }

    const evmc_revision rev{evm_.revision()};
    if (rev >= EVMC_SHANGHAI) {
        // EIP-3651: Warm COINBASE
        state_.access_account(evm_.beneficiary);
    }

    const intx::uint256 base_fee_per_gas{evm_.block().header.base_fee_per_gas.value_or(0)};
    const intx::uint256 effective_gas_price{txn.effective_gas_price(base_fee_per_gas,evm_.block().header.number)};
    if (*txn.from != 0x0000000000000000000000000000000000000000_address) {
        state_.subtract_from_balance(*txn.from, txn.gas_limit * effective_gas_price);
    }

    const intx::uint128 g0{intrinsic_gas(txn, rev)};
    assert(g0 <= UINT64_MAX);  // true due to the precondition (transaction must be valid)
    if (evm_.block().header.number == 228256621) {
        MyTracer tracer1;
        evm_.add_tracer(tracer1);
    }
    const CallResult vm_res{evm_.execute(txn, txn.gas_limit - static_cast<uint64_t>(g0))};
    const uint64_t gas_used{txn.gas_limit - refund_gas(txn, vm_res.gas_left, vm_res.gas_refund)};
    // std::cout<<vm_res.gas_left<<" "<<vm_res.gas_refund<<" "<<vm_res.status<<std::endl;
    // refund_gas(txn, vm_res.gas_left, vm_res.gas_refund);

    // award the fee recipient
    const intx::uint256 priority_fee_per_gas{txn.priority_fee_per_gas(base_fee_per_gas)};
    // state_.add_to_balance(evm_.beneficiary, priority_fee_per_gas * gas_used);

    state_.destruct_suicides();
    if (rev >= EVMC_SPURIOUS_DRAGON) {
        state_.destruct_touched_dead();
    }

    state_.finalize_transaction();

    cumulative_gas_used_ += gas_used;

    receipt.type = txn.type;
    receipt.success = vm_res.status == EVMC_SUCCESS;
    receipt.cumulative_gas_used = cumulative_gas_used_;
    receipt.bloom = logs_bloom(state_.logs());
    std::swap(receipt.logs, state_.logs());
}

uint64_t ExecutionProcessor::available_gas() const noexcept {
    return evm_.block().header.gas_limit - cumulative_gas_used_;
}

uint64_t ExecutionProcessor::refund_gas(const Transaction& txn, uint64_t gas_left, uint64_t gas_refund) noexcept {
    const evmc_revision rev{evm_.revision()};

    const uint64_t max_refund_quotient{rev >= EVMC_LONDON ? param::kMaxRefundQuotientLondon
                                                          : param::kMaxRefundQuotientFrontier};
    const uint64_t max_refund{(txn.gas_limit - gas_left) / max_refund_quotient};
    uint64_t refund = std::min(gas_refund, max_refund);
    gas_left += refund;

    const intx::uint256 base_fee_per_gas{evm_.block().header.base_fee_per_gas.value_or(0)};
    const intx::uint256 effective_gas_price{txn.effective_gas_price(base_fee_per_gas,evm().block().header.number)};
    if (*txn.from != 0x0000000000000000000000000000000000000000_address) {
        state_.add_to_balance(*txn.from, gas_left * effective_gas_price);
    }
    return gas_left;
}

ValidationResult ExecutionProcessor::execute_block_no_post_validation(std::vector<Receipt>& receipts) noexcept {
    const Block& block{evm_.block()};

    if (block.header.number == evm_.config().dao_block) {
        dao::transfer_balances(state_);
    }

    cumulative_gas_used_ = 0;

    receipts.resize(block.transactions.size());
    auto receipt_it{receipts.begin()};
    for (const auto& txn : block.transactions) {
        const ValidationResult err{validate_transaction(txn)};
        if (err != ValidationResult::kOk) {
            return err;
        }
        execute_transaction(txn, *receipt_it);
        ++receipt_it;
    }

    consensus_engine_.finalize(state_, block, evm_.revision());

    return ValidationResult::kOk;
}

ValidationResult ExecutionProcessor::execute_and_write_block(std::vector<Receipt>& receipts) noexcept {
    if (const ValidationResult res{execute_block_no_post_validation(receipts)}; res != ValidationResult::kOk) {
        return res;
    }

    const auto& header{evm_.block().header};

    if (cumulative_gas_used() != header.gas_used) {
        std::cout<<cumulative_gas_used()<<" "<<header.gas_used<<" "<<header.gas_limit<<std::endl;
        return ValidationResult::kWrongBlockGas;
    }

    if (evm_.revision() >= EVMC_BYZANTIUM) {
        static constexpr auto kEncoder = [](Bytes& to, const Receipt& r) { rlp::encode(to, r); };
        evmc::bytes32 receipt_root{trie::root_hash(receipts, kEncoder)};
        if (receipt_root != header.receipts_root) {
            return ValidationResult::kWrongReceiptsRoot;
        }
    }

    Bloom bloom{};  // zero initialization
    for (const Receipt& receipt : receipts) {
        join(bloom, receipt.bloom);
    }
    if (bloom != header.logs_bloom) {
        return ValidationResult::kWrongLogsBloom;
    }

    state_.write_to_db(header.number);

    return ValidationResult::kOk;
}

}  // namespace silkworm
