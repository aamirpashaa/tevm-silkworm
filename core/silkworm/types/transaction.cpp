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

#include "transaction.hpp"

#include <cassert>
#include <cstring>

#include <ethash/keccak.hpp>
#include <silkpre/ecdsa.h>

#include <silkworm/common/util.hpp>
#include <silkworm/rlp/encode_vector.hpp>

#include "y_parity_and_chain_id.hpp"

namespace silkworm {

bool operator==(const Transaction& a, const Transaction& b) {
    // from is omitted since it's derived from the signature
    return a.type == b.type && a.nonce == b.nonce && a.max_priority_fee_per_gas == b.max_priority_fee_per_gas &&
           a.max_fee_per_gas == b.max_fee_per_gas && a.gas_limit == b.gas_limit && a.to == b.to && a.value == b.value &&
           a.data == b.data && a.odd_y_parity == b.odd_y_parity && a.chain_id == b.chain_id && a.r == b.r &&
           a.s == b.s && a.access_list == b.access_list;
}

// https://eips.ethereum.org/EIPS/eip-155
intx::uint256 Transaction::v() const { return y_parity_and_chain_id_to_v(odd_y_parity, chain_id); }

// https://eips.ethereum.org/EIPS/eip-155
bool Transaction::set_v(const intx::uint256& v) {
    const std::optional<YParityAndChainId> parity_and_id{v_to_y_parity_and_chain_id(v)};
    if (parity_and_id == std::nullopt) {
        return false;
    }
    odd_y_parity = parity_and_id->odd;
    chain_id = parity_and_id->chain_id;
    return true;
}

namespace rlp {

    static Header rlp_header(const AccessListEntry& e) {
        Header h{true, kAddressLength + 1};
        h.payload_length += length(e.storage_keys);
        return h;
    }

    size_t length(const AccessListEntry& e) {
        Header rlp_head{rlp_header(e)};
        return length_of_length(rlp_head.payload_length) + rlp_head.payload_length;
    }

    void encode(Bytes& to, const AccessListEntry& e) {
        encode_header(to, rlp_header(e));
        encode(to, e.account.bytes);
        encode(to, e.storage_keys);
    }

    template <>
    DecodingResult decode(ByteView& from, AccessListEntry& to) noexcept {
        auto [rlp_head, err0]{decode_header(from)};
        if (err0 != DecodingResult::kOk) {
            return err0;
        }
        if (!rlp_head.list) {
            return DecodingResult::kUnexpectedString;
        }
        uint64_t leftover{from.length() - rlp_head.payload_length};

        if (DecodingResult err{decode(from, to.account.bytes)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.storage_keys)}; err != DecodingResult::kOk) {
            return err;
        }

        return from.length() == leftover ? DecodingResult::kOk : DecodingResult::kListLengthMismatch;
    }

    static Header rlp_header(const Transaction& txn, bool for_signing) {
        Header h{true, 0};

        if (txn.type != Transaction::Type::kLegacy) {
            h.payload_length += length(txn.chain_id.value_or(0));
        }

        h.payload_length += length(txn.nonce);
        if (txn.type == Transaction::Type::kEip1559) {
            h.payload_length += length(txn.max_priority_fee_per_gas);
        }
        h.payload_length += length(txn.max_fee_per_gas);
        h.payload_length += length(txn.gas_limit);
        h.payload_length += txn.to ? (kAddressLength + 1) : 1;
        h.payload_length += length(txn.value);
        h.payload_length += length(txn.data);

        if (txn.type != Transaction::Type::kLegacy) {
            assert(txn.type == Transaction::Type::kEip2930 || txn.type == Transaction::Type::kEip1559);
            h.payload_length += length(txn.access_list);
        }

        if (!for_signing) {
            if (txn.type != Transaction::Type::kLegacy) {
                h.payload_length += length(txn.odd_y_parity);
            } else {
                h.payload_length += length(txn.v());
            }
            h.payload_length += length(txn.r);
            h.payload_length += length(txn.s);
        } else if (txn.type == Transaction::Type::kLegacy && txn.chain_id) {
            h.payload_length += length(*txn.chain_id) + 2;
        }

        return h;
    }

    size_t length(const Transaction& txn) {
        Header rlp_head{rlp_header(txn, /*for_signing=*/false)};
        auto rlp_len{static_cast<size_t>(length_of_length(rlp_head.payload_length) + rlp_head.payload_length)};
        if (txn.type != Transaction::Type::kLegacy) {
            // EIP-2718 transactions are wrapped into byte array in block RLP
            return length_of_length(rlp_len + 1) + rlp_len + 1;
        } else {
            return rlp_len;
        }
    }

    static void legacy_encode(Bytes& to, const Transaction& txn, bool for_signing) {
        encode_header(to, rlp_header(txn, for_signing));

        encode(to, txn.nonce);
        encode(to, txn.max_fee_per_gas);
        encode(to, txn.gas_limit);
        if (txn.to) {
            encode(to, txn.to->bytes);
        } else {
            to.push_back(kEmptyStringCode);
        }
        encode(to, txn.value);
        encode(to, txn.data);

        if (!for_signing) {
            encode(to, txn.v());
            encode(to, txn.r);
            encode(to, txn.s);
        } else if (txn.chain_id) {
            encode(to, *txn.chain_id);
            encode(to, 0u);
            encode(to, 0u);
        }
    }

    static void eip2718_encode(Bytes& to, const Transaction& txn, bool for_signing, bool wrap_into_array) {
        assert(txn.type == Transaction::Type::kEip2930 || txn.type == Transaction::Type::kEip1559);

        Header rlp_head{rlp_header(txn, for_signing)};

        if (wrap_into_array) {
            auto rlp_len{static_cast<size_t>(length_of_length(rlp_head.payload_length) + rlp_head.payload_length)};
            encode_header(to, {false, rlp_len + 1});
        }

        to.push_back(static_cast<uint8_t>(txn.type));

        encode_header(to, rlp_head);

        encode(to, txn.chain_id.value_or(0));

        encode(to, txn.nonce);
        if (txn.type == Transaction::Type::kEip1559) {
            encode(to, txn.max_priority_fee_per_gas);
        }
        encode(to, txn.max_fee_per_gas);
        encode(to, txn.gas_limit);
        if (txn.to) {
            encode(to, txn.to->bytes);
        } else {
            to.push_back(kEmptyStringCode);
        }
        encode(to, txn.value);
        encode(to, txn.data);
        encode(to, txn.access_list);

        if (!for_signing) {
            encode(to, txn.odd_y_parity);
            encode(to, txn.r);
            encode(to, txn.s);
        }
    }

    void encode(Bytes& to, const Transaction& txn, bool for_signing, bool wrap_eip2718_into_string) {
        if (txn.type == Transaction::Type::kLegacy) {
            legacy_encode(to, txn, for_signing);
        } else {
            eip2718_encode(to, txn, for_signing, wrap_eip2718_into_string);
        }
    }

    static DecodingResult legacy_decode(ByteView& from, Transaction& to) noexcept {
        if (DecodingResult err{decode(from, to.nonce)}; err != DecodingResult::kOk) {
            return err;
        }

        if (DecodingResult err{decode(from, to.max_priority_fee_per_gas)}; err != DecodingResult::kOk) {
            return err;
        }
        to.max_fee_per_gas = to.max_priority_fee_per_gas;

        if (DecodingResult err{decode(from, to.gas_limit)}; err != DecodingResult::kOk) {
            return err;
        }

        if (from[0] == kEmptyStringCode) {
            to.to = std::nullopt;
            from.remove_prefix(1);
        } else {
            to.to = evmc::address{};
            if (DecodingResult err{decode(from, to.to->bytes)}; err != DecodingResult::kOk) {
                return err;
            }
        }

        if (DecodingResult err{decode(from, to.value)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.data)}; err != DecodingResult::kOk) {
            return err;
        }

        intx::uint256 v;
        if (DecodingResult err{decode(from, v)}; err != DecodingResult::kOk) {
            return err;
        }
        if (!to.set_v(v)) {
            return DecodingResult::kInvalidVInSignature;
        }

        if (DecodingResult err{decode(from, to.r)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.s)}; err != DecodingResult::kOk) {
            return err;
        }

        to.access_list.clear();

        return DecodingResult::kOk;
    }

    static DecodingResult eip2718_decode(ByteView& from, Transaction& to) noexcept {
        if (to.type != Transaction::Type::kEip2930 && to.type != Transaction::Type::kEip1559) {
            return DecodingResult::kUnsupportedTransactionType;
        }

        auto [h, err0]{decode_header(from)};
        if (err0 != DecodingResult::kOk) {
            return err0;
        }
        if (!h.list) {
            return DecodingResult::kUnexpectedString;
        }

        intx::uint256 chain_id;
        if (DecodingResult err{decode(from, chain_id)}; err != DecodingResult::kOk) {
            return err;
        }
        to.chain_id = chain_id;

        if (DecodingResult err{decode(from, to.nonce)}; err != DecodingResult::kOk) {
            return err;
        }

        if (DecodingResult err{decode(from, to.max_priority_fee_per_gas)}; err != DecodingResult::kOk) {
            return err;
        }
        if (to.type == Transaction::Type::kEip2930) {
            to.max_fee_per_gas = to.max_priority_fee_per_gas;
        } else if (DecodingResult err{decode(from, to.max_fee_per_gas)}; err != DecodingResult::kOk) {
            return err;
        }

        if (DecodingResult err{decode(from, to.gas_limit)}; err != DecodingResult::kOk) {
            return err;
        }

        if (from[0] == kEmptyStringCode) {
            to.to = std::nullopt;
            from.remove_prefix(1);
        } else {
            to.to = evmc::address{};
            if (DecodingResult err{decode(from, to.to->bytes)}; err != DecodingResult::kOk) {
                return err;
            }
        }

        if (DecodingResult err{decode(from, to.value)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.data)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.access_list)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.odd_y_parity)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.r)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.s)}; err != DecodingResult::kOk) {
            return err;
        }

        return DecodingResult::kOk;
    }

    DecodingResult decode_transaction(ByteView& from, Transaction& to, Eip2718Wrapping allowed) noexcept {
        to.from.reset();

        if (from.empty()) {
            return DecodingResult::kInputTooShort;
        }

        if (0 < from[0] && from[0] < kEmptyStringCode) {  // Raw serialization of a typed transaction
            if (allowed == Eip2718Wrapping::kString) {
                return DecodingResult::kUnexpectedEip2718Serialization;
            }

            to.type = static_cast<Transaction::Type>(from[0]);
            from.remove_prefix(1);

            return eip2718_decode(from, to);
        }

        auto [h, err0]{decode_header(from)};
        if (err0 != DecodingResult::kOk) {
            return err0;
        }

        if (h.list) {  // Legacy transaction
            to.type = Transaction::Type::kLegacy;
            uint64_t leftover{from.length() - h.payload_length};
            if (DecodingResult err{legacy_decode(from, to)}; err != DecodingResult::kOk) {
                return err;
            }
            return from.length() == leftover ? DecodingResult::kOk : DecodingResult::kListLengthMismatch;
        }

        // String-wrapped typed transaction

        if (allowed == Eip2718Wrapping::kNone) {
            return DecodingResult::kUnexpectedEip2718Serialization;
        }

        if (h.payload_length == 0) {
            return DecodingResult::kInputTooShort;
        }

        to.type = static_cast<Transaction::Type>(from[0]);
        from.remove_prefix(1);

        ByteView eip2718_view{from.substr(0, h.payload_length - 1)};

        if (DecodingResult err{eip2718_decode(eip2718_view, to)}; err != DecodingResult::kOk) {
            return err;
        }

        if (!eip2718_view.empty()) {
            return DecodingResult::kListLengthMismatch;
        }

        from.remove_prefix(h.payload_length - 1);
        return DecodingResult::kOk;
    }

}  // namespace rlp

void Transaction::recover_sender() {
    if (from.has_value()) {
        return;
    }
    Bytes rlp{};
    rlp::encode(rlp, *this, /*for_signing=*/true, /*wrap_eip2718_into_string=*/false);
    ethash::hash256 hash{keccak256(rlp)};

    uint8_t signature[kHashLength * 2];
    intx::be::unsafe::store(signature, r);
    intx::be::unsafe::store(signature + kHashLength, s);

    from = evmc::address{};
    static secp256k1_context* context{secp256k1_context_create(SILKPRE_SECP256K1_CONTEXT_FLAGS)};
    if (v() != intx::uint256{42}) {
        if (!silkpre_recover_address(from->bytes, hash.bytes, signature, odd_y_parity, context)) {
            from = std::nullopt;
        }
    } else {
        auto s_hex = intx::hex(s);
        auto number_of_zeros = 64 - s_hex.length();
        s_hex.insert(0, number_of_zeros, '0');
        from = to_evmc_address(*from_hex(s_hex.substr(0,40)));
        // from = std::nullopt;
    }
}

intx::uint256 Transaction::priority_fee_per_gas(const intx::uint256& base_fee_per_gas) const {
    assert(max_fee_per_gas >= base_fee_per_gas);
    return std::min(max_priority_fee_per_gas, max_fee_per_gas - base_fee_per_gas);
}

intx::uint256 Transaction::effective_gas_price(const intx::uint256& base_fee_per_gas, const uint64_t block_number) const {
    intx::uint256 charged_gas_price = priority_fee_per_gas(base_fee_per_gas) + base_fee_per_gas; 
    if (block_number < 255838760) {
        if (charged_gas_price > 499809179185) {
            charged_gas_price = intx::uint256{499809179185};
        }
    } else if (block_number < 256919102) {
        if (charged_gas_price > 503604564858) {
            charged_gas_price = intx::uint256{503604564858};
        }
    } else if (block_number < 258567748) {
        if (charged_gas_price > 503624212149) {
            charged_gas_price = intx::uint256{503624212149};
        }
    } else if (block_number < 260508029) {
        if (charged_gas_price > 503659916170) {
            charged_gas_price = intx::uint256{503659916170};
        }
    } else if (block_number < 261916623) {
        if (charged_gas_price > 503692840132) {
            charged_gas_price = intx::uint256{503692840132};
        }
    } else if (block_number < 263258684) {
        if (charged_gas_price > 503730067379) {
            charged_gas_price = intx::uint256{503730067379};
        }
    } else if (block_number < 265110408) {
        if (charged_gas_price > 503766558895) {
            charged_gas_price = intx::uint256{503766558895};
        }
    } else if (block_number < 266854672) {
        if (charged_gas_price > 503847329123) {
            charged_gas_price = intx::uint256{503847329123};
        }
    } else if (block_number < 271693305) {
        if (charged_gas_price > 503937085418) {
            charged_gas_price = intx::uint256{503937085418};
        }
    } else if (block_number < 277570654) {
        if (charged_gas_price > 504169102143) {
            charged_gas_price = intx::uint256{504169102143};
        }
    } else if (block_number < 281052225) {
        if (charged_gas_price > 504588007093) {
            charged_gas_price = intx::uint256{504588007093};
        }
    } else if (block_number < 282427274) {
        if (charged_gas_price > 504730060459) {
            charged_gas_price = intx::uint256{504730060459};
        }
    } else if (block_number < 286905983) {
        if (charged_gas_price > 504777487548) {
            charged_gas_price = intx::uint256{504777487548};
        }
    } else if (block_number < 290533301) {
        if (charged_gas_price > 504901632992) {
            charged_gas_price = intx::uint256{504901632992};
        }
    } else if (block_number < 296069390) {
        if (charged_gas_price > 505018605664) {
            charged_gas_price = intx::uint256{505018605664};
        }
    } else if (block_number < 300562146) {
        if (charged_gas_price > 505225116066) {
            charged_gas_price = intx::uint256{505225116066};
        }
    } else if (block_number < 307967043) {
        if (charged_gas_price > 505764887222) {
            charged_gas_price = intx::uint256{505764887222};
        }
    } else if (block_number < 309157097) {
        if (charged_gas_price > 507293569984) {
            charged_gas_price = intx::uint256{507293569984};
        }
    } else if (block_number < 312517437) {
        if (charged_gas_price > 507611802460) {
            charged_gas_price = intx::uint256{507611802460};
        }
    } else if (block_number < 314907931) {
        if (charged_gas_price > 508508333703) {
            charged_gas_price = intx::uint256{508508333703};
        }
    } else if (block_number < 319569825) {
        if (charged_gas_price > 509215569036) {
            charged_gas_price = intx::uint256{509215569036};
        }
    } else if (block_number < 323391709) {
        if (charged_gas_price > 510837337450) {
            charged_gas_price = intx::uint256{510837337450};
        }
    } else if (block_number < 324360809) {
        if (charged_gas_price > 511832996910) {
            charged_gas_price = intx::uint256{511832996910};
        }
    } else if (block_number < 324398028) {
        if (charged_gas_price > 512009459358) {
            charged_gas_price = intx::uint256{512009459358};
        }
    } else if (block_number < 325597355) {
        if (charged_gas_price > 512023715983) {
            charged_gas_price = intx::uint256{512023715983};
        }
    } else if (block_number < 329239018) {
        if (charged_gas_price > 512509489520) {
            charged_gas_price = intx::uint256{512509489520};
        }
    } else if (block_number < 329714374) {
        if (charged_gas_price > 513753813459) {
            charged_gas_price = intx::uint256{513753813459};
        }
    } else if (block_number < 332358496) {
        if (charged_gas_price > 513889289168) {
            charged_gas_price = intx::uint256{513889289168};
        }
    } else if (block_number < 334211846) {
        if (charged_gas_price > 514927973622) {
            charged_gas_price = intx::uint256{514927973622};
        }
    } else if (block_number < 338022602) {
        if (charged_gas_price > 515474978733) {
            charged_gas_price = intx::uint256{515474978733};
        }
    } else if (block_number < 339221402) {
        if (charged_gas_price > 516125417219) {
            charged_gas_price = intx::uint256{516125417219};
        }
    } else if (block_number < 344908827) {
        if (charged_gas_price > 516282803626) {
            charged_gas_price = intx::uint256{516282803626};
        }
    } else {
        if (charged_gas_price > 516900477336) {
            charged_gas_price = intx::uint256{516900477336};
        }
    }
    return charged_gas_price;
}

}  // namespace silkworm
