/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_TYPES_HPP
#define SILKWORM_TYPES_HPP

#include <chrono>

#include <silkworm/common/util.hpp>
#include <silkworm/rlp/decode.hpp>
#include <silkworm/rlp/encode.hpp>
#include <silkworm/types/block.hpp>
#include <silkworm/types/transaction.hpp>

namespace silkworm {

class Hash : public evmc::bytes32 {
  public:
    using evmc::bytes32::bytes32;

    Hash() = default;
    Hash(ByteView bv) { std::memcpy(bytes, bv.data(), length()); }

    operator Bytes() { return {bytes, length()}; }
    operator ByteView() { return {bytes, length()}; }

    static constexpr size_t length() { return sizeof(evmc::bytes32); }

    std::string to_hex() { return silkworm::to_hex(*this); }
    static Hash from_hex(const std::string& hex) {
        return Hash(evmc::literals::internal::from_hex<bytes32>(hex.c_str()));
    }

    static_assert(sizeof(evmc::bytes32) == 32);
};

using BigInt = intx::uint256;  // use intx::to_string, from_string, ...

// using Bytes = std::basic_string<uint8_t>; already defined elsewhere
// using std::string to_hex(ByteView bytes);
// using std::optional<Bytes> from_hex(std::string_view hex) noexcept;

using time_point_t = std::chrono::time_point<std::chrono::system_clock>;
using seconds_t = std::chrono::seconds;

// defined elsewhere: ByteView string_view_to_byte_view(std::string_view sv)
inline Bytes string_to_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

inline std::ostream& operator<<(std::ostream& out, const silkworm::ByteView& bytes) {
    out << silkworm::to_hex(bytes);
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const evmc::address& addr) {
    out << silkworm::to_hex(addr);
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const evmc::bytes32& b32) {
    out << silkworm::to_hex(b32);
    return out;
}

using PeerId = std::string;

enum Penalty : int {
    NoPenalty = 0,
    BadBlockPenalty,
    DuplicateHeaderPenalty,
    WrongChildBlockHeightPenalty,
    WrongChildDifficultyPenalty,
    InvalidSealPenalty,
    TooFarFuturePenalty,
    TooFarPastPenalty,
    AbandonedAnchorPenalty
};

struct PeerPenalization {
    Penalty penalty;
    PeerId peerId;

    PeerPenalization(Penalty p, PeerId id) : penalty(p), peerId(id) {}  // unnecessary with c++20
};

struct Announce {
    Hash hash;
    BlockNum number;
};

namespace rlp {
    void encode(Bytes& to, const Hash& h);

    template <>
    DecodingResult decode(ByteView& from, Hash& to) noexcept;

}  // namespace rlp

}  // namespace silkworm

namespace std {

template <>
struct hash<silkworm::Hash> : public std::hash<evmc::bytes32>  // to use Hash with std::unordered_set/map
{};

}  // namespace std

#endif  // SILKWORM_TYPES_HPP
