/*
   Copyright 2020-2021 The Silkworm Authors

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

#pragma once

#include <numeric>
#include <vector>

#include <silkworm/rlp/encode.hpp>

namespace silkworm::rlp {

template <typename T>
size_t length_items(const std::vector<T>& v) {
    return std::accumulate(v.cbegin(), v.cend(), size_t{0}, [] (size_t sum, const T &x) { return sum + length(x); });
}

template <typename T>
size_t length(const std::vector<T>& v) {
    const size_t payload_length = length_items(v);
    return length_of_length(payload_length) + payload_length;
}

template <typename T>
void encode_items(Bytes& to, const std::vector<T>& v) {
    for (const T& x : v) {
        encode(to, x);
    }
}

template <typename T>
void encode(Bytes& to, const std::vector<T>& v) {
    const Header h{/*list=*/true, /*payload_length=*/length_items(v)};
    to.reserve(to.size() + length_of_length(h.payload_length) + h.payload_length);
    encode_header(to, h);
    encode_items(to, v);
}

template <typename Arg1, typename Arg2>
size_t length_items(const Arg1& arg1, const Arg2& arg2) {
    return length(arg1) + length(arg2);
}

template <typename Arg1, typename Arg2, typename... Args>
size_t length_items(const Arg1& arg1, const Arg2& arg2, const Args&... args) {
    return length(arg1) + length_items(arg2, args...);
}

template <typename Arg1, typename Arg2, typename... Args>
size_t length(const Arg1& arg1, const Arg2& arg2, const Args&... args) {
    const size_t payload_length = length_items(arg1, arg2, args...);
    return length_of_length(payload_length) + payload_length;
}

template <typename Arg1, typename Arg2>
void encode_items(Bytes& to, const Arg1& arg1, const Arg2& arg2) {
    encode(to, arg1);
    encode(to, arg2);
}

template <typename Arg1, typename Arg2, typename... Args>
void encode_items(Bytes& to, const Arg1& arg1, const Arg2& arg2, const Args&... args) {
    encode(to, arg1);
    encode_items(to, arg2, args...);
}

template <typename Arg1, typename Arg2, typename... Args>
void encode(Bytes& to, const Arg1& arg1, const Arg2& arg2, const Args&... args) {
    const Header h{/*list=*/true, /*payload_length=*/length_items(arg1, arg2, args...)};
    to.reserve(to.size() + length_of_length(h.payload_length) + h.payload_length);
    encode_header(to, h);
    encode_items(to, arg1, arg2, args...);
}

}  // namespace silkworm::rlp
