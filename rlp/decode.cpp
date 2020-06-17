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

#include "decode.hpp"

#include <gsl/gsl_assert>

namespace {

uint64_t read_uint64(std::istream& from, size_t len) {
  Expects(len <= 8);

  if (len == 0) {
    return 0;
  }

  if (from.peek() == 0) {
    throw silkworm::rlp::DecodingError("leading zero(s)");
  }

  thread_local uint64_t buf;

  buf = 0;
  char* p = reinterpret_cast<char*>(&buf);
  from.read(p + (8 - len), len);

  // We assume a little-endian architecture like amd64
  return intx::bswap(buf);
}

}  // namespace

namespace silkworm::rlp {

Header decode_header(std::istream& from) {
  Header h;
  uint8_t b = from.get();
  if (b < 0x80) {
    from.unget();
    h.length = 1;
  } else if (b < 0xB8) {
    h.length = b - 0x80;
    if (h.length == 1 && static_cast<uint8_t>(from.peek()) < 0x80) {
      throw DecodingError("non-canonical single byte");
    }
  } else if (b < 0xC0) {
    h.length = read_uint64(from, b - 0xB7);
    if (h.length < 56) {
      throw DecodingError("non-canonical size");
    }
  } else if (b < 0xF8) {
    h.list = true;
    h.length = b - 0xC0;
  } else {
    h.list = true;
    h.length = read_uint64(from, b - 0xF7);
    if (h.length < 56) {
      throw DecodingError("non-canonical size");
    }
  }
  return h;
}

std::string decode_string(std::istream& from) {
  Header h = decode_header(from);
  if (h.list) {
    throw DecodingError("unexpected list");
  }
  std::string str(h.length, '\0');
  from.read(str.data(), h.length);
  return str;
}

uint64_t decode_uint64(std::istream& from) {
  Header h = decode_header(from);
  if (h.list) {
    throw DecodingError("unexpected list");
  }
  if (h.length > 8) {
    throw DecodingError("uint64 overflow");
  }
  return read_uint64(from, h.length);
}

}  // namespace silkworm::rlp
