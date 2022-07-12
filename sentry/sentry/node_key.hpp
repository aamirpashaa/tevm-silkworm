/*
Copyright 2020-2022 The Silkworm Authors

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

#include <string>
#include <silkworm/common/base.hpp>

namespace silkworm::sentry {

class NodeKey {
  public:
    NodeKey();
    explicit NodeKey(Bytes data);
    explicit NodeKey(const ByteView& data);

    [[nodiscard]]
    std::string to_hex() const;

  private:
    Bytes private_key_;
};

}  // namespace silkworm::sentry
