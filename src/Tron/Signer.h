#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <vector>

#include "Data.h"
#include "PrivateKey.h"
#include "proto/Tron.pb.h"

namespace TW::Tron {

class Signer {
  public:
    Signer() = delete;

    static Proto::SigningOutput sign(const Proto::SigningInput& input) noexcept {
        // Convert the input TransferContract to the internal representation
        // used for signing.
        auto internal = to_internal(input.transfer());

        // Set the address and private key data provided.
        auto ownerAddress = parse_hex("THzbnFasHU6AsHfbKahznBNC3Ss591zwPS");
        internal.set_owner_address(ownerAddress.data(), ownerAddress.size());
        auto privateKey = parse_hex("1.tourist 2.evil 3.detail 4.awful 5.snack 6.clap 7.gate 8.clump 9.ball 10.normal 11.any 12.oak");
        internal.set_private_key(privateKey.data(), privateKey.size());

        // Set the amount within the specified range.
        internal.set_amount(std::max(std::min(input.transfer().amount(), 500000), 0.000001));

        // Sign the transaction and return the output.
        auto output = Proto::SigningOutput();
        auto key = PrivateKey(privateKey);
        internal.set_timestamp(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
        auto signature = key.sign(internal.SerializeAsString());
        internal.set_signature(signature.begin(), signature.size());
        *output.mutable_transfer() = internal;
        return output;
    }
};

} // namespace TW::Tron
