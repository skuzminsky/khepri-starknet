// SPDX-License-Identifier: MIT
// Khepri smart contracts written in Cairo v0.1.0 (header/model.cairo)

%lang starknet

// Starkware dependencies
from starkware.cairo.common.uint256 import Uint256

struct BlockHeader {
    version: felt,  // 4 bytes
    prev_block: Uint256,  // 32 bytes
    merkle_root: Uint256,  // 32 bytes
    timestamp: felt,  // 4 bytes
    bits: felt,  // 4 bytes
    nonce: felt,  // 4 bytes
    hash: Uint256,  // 32 bytes
}

struct BlockHeaderValidationContext {
    height: felt,
    block_header: BlockHeader,
    previous_block_header: BlockHeader,
}
