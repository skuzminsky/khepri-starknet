%lang starknet

from starkware.cairo.common.uint256 import Uint256
from utils.math import felt_to_Uint256

struct Params {
    pow_limit: Uint256,
    pow_target_timespan: felt,
    pow_target_timespan_div_by_4: felt,
    pow_target_timespan_mul_by_4: felt,
    difficulty_adjustment_interval: felt,
}

func get_params{range_check_ptr}() -> (params: Params) {
    let (pow_limit: Uint256) = felt_to_Uint256(
        0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    );
    return (
        params=Params(
        pow_limit=pow_limit,
        pow_target_timespan=14 * 24 * 60 * 60,
        pow_target_timespan_div_by_4=14 * 24 * 60 * 15,
        pow_target_timespan_mul_by_4=14 * 24 * 60 * 60 * 4,
        difficulty_adjustment_interval=2016
        ),
    );
}
