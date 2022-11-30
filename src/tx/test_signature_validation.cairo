//
// To run only this test suite use:
// protostar test  --cairo-path=./src target src/**/*_transaction*
//

%lang starknet

from starkware.cairo.common.alloc import alloc
from serialize.serialize import init_reader, init_writer, flush_writer, read_uint8
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.memcpy import memcpy
from crypto.sha256d.sha256d import assert_hashes_equal
from utils.python_utils import setup_python_defs

from tx.transaction import read_transaction
from tx.signature_validation import write_transaction, validate_transaction_signature, assert_p2pkh

// Transaction example
//
// See also
// - https://blockstream.info/tx/cca7507897abc89628f450e8b1e0c6fca4ec3f7b34cccf55f3f531c659ff4d79
// - https://blockstream.info/api/tx/cca7507897abc89628f450e8b1e0c6fca4ec3f7b34cccf55f3f531c659ff4d79/hex
@external
func test_signature_pubkey04{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() {
    alloc_locals;
    setup_python_defs();

    let (transaction_raw) = alloc();

    // Use Python to convert hex string into uint32 array
    %{
        from_hex(
            "01000000018dd4f5fbd5e980fc02f35c6ce145935b11e284605bf599a13c6d41"
            "5db55d07a1000000008b4830450221009908144ca6539e09512b9295c8a27050"
            "d478fbb96f8addbc3d075544dc41328702201aa528be2b907d316d2da068dd9e"
            "b1e23243d97e444d59290d2fddf25269ee0e0141042e930f39ba62c6534ee98e"
            "d20ca98959d34aa9e057cda01cfd422c6bab3667b76426529382c23f42b9b08d"
            "7832d4fee1d6b437a8526e59667ce9c4e9dcebcabbffffffff0200719a818600"
            "00001976a914df1bd49a6c9e34dfa8631f2c54cf39986027501b88ac009f0a53"
            "62000000434104cd5e9726e6afeae357b1806be25a4c3d3811775835d235417e"
            "a746b7db9eeab33cf01674b944c64561ce3388fa1abd0fa88b06c44ce81e2234"
            "aa70fe578d455dac00000000", ids.transaction_raw)
    %}

    let (reader) = init_reader(transaction_raw);

    let (transaction, byte_size) = read_transaction{reader=reader}();
    with_attr error_message("Transaction values are incorrect.") {
        assert transaction.version = 0x01;
        assert byte_size = 300;
        assert_p2pkh(transaction);
    }

    let (tx, tx_byte_size) = write_transaction(transaction);

    validate_transaction_signature(tx, tx_byte_size, transaction);

    return ();
}

// Transaction example
//
// See also
// - https://blockstream.info/tx/757b56e1d5072bb7cb9f8cffbac450cb93af63ec391378b4e73d12778cdfabdc
// - https://blockstream.info/api/tx/757b56e1d5072bb7cb9f8cffbac450cb93af63ec391378b4e73d12778cdfabdc/hex
@external
func test_signature_pubkey03{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() {
    alloc_locals;
    setup_python_defs();

    let (transaction_raw) = alloc();

    // Use Python to convert hex string into uint32 array
    %{
        from_hex(
            "0100000001e7e4daf6ecb8773058c9680d9e24f2c31dff40090deb01b46339a4"
            "ece4951f81000000006a473044022012f5a907fa0385a780886be1c04d4bbd45"
            "d9d82377844e2b5249695e2b9112b0022058e9dd2cf072d3d595d1a6fa5c51ab"
            "1ee5f7cf9e8404d05b37ca9fcec73e779c01210369e03e2c91f0badec46c9c90"
            "3d9e9edae67c167b9ef9b550356ee791c9a40896ffffffff024f76b100000000"
            "001976a9149f21a07a0c7c3cf65a51f586051395762267cdaf88ac14b2960000"
            "00000017a9149a854477ae1f5fda4eddec287150aef752143aa18700000000", ids.transaction_raw)
    %}

    let (reader) = init_reader(transaction_raw);

    let (transaction, byte_size) = read_transaction{reader=reader}();
    with_attr error_message("Transaction values are incorrect.") {
        assert transaction.version = 0x01;
        assert byte_size = 223;
        assert_p2pkh(transaction);
    }

    let (tx, tx_byte_size) = write_transaction(transaction);

    validate_transaction_signature(tx, tx_byte_size, transaction);

    return ();
}

// Transaction example
//
// See also
// - https://blockstream.info/tx/4269fdc239d027922dcec96f1ae283dbaff10e2d1bd49605661d091e79714956
// - https://blockstream.info/api/tx/4269fdc239d027922dcec96f1ae283dbaff10e2d1bd49605661d091e79714956/hex
@external
func test_signature_pubkey02{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() {
    alloc_locals;
    setup_python_defs();

    let (transaction_raw) = alloc();

    // Use Python to convert hex string into uint32 array
    %{
        from_hex(
            "01000000017f950ab790838e0c05e79856d25d586823fe139e1807405a3f207f"
            "f33f9b7663010000006b483045022100d8629403cd3b49950da9293653c62791"
            "49c029e6b7b15371342d0d2ce286c8f2022078787985a644e94fd9246f6c2573"
            "3336c94af5f00d9d34a07dc2f9e0987ef990012102b726d7eae11a6d5cf3b236"
            "2e773e116a6140347dcee1b2943f4a2897351e5d90ffffffff021bf03c000000"
            "000017a91469f3757380a56820abc7052867216599e575cddd8777c1ca1c0000"
            "00001976a914d5f950abe0b559b2b7a7ab3d18a507ea1c3e4ac688ac00000000", ids.transaction_raw)
    %}

    let (reader) = init_reader(transaction_raw);

    let (transaction, byte_size) = read_transaction{reader=reader}();
    with_attr error_message("Transaction values are incorrect.") {
        assert transaction.version = 0x01;
        assert byte_size = 224;
        assert_p2pkh(transaction);
    }

    let (tx, tx_byte_size) = write_transaction(transaction);

    validate_transaction_signature(tx, tx_byte_size, transaction);

    return ();
}
