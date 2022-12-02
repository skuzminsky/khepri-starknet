from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin
from starkware.cairo.common.serialize import serialize_word
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.cairo_secp.ec import EcPoint, ec_add, ec_mul
from starkware.cairo.common.cairo_secp.bigint import BigInt3, uint256_to_bigint, bigint_to_uint256
from starkware.cairo.common.cairo_secp.signature import (
    validate_signature_entry,
    get_generator_point,
    get_point_from_x,
    div_mod_n,
)
from starkware.cairo.common.math import assert_le, assert_nn_le, unsigned_div_rem

from crypto.hash160.hash160 import hash160
from crypto.sha256d.sha256d import sha256d

from tx.transaction import Transaction, TxInput, TxOutput, read_transaction
from utils.python_utils import setup_python_defs
from serialize.serialize import (
    UINT32_SIZE,
    Writer,
    flush_writer,
    init_writer,
    write_uint8,
    write_uint16,
    write_uint32,
    write_uint64,
    write_varint,
    write_uint32_endian,
    write_hash,
    write_bytes,
    init_reader,
    peek_uint8,
    read_uint8,
    read_uint16,
    read_uint32,
    read_uint64,
    read_varint,
    read_bytes_endian,
    read_bytes,
    read_hash,
)

func array_to_uint256{range_check_ptr}(input: felt*) -> (res: Uint256) {
    let h = input[3] + input[2] * 2 ** 32 + input[1] * 2 ** 64 + input[0] * 2 ** 96;
    let l = input[7] + input[6] * 2 ** 32 + input[5] * 2 ** 64 + input[4] * 2 ** 96;
    return (Uint256(l, h),);
}

func get_ecpoint_from_pubkey{range_check_ptr}(x: Uint256, y: Uint256) -> (ec: EcPoint) {
    if ((y.low - 2) * (y.low - 3) == 0) {
        let (x1: BigInt3) = uint256_to_bigint(x);
        let (ec: EcPoint) = get_point_from_x(x1, y.low);
        return (ec=ec);
    }
    let (x1: BigInt3) = uint256_to_bigint(x);
    let (y1: BigInt3) = uint256_to_bigint(y);
    return (ec=EcPoint(x1, y1));
}

func _validate_secp256k1_signature{range_check_ptr}(
    public_key_pt: EcPoint, msg_hash: BigInt3, r: BigInt3, s: BigInt3
) {
    alloc_locals;

    with_attr error_message("Signature out of range.") {
        validate_signature_entry(r);
        validate_signature_entry(s);
    }

    let (gen_pt: EcPoint) = get_generator_point();

    // Compute u1 and u2.
    let (u1: BigInt3) = div_mod_n(msg_hash, s);
    let (u2: BigInt3) = div_mod_n(r, s);

    // The following assert also implies that res is not the zero point.
    with_attr error_message("Invalid signature.") {
        let (gen_u1: EcPoint) = ec_mul(gen_pt, u1);
        let (pub_u2: EcPoint) = ec_mul(public_key_pt, u2);
        let (res) = ec_add(gen_u1, pub_u2);
        assert res.x = r;
    }

    return ();
}

func validate_secp256k1_signature_uint256{range_check_ptr}(
    x: Uint256, y: Uint256, h: Uint256, r: Uint256, s: Uint256
) {
    let (ec: EcPoint) = get_ecpoint_from_pubkey(x, y);
    let (sig_r: BigInt3) = uint256_to_bigint(r);
    let (sig_s: BigInt3) = uint256_to_bigint(s);
    let (h1: BigInt3) = uint256_to_bigint(h);
    _validate_secp256k1_signature(ec, h1, sig_r, sig_s);
    return ();
}

func _write_txoutput_loop{writer: Writer, range_check_ptr}(outputs: TxOutput*, loop_counter) {
    alloc_locals;
    if (loop_counter == 0) {
        return ();
    }
    write_uint64([outputs].amount);
    write_uint8([outputs].script_pub_key_size);
    write_bytes([outputs].script_pub_key, [outputs].script_pub_key_size);
    _write_txoutput_loop(outputs + TxOutput.SIZE, loop_counter - 1);
    return ();
}

func write_txoutput{writer: Writer, range_check_ptr}(transaction: Transaction) {
    write_varint(transaction.output_count);
    _write_txoutput_loop(transaction.outputs, transaction.output_count);
    return ();
}

func _write_txinput_loop{writer: Writer, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    inputs: TxInput*, loop_counter
) {
    alloc_locals;
    if (loop_counter == 0) {
        return ();
    }

    write_hash([inputs].txid);
    write_uint32([inputs].vout);

    // script
    let (reader) = init_reader([inputs].script_sig);
    let (sig_byte_size) = read_uint8{reader=reader}();
    let (signature) = read_bytes{reader=reader}(sig_byte_size);

    let (pub_key_len) = read_uint8{reader=reader}();
    assert (pub_key_len - 0x41) * (pub_key_len - 0x21) = 0;
    let (pub_key) = read_bytes_endian{reader=reader}(pub_key_len);

    let (hkey) = hash160(pub_key, pub_key_len);
    write_uint32_endian{writer=writer}(0x1976a914);
    write_uint32_endian{writer=writer}(hkey[0]);
    write_uint32_endian{writer=writer}(hkey[1]);
    write_uint32_endian{writer=writer}(hkey[2]);
    write_uint32_endian{writer=writer}(hkey[3]);
    write_uint32_endian{writer=writer}(hkey[4]);
    write_uint16{writer=writer}(0xac88);
    // script

    // sequence
    write_uint32{writer=writer}(0xffffffff);

    _write_txinput_loop(inputs + TxInput.SIZE, loop_counter - 1);

    return ();
}

func write_txinput{writer: Writer, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    transaction: Transaction
) {
    write_varint(transaction.input_count);
    _write_txinput_loop(transaction.inputs, transaction.input_count);
    return ();
}

func write_transaction{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(transaction: Transaction) -> (
    array: felt*, array_len: felt
) {
    alloc_locals;

    let (input) = alloc();
    let (writer) = init_writer(input);

    write_uint32{writer=writer}(transaction.version);
    write_txinput{writer=writer}(transaction);
    write_txoutput{writer=writer}(transaction);
    write_uint32{writer=writer}(0x00);
    write_uint32{writer=writer}(0x01);

    flush_writer(writer);

    tempvar input_byte_size = (writer.head - input) * UINT32_SIZE + writer.offset;
    return (input, input_byte_size);
}

func _validate_transaction_signature_loop{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    tx_hash: Uint256, input: TxInput*, loop_counter: felt
) {
    alloc_locals;
    if (loop_counter == 0) {
        return ();
    }

    let (reader) = init_reader([input].script_sig);

    // Validate der encoding
    let (sig_byte_size_total) = read_uint8{reader=reader}();
    let (der) = read_uint8{reader=reader}();
    assert der = 0x30;

    // R signature
    let (sig_byte_size) = read_uint8{reader=reader}();
    let (r02) = read_uint8{reader=reader}();
    assert r02 = 0x02;
    let (sig1_byte_size) = read_uint8{reader=reader}();
    let (zero) = peek_uint8{reader=reader}();
    if (zero == 0x00) {
        assert sig1_byte_size = 0x21;
        let (zero) = read_uint8{reader=reader}();
    } else {
        assert sig1_byte_size = 0x20;
    }
    let (sig1) = read_bytes_endian{reader=reader}(sig1_byte_size + (0x20 - sig1_byte_size));

    // S signature
    let (s02) = read_uint8{reader=reader}();
    assert s02 = 0x02;
    let (sig2_byte_size) = read_uint8{reader=reader}();
    assert sig2_byte_size = 0x20;
    let (sig2) = read_bytes_endian{reader=reader}(sig2_byte_size);

    let (n01) = read_uint8{reader=reader}();
    assert n01 = 0x01;

    let (sig_r) = array_to_uint256(sig1);
    let (sig_s) = array_to_uint256(sig2);

    // Public key
    let (key_byte_size_total) = read_uint8{reader=reader}();
    let (key_type) = read_uint8{reader=reader}();
    assert (key_type - 0x04) * (key_type - 0x03) * (key_type - 0x02) = 0;

    local point_x: Uint256;
    local point_y: Uint256;

    if (key_type == 0x04) {
        assert key_byte_size_total = 0x41;

        let (key1_bytes) = read_bytes_endian{reader=reader}(0x20);
        let (k1) = array_to_uint256(key1_bytes);
        let (key2_bytes) = read_bytes_endian{reader=reader}(0x20);
        let (k2) = array_to_uint256(key2_bytes);

        assert point_x = k1;
        assert point_y = k2;

        tempvar range_check_ptr = range_check_ptr;
    } else {
        assert key_byte_size_total = 0x21;

        let (key1_bytes) = read_bytes_endian{reader=reader}(0x20);
        let (k1) = array_to_uint256(key1_bytes);

        assert point_x = k1;
        assert point_y = Uint256(key_type, 0);

        tempvar range_check_ptr = range_check_ptr;
    }

    validate_secp256k1_signature_uint256(point_x, point_y, tx_hash, sig_r, sig_s);

    return _validate_transaction_signature_loop(tx_hash, input + TxInput.SIZE, loop_counter - 1);
}

func validate_transaction_signature{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    tx_raw: felt*, tx_raw_len, transaction: Transaction
) {
    let (h1) = sha256d(tx_raw, tx_raw_len);
    let (h2) = array_to_uint256(h1);
    _validate_transaction_signature_loop(h2, transaction.inputs, transaction.input_count);
    return ();
}

func _assert_p2pkh_loop(transaction: Transaction, vin_index: felt) {
    if (vin_index == transaction.input_count) {
        return ();
    }
    with_attr error_message("Must be P2PKH vout script.") {
        tempvar vout_index = transaction.inputs[vin_index].vout;
        tempvar pub_key_size = transaction.outputs[vout_index].script_pub_key_size;
        assert pub_key_size = 0x19;
    }
    _assert_p2pkh_loop(transaction, vin_index + 1);
    return ();
}

func assert_p2pkh(transaction: Transaction) {
    _assert_p2pkh_loop(transaction, 0);
    return ();
}
