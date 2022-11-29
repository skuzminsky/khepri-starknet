// https://github.com/ZeroSync/ZeroSync
//
// Serialization and Validation of a Bitcoin Transaction
//
// See also:
// - Bitcoin Core: https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
// - Example transactions of all types: https://github.com/coins/research/blob/master/bitcoin-tx.md

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin
from starkware.cairo.common.math import assert_le

from crypto.sha256d.sha256d import HASH_SIZE
from serialize.serialize import (
    init_reader, Reader, read_uint8, read_uint16, read_uint32, read_uint64, read_varint, read_hash, 
    read_bytes_endian, peek_uint8, Writer, write_uint32, write_varint, UINT32_SIZE, UINT64_SIZE )

//from block.block_header import BlockHeaderValidationContext
//from utxo_set.utxo_set import utxo_set_insert, utxo_set_extract

// Definition of a Bitcoin transaction
//
// See also:
// - https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
//
struct Transaction {
    version: felt,
    input_count: felt,
    inputs: TxInput*,
    output_count: felt,
    outputs: TxOutput*,
    locktime: felt,
}

// A transaction input
struct TxInput {
    txid: felt*,
    vout: felt,
    script_sig_size: felt,
    script_sig: felt*,
    sequence: felt,
}

// A transaction output
struct TxOutput {
    amount: felt,
    script_pub_key_size: felt,
    script_pub_key: felt*,
}

// Read a Transaction from a buffer
func read_transaction{reader: Reader, range_check_ptr}() -> (
    transaction: Transaction, byte_size: felt
) {
    alloc_locals;
    let (version) = read_uint32();

    // Parse the SegWit flag
    let (is_not_segwit) = peek_uint8();
    if (is_not_segwit == 0) {
        // This is a SegWit transaction
        // Read the 2 bytes of "marker" and "flag"
        let (flag) = read_uint16();
        // Validate that they are set correctly
        with_attr error_message("Flag is not setted correctly.") {
            assert flag = 0x0100;
        }
    }

    let input_count = read_varint();
    let inputs = read_inputs(input_count.value);
    let output_count = read_varint();
    let outputs = read_outputs(output_count.value);
    let (locktime) = read_uint32();

    // Compute the byte size of the transaction
    return (
        Transaction(
            version,
            input_count.value,
            inputs.inputs,
            output_count.value,
            outputs.outputs,
            locktime
        ),
            UINT32_SIZE +
            input_count.byte_size +
            inputs.byte_size +
            output_count.byte_size +
            outputs.byte_size +
            UINT32_SIZE,
    );
}

// Read transaction inputs from a buffer
func read_inputs{reader: Reader, range_check_ptr}(input_count) -> (
    inputs: TxInput*, byte_size: felt
) {
    alloc_locals;
    let (inputs: TxInput*) = alloc();
    let (byte_size) = _read_inputs_loop(inputs, input_count);
    return (inputs, byte_size);
}

// LOOP: Read transaction inputs from a buffer
func _read_inputs_loop{reader: Reader, range_check_ptr}(inputs: TxInput*, loop_counter) -> (
    byte_size: felt
) {
    alloc_locals;
    if (loop_counter == 0) {
        return (0,);
    }
    let input = read_input();
    with_attr error_message("Inputs do not match.") {
        assert [inputs] = input.input;
    }
    let (byte_size_accu) = _read_inputs_loop(inputs + TxInput.SIZE, loop_counter - 1);
    return (byte_size_accu + input.byte_size,);
}

// Read a transaction input from a buffer
func read_input{reader: Reader, range_check_ptr}() -> (input: TxInput, byte_size: felt) {
    alloc_locals;
    let (txid) = read_hash();
    let (vout) = read_uint32();
    let script_sig_size = read_varint();
    let (script_sig) = read_bytes_endian(script_sig_size.value);
    let (sequence) = read_uint32();
    // Compute the input's byte size
    return (
        TxInput(
            txid,
            vout,
            script_sig_size.value,
            script_sig,
            sequence
        ),
            HASH_SIZE +
            UINT32_SIZE +
            script_sig_size.byte_size +
            script_sig_size.value +
            UINT32_SIZE,
    );
}

// Read outputs from a buffer
func read_outputs{reader: Reader, range_check_ptr}(output_count) -> (
    outputs: TxOutput*, byte_size: felt
) {
    alloc_locals;
    let outputs: TxOutput* = alloc();
    let (byte_size) = _read_outputs_loop(outputs, output_count);
    return (outputs, byte_size);
}

// LOOP: Read transaction outputs
func _read_outputs_loop{reader: Reader, range_check_ptr}(outputs: TxOutput*, loop_counter) -> (
    byte_size: felt
) {
    alloc_locals;
    if (loop_counter == 0) {
        return (0,);
    }
    let (output, byte_size) = read_output();
    with_attr error_message("Outputs do not match.") {
        assert [outputs] = output;
    }
    let (byte_size_accu) = _read_outputs_loop(outputs + TxOutput.SIZE, loop_counter - 1);
    return (byte_size_accu + byte_size,);
}

// Read an output from a buffer
// Compute the output's byte size
func read_output{reader: Reader, range_check_ptr}() -> (output: TxOutput, byte_size: felt) {
    alloc_locals;
    let (amount) = read_uint64();
    let script_pub_key_size = read_varint();
    let (script_pub_key) = read_bytes_endian(script_pub_key_size.value);
    return (
        TxOutput(
            amount,
            script_pub_key_size.value,
            script_pub_key
        ),
            UINT64_SIZE +
            script_pub_key_size.byte_size +
            script_pub_key_size.value,
    );
}
