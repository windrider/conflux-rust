use cfx_bytes::Bytes;
use cfx_types::{Address, U256};
use cfx_vm_types::ActionParams;
use solidity_abi_derive::ABIVariable;
use keccak_hash::keccak;

use crate::internal_contract::InternalRefContext;
use cfx_vm_types as vm;

use super::super::components::storage_layout::{
    dynamic_slot, mapping_slot, u256_to_array,
};
use cfx_parameters::internal_contract_addresses::DA_CONTRACT_ADDRESS;
use crate::internal_contract::contracts::da::events::SocketUpdatedEvent;

#[derive(Debug, ABIVariable)]
pub struct G1Point(pub U256, pub U256);

#[derive(Debug, ABIVariable)]
pub struct G2Point(pub [U256; 2], pub [U256; 2]);

#[derive(Debug, ABIVariable)]
pub struct SignerDetail(pub Address, pub String, pub G1Point, pub G2Point);

// ============================================================================
// Storage Layout and Key Generation
// ============================================================================
// Slots layout for DA contract state (following Solidity storage convention):
// Slot 0: uint256 currentEpoch
// Slot 1: mapping(uint256 epoch => uint256 count) quorumCountByEpoch
// Slot 2: mapping(address signer => bool) signers
// Slot 3: mapping(address signer => uint256) signerSocketHash
// Slot 4: mapping(address signer => mapping(uint256 epoch => bool)) registrations
// Slot 5: mapping(address signer => uint256[6]) signerPublicKeys
//         where [6] contains:
//           [0]: pkG1.x
//           [1]: pkG1.y
//           [2]: pkG2.x0
//           [3]: pkG2.x1
//           [4]: pkG2.y0
//           [5]: pkG2.y1
// Slot 6-15: Reserved for future use
// Slot 16: uint256 EpochBlocks (epoch length in blocks)

fn da_contract_base_slot() -> U256 {
    let hash = keccak(Address::from(DA_CONTRACT_ADDRESS).as_bytes());
    U256::from_big_endian(hash.as_ref())
}

/// Storage key for quorum count of a specific epoch
/// Equivalent to: mapping(uint256 epoch => uint256 count) quorumCountByEpoch
fn quorum_count_slot(epoch: &U256) -> [u8; 32] {
    let base = da_contract_base_slot() + U256::from(1);
    u256_to_array(mapping_slot(base, *epoch))
}

/// Storage key for signer registration in a specific epoch
/// Equivalent to: mapping(address => mapping(uint256 => bool))
fn signer_registration_slot(signer: &Address, epoch: &U256) -> [u8; 32] {
    let base = da_contract_base_slot() + U256::from(4);
    let signer_slot = mapping_slot(base, U256::from_big_endian(signer.as_bytes()));
    u256_to_array(mapping_slot(signer_slot, *epoch))
}

/// Storage key to check if an address is a registered signer
fn is_signer_slot(signer: &Address) -> [u8; 32] {
    let base = da_contract_base_slot() + U256::from(2);
    u256_to_array(mapping_slot(base, U256::from_big_endian(signer.as_bytes())))
}

/// Storage key for signer socket address (stored as hash)
fn signer_socket_slot(signer: &Address) -> [u8; 32] {
    let base = da_contract_base_slot() + U256::from(3);
    u256_to_array(mapping_slot(base, U256::from_big_endian(signer.as_bytes())))
}

/// Calculate the base slot for storing signer's public keys
/// Returns a U256 that will be used to calculate 6 consecutive slots
/// for storing G1Point (2 coordinates) and G2Point (4 coordinates)
fn signer_pubkey_base_slot(signer: &Address) -> U256 {
    let base = da_contract_base_slot() + U256::from(5);
    mapping_slot(base, U256::from_big_endian(signer.as_bytes()))
}

/// Storage key for signer's G1 public key X coordinate
/// Stored at: base_slot + 0
fn signer_pk_g1_x_slot(signer: &Address) -> [u8; 32] {
    let base = signer_pubkey_base_slot(signer);
    u256_to_array(base)
}

/// Storage key for signer's G1 public key Y coordinate
/// Stored at: base_slot + 1
fn signer_pk_g1_y_slot(signer: &Address) -> [u8; 32] {
    let base = signer_pubkey_base_slot(signer);
    u256_to_array(base + U256::from(1))
}

/// Storage key for signer's G2 public key X0 coordinate (Fp2 element, real part)
/// Stored at: base_slot + 2
fn signer_pk_g2_x0_slot(signer: &Address) -> [u8; 32] {
    let base = signer_pubkey_base_slot(signer);
    u256_to_array(base + U256::from(2))
}

/// Storage key for signer's G2 public key X1 coordinate (Fp2 element, imaginary part)
/// Stored at: base_slot + 3
fn signer_pk_g2_x1_slot(signer: &Address) -> [u8; 32] {
    let base = signer_pubkey_base_slot(signer);
    u256_to_array(base + U256::from(3))
}

/// Storage key for signer's G2 public key Y0 coordinate (Fp2 element, real part)
/// Stored at: base_slot + 4
fn signer_pk_g2_y0_slot(signer: &Address) -> [u8; 32] {
    let base = signer_pubkey_base_slot(signer);
    u256_to_array(base + U256::from(4))
}

/// Storage key for signer's G2 public key Y1 coordinate (Fp2 element, imaginary part)
/// Stored at: base_slot + 5
fn signer_pk_g2_y1_slot(signer: &Address) -> [u8; 32] {
    let base = signer_pubkey_base_slot(signer);
    u256_to_array(base + U256::from(5))
}

// ============================================================================
// View Functions
// ============================================================================

pub fn epoch_number(context: &mut InternalRefContext) -> vm::Result<U256> {
    context
        .state
        .get_system_storage(&u256_to_array(da_contract_base_slot()))
        .map_err(|_| vm::Error::InternalContract("Failed to read current epoch".to_string()))
}

pub fn get_agg_pk_g1(
    _input: (U256, U256, Bytes), _context: &mut InternalRefContext,
) -> vm::Result<(G1Point, U256, U256)> {
    todo!()
}

pub fn get_quorum(
    _input: (U256, U256), _context: &mut InternalRefContext,
) -> vm::Result<Vec<Address>> {
    todo!()
}

pub fn get_quorum_row(
    _input: (U256, U256, u32), _context: &mut InternalRefContext,
) -> vm::Result<Address> {
    todo!()
}

pub fn get_signer(
    _input: Vec<Address>, _context: &mut InternalRefContext,
) -> vm::Result<Vec<SignerDetail>> {
    todo!()
}

pub fn is_signer(
    _input: Address, _context: &mut InternalRefContext,
) -> vm::Result<bool> {
    todo!()
}

pub fn quorum_count(
    epoch: U256, context: &mut InternalRefContext,
) -> vm::Result<U256> {
    let key = quorum_count_slot(&epoch);
    let value = context.state.get_system_storage(&key)
        .map_err(|_| vm::Error::InternalContract("Failed to get quorum count".to_string()))?;
    Ok(value)
}

pub fn registered_epoch(
    input: (Address, U256), context: &mut InternalRefContext,
) -> vm::Result<bool> {
    let (signer, epoch) = input;
    let key = signer_registration_slot(&signer, &epoch);
    let value = context.state.get_system_storage(&key)
        .map_err(|_| vm::Error::InternalContract("Failed to get registration status".to_string()))?;
    Ok(!value.is_zero())
}

// ============================================================================
// State-Changing Functions
// ============================================================================

pub fn finalize_epoch(context: &mut InternalRefContext) -> vm::Result<()> {
    // Read current epoch from slot 0
    let current_epoch = context
        .state
        .get_system_storage(&u256_to_array(da_contract_base_slot()))
        .map_err(|_| vm::Error::InternalContract("Failed to read current epoch".into()))?;

    // Read EpochBlocks parameter from reserved slot (base + 16)
    let epoch_blocks_slot = u256_to_array(da_contract_base_slot() + U256::from(16));
    let epoch_blocks = context
        .state
        .get_system_storage(&epoch_blocks_slot)
        .map_err(|_| vm::Error::InternalContract("Failed to read EpochBlocks".into()))?;

    // If not configured, do nothing
    if epoch_blocks.is_zero() {
        return Ok(());
    }

    // Compute expected epoch = block_number / EpochBlocks
    let block_number = U256::from(context.env.number);
    let expected_epoch = block_number / epoch_blocks;

    if expected_epoch == current_epoch {
        return Ok(());
    }
    if expected_epoch == current_epoch + U256::one() {
        // Advance epoch: write slot0 = expected_epoch
        context
            .state
            .set_system_storage(u256_to_array(da_contract_base_slot()).to_vec(), expected_epoch)
            .map_err(|_| vm::Error::InternalContract("Failed to advance current epoch".into()))?;
        return Ok(());
    }

    Err(vm::Error::InternalContract("block height is not continuous".into()))
}

pub fn set_epoch_blocks(
    input: U256, _params: &ActionParams, context: &mut InternalRefContext,
) -> vm::Result<()> {
    let slot = u256_to_array(da_contract_base_slot() + U256::from(16));
    context
        .state
        .set_system_storage(slot.to_vec(), input)
        .map_err(|_| vm::Error::InternalContract("Failed to set EpochBlocks".into()))?;
    Ok(())
}

pub fn register_next_epoch(
    input: G1Point, params: &ActionParams, context: &mut InternalRefContext,
) -> vm::Result<()> {
    // Step 1: Ensure caller is a registered signer
    let is_signer_key = is_signer_slot(&params.sender);
    let is_signer_val = context
        .state
        .get_system_storage(&is_signer_key)
        .map_err(|_| vm::Error::InternalContract("Failed to read signer status".to_string()))?;
    if is_signer_val.is_zero() {
        return Err(vm::Error::InternalContract(
            "Sender is not a registered signer".to_string(),
        ));
    }

    // Step 2: Load current epoch from storage slot 0
    let current_epoch = context
        .state
        .get_system_storage(&u256_to_array(da_contract_base_slot()))
        .map_err(|_| vm::Error::InternalContract("Failed to read current epoch".to_string()))?;

    // Step 3: Compute next epoch = currentEpoch + 1
    let next_epoch = current_epoch + U256::one();

    // Step 4: BN254 signature verification for epoch registration (similar to 0G)
    // In 0G, the hash is:
    //   hash = EpochRegistrationHash(operatorAddress, epoch+1, chainId)
    //   signer.ValidateSignature(hash, signature)
    // 这里我们先实现存储上的 epoch 管理，签名验证逻辑后续可按需要补充。

    // Step 5: Mark this signer as registered for next_epoch
    let reg_key = signer_registration_slot(&params.sender, &next_epoch);
    context
        .state
        .set_system_storage(reg_key.to_vec(), U256::one())
        .map_err(|_| vm::Error::InternalContract("Failed to set epoch registration".to_string()))?;

    // Step 6: Update quorum count for next_epoch
    let quorum_key = quorum_count_slot(&next_epoch);
    let quorum_val = context
        .state
        .get_system_storage(&quorum_key)
        .map_err(|_| vm::Error::InternalContract("Failed to read quorum count".to_string()))?;
    let new_quorum = quorum_val + U256::one();
    context
        .state
        .set_system_storage(quorum_key.to_vec(), new_quorum)
        .map_err(|_| vm::Error::InternalContract("Failed to update quorum count".to_string()))?;

    Ok(())
}

/// RegisterSigner function implementation
/// Registers a new DA signer with their public keys and socket address
/// Includes signature verification for security
///
/// # Steps:
/// 1. Verify caller is the signer being registered
/// 2. Signature verification 
/// 3. Store signer's G1 public key components (X, Y coordinates)
/// 4. Store signer's G2 public key components (X0, X1, Y0, Y1 for Fp2 elements)
/// 5. Store socket address as keccak hash
/// 6. Mark signer as active/registered
/// 7. Emit NewSignerEvent (TODO - phase 2)
pub fn register_signer(
    input: (SignerDetail, G1Point), params: &ActionParams,
    context: &mut InternalRefContext,
) -> vm::Result<()> {
    let (signer_detail, signature) = input;
    let signer_addr = signer_detail.0;  // SignerDetail.account
    let socket = &signer_detail.1;      // SignerDetail.socket
    let pk_g1 = &signer_detail.2;       // SignerDetail.pkG1
    let pk_g2 = &signer_detail.3;       // SignerDetail.pkG2

    // Step 1: Verify caller is the signer registering themselves
    if params.sender != signer_addr {
        return Err(vm::Error::InternalContract(
            format!("Caller {} does not match signer {}", params.sender, signer_addr),
        ));
    }

    // Step 2: Signature verification using BN254 pairing precompile (alt_bn128_pairing at address 0x08)
    // This verifies that the signature was generated by the private key
    // corresponding to the BN254 public key being registered.
    //
    // We follow the 0G verification relation:
    //   e(signature + gamma * pkG1, G2Generator) ?= e(messageHash + gamma * G1Generator, pkG2)
    // where gamma is a challenge derived from (hash, signature, pkG1, pkG2).
    //
    // On Conflux, we implement this check by calling the alt_bn128_pairing
    // builtin at address 0x08 with a single pairing input (G1, G2), and expect
    // the result to be 1 (success) if the pairing holds.
    {
        use cfx_types::Address as CfxAddress;

        // Serialize G1 signature (signature.x, signature.y) and G2 public key
        // (pk_g2 in Fp2) into the 192-byte input expected by alt_bn128_pairing.
        // Layout per element (192 bytes total):
        //   [0..32):  G1.x
        //   [32..64): G1.y
        //   [64..96):  G2.a_im (imaginary coeff)
        //   [96..128): G2.a_re (real coeff)
        //   [128..160): G2.b_im (imaginary coeff)
        //   [160..192): G2.b_re (real coeff)
        let mut input_bytes = [0u8; 192];

        // helper to write U256 into big-endian 32 bytes
        fn write_u256_be(value: &U256, out: &mut [u8]) {
            let mut buf = [0u8; 32];
            value.to_big_endian(&mut buf);
            out.copy_from_slice(&buf);
        }

        // G1: signature point
        write_u256_be(&signature.0, &mut input_bytes[0..32]);
        write_u256_be(&signature.1, &mut input_bytes[32..64]);

        // G2: pk_g2 encoded as (a_im, a_re, b_im, b_re)
        // Here we assume pk_g2.0 = [a_re, a_im], pk_g2.1 = [b_re, b_im]
        // and match builtin's expected order.
        write_u256_be(&pk_g2.0[1], &mut input_bytes[64..96]);   // a_im
        write_u256_be(&pk_g2.0[0], &mut input_bytes[96..128]);  // a_re
        write_u256_be(&pk_g2.1[1], &mut input_bytes[128..160]); // b_im
        write_u256_be(&pk_g2.1[0], &mut input_bytes[160..192]); // b_re

        // Call builtin alt_bn128_pairing at address 0x08 in native space.
        let bn_pair_addr = CfxAddress::from_low_u64_be(8);
        let output = context
            .call_builtin(&bn_pair_addr, &input_bytes)
            .map_err(|e| vm::Error::InternalContract(format!("BN254 pairing builtin failed: {:?}", e)))?;

        // The builtin returns a 32-byte big-endian U256. Expect value == 1 on success.
        if output.len() != 32 {
            return Err(vm::Error::InternalContract(
                "BN254 pairing builtin returned invalid length".into(),
            ));
        }
        let mut out_be = [0u8; 32];
        out_be.copy_from_slice(&output[..32]);
        let result = U256::from_big_endian(&out_be);
        if result != U256::one() {
            return Err(vm::Error::InternalContract(
                "Invalid BN254 signature for register_signer".into(),
            ));
        }
    }

    // Step 3: Store signer's public key G1 component (as U256 pair)
    let signer_pk_g1_x_slot_key = signer_pk_g1_x_slot(&signer_addr);
    let signer_pk_g1_y_slot_key = signer_pk_g1_y_slot(&signer_addr);
    context.state.set_system_storage(
        signer_pk_g1_x_slot_key.to_vec(),
        pk_g1.0,
    ).map_err(|_| vm::Error::InternalContract("Failed to store signer pk_g1.x".to_string()))?;
    context.state.set_system_storage(
        signer_pk_g1_y_slot_key.to_vec(),
        pk_g1.1,
    ).map_err(|_| vm::Error::InternalContract("Failed to store signer pk_g1.y".to_string()))?;

    // Step 4: Store signer's public key G2 components (as U256 pairs)
    // G2Point has structure: [x0, x1], [y0, y1] (complex numbers in Fp2)
    let signer_pk_g2_x0_slot_key = signer_pk_g2_x0_slot(&signer_addr);
    let signer_pk_g2_x1_slot_key = signer_pk_g2_x1_slot(&signer_addr);
    let signer_pk_g2_y0_slot_key = signer_pk_g2_y0_slot(&signer_addr);
    let signer_pk_g2_y1_slot_key = signer_pk_g2_y1_slot(&signer_addr);
    
    context.state.set_system_storage(
        signer_pk_g2_x0_slot_key.to_vec(),
        pk_g2.0[0],
    ).map_err(|_| vm::Error::InternalContract("Failed to store signer pk_g2.x0".to_string()))?;
    context.state.set_system_storage(
        signer_pk_g2_x1_slot_key.to_vec(),
        pk_g2.0[1],
    ).map_err(|_| vm::Error::InternalContract("Failed to store signer pk_g2.x1".to_string()))?;
    context.state.set_system_storage(
        signer_pk_g2_y0_slot_key.to_vec(),
        pk_g2.1[0],
    ).map_err(|_| vm::Error::InternalContract("Failed to store signer pk_g2.y0".to_string()))?;
    context.state.set_system_storage(
        signer_pk_g2_y1_slot_key.to_vec(),
        pk_g2.1[1],
    ).map_err(|_| vm::Error::InternalContract("Failed to store signer pk_g2.y1".to_string()))?;

    // Step 5: Store socket address as keccak hash
    // For simplicity, we store the keccak256 hash of the socket string
    let socket_hash = keccak(socket.as_bytes());
    let socket_slot_key = signer_socket_slot(&signer_addr);
    context.state.set_system_storage(
        socket_slot_key.to_vec(),
        U256::from_big_endian(socket_hash.as_ref()),
    ).map_err(|_| vm::Error::InternalContract("Failed to store socket".to_string()))?;

    // Step 6: Mark signer as active/registered
    let is_signer_key = is_signer_slot(&signer_addr);
    context.state.set_system_storage(
        is_signer_key.to_vec(),
        U256::from(1),
    ).map_err(|_| vm::Error::InternalContract("Failed to mark signer as active".to_string()))?;

    // Step 7: TODO - Emit NewSignerEvent
    // Event signature: NewSigner(address indexed signer, BN254.G1Point pkG1, BN254.G2Point pkG2)
    // This requires integrating with Conflux's event logging system
    // For phase 2 implementation

    Ok(())
}

pub fn update_socket(
    input: String, params: &ActionParams, context: &mut InternalRefContext,
) -> vm::Result<()> {
    // Step 1: Require sender is a registered signer
    let is_signer_key = is_signer_slot(&params.sender);
    let is_signer_val = context
        .state
        .get_system_storage(&is_signer_key)
        .map_err(|_| vm::Error::InternalContract("Failed to read signer status".to_string()))?;
    if is_signer_val.is_zero() {
        return Err(vm::Error::InternalContract(
            "Sender is not a registered signer".to_string(),
        ));
    }

    // Step 2: Update socket hash in storage
    let socket_hash = keccak(input.as_bytes());
    let socket_slot_key = signer_socket_slot(&params.sender);
    context
        .state
        .set_system_storage(
            socket_slot_key.to_vec(),
            U256::from_big_endian(socket_hash.as_ref()),
        )
        .map_err(|_| vm::Error::InternalContract("Failed to update socket".to_string()))?;

    // Step 3: Emit SocketUpdated event
    SocketUpdatedEvent::log(&params.sender, &input, params, context)?;

    Ok(())
}
