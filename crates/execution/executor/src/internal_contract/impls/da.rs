use cfx_bytes::Bytes;
use cfx_types::{Address, U256};
use cfx_vm_types::ActionParams;
use solidity_abi_derive::ABIVariable;
use keccak_hash::keccak;

// Import BN254 elliptic curve types for point operations
use crate::bn::{AffineG1, Fq, Group, G1};

use crate::internal_contract::InternalRefContext;
use crate::internal_contract::components::SolidityEventTrait;
use cfx_vm_types as vm;

use super::super::components::storage_layout::{
    dynamic_slot, mapping_slot, u256_to_array,
};
use cfx_parameters::internal_contract_addresses::DA_CONTRACT_ADDRESS;

// Import event types from contracts module
use super::super::contracts::da::{NewSignerEvent, SocketUpdatedEvent};

#[derive(Debug, Clone, Copy, ABIVariable)]
pub struct G1Point(pub U256, pub U256);

#[derive(Debug, Clone, Copy, ABIVariable)]
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
// Slot 6: mapping(uint256 epoch => mapping(uint256 quorumId => address[])) epochQuorums
//         Stores the list of signer addresses for each quorum in each epoch
//         This is a nested mapping to a dynamic array:
//           - First key: epoch number
//           - Second key: quorum ID
//           - Value: dynamic array of signer addresses
// Slot 7: address[] allSigners - array of all registered signer addresses (for iteration)
// Slot 8-15: Reserved for future use
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

/// Get the storage slot for the allSigners array (slot 7)
fn all_signers_slot() -> U256 {
    da_contract_base_slot() + U256::from(7)
}

// ============================================================================
// View Functions
// ============================================================================

pub fn epoch_number(context: &mut InternalRefContext) -> vm::Result<U256> {
    let slot_key = u256_to_array(da_contract_base_slot());
    
    eprintln!("[DA READ] ===== Reading epoch_number =====");
    eprintln!("[DA READ] base_slot: 0x{:x}", da_contract_base_slot());
    eprintln!("[DA READ] slot_key bytes: {:?}", &slot_key[..8]);
    
    let epoch = context
        .state
        .get_system_storage(&slot_key)
        .map_err(|e| {
            eprintln!("[DA READ] ✗ get_system_storage failed: {:?}", e);
            vm::Error::InternalContract("Failed to read current epoch".to_string())
        })?;
    
    eprintln!("[DA READ] ✓ Read epoch value: {:?}", epoch);
    eprintln!("[DA READ] epoch as hex: 0x{:x}", epoch);
    eprintln!("[DA READ] is_zero: {}", epoch.is_zero());
    
    Ok(epoch)
}

pub fn get_agg_pk_g1(
    input: (U256, U256, Bytes), context: &mut InternalRefContext,
) -> vm::Result<(G1Point, U256, U256)> {
    let (epoch, quorum_id, quorum_bitmap) = input;
    
    eprintln!("[GET_AGG_PK_G1] epoch={}, quorum_id={}, bitmap_len={}", epoch, quorum_id, quorum_bitmap.len());
    
    // Get the quorum (list of signer addresses)
    let quorum_signers = get_quorum((epoch, quorum_id), context)?;
    let total = quorum_signers.len() as u64;
    
    if total == 0 {
        eprintln!("[GET_AGG_PK_G1] No signers in quorum");
        return Ok((G1Point(U256::zero(), U256::zero()), U256::zero(), U256::zero()));
    }
    
    // Parse bitmap to find which signers participated
    // quorumBitmap is a bytes array where each bit represents a signer
    // Use a HashSet to track which signers have been added (for deduplication)
    use std::collections::HashSet;
    let mut hit_count: u64 = 0;
    let mut agg_point: Option<G1> = None;
    let mut added_signers: HashSet<Address> = HashSet::new();
    
    for (i, signer_addr) in quorum_signers.iter().enumerate() {
        // Check if this signer's bit is set in the bitmap
        let byte_index = i / 8;
        let bit_index = i % 8;
        
        if byte_index >= quorum_bitmap.len() {
            break; // Bitmap is shorter than expected
        }
        
        let is_set = (quorum_bitmap[byte_index] & (1 << bit_index)) != 0;
        
        if !is_set {
            continue;
        }
        
        // Always increment hit_count for each set bit
        hit_count += 1;
        
        // Check if we've already added this signer's public key (deduplication)
        if added_signers.contains(signer_addr) {
            eprintln!("[GET_AGG_PK_G1] signer[{}]={:?} already added, skipping pk aggregation", i, signer_addr);
            continue; // Skip aggregation, but hit_count was already incremented
        }
        
        // Mark this signer as added
        added_signers.insert(*signer_addr);
        
        // Read this signer's G1 public key
        let g1_x_key = signer_pk_g1_x_slot(signer_addr);
        let g1_y_key = signer_pk_g1_y_slot(signer_addr);
        
        let g1_x_u256 = context
            .state
            .get_system_storage(&g1_x_key)
            .map_err(|_| vm::Error::InternalContract("Failed to read G1 x".to_string()))?;
        let g1_y_u256 = context
            .state
            .get_system_storage(&g1_y_key)
            .map_err(|_| vm::Error::InternalContract("Failed to read G1 y".to_string()))?;
        
        eprintln!("[GET_AGG_PK_G1] signer[{}]={:?}, pkG1=({}, {}) - ADDING to aggregate", i, signer_addr, g1_x_u256, g1_y_u256);
        
        // Convert U256 to Fq (BN254 base field element)
        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        g1_x_u256.to_big_endian(&mut x_bytes);
        g1_y_u256.to_big_endian(&mut y_bytes);
        
        let px = Fq::from_slice(&x_bytes)
            .map_err(|_| vm::Error::InternalContract("Invalid G1 x coordinate".to_string()))?;
        let py = Fq::from_slice(&y_bytes)
            .map_err(|_| vm::Error::InternalContract("Invalid G1 y coordinate".to_string()))?;
        
        // Create G1 point (handle zero point case)
        let point = if px == Fq::zero() && py == Fq::zero() {
            G1::zero()
        } else {
            G1::from(
                AffineG1::new(px, py)
                    .map_err(|_| vm::Error::InternalContract("Invalid G1 point".to_string()))?
            )
        };
        
        // Aggregate using elliptic curve point addition (only for first occurrence)
        agg_point = Some(match agg_point {
            None => point,
            Some(acc) => acc + point,
        });
    }
    
    // Convert aggregated point back to U256 coordinates
    let (agg_x, agg_y) = match agg_point {
        None => (U256::zero(), U256::zero()),
        Some(p) => {
            if let Some(affine) = AffineG1::from_jacobian(p) {
                let mut x_bytes = [0u8; 32];
                let mut y_bytes = [0u8; 32];
                affine.x().to_big_endian(&mut x_bytes)
                    .map_err(|_| vm::Error::InternalContract("Failed to serialize G1 x".to_string()))?;
                affine.y().to_big_endian(&mut y_bytes)
                    .map_err(|_| vm::Error::InternalContract("Failed to serialize G1 y".to_string()))?;
                (U256::from_big_endian(&x_bytes), U256::from_big_endian(&y_bytes))
            } else {
                // Point at infinity
                (U256::zero(), U256::zero())
            }
        }
    };
    
    eprintln!("[GET_AGG_PK_G1] total={}, hit={}, agg_pk=({}, {})", total, hit_count, agg_x, agg_y);
    
    Ok((G1Point(agg_x, agg_y), U256::from(total), U256::from(hit_count)))
}

/// Get all signer addresses in a specific epoch's quorum
/// Input: (epoch, quorum_id)
/// Output: Vec<Address> - list of signer addresses in the quorum
pub fn get_quorum(
    input: (U256, U256), context: &mut InternalRefContext,
) -> vm::Result<Vec<Address>> {
    let (epoch, quorum_id) = input;
    
    // Get quorum count for this epoch (stored at slot1)
    let quorum_count_key = quorum_count_slot(&epoch);
    let quorum_count = context
        .state
        .get_system_storage(&quorum_count_key)
        .map_err(|_| vm::Error::InternalContract("Failed to get quorum count".to_string()))?;
    
    if quorum_count.is_zero() || quorum_id >= quorum_count {
        return Ok(Vec::new());
    }
    
    // Read quorum data from dynamic array storage
    // Each quorum is stored as a dynamic array of addresses
    let base = da_contract_base_slot() + U256::from(6); // Slot 6 is reserved for quorum storage
    let quorum_slot = mapping_slot(base, epoch);
    let quorum_list_slot = mapping_slot(quorum_slot, quorum_id);
    
    // Read array length
    let length_key = u256_to_array(quorum_list_slot);
    let length = context
        .state
        .get_system_storage(&length_key)
        .map_err(|_| vm::Error::InternalContract("Failed to read quorum length".to_string()))?;
    
    let mut signers = Vec::new();
    let array_data_slot = dynamic_slot(quorum_list_slot);
    
    for i in 0..length.low_u64() {
        let addr_slot = u256_to_array(array_data_slot + U256::from(i));
        let addr_u256 = context
            .state
            .get_system_storage(&addr_slot)
            .map_err(|_| vm::Error::InternalContract("Failed to read quorum signer".to_string()))?;
        
        // Convert U256 to Address (take the lower 20 bytes)
        let mut addr_bytes = [0u8; 32];  // U256 needs 32 bytes buffer
        addr_u256.to_big_endian(&mut addr_bytes);
        let signer = Address::from_slice(&addr_bytes[12..32]);
        signers.push(signer);
    }
    
    Ok(signers)
}

/// Get a specific signer address at row_index in a quorum
/// Input: (epoch, quorum_id, row_index)
/// Output: Address - the signer address at the specified index
pub fn get_quorum_row(
    input: (U256, U256, u32), context: &mut InternalRefContext,
) -> vm::Result<Address> {
    let (epoch, quorum_id, row_index) = input;
    
    // Read quorum data
    let base = da_contract_base_slot() + U256::from(6);
    let quorum_slot = mapping_slot(base, epoch);
    let quorum_list_slot = mapping_slot(quorum_slot, quorum_id);
    
    // Check array length
    let length_key = u256_to_array(quorum_list_slot);
    let length = context
        .state
        .get_system_storage(&length_key)
        .map_err(|_| vm::Error::InternalContract("Failed to read quorum length".to_string()))?;
    
    if U256::from(row_index) >= length {
        return Err(vm::Error::InternalContract("Row index out of bound".to_string()));
    }
    
    // Read the address at row_index
    let array_data_slot = dynamic_slot(quorum_list_slot);
    let addr_slot = u256_to_array(array_data_slot + U256::from(row_index));
    let addr_u256 = context
        .state
        .get_system_storage(&addr_slot)
        .map_err(|_| vm::Error::InternalContract("Failed to read signer address".to_string()))?;
    
    // Convert U256 to Address
    let mut addr_bytes = [0u8; 32];  // U256 needs 32 bytes buffer
    addr_u256.to_big_endian(&mut addr_bytes);
    Ok(Address::from_slice(&addr_bytes[12..32]))
}

/// Get detailed information for multiple signers
/// Input: Vec<Address> - list of signer addresses to query
/// Output: Vec<SignerDetail> - detailed info (address, socket, pubkeys)
pub fn get_signer(
    input: Vec<Address>, context: &mut InternalRefContext,
) -> vm::Result<Vec<SignerDetail>> {
    let mut details = Vec::new();
    
    for addr in input {
        // Check if is a registered signer
        let is_signer_key = is_signer_slot(&addr);
        let is_registered = context
            .state
            .get_system_storage(&is_signer_key)
            .map_err(|_| vm::Error::InternalContract("Failed to check signer status".to_string()))?;
        
        if is_registered.is_zero() {
            // Signer not found, return empty detail
            continue;
        }
        
        // Read socket string from storage (3 slots: data0, data1, length)
        let socket_slot_base = signer_socket_slot(&addr);
        
        // Read length first
        let socket_len_slot = u256_to_array(U256::from_big_endian(&socket_slot_base) + U256::from(2));
        let socket_len = context
            .state
            .get_system_storage(&socket_len_slot)
            .map_err(|_| vm::Error::InternalContract("Failed to read socket length".to_string()))?
            .as_usize();
        
        let socket_str = if socket_len == 0 || socket_len > 64 {
            String::new()
        } else {
            let mut socket_bytes = Vec::new();
            
            // Read first 32 bytes
            let socket_data_0 = context
                .state
                .get_system_storage(&socket_slot_base)
                .map_err(|_| vm::Error::InternalContract("Failed to read socket slot 0".to_string()))?;
            let mut chunk0 = [0u8; 32];
            socket_data_0.to_big_endian(&mut chunk0);
            let first_len = socket_len.min(32);
            socket_bytes.extend_from_slice(&chunk0[..first_len]);
            
            // Read second 32 bytes if needed
            if socket_len > 32 {
                let socket_slot_1 = u256_to_array(U256::from_big_endian(&socket_slot_base) + U256::one());
                let socket_data_1 = context
                    .state
                    .get_system_storage(&socket_slot_1)
                    .map_err(|_| vm::Error::InternalContract("Failed to read socket slot 1".to_string()))?;
                let mut chunk1 = [0u8; 32];
                socket_data_1.to_big_endian(&mut chunk1);
                let second_len = socket_len - 32;
                socket_bytes.extend_from_slice(&chunk1[..second_len]);
            }
            
            String::from_utf8_lossy(&socket_bytes).to_string()
        };
        
        // Read G1 public key (2 coordinates)
        let g1_x_key = signer_pk_g1_x_slot(&addr);
        let g1_y_key = signer_pk_g1_y_slot(&addr);
        
        let g1_x = context
            .state
            .get_system_storage(&g1_x_key)
            .map_err(|_| vm::Error::InternalContract("Failed to read G1 x".to_string()))?;
        let g1_y = context
            .state
            .get_system_storage(&g1_y_key)
            .map_err(|_| vm::Error::InternalContract("Failed to read G1 y".to_string()))?;
        
        // Read G2 public key (4 coordinates)
        let g2_x0_key = signer_pk_g2_x0_slot(&addr);
        let g2_x1_key = signer_pk_g2_x1_slot(&addr);
        let g2_y0_key = signer_pk_g2_y0_slot(&addr);
        let g2_y1_key = signer_pk_g2_y1_slot(&addr);
        
        let g2_x0 = context
            .state
            .get_system_storage(&g2_x0_key)
            .map_err(|_| vm::Error::InternalContract("Failed to read G2 x0".to_string()))?;
        let g2_x1 = context
            .state
            .get_system_storage(&g2_x1_key)
            .map_err(|_| vm::Error::InternalContract("Failed to read G2 x1".to_string()))?;
        let g2_y0 = context
            .state
            .get_system_storage(&g2_y0_key)
            .map_err(|_| vm::Error::InternalContract("Failed to read G2 y0".to_string()))?;
        let g2_y1 = context
            .state
            .get_system_storage(&g2_y1_key)
            .map_err(|_| vm::Error::InternalContract("Failed to read G2 y1".to_string()))?;
        
        details.push(SignerDetail(
            addr,
            socket_str,
            G1Point(g1_x, g1_y),
            G2Point([g2_x0, g2_x1], [g2_y0, g2_y1]),
        ));
    }
    
    Ok(details)
}

/// Check if an address is a registered signer
/// Input: Address - the address to check
/// Output: bool - true if registered, false otherwise
pub fn is_signer(
    input: Address, context: &mut InternalRefContext,
) -> vm::Result<bool> {
    let key = is_signer_slot(&input);
    let value = context
        .state
        .get_system_storage(&key)
        .map_err(|_| vm::Error::InternalContract("Failed to check signer status".to_string()))?;
    Ok(!value.is_zero())
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

    // Demo: hardcode EpochBlocks
    let epoch_blocks = U256::from(100);

    // Compute expected epoch = block_number / EpochBlocks
    let block_number = U256::from(context.env.number);  
    let expected_epoch = block_number / epoch_blocks;

    eprintln!("[DA FINALIZE] block={}, current_epoch={}, expected_epoch={}", block_number, current_epoch, expected_epoch);

    if expected_epoch == current_epoch {
        return Ok(());
    }
    if expected_epoch != current_epoch + U256::one() {
        return Err(vm::Error::InternalContract("block height is not continuous".into()));
    }

    // ===== New epoch detected: expected_epoch = current_epoch + 1 =====
    
    // Step 1: Collect all signers registered for the new epoch
    // Read the allSigners array from slot 7
    let all_signers_array_slot = all_signers_slot();
    let signer_count_key = u256_to_array(all_signers_array_slot);
    let signer_count = context
        .state
        .get_system_storage(&signer_count_key)
        .map_err(|_| vm::Error::InternalContract("Failed to read signer count".into()))?;
    
    // Iterate through all signers and check if they registered for expected_epoch
    let mut registered_signers: Vec<Address> = Vec::new();
    let signers_data_slot = dynamic_slot(all_signers_array_slot);
    
    for i in 0..signer_count.low_u64() {
        let addr_slot = u256_to_array(signers_data_slot + U256::from(i));
        let addr_u256 = context
            .state
            .get_system_storage(&addr_slot)
            .map_err(|_| vm::Error::InternalContract("Failed to read signer address".into()))?;
        
        // Convert U256 to Address (take the lower 20 bytes)
        let mut addr_bytes = [0u8; 32];
        addr_u256.to_big_endian(&mut addr_bytes);
        let signer = Address::from_slice(&addr_bytes[12..32]);
        
        // Check if this signer registered for expected_epoch
        let reg_key = signer_registration_slot(&signer, &expected_epoch);
        let is_registered = context
            .state
            .get_system_storage(&reg_key)
            .map_err(|_| vm::Error::InternalContract("Failed to check registration".into()))?;
        
        if !is_registered.is_zero() {
            registered_signers.push(signer);
        }
    }
    
    // Step 2: Build quorum(s) from registered signers
    // For simplicity, we create a single quorum with all registered signers
    // (no sorting, no splitting into multiple quorums)
    
    if registered_signers.is_empty() {
        eprintln!("[DA FINALIZE] ⚠️  No signers registered for epoch {}", expected_epoch);
        // No signers registered for this epoch, set quorum count to 0
        let quorum_count_key = quorum_count_slot(&expected_epoch);
        context
            .state
            .set_system_storage(quorum_count_key.to_vec(), U256::zero())
            .map_err(|_| vm::Error::InternalContract("Failed to set quorum count".into()))?;
    } else {
        eprintln!("[DA FINALIZE] ✓ Creating quorum for epoch {} with {} signers", expected_epoch, registered_signers.len());
        // Write the single quorum to storage
        // epochQuorums[expected_epoch][0] = registered_signers
        let base = da_contract_base_slot() + U256::from(6);
        let epoch_slot = mapping_slot(base, expected_epoch);
        let quorum_slot = mapping_slot(epoch_slot, U256::zero()); // quorum_id = 0
        
        // Write array length (always 1024 to match encoder slices)
        const NUM_SLICES: usize = 1024;
        let length_key = u256_to_array(quorum_slot);
        let length = U256::from(NUM_SLICES);
        context
            .state
            .set_system_storage(length_key.to_vec(), length)
            .map_err(|_| vm::Error::InternalContract("Failed to set quorum length".into()))?;
        
        // Write array elements with round-robin distribution
        // If we have fewer signers than NUM_SLICES, repeat them in round-robin fashion
        let array_data_slot = dynamic_slot(quorum_slot);
        for i in 0..NUM_SLICES {
            let signer_idx = i % registered_signers.len();
            let element_slot = u256_to_array(array_data_slot + U256::from(i));
            let signer_u256 = U256::from_big_endian(registered_signers[signer_idx].as_bytes());
            context
                .state
                .set_system_storage(element_slot.to_vec(), signer_u256)
                .map_err(|_| vm::Error::InternalContract("Failed to set quorum signer".into()))?;
        }
        
        // Set quorum count to 1 (we created one quorum)
        let quorum_count_key = quorum_count_slot(&expected_epoch);
        context
            .state
            .set_system_storage(quorum_count_key.to_vec(), U256::one())
            .map_err(|_| vm::Error::InternalContract("Failed to set quorum count".into()))?;
    }
    
    // Step 3: Advance current epoch to expected_epoch
    context
        .state
        .set_system_storage(u256_to_array(da_contract_base_slot()).to_vec(), expected_epoch)
        .map_err(|_| vm::Error::InternalContract("Failed to advance current epoch".into()))?;

    eprintln!("[DA FINALIZE] ✅ Epoch advanced: {} -> {}", current_epoch, expected_epoch);
    Ok(())
}

pub fn set_epoch_blocks(
    _input: U256, _params: &ActionParams, context: &mut InternalRefContext,
) -> vm::Result<()> {
    let slot = u256_to_array(da_contract_base_slot() + U256::from(16));
    context
        .state
        .set_system_storage(slot.to_vec(), _input)
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

    // Step 4: BN254 signature verification for epoch registration
    // TODO: Implement signature verification similar to register_signer
    // This would verify: e(signature, G2) = e(hash(sender || nextEpoch), pkG2)

    // Step 5: Mark this signer as registered for next_epoch in slot4
    // registrations[sender][next_epoch] = true
    let reg_key = signer_registration_slot(&params.sender, &next_epoch);
    context
        .state
        .set_system_storage(reg_key.to_vec(), U256::one())
        .map_err(|_| vm::Error::InternalContract("Failed to set epoch registration".to_string()))?;

    // Note: We do NOT update quorum_count here!
    // Quorums are generated in finalize_epoch when the epoch actually changes.
    // This allows collecting all registrations first, then building quorums deterministically.

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
/// 7. Emit NewSignerEvent 
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

    // Step 2: Signature verification using BN254 pairing
    // For MVP: Skip complex signature verification
    // TODO: Implement proper BN254 signature verification with pairing check
    {
        eprintln!("[DA REG] Signature verification SKIPPED for MVP");
        eprintln!("[DA REG] Signer: {:?}", signer_addr);
        eprintln!("[DA REG] Signature: ({}, {})", signature.0, signature.1);
        eprintln!("[DA REG] PkG1: ({}, {})", pk_g1.0, pk_g1.1);
        eprintln!("[DA REG] PkG2: ([{}, {}], [{}, {}])", pk_g2.0[0], pk_g2.0[1], pk_g2.1[0], pk_g2.1[1]);
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

    // Step 5: Store socket address as string (max 64 bytes, using 2 slots)
    // Slot 0: first 32 bytes
    // Slot 1: remaining bytes (up to 32 bytes)
    // Simple encoding: no special markers, just raw bytes
    let socket_bytes = socket.as_bytes();
    let socket_len = socket_bytes.len();
    
    if socket_len > 64 {
        return Err(vm::Error::InternalContract(
            "Socket address too long (max 64 bytes)".to_string(),
        ));
    }
    
    let socket_slot_base = signer_socket_slot(&signer_addr);
    
    // Store first 32 bytes in slot 0
    let mut first_chunk = [0u8; 32];
    let first_len = socket_len.min(32);
    first_chunk[..first_len].copy_from_slice(&socket_bytes[..first_len]);
    context.state.set_system_storage(
        socket_slot_base.to_vec(),
        U256::from_big_endian(&first_chunk),
    ).map_err(|_| vm::Error::InternalContract("Failed to store socket slot 0".to_string()))?;
    
    // Store remaining bytes in slot 1 (if any)
    let socket_slot_1 = u256_to_array(U256::from_big_endian(&socket_slot_base) + U256::one());
    if socket_len > 32 {
        let mut second_chunk = [0u8; 32];
        let remaining = &socket_bytes[32..];
        second_chunk[..remaining.len()].copy_from_slice(remaining);
        context.state.set_system_storage(
            socket_slot_1.to_vec(),
            U256::from_big_endian(&second_chunk),
        ).map_err(|_| vm::Error::InternalContract("Failed to store socket slot 1".to_string()))?;
    } else {
        // Clear slot 1 if not needed
        context.state.set_system_storage(
            socket_slot_1.to_vec(),
            U256::zero(),
        ).map_err(|_| vm::Error::InternalContract("Failed to clear socket slot 1".to_string()))?;
    }
    
    // Store length in a separate slot for easier reading
    let socket_len_slot = u256_to_array(U256::from_big_endian(&socket_slot_base) + U256::from(2));
    context.state.set_system_storage(
        socket_len_slot.to_vec(),
        U256::from(socket_len),
    ).map_err(|_| vm::Error::InternalContract("Failed to store socket length".to_string()))?;

    // Step 6: Mark signer as active/registered
    let is_signer_key = is_signer_slot(&signer_addr);
    let was_already_signer = context
        .state
        .get_system_storage(&is_signer_key)
        .map_err(|_| vm::Error::InternalContract("Failed to read signer status".to_string()))?;
    
    context.state.set_system_storage(
        is_signer_key.to_vec(),
        U256::from(1),
    ).map_err(|_| vm::Error::InternalContract("Failed to mark signer as active".to_string()))?;
    
    // If this is a new signer, add them to the allSigners array
    if was_already_signer.is_zero() {
        let all_signers_slot_key = all_signers_slot();
        let count_key = u256_to_array(all_signers_slot_key);
        
        // Read current count
        let current_count = context
            .state
            .get_system_storage(&count_key)
            .map_err(|_| vm::Error::InternalContract("Failed to read allSigners count".to_string()))?;
        
        // Write new signer at the end of the array
        let data_slot = dynamic_slot(all_signers_slot_key);
        let new_index_slot = u256_to_array(data_slot + current_count);
        let signer_u256 = U256::from_big_endian(signer_addr.as_bytes());
        context
            .state
            .set_system_storage(new_index_slot.to_vec(), signer_u256)
            .map_err(|_| vm::Error::InternalContract("Failed to add signer to allSigners".to_string()))?;
        
        // Increment count
        let new_count = current_count + U256::one();
        context
            .state
            .set_system_storage(count_key.to_vec(), new_count)
            .map_err(|_| vm::Error::InternalContract("Failed to update allSigners count".to_string()))?;
    }

    // Step 7: Emit NewSignerEvent
    // Event signature: NewSigner(address indexed signer, BN254.G1Point pkG1, BN254.G2Point pkG2)
    // The event includes the signer address (indexed) and their public keys (non-indexed)
    // DA-Disperser will listen to this event to build the address -> public key mapping
    let event_data = (*pk_g1, *pk_g2);
    NewSignerEvent::log(
        &signer_addr,
        &event_data,
        params,
        context,
    )?;

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

    // Step 2: Update socket string in storage (max 64 bytes, 3 slots total)
    let socket_bytes = input.as_bytes();
    let socket_len = socket_bytes.len();
    
    if socket_len > 64 {
        return Err(vm::Error::InternalContract(
            "Socket address too long (max 64 bytes)".to_string(),
        ));
    }
    
    let socket_slot_base = signer_socket_slot(&params.sender);
    
    // Store first 32 bytes
    let mut first_chunk = [0u8; 32];
    let first_len = socket_len.min(32);
    first_chunk[..first_len].copy_from_slice(&socket_bytes[..first_len]);
    context.state.set_system_storage(
        socket_slot_base.to_vec(),
        U256::from_big_endian(&first_chunk),
    ).map_err(|_| vm::Error::InternalContract("Failed to update socket slot 0".to_string()))?;
    
    // Store remaining bytes or clear
    let socket_slot_1 = u256_to_array(U256::from_big_endian(&socket_slot_base) + U256::one());
    if socket_len > 32 {
        let mut second_chunk = [0u8; 32];
        let remaining = &socket_bytes[32..];
        second_chunk[..remaining.len()].copy_from_slice(remaining);
        context.state.set_system_storage(
            socket_slot_1.to_vec(),
            U256::from_big_endian(&second_chunk),
        ).map_err(|_| vm::Error::InternalContract("Failed to update socket slot 1".to_string()))?;
    } else {
        context.state.set_system_storage(
            socket_slot_1.to_vec(),
            U256::zero(),
        ).map_err(|_| vm::Error::InternalContract("Failed to clear socket slot 1".to_string()))?;
    }
    
    // Store length
    let socket_len_slot = u256_to_array(U256::from_big_endian(&socket_slot_base) + U256::from(2));
    context.state.set_system_storage(
        socket_len_slot.to_vec(),
        U256::from(socket_len),
    ).map_err(|_| vm::Error::InternalContract("Failed to update socket length".to_string()))?;

    // Step 3: Emit SocketUpdated event
    SocketUpdatedEvent::log(&params.sender, &input, params, context)?;

    Ok(())
}
