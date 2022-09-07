use failure::format_err;
use ffi_helpers::panic::catch_panic;
use hdwallet::{
    traits::{Deserialize, Serialize},
    ExtendedPrivKey, KeyChain,
};
use schemer::MigratorError;
use secp256k1::PublicKey;
use secrecy::Secret;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::{CStr, CString, OsStr};
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::slice;
use std::str::FromStr;

use zcash_client_backend::{
    address::RecipientAddress,
    data_api::{
        chain::{scan_cached_blocks, validate_chain},
        error::Error,
        wallet::{
            create_spend_to_address, decrypt_and_store_transaction, shield_transparent_funds,
        },
        WalletRead, WalletReadTransparent, WalletWrite, WalletWriteTransparent,
    },
    encoding::{
        decode_extended_full_viewing_key, decode_extended_spending_key,
        encode_extended_full_viewing_key, encode_extended_spending_key, encode_payment_address,
        AddressCodec,
    },
    keys::{sapling, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::{OvkPolicy, WalletTransparentOutput},
};
#[allow(deprecated)]
use zcash_client_sqlite::wallet::{delete_utxos_above, get_rewind_height};
use zcash_client_sqlite::{
    error::SqliteClientError,
    wallet::init::{init_accounts_table, init_blocks_table, init_wallet_db, WalletMigrationError},
    BlockDb, NoteId, WalletDb,
};
use zcash_primitives::consensus::Network::{MainNetwork, TestNetwork};
use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, BranchId, Network, Parameters},
    legacy::{self, keys::IncomingViewingKey, TransparentAddress},
    memo::{Memo, MemoBytes},
    transaction::{
        components::{Amount, OutPoint, TxOut},
        Transaction,
    },
    zip32::{AccountId, ExtendedFullViewingKey},
};
use zcash_proofs::prover::LocalTxProver;

const ANCHOR_OFFSET: u32 = 10;

fn unwrap_exc_or<T>(exc: Result<T, ()>, def: T) -> T {
    match exc {
        Ok(value) => value,
        Err(_) => def,
    }
}

fn unwrap_exc_or_null<T>(exc: Result<T, ()>) -> T
where
    T: ffi_helpers::Nullable,
{
    match exc {
        Ok(value) => value,
        Err(_) => ffi_helpers::Nullable::NULL,
    }
}

/// Helper method for construcing a WalletDb value from path data provided over the FFI.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
unsafe fn wallet_db(
    db_data: *const u8,
    db_data_len: usize,
    network: Network,
) -> Result<WalletDb<Network>, failure::Error> {
    let db_data = Path::new(OsStr::from_bytes(slice::from_raw_parts(
        db_data,
        db_data_len,
    )));
    WalletDb::for_path(db_data, network)
        .map_err(|e| format_err!("Error opening wallet database connection: {}", e))
}

/// Helper method for construcing a BlockDb value from path data provided over the FFI.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
unsafe fn block_db(cache_db: *const u8, cache_db_len: usize) -> Result<BlockDb, failure::Error> {
    let cache_db = Path::new(OsStr::from_bytes(slice::from_raw_parts(
        cache_db,
        cache_db_len,
    )));
    BlockDb::for_path(cache_db)
        .map_err(|e| format_err!("Error opening block source database connection: {}", e))
}

/// Returns the length of the last error message to be logged.
#[no_mangle]
pub extern "C" fn zcashlc_last_error_length() -> i32 {
    ffi_helpers::error_handling::last_error_length()
}

/// Copies the last error message into the provided allocated buffer.
///
/// # Safety
///
/// - `buf` must be non-null and valid for reads for `length` bytes, and it must have an alignment
///   of `1`.
/// - The memory referenced by `buf` must not be mutated for the duration of the function call.
/// - The total size `length` must be no larger than `isize::MAX`. See the safety documentation of
///   pointer::offset.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_error_message_utf8(buf: *mut c_char, length: i32) -> i32 {
    ffi_helpers::error_handling::error_message_utf8(buf, length)
}

/// Clears the record of the last error message.
#[no_mangle]
pub extern "C" fn zcashlc_clear_last_error() {
    ffi_helpers::error_handling::clear_last_error()
}

/// Sets up the internal structure of the data database.  The value for `seed` may be provided as a
/// null pointer if the caller wishes to attempt migrations without providing the wallet's seed
/// value.
///
/// Returns 0 if successful, 1 if the seed must be provided in order to execute the requested
/// migrations, or -1 otherwise.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_init_data_database(
    db_data: *const u8,
    db_data_len: usize,
    seed: *const u8,
    seed_len: usize,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let mut db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let seed = if seed.is_null() {
            None
        } else {
            Some(Secret::new(
                (unsafe { slice::from_raw_parts(seed, seed_len) }).to_vec(),
            ))
        };

        match init_wallet_db(&mut db_data, seed) {
            Ok(_) => Ok(0),
            Err(MigratorError::Adapter(WalletMigrationError::SeedRequired)) => Ok(1),
            Err(e) => Err(format_err!("Error while initializing data DB: {}", e)),
        }
    });
    unwrap_exc_or(res, -1)
}

/// Initialises the data database with the given number of accounts using the given seed.
/// Accounts will be sequentially numbered starting from `0`.
///
/// Returns the Bech32-encoded string representation of the ExtendedSpendingKey for each account,
/// in order of account identifier, encoded as null-terminated UTF-8 strings. The caller should
/// manage the memory of (and store) the returned spending keys in a secure fashion.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
/// - Call [`zcashlc_free_keys`] to free the memory associated with the returned pointer when
///   you are finished using it.
#[no_mangle]
pub extern "C" fn zcashlc_init_accounts_table(
    db_data: *const u8,
    db_data_len: usize,
    seed: *const u8,
    seed_len: usize,
    accounts: i32,
    network_id: u32,
) -> *mut FFIEncodedKeys {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let seed = unsafe { slice::from_raw_parts(seed, seed_len) };
        let accounts = if accounts >= 0 {
            accounts as u32
        } else {
            return Err(format_err!("accounts argument must be positive"));
        };

        let usks: Vec<_> = (0..accounts)
            .map(|account| {
                let account_id = AccountId::from(account);
                UnifiedSpendingKey::from_seed(&network, seed, account_id)
                    .map(|usk| (account_id, usk))
                    .map_err(|e| {
                        format_err!("error generating unified spending key from seed: {:?}", e)
                    })
            })
            .collect::<Result<_, _>>()?;

        let ufvks: HashMap<AccountId, UnifiedFullViewingKey> = usks
            .iter()
            .map(|(account, usk)| (*account, usk.to_unified_full_viewing_key()))
            .collect();

        init_accounts_table(&db_data, &ufvks)
            .map(|_| {
                // Return the Sapling ExtendedSpendingKeys for the created accounts.
                let v: Vec<_> = usks
                    .iter()
                    .map(|(account, usk)| {
                        let encoded = encode_extended_spending_key(
                            network.hrp_sapling_extended_spending_key(),
                            usk.sapling(),
                        );
                        FFIEncodedKey::new(*account, encoded)
                    })
                    .collect();

                FFIEncodedKeys::ptr_from_vec(v)
            })
            .map_err(|e| format_err!("Error while initializing accounts: {}", e))
    });
    unwrap_exc_or_null(res)
}

/// Initialises the data database with the given set of unified full viewing keys.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `uvks` must be non-null and must point to a struct having the layout of [`FFIEncodedKeys`].
///   See the safety documentation of [`FFIEncodedKeys`].
#[no_mangle]
pub extern "C" fn zcashlc_init_accounts_table_with_keys(
    db_data: *const u8,
    db_data_len: usize,
    uvks: *mut FFIEncodedKeys,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let s: Box<FFIEncodedKeys> = unsafe { Box::from_raw(uvks) };
        let slice: &mut [FFIEncodedKey] = unsafe { slice::from_raw_parts_mut(s.ptr, s.len) };

        let ufvks: HashMap<AccountId, UnifiedFullViewingKey> = slice
            .iter_mut()
            .map(|u| {
                let ufvkstr = unsafe { CStr::from_ptr(u.encoding).to_str().unwrap() };
                UnifiedFullViewingKey::decode(&network, ufvkstr)
                    .map(|ufvk| (AccountId::from(u.account_id), ufvk))
            })
            .collect::<Result<HashMap<_, _>, _>>()
            .map_err(|e| format_err!("Error decoding unified full viewing keys: {:?}", e))?;

        match init_accounts_table(&db_data, &ufvks) {
            Ok(()) => Ok(true),
            Err(e) => Err(format_err!("Error while initializing accounts: {}", e)),
        }
    });
    unwrap_exc_or(res, false)
}

/// Derives and returns Sapling extended spending keys from the given seed for the given number of
/// accounts. Accounts will be sequentially numbered starting at `0`.
///
/// Returns the Bech32-encoded string representation of the ExtendedSpendingKey for each
/// account, in order of account identifier, encoded as null-terminated UTF-8 strings. The caller
/// should manage the memory of (and store) the returned spending keys in a secure fashion.
///
/// # Safety
///
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
/// - Call `zcashlc_free_keys` to free the memory associated with the returned pointer when
///   you are finished using it.
#[no_mangle]
pub unsafe extern "C" fn zcashlc_derive_extended_spending_keys(
    seed: *const u8,
    seed_len: usize,
    accounts: i32,
    network_id: u32,
) -> *mut FFIEncodedKeys {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let seed = slice::from_raw_parts(seed, seed_len);
        let accounts = if accounts > 0 {
            accounts as u32
        } else {
            return Err(format_err!("accounts argument must be greater than zero"));
        };

        Ok(FFIEncodedKeys::ptr_from_vec(
            (0..accounts)
                .map(|account| {
                    let account = AccountId::from(account);
                    UnifiedSpendingKey::from_seed(&network, seed, account)
                        .map_err(|e| {
                            format_err!("error generating unified spending key from seed: {:?}", e)
                        })
                        .map(move |usk| {
                            let encoded = encode_extended_spending_key(
                                network.hrp_sapling_extended_spending_key(),
                                usk.sapling(),
                            );
                            FFIEncodedKey::new(account, encoded)
                        })
                })
                .collect::<Result<_, _>>()?,
        ))
    });
    unwrap_exc_or_null(res)
}

/// A struct that contains an account identifier along with a pointer to the string encoding
/// of a [`UnifiedFullViewingKey`] value.
///
/// # Safety
///
/// - `encoding` must be non-null and must point to a null-terminated UTF-8 string.
#[repr(C)]
pub struct FFIEncodedKey {
    account_id: u32,
    encoding: *const c_char,
}

impl FFIEncodedKey {
    fn new(account_id: AccountId, encoded: String) -> Self {
        FFIEncodedKey {
            account_id: account_id.into(),
            encoding: CString::new(encoded).unwrap().into_raw(),
        }
    }
}

/// A struct that contains a pointer to, and length information for, a heap-allocated
/// slice of [`FFIEncodedKey`] values.
///
/// # Safety
///
/// - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<FFIEncodedKey>()`
///   many bytes, and it must be properly aligned. This means in particular:
///   - The entire memory range pointed to by `ptr` must be contained within a single allocated
///     object. Slices can never span across multiple allocated objects.
///   - `ptr` must be non-null and aligned even for zero-length slices.
///   - `ptr` must point to `len` consecutive properly initialized values of type
///     [`FFIEncodedKey`].
/// - The total size `len * mem::size_of::<FFIEncodedKey>()` of the slice pointed to
///   by `ptr` must be no larger than isize::MAX. See the safety documentation of pointer::offset.
/// - See the safety documentation of [`FFIEncodedKey`]
#[repr(C)]
pub struct FFIEncodedKeys {
    ptr: *mut FFIEncodedKey,
    len: usize, // number of elems
}

impl FFIEncodedKeys {
    pub fn ptr_from_vec(v: Vec<FFIEncodedKey>) -> *mut Self {
        // Going from Vec<_> to Box<[_]> just drops the (extra) `capacity`
        let boxed_slice: Box<[FFIEncodedKey]> = v.into_boxed_slice();
        let len = boxed_slice.len();
        let fat_ptr: *mut [FFIEncodedKey] = Box::into_raw(boxed_slice);
        // It is guaranteed to be possible to obtain a raw pointer to the start
        // of a slice by casting the pointer-to-slice, as documented e.g. at
        // <https://doc.rust-lang.org/std/primitive.pointer.html#method.as_mut_ptr>.
        // TODO: replace with `as_mut_ptr()` when that is stable.
        let slim_ptr: *mut FFIEncodedKey = fat_ptr as _;
        Box::into_raw(Box::new(FFIEncodedKeys { ptr: slim_ptr, len }))
    }
}

/// Frees an array of FFIEncodedKeys values as allocated by `zcashlc_derive_unified_viewing_keys_from_seed`
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of [`FFIEncodedKeys`].
///   See the safety documentation of [`FFIEncodedKeys`].
#[no_mangle]
pub unsafe extern "C" fn zcashlc_free_keys(ptr: *mut FFIEncodedKeys) {
    if !ptr.is_null() {
        let s: Box<FFIEncodedKeys> = Box::from_raw(ptr);

        let slice: &mut [FFIEncodedKey] = slice::from_raw_parts_mut(s.ptr, s.len);
        drop(Box::from_raw(slice));
        drop(s);
    }
}

/// Derives a new unified full viewing key from the specified seed data for each account id in the
/// range `0..accounts` and returns the resulting encoded values in a [`FFIEncodedKeys`].
///
/// # Safety
///
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
/// - Call [`zcashlc_free_keys`] to free the memory associated with the returned pointer
///   when you are done using it.
#[no_mangle]
pub extern "C" fn zcashlc_derive_unified_full_viewing_keys_from_seed(
    seed: *const u8,
    seed_len: usize,
    accounts: i32,
    network_id: u32,
) -> *mut FFIEncodedKeys {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let seed = unsafe { slice::from_raw_parts(seed, seed_len) };
        let accounts = if accounts > 0 {
            accounts as u32
        } else {
            return Err(format_err!("accounts argument must be greater than zero"));
        };

        let uvks = (0..accounts)
            .map(|account| {
                let account_id = AccountId::from(account);
                UnifiedSpendingKey::from_seed(&network, seed, account_id)
                    .map_err(|e| {
                        format_err!("error generating unified spending key from seed: {:?}", e)
                    })
                    .map(|usk| {
                        let ufvk = usk.to_unified_full_viewing_key();
                        FFIEncodedKey::new(account_id, ufvk.encode(&network))
                    })
            })
            .collect::<Result<_, _>>()?;
        Ok(FFIEncodedKeys::ptr_from_vec(uvks))
    });
    unwrap_exc_or_null(res)
}

/// Derives a new Sapling extended full viewing key from the specified seed data for each account
/// id in the range `0..accounts` and returns the resulting encoded values in a
/// [`FFIEncodedKeys`].
///
/// # Safety
///
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
/// - Call [`zcashlc_free_keys`] to free the memory associated with the returned pointer
///   when you are done using it.
#[no_mangle]
pub extern "C" fn zcashlc_derive_extended_full_viewing_keys(
    seed: *const u8,
    seed_len: usize,
    accounts: i32,
    network_id: u32,
) -> *mut FFIEncodedKeys {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let seed = unsafe { slice::from_raw_parts(seed, seed_len) };
        let accounts = if accounts > 0 {
            accounts as u32
        } else {
            return Err(format_err!("accounts argument must be greater than zero"));
        };

        Ok(FFIEncodedKeys::ptr_from_vec(
            (0..accounts)
                .map(|account| {
                    let account = AccountId::from(account);
                    let extfvk = ExtendedFullViewingKey::from(&sapling::spending_key(
                        seed,
                        network.coin_type(),
                        account,
                    ));
                    let encoded = encode_extended_full_viewing_key(
                        network.hrp_sapling_extended_full_viewing_key(),
                        &extfvk,
                    );
                    FFIEncodedKey::new(account, encoded)
                })
                .collect(),
        ))
    });
    unwrap_exc_or_null(res)
}

/// Derives a unified address from the given seed and account index.
///
/// Returns the Bech32-encoded string representation of the derived address.
///
/// # Safety
///
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of the function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
///   of pointer::offset.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub extern "C" fn zcashlc_derive_unified_address_from_seed(
    seed: *const u8,
    seed_len: usize,
    account_index: i32,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let seed = unsafe { slice::from_raw_parts(seed, seed_len) };
        let account_index = if account_index >= 0 {
            account_index as u32
        } else {
            return Err(format_err!("accounts argument must be greater than zero"));
        };
        let account_id = AccountId::from(account_index);
        let ufvk = UnifiedSpendingKey::from_seed(&network, seed, account_id)
            .map_err(|e| format_err!("error generating unified spending key from seed: {:?}", e))
            .map(|usk| usk.to_unified_full_viewing_key())?;

        // Derive the default Unified Address (containing the default Sapling payment
        // address that older SDKs used).
        let (ua, _) = ufvk.default_address();
        let address_str = ua.encode(&network);
        Ok(CString::new(address_str).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Derives a transparent address from the given public key.
///
/// Returns a pointer to Base58-encoded UTF-8 string corresponding to the
/// generated address.
///
/// # Safety
///
/// - `pubkey` must be non-null and must point to a null-terminated UTF-8 string representing
///   a base58-encoded BIP 32 public key.
/// - The memory referenced by `pubkey` must not be mutated for the duration of the function call.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub extern "C" fn zcashlc_derive_transparent_address_from_public_key(
    pubkey: *const c_char,
    network_id: u32,
) -> *mut c_char {
    #[allow(deprecated)]
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let public_key_str = unsafe { CStr::from_ptr(pubkey).to_str()? };
        let pk = PublicKey::from_str(public_key_str)?;
        let taddr = legacy::keys::pubkey_to_address(&pk).encode(&network);

        Ok(CString::new(taddr).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Derives a unified address from the given unified full viewing key.
///
/// Returns the Bech32-encoded string representation of the unified address,
/// encoded as a null-terminated UTF-8 string.
///
/// # Safety
///
/// - `ufvk` must be non-null and must point to a null-terminated UTF-8 string representing
///   a Bech32-encoded unified full viewing key for the given network.
/// - The memory referenced by `ufvk` must not be mutated for the duration of the function call.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub extern "C" fn zcashlc_derive_unified_address_from_viewing_key(
    ufvk: *const c_char,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let ufvk_string = unsafe { CStr::from_ptr(ufvk).to_str()? };
        let ufvk = match UnifiedFullViewingKey::decode(&network, ufvk_string) {
            Ok(ufvk) => ufvk,
            Err(e) => {
                return Err(format_err!(
                    "Error while deriving viewing key from string input: {}",
                    e
                ));
            }
        };
        // Derive the default Unified Address (containing the default Sapling payment
        // address that older SDKs used).
        let (ua, _) = ufvk.default_address();
        let address_str = ua.encode(&network);
        Ok(CString::new(address_str).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Derives a Sapling extended full viewing key from address from the given extended
/// spending key.
///
/// Returns the Bech32-encoded string representation of the ExtendedFullViewingKey,
/// encoded as a null-terminated UTF-8 string.
///
/// # Safety
///
/// - `extsk` must be non-null and must point to a null-terminated UTF-8 string representing
///   a Bech32-encoded Sapling extended spending key for the given network.
/// - The memory referenced by `extsk` must not be mutated for the duration of the function call.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub extern "C" fn zcashlc_derive_extended_full_viewing_key(
    extsk: *const c_char,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let extsk = unsafe { CStr::from_ptr(extsk).to_str()? };
        let extfvk = match decode_extended_spending_key(
            network.hrp_sapling_extended_spending_key(),
            extsk,
        ) {
            Ok(extsk) => ExtendedFullViewingKey::from(&extsk),
            Err(e) => {
                return Err(format_err!(
                    "Error while deriving viewing key from spending key: {}",
                    e
                ));
            }
        };

        let encoded = encode_extended_full_viewing_key(
            network.hrp_sapling_extended_full_viewing_key(),
            &extfvk,
        );

        Ok(CString::new(encoded).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Initialises the data database with the given block metadata.
///
/// This enables a newly-created database to be immediately-usable, without needing to
/// synchronise historic blocks.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `hash_hex` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `hash_hex` must not be mutated for the duration of the function call.
/// - `sapling_tree_hex` must be non-null and must point to a null-terminated UTF-8 string
///   containing the encoded byte representation of a Sapling commitment tree.
/// - The memory referenced by `sapling_tree_hex` must not be mutated for the duration of the
///   function call.
#[no_mangle]
pub extern "C" fn zcashlc_init_blocks_table(
    db_data: *const u8,
    db_data_len: usize,
    height: i32,
    hash_hex: *const c_char,
    time: u32,
    sapling_tree_hex: *const c_char,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let hash = {
            let mut hash = hex::decode(unsafe { CStr::from_ptr(hash_hex) }.to_str()?).unwrap();
            hash.reverse();
            BlockHash::from_slice(&hash)
        };
        let sapling_tree =
            hex::decode(unsafe { CStr::from_ptr(sapling_tree_hex) }.to_str()?).unwrap();

        match init_blocks_table(
            &db_data,
            BlockHeight::from_u32(height as u32),
            hash,
            time,
            &sapling_tree,
        ) {
            Ok(()) => Ok(1),
            Err(e) => Err(format_err!("Error while initializing blocks table: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Returns the default Sapling payment address for the specified account.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub extern "C" fn zcashlc_get_address(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let account = if account >= 0 {
            account as u32
        } else {
            return Err(format_err!("accounts argument must be positive"));
        };

        let account = AccountId::from(account);

        match (&db_data).get_address(account) {
            Ok(Some(addr)) => {
                let addr_str = encode_payment_address(network.hrp_sapling_payment_address(), &addr);
                let c_str_addr = CString::new(addr_str).unwrap();
                Ok(c_str_addr.into_raw())
            }
            Ok(None) => Err(format_err!(
                "No payment address was available for account {:?}",
                account
            )),
            Err(e) => Err(format_err!("Error while fetching address: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Returns true when the provided address decodes to a valid Sapling payment address for the
/// specified network, false in any other case.
///
/// # Safety
///
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub extern "C" fn zcashlc_is_valid_shielded_address(
    address: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        Ok(is_valid_shielded_address(addr, &network))
    });
    unwrap_exc_or(res, false)
}

fn is_valid_shielded_address(address: &str, network: &Network) -> bool {
    match RecipientAddress::decode(network, address) {
        Some(addr) => match addr {
            RecipientAddress::Shielded(_) => true,
            RecipientAddress::Transparent(_) | RecipientAddress::Unified(_) => false,
        },
        None => false,
    }
}

/// Returns true when the address is a valid transparent payment address for the specified network,
/// false in any other case.
///
/// # Safety
///
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub extern "C" fn zcashlc_is_valid_transparent_address(
    address: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        Ok(is_valid_transparent_address(addr, &network))
    });
    unwrap_exc_or(res, false)
}

fn is_valid_transparent_address(address: &str, network: &Network) -> bool {
    match RecipientAddress::decode(network, address) {
        Some(addr) => match addr {
            RecipientAddress::Shielded(_) | RecipientAddress::Unified(_) => false,
            RecipientAddress::Transparent(_) => true,
        },
        None => false,
    }
}

/// Returns true when the provided key decodes to a valid Sapling extended spending key for the
/// specified network, false in any other case.
///
/// # Safety
///
/// - `extsk` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `extsk` must not be mutated for the duration of the function call.
#[no_mangle]
pub extern "C" fn zcashlc_is_valid_sapling_extended_spending_key(
    extsk: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let extsk = unsafe { CStr::from_ptr(extsk).to_str()? };

        Ok(
            decode_extended_spending_key(network.hrp_sapling_extended_spending_key(), extsk)
                .is_ok(),
        )
    });
    unwrap_exc_or(res, false)
}

/// Returns true when the provided key decodes to a valid Sapling extended full viewing key for the
/// specified network, false in any other case.
///
/// # Safety
///
/// - `key` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `key` must not be mutated for the duration of the function call.
#[no_mangle]
pub extern "C" fn zcashlc_is_valid_viewing_key(key: *const c_char, network_id: u32) -> bool {
    let res =
        catch_panic(|| {
            let network = parse_network(network_id)?;
            let vkstr = unsafe { CStr::from_ptr(key).to_str()? };

            Ok(decode_extended_full_viewing_key(
                network.hrp_sapling_extended_full_viewing_key(),
                vkstr,
            )
            .is_ok())
        });
    unwrap_exc_or(res, false)
}

/// Returns true when the provided key decodes to a valid unified full viewing key for the
/// specified network, false in any other case.
///
/// # Safety
///
/// - `ufvk` must be non-null and must point to a null-terminated UTF-8 string.  - The memory
/// referenced by `ufvk` must not be mutated for the duration of the function call.
#[no_mangle]
pub extern "C" fn zcashlc_is_valid_unified_full_viewing_key(
    ufvk: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let ufvkstr = unsafe { CStr::from_ptr(ufvk).to_str()? };

        Ok(UnifiedFullViewingKey::decode(&network, ufvkstr).is_ok())
    });
    unwrap_exc_or(res, false)
}

/// Returns true when the provided key decodes to a valid unified address for the
/// specified network, false in any other case.
///
/// # Safety
///
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.  - The memory
/// referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub extern "C" fn zcashlc_is_valid_unified_address(
    address: *const c_char,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        Ok(is_valid_unified_address(addr, &network))
    });
    unwrap_exc_or(res, false)
}

fn is_valid_unified_address(address: &str, network: &Network) -> bool {
    match RecipientAddress::decode(network, address) {
        Some(addr) => match addr {
            RecipientAddress::Unified(_) => true,
            RecipientAddress::Shielded(_) | RecipientAddress::Transparent(_) => false,
        },
        None => false,
    }
}

/// Returns the balance for the specified account, including all unspent notes that we know about.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_get_balance(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        if account >= 0 {
            let (_, max_height) = (&db_data)
                .block_height_extrema()
                .map_err(|e| format_err!("Error while fetching max block height: {}", e))
                .and_then(|opt| {
                    opt.ok_or_else(|| {
                        format_err!("No blockchain information available; scan required.")
                    })
                })?;

            (&db_data)
                .get_balance_at(AccountId::from(account as u32), max_height)
                .map(|b| b.into())
                .map_err(|e| format_err!("Error while fetching balance: {}", e))
        } else {
            Err(format_err!("account argument must be positive"))
        }
    });
    unwrap_exc_or(res, -1)
}

/// Returns the verified balance for the account, which ignores notes that have been
/// received too recently and are not yet deemed spendable according to `min_confirmations`.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_get_verified_balance(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    network_id: u32,
    min_confirmations: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        if account >= 0 {
            (&db_data)
                .get_target_and_anchor_heights(min_confirmations)
                .map_err(|e| format_err!("Error while fetching anchor height: {}", e))
                .and_then(|opt_anchor| {
                    opt_anchor
                        .map(|(_, a)| a)
                        .ok_or_else(|| format_err!("Anchor height not available; scan required."))
                })
                .and_then(|anchor| {
                    (&db_data)
                        .get_balance_at(AccountId::from(account as u32), anchor)
                        .map_err(|e| format_err!("Error while fetching verified balance: {}", e))
                })
                .map(|amount| amount.into())
        } else {
            Err(format_err!("account argument must be positive"))
        }
    });
    unwrap_exc_or(res, -1)
}

/// Returns the verified transparent balance for `address`, which ignores utxos that have been
/// received too recently and are not yet deemed spendable according to `min_confirmations`.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub extern "C" fn zcashlc_get_verified_transparent_balance(
    db_data: *const u8,
    db_data_len: usize,
    address: *const c_char,
    network_id: u32,
    min_confirmations: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        let taddr = TransparentAddress::decode(&network, addr).unwrap();
        let amount = (&db_data)
            .get_target_and_anchor_heights(min_confirmations)
            .map_err(|e| format_err!("Error while fetching anchor height: {}", e))
            .and_then(|opt_anchor| {
                opt_anchor
                    .map(|(h, _)| h)
                    .ok_or_else(|| format_err!("height not available; scan required."))
            })
            .and_then(|anchor| {
                (&db_data)
                    .get_unspent_transparent_outputs(&taddr, anchor)
                    .map_err(|e| {
                        format_err!("Error while fetching verified transparent balance: {}", e)
                    })
            })?
            .iter()
            .map(|utxo| utxo.txout.value)
            .sum::<Option<Amount>>()
            .ok_or_else(|| format_err!("Balance overflowed MAX_MONEY."))?;

        Ok(amount.into())
    });
    unwrap_exc_or(res, -1)
}

/// Returns the balance for `address`, including all UTXOs that we know about.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub extern "C" fn zcashlc_get_total_transparent_balance(
    db_data: *const u8,
    db_data_len: usize,
    address: *const c_char,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let addr = unsafe { CStr::from_ptr(address).to_str()? };
        let taddr = TransparentAddress::decode(&network, addr).unwrap();
        let amount = (&db_data)
            .get_target_and_anchor_heights(0u32)
            .map_err(|e| format_err!("Error while fetching anchor height: {}", e))
            .and_then(|opt_anchor| {
                opt_anchor
                    .map(|(h, _)| h)
                    .ok_or_else(|| format_err!("height not available; scan required."))
            })
            .and_then(|anchor| {
                (&db_data)
                    .get_unspent_transparent_outputs(&taddr, anchor)
                    .map_err(|e| {
                        format_err!("Error while fetching total transparent balance: {}", e)
                    })
            })?
            .iter()
            .map(|utxo| utxo.txout.value)
            .sum::<Option<Amount>>()
            .ok_or_else(|| format_err!("Balance overflowed MAX_MONEY."))?;

        Ok(amount.into())
    });
    unwrap_exc_or(res, -1)
}

/// Returns the memo for a received note, if it is known and a valid UTF-8 string.
///
/// The note is identified by its row index in the `received_notes` table within the data
/// database.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub extern "C" fn zcashlc_get_received_memo_as_utf8(
    db_data: *const u8,
    db_data_len: usize,
    id_note: i64,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let memo = (&db_data)
            .get_memo(NoteId::ReceivedNoteId(id_note))
            .map_err(|e| format_err!("An error occurred retrieving the memo, {}", e))
            .and_then(|memo| match memo {
                Memo::Empty => Ok("".to_string()),
                Memo::Text(memo) => Ok(memo.into()),
                _ => Err(format_err!("This memo does not contain UTF-8 text")),
            })?;

        Ok(CString::new(memo).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Returns the memo for a received note by copying the corresponding bytes to the received
/// pointer in `memo_bytes_ret`.
///
/// The note is identified by its row index in the `received_notes` table within the data
/// database.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `memo_bytes_ret` must be non-null and must point to an allocated 512-byte region of memory.
#[no_mangle]
pub extern "C" fn zcashlc_get_received_memo(
    db_data: *const u8,
    db_data_len: usize,
    id_note: i64,
    memo_bytes_ret: *mut u8,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data =unsafe { wallet_db(db_data, db_data_len, network)? };
        
        let memo_bytes = (&db_data).get_memo(NoteId::ReceivedNoteId(id_note))
            .map_err(|e| format_err!("An error occurred retrieving the memo, {}", e))
            .map(|memo| memo.encode())
            .unwrap();
        let memo_slice = memo_bytes.as_slice();

        if memo_slice.len() != 512 {
            return Err(format_err!("An error ocurred retrieving the memo, memo lenght is not 512 bytes."))
        }

        unsafe { memo_bytes_ret.copy_from(memo_slice.as_ptr(), 512) }
        Ok(true)
    });
    unwrap_exc_or(res, false)
}


/// Returns the memo for a sent note, if it is known and a valid UTF-8 string.
///
/// The note is identified by its row index in the `sent_notes` table within the data
/// database.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
///   when done using it.
#[no_mangle]
pub extern "C" fn zcashlc_get_sent_memo_as_utf8(
    db_data: *const u8,
    db_data_len: usize,
    id_note: i64,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let memo = (&db_data)
            .get_memo(NoteId::SentNoteId(id_note))
            .map_err(|e| format_err!("An error occurred retrieving the memo, {}", e))
            .and_then(|memo| match memo {
                Memo::Empty => Ok("".to_string()),
                Memo::Text(memo) => Ok(memo.into()),
                _ => Err(format_err!("This memo does not contain UTF-8 text")),
            })?;

        Ok(CString::new(memo).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Returns the memo for a sent note, by copying the corresponding bytes to the received
/// pointer in `memo_bytes_ret`.
///
/// The note is identified by its row index in the `sent_notes` table within the data
/// database.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `memo_bytes_ret` must be non-null and must point to an allocated 512-byte region of memory.
#[no_mangle]
pub extern "C" fn zcashlc_get_sent_memo(
    db_data: *const u8,
    db_data_len: usize,
    id_note: i64,
    memo_bytes_ret: *mut u8,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? }; 
        
        let memo_bytes = (&db_data).get_memo(NoteId::SentNoteId(id_note))
            .map_err(|e| format_err!("An error occurred retrieving the memo, {}", e))
            .map(|memo| memo.encode())
            .unwrap();

        let memo_slice = memo_bytes.as_slice();

        if memo_slice.len() != 512 {
            return Err(format_err!("An error ocurred retrieving the memo, memo lenght is not 512 bytes."))
        }

        unsafe { memo_bytes_ret.copy_from(memo_slice.as_ptr(), 512) }
        Ok(true)
    });
    unwrap_exc_or(res, false)
}

/// Checks that the scanned blocks in the data database, when combined with the recent
/// `CompactBlock`s in the cache database, form a valid chain.
///
/// This function is built on the core assumption that the information provided in the
/// cache database is more likely to be accurate than the previously-scanned information.
/// This follows from the design (and trust) assumption that the `lightwalletd` server
/// provides accurate block information as of the time it was requested.
///
/// Returns:
/// - `-1` if the combined chain is valid.
/// - `upper_bound` if the combined chain is invalid.
///   `upper_bound` is the height of the highest invalid block (on the assumption that the
///   highest block in the cache database is correct).
/// - `0` if there was an error during validation unrelated to chain validity.
///
/// This function does not mutate either of the databases.
///
/// # Safety
///
/// - `db_cache` must be non-null and valid for reads for `db_cache_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_cache` must not be mutated for the duration of the function call.
/// - The total size `db_cache_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_validate_combined_chain(
    db_cache: *const u8,
    db_cache_len: usize,
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let block_db = unsafe { block_db(db_cache, db_cache_len)? };
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };

        let validate_from = (&db_data)
            .get_max_height_hash()
            .map_err(|e| format_err!("Error while validating chain: {}", e))?;

        let val_res = validate_chain(&network, &block_db, validate_from);

        if let Err(e) = val_res {
            match e {
                SqliteClientError::BackendError(Error::InvalidChain(upper_bound, _)) => {
                    let upper_bound_u32 = u32::from(upper_bound);
                    Ok(upper_bound_u32 as i32)
                }
                _ => Err(format_err!("Error while validating chain: {}", e)),
            }
        } else {
            // All blocks are valid, so "highest invalid block height" is below genesis.
            Ok(-1)
        }
    });
    unwrap_exc_or_null(res)
}

/// Returns the most recent block height to which it is possible to reset the state
/// of the data database.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_get_nearest_rewind_height(
    db_data: *const u8,
    db_data_len: usize,
    height: i32,
    network_id: u32,
) -> i32 {
    #[allow(deprecated)]
    let res = catch_panic(|| {
        if height < 100 {
            Ok(height)
        } else {
            let network = parse_network(network_id)?;
            let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
            let height = BlockHeight::try_from(height)?;
            match get_rewind_height(&db_data) {
                Ok(Some(best_height)) => {
                    let first_unspent_note_height = u32::from(best_height);
                    let rewind_height = u32::from(height);
                    Ok(std::cmp::min(
                        first_unspent_note_height as i32,
                        rewind_height as i32,
                    ))
                }
                Ok(None) => {
                    let rewind_height = u32::from(height);
                    Ok(rewind_height as i32)
                }
                Err(e) => Err(format_err!(
                    "Error while getting nearest rewind height for {}: {}",
                    height,
                    e
                )),
            }
        }
    });
    unwrap_exc_or(res, -1)
}

/// Rewinds the data database to the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned
/// block, this function does nothing.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_rewind_to_height(
    db_data: *const u8,
    db_data_len: usize,
    height: i32,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let mut db_data = db_data.get_update_ops()?;

        let height = BlockHeight::try_from(height)?;
        db_data
            .rewind_to_height(height)
            .map(|_| true)
            .map_err(|e| format_err!("Error while rewinding data DB to height {}: {}", height, e))
    });
    unwrap_exc_or(res, false)
}

/// Scans new blocks added to the cache for any transactions received by the tracked
/// accounts.
///
/// This function pays attention only to cached blocks with heights greater than the
/// highest scanned block in `db_data`. Cached blocks with lower heights are not verified
/// against previously-scanned blocks. In particular, this function **assumes** that the
/// caller is handling rollbacks.
///
/// For brand-new light client databases, this function starts scanning from the Sapling
/// activation height. This height can be fast-forwarded to a more recent block by calling
/// [`zcashlc_init_blocks_table`] before this function.
///
/// Scanned blocks are required to be height-sequential. If a block is missing from the
/// cache, an error will be signalled.
///
/// # Safety
///
/// - `db_cache` must be non-null and valid for reads for `db_cache_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_cache` must not be mutated for the duration of the function call.
/// - The total size `db_cache_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_scan_blocks(
    db_cache: *const u8,
    db_cache_len: usize,
    db_data: *const u8,
    db_data_len: usize,
    scan_limit: u32,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let block_db = unsafe { block_db(db_cache, db_cache_len)? };
        let db_read = unsafe { wallet_db(db_data, db_data_len, network)? };
        let mut db_data = db_read.get_update_ops()?;
        let limit = if scan_limit == 0 {
            None
        } else {
            Some(scan_limit)
        };
        match scan_cached_blocks(&network, &block_db, &mut db_data, limit) {
            Ok(()) => Ok(1),
            Err(e) => Err(format_err!("Error while scanning blocks: {}", e)),
        }
    });
    unwrap_exc_or_null(res)
}

/// Inserts a UTXO into the wallet database.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `txid_bytes` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `txid_bytes_len` must not be mutated for the duration of the function call.
/// - The total size `txid_bytes_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `script_bytes` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `script_bytes_len` must not be mutated for the duration of the function call.
/// - The total size `script_bytes_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_put_utxo(
    db_data: *const u8,
    db_data_len: usize,
    txid_bytes: *const u8,
    txid_bytes_len: usize,
    index: i32,
    script_bytes: *const u8,
    script_bytes_len: usize,
    value: i64,
    height: i32,
    network_id: u32,
) -> bool {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let mut db_data = db_data.get_update_ops()?;

        let txid_bytes = unsafe { slice::from_raw_parts(txid_bytes, txid_bytes_len) };
        let mut txid = [0u8; 32];
        txid.copy_from_slice(txid_bytes);

        let script_bytes = unsafe { slice::from_raw_parts(script_bytes, script_bytes_len) };
        let script_pubkey = legacy::Script(script_bytes.to_vec());

        let output = WalletTransparentOutput {
            outpoint: OutPoint::new(txid, index as u32),
            txout: TxOut {
                value: Amount::from_i64(value).unwrap(),
                script_pubkey,
            },
            height: BlockHeight::from(height as u32),
        };
        match db_data.put_received_transparent_utxo(&output) {
            Ok(_) => Ok(true),
            Err(e) => Err(format_err!("Error while inserting UTXO: {}", e)),
        }
    });
    unwrap_exc_or(res, false)
}

/// Deletes the transparent UTXO data associated with the given transparent address for UTXOs
/// received at block heights above the specified height.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `taddress` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `taddress` must not be mutated for the duration of the function call.
#[no_mangle]
pub extern "C" fn zcashlc_clear_utxos(
    db_data: *const u8,
    db_data_len: usize,
    taddress: *const c_char,
    above_height: i32,
    network_id: u32,
) -> i32 {
    #[allow(deprecated)]
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let mut db_data = db_data.get_update_ops()?;
        let addr = unsafe { CStr::from_ptr(taddress).to_str()? };
        let taddress = TransparentAddress::decode(&network, addr).unwrap();
        let height = BlockHeight::from(above_height as u32);
        match delete_utxos_above(&mut db_data, &taddress, height) {
            Ok(rows) => Ok(rows as i32),
            Err(e) => Err(format_err!("Error while clearing UTXOs: {}", e)),
        }
    });
    unwrap_exc_or(res, -1)
}

/// Attempts to decrypt the specified transaction from its network byte representation
/// and store its
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `tx` must be non-null and valid for reads for `tx_len` bytes, and it must have an
///   alignment of `1`.
/// - The memory referenced by `tx` must not be mutated for the duration of the function call.
/// - The total size `tx_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_decrypt_and_store_transaction(
    db_data: *const u8,
    db_data_len: usize,
    tx: *const u8,
    tx_len: usize,
    _mined_height: u32,
    network_id: u32,
) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_read = unsafe { wallet_db(db_data, db_data_len, network)? };
        let mut db_data = db_read.get_update_ops()?;
        let tx_bytes = unsafe { slice::from_raw_parts(tx, tx_len) };

        // The consensus branch ID passed in here does not matter:
        // - v4 and below cache it internally, but all we do with this transaction while
        //   it is in memory is decryption and serialization, neither of which use the
        //   consensus branch ID.
        // - v5 and above transactions ignore the argument, and parse the correct value
        //   from their encoding.
        let tx = Transaction::read(tx_bytes, BranchId::Sapling)?;

        match decrypt_and_store_transaction(&network, &mut db_data, &tx) {
            Ok(()) => Ok(1),
            Err(e) => Err(format_err!("Error while decrypting transaction: {}", e)),
        }
    });
    unwrap_exc_or(res, -1)
}

/// Creates a transaction paying the specified address from the given account.
///
/// Returns the row index of the newly-created transaction in the `transactions` table
/// within the data database. The caller can read the raw transaction bytes from the `raw`
/// column in order to broadcast the transaction to the network.
///
/// Do not call this multiple times in parallel, or you will generate transactions that
/// double-spend the same notes.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `extsk` must be non-null and must point to a null-terminated UTF-8 string representing
///   a Bech32-encoded Sapling extended spending key for the given network.
/// - `to` must be non-null and must point to a null-terminated UTF-8 string.
/// - `memo` must either be null (indicating an empty memo or a transparent recipient) or point to a
///    512-byte array.
/// - `spend_params` must be non-null and valid for reads for `spend_params_len` bytes, and it must have an
///   alignment of `1`. Its contents must be the Sapling spend proving parameters.
/// - The memory referenced by `spend_params` must not be mutated for the duration of the function call.
/// - The total size `spend_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `output_params` must be non-null and valid for reads for `output_params_len` bytes, and it must have an
///   alignment of `1`. Its contents must be the Sapling output proving parameters.
/// - The memory referenced by `output_params` must not be mutated for the duration of the function call.
/// - The total size `output_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_create_to_address(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    extsk: *const c_char,
    to: *const c_char,
    value: i64,
    memo: *const u8,
    spend_params: *const u8,
    spend_params_len: usize,
    output_params: *const u8,
    output_params_len: usize,
    network_id: u32,
    min_confirmations: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_read = unsafe { wallet_db(db_data, db_data_len, network)? };
        let mut db_data = db_read.get_update_ops()?;
        let account = if account >= 0 {
            account as u32
        } else {
            return Err(format_err!("account argument must be positive"));
        };
        let extsk = unsafe { CStr::from_ptr(extsk) }.to_str()?;
        let to = unsafe { CStr::from_ptr(to) }.to_str()?;
        let value =
            Amount::from_i64(value).map_err(|()| format_err!("Invalid amount, out of range"))?;
        if value.is_negative() {
            return Err(format_err!("Amount is negative"));
        }
        let spend_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(spend_params, spend_params_len)
        }));
        let output_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(output_params, output_params_len)
        }));

        let extsk =
            decode_extended_spending_key(network.hrp_sapling_extended_spending_key(), extsk)
                .map_err(|e| format_err!("Invalid ExtendedSpendingKey: {}", e))?;

        let to = RecipientAddress::decode(&network, to)
            .ok_or_else(|| format_err!("PaymentAddress is for the wrong network"))?;

        let memo = match to {
            RecipientAddress::Shielded(_) | RecipientAddress::Unified(_) => {
                if memo.is_null() {
                    Ok(None)
                } else {
                    MemoBytes::from_bytes(unsafe { slice::from_raw_parts(memo, 512) })
                        .map(Some)
                        .map_err(|e| format_err!("Invalid MemoBytes {}", e))
                }
            }
            RecipientAddress::Transparent(_) => Err(format_err!(
                "Memos are not permitted when sending to transparent recipients."
            )),
        }?;

        let prover = LocalTxProver::new(spend_params, output_params);

        create_spend_to_address(
            &mut db_data,
            &network,
            prover,
            AccountId::from(account),
            &extsk,
            &to,
            value,
            memo,
            OvkPolicy::Sender,
            min_confirmations,
        )
        .map_err(|e| format_err!("Error while sending funds: {}", e))
    });
    unwrap_exc_or(res, -1)
}

#[no_mangle]
pub extern "C" fn zcashlc_branch_id_for_height(height: i32, network_id: u32) -> i32 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let branch: BranchId = BranchId::for_height(&network, BlockHeight::from(height as u32));
        let branch_id: u32 = u32::from(branch);
        Ok(branch_id as i32)
    });
    unwrap_exc_or(res, -1)
}

/// Frees strings returned by other zcashlc functions.
///
/// # Safety
///
/// - `s` should not be a null pointer.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub unsafe extern "C" fn zcashlc_string_free(s: *mut c_char) {
    if !s.is_null() {
        let s = CString::from_raw(s);
        drop(s);
    }
}

/// Derives a transparent account private key from seed
///
/// # Safety
///
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of this function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_derive_transparent_account_private_key_from_seed(
    seed: *const u8,
    seed_len: usize,
    account: i32,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let seed = unsafe { slice::from_raw_parts(seed, seed_len) };
        let account = if account >= 0 {
            AccountId::from(account as u32)
        } else {
            return Err(format_err!("account argument must be positive"));
        };

        // Derive the USK to ensure it exists, and fetch its transparent component.
        let usk = UnifiedSpendingKey::from_seed(&network, seed, account)
            .map_err(|e| format_err!("error generating unified spending key from seed: {:?}", e))?;
        // Derive the corresponding BIP 32 extended privkey.
        let xprv =
            p2pkh_xprv(&network, seed, account).expect("USK derivation should ensure this exists");
        // Verify that we did derive the same privkey.
        assert_eq!(
            usk.transparent().to_account_pubkey().serialize(),
            legacy::keys::AccountPrivKey::from_extended_privkey(xprv.extended_key.clone())
                .to_account_pubkey()
                .serialize(),
        );
        // Encode using the BIP 32 xprv serialization format.
        let xprv_str: String = xprv.serialize();

        Ok(CString::new(xprv_str).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

fn p2pkh_xprv<P: Parameters>(
    params: &P,
    seed: &[u8],
    account: AccountId,
) -> Result<hdwallet_bitcoin::PrivKey, hdwallet::error::Error> {
    let master_key = ExtendedPrivKey::with_seed(seed)?;
    let key_chain = hdwallet::DefaultKeyChain::new(master_key);
    let chain_path = format!("m/44H/{}H/{}H", params.coin_type(), u32::from(account)).into();
    let (extended_key, derivation) = key_chain.derive_private_key(chain_path)?;
    Ok(hdwallet_bitcoin::PrivKey {
        network: hdwallet_bitcoin::Network::MainNet,
        derivation,
        extended_key,
    })
}

fn p2pkh_addr(
    tfvk: legacy::keys::AccountPubKey,
    index: u32,
) -> Result<TransparentAddress, hdwallet::error::Error> {
    tfvk.derive_external_ivk()
        .and_then(|tivk| tivk.derive_address(index))
}

/// Derives a transparent address from the given seed
///
/// # Safety
///
/// - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an alignment of `1`.
/// - The memory referenced by `seed` must not be mutated for the duration of this function call.
/// - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_derive_transparent_address_from_seed(
    seed: *const u8,
    seed_len: usize,
    account: i32,
    index: i32,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let seed = unsafe { slice::from_raw_parts(seed, seed_len) };
        let network = parse_network(network_id)?;
        let account = if account >= 0 {
            account as u32
        } else {
            return Err(format_err!("account argument must be positive"));
        };

        let index = if index >= 0 {
            index as u32
        } else {
            return Err(format_err!("index argument must be positive"));
        };
        let tfvk = UnifiedSpendingKey::from_seed(&network, seed, AccountId::from(account))
            .map_err(|e| format_err!("error generating unified spending key from seed: {:?}", e))
            .map(|usk| usk.transparent().to_account_pubkey())?;
        let taddr = match p2pkh_addr(tfvk, index) {
            Ok(taddr) => taddr,
            Err(e) => return Err(format_err!("Couldn't derive transparent address: {:?}", e)),
        };
        let taddr = taddr.encode(&network);

        Ok(CString::new(taddr).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Derives a transparent address from the given account private key.
///
/// # Safety
///
/// - `xprv` must be non-null and must point to a null-terminated UTF-8 string.
#[no_mangle]
pub extern "C" fn zcashlc_derive_transparent_address_from_account_private_key(
    xprv: *const c_char,
    index: i32,
    network_id: u32,
) -> *mut c_char {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let index = if index >= 0 {
            index as u32
        } else {
            return Err(format_err!("index argument must be positive"));
        };
        let xprv_str = unsafe { CStr::from_ptr(xprv).to_str()? };

        let xprv = match hdwallet_bitcoin::PrivKey::deserialize(xprv_str.to_owned()) {
            Ok(xprv) => xprv,
            Err(e) => return Err(format_err!("Invalid transparent extended privkey: {:?}", e)),
        };

        let tfvk = legacy::keys::AccountPrivKey::from_extended_privkey(xprv.extended_key)
            .to_account_pubkey();
        let taddr = match p2pkh_addr(tfvk, index) {
            Ok(taddr) => taddr,
            Err(e) => return Err(format_err!("Couldn't derive transparent address: {:?}", e)),
        };
        let taddr = taddr.encode(&network);
        Ok(CString::new(taddr).unwrap().into_raw())
    });
    unwrap_exc_or_null(res)
}

/// Shield transparent UTXOs by sending them to an address associated with the specified Sapling
/// spending key.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
///   alignment of `1`. Its contents must be a string representing a valid system path in the
///   operating system's preferred representation.
/// - The memory referenced by `db_data` must not be mutated for the duration of the function call.
/// - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `xprv` must be non-null and must point to a null-terminated UTF-8 string representing
///   a Base58-encoded transparent spending key.
/// - `memo` must either be null (indicating an empty memo) or point to a 512-byte array.
/// - `spend_params` must be non-null and valid for reads for `spend_params_len` bytes, and it must have an
///   alignment of `1`. Its contents must be the Sapling spend proving parameters.
/// - The memory referenced by `spend_params` must not be mutated for the duration of the function call.
/// - The total size `spend_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
/// - `output_params` must be non-null and valid for reads for `output_params_len` bytes, and it must have an
///   alignment of `1`. Its contents must be the Sapling output proving parameters.
/// - The memory referenced by `output_params` must not be mutated for the duration of the function call.
/// - The total size `output_params_len` must be no larger than `isize::MAX`. See the safety
///   documentation of pointer::offset.
#[no_mangle]
pub extern "C" fn zcashlc_shield_funds(
    db_data: *const u8,
    db_data_len: usize,
    account: i32,
    xprv: *const c_char,
    memo: *const u8,
    spend_params: *const u8,
    spend_params_len: usize,
    output_params: *const u8,
    output_params_len: usize,
    network_id: u32,
) -> i64 {
    let res = catch_panic(|| {
        let network = parse_network(network_id)?;
        let db_data = unsafe { wallet_db(db_data, db_data_len, network)? };
        let mut update_ops = (&db_data)
            .get_update_ops()
            .map_err(|e| format_err!("Could not obtain a writable database connection: {}", e))?;

        let account = if account >= 0 {
            account as u32
        } else {
            return Err(format_err!("account argument must be positive"));
        };

        let xprv_str = unsafe { CStr::from_ptr(xprv) }.to_str()?;
        let memo_bytes = if memo.is_null() {
            MemoBytes::empty()
        } else {
            MemoBytes::from_bytes(unsafe { slice::from_raw_parts(memo, 512) })
                .map_err(|e| format_err!("Invalid MemoBytes {}", e))?
        };

        let spend_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(spend_params, spend_params_len)
        }));
        let output_params = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(output_params, output_params_len)
        }));

        //grab secret private key for t-funds
        let xprv = match hdwallet_bitcoin::PrivKey::deserialize(xprv_str.to_owned()) {
            Ok(xprv) => xprv,
            Err(e) => return Err(format_err!("Invalid transparent extended privkey: {:?}", e)),
        };
        let sk = legacy::keys::AccountPrivKey::from_extended_privkey(xprv.extended_key);

        shield_transparent_funds(
            &mut update_ops,
            &network,
            LocalTxProver::new(spend_params, output_params),
            &sk,
            AccountId::from(account),
            &memo_bytes,
            ANCHOR_OFFSET,
        )
        .map_err(|e| format_err!("Error while shielding transaction: {}", e))
    });
    unwrap_exc_or(res, -1)
}

//
// Utility functions
//

fn parse_network(value: u32) -> Result<Network, failure::Error> {
    match value {
        0 => Ok(TestNetwork),
        1 => Ok(MainNetwork),
        _ => Err(format_err!("Invalid network type: {}. Expected either 0 or 1 for Testnet or Mainnet, respectively.", value))
    }
}
