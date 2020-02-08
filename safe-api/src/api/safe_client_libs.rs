// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#[cfg(not(feature = "fake-auth"))]
use super::helpers::{decode_ipc_msg, AuthResponseType};
use super::{
    helpers::{xorname_from_pk, xorname_to_hex},
    safe_net::SequenceRawData,
    Error, Result, SafeApp,
};
use futures::future::Future;
use log::{debug, info, warn};
#[cfg(feature = "fake-auth")]
use safe_app::test_utils::create_app;
use safe_app::{
    ffi::errors::Error as SafeAppFfiError, run, App, AppError::CoreError as SafeAppError,
};
use safe_core::client::Client;
use safe_core::{client::test_create_balance, immutable_data, CoreError as SafeCoreError};
use safe_nd::{
    AccessType, Address, AppendOperation, ClientFullId, Coins, Error as SafeNdError, IDataAddress,
    MDataAction, MDataPermissionSet, MDataSeqEntryActions, MDataSeqValue, Owner, PublicAccessList,
    PublicKey as SafeNdPublicKey, PublicSequence, PublicUserAccess, SeqMutableData, Sequence,
    Transaction, TransactionId, User, Version, XorName,
};

pub use threshold_crypto::{PublicKey, SecretKey};

use std::collections::BTreeMap;

const APP_NOT_CONNECTED: &str = "Application is not connected to the network";

#[derive(Default)]
pub struct SafeAppScl {
    safe_conn: Option<App>,
}

impl SafeAppScl {
    // Private helper to obtain the App instance
    fn get_safe_app(&self) -> Result<&App> {
        match &self.safe_conn {
            Some(app) => Ok(app),
            None => Err(Error::ConnectionError(APP_NOT_CONNECTED.to_string())),
        }
    }

    fn mutate_seq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
        entry_actions: MDataSeqEntryActions,
        error_msg: &str,
    ) -> Result<()> {
        let safe_app = self.get_safe_app()?;
        let message = error_msg.to_string();
        run(safe_app, move |client, _app_context| {
            client
                .mutate_seq_mdata_entries(name, tag, entry_actions)
                .map_err(SafeAppError)
        })
        .map_err(|err| {
            if let SafeAppFfiError(SafeAppError(SafeCoreError::DataError(
                SafeNdError::InvalidEntryActions(_),
            ))) = err
            {
                Error::EntryExists(format!("{}: {}", message, err))
            } else {
                Error::NetDataError(format!("{}: {}", message, err))
            }
        })
    }
}

impl SafeApp for SafeAppScl {
    fn new() -> Self {
        Self { safe_conn: None }
    }

    #[allow(dead_code)]
    #[cfg(feature = "fake-auth")]
    fn connect(&mut self, _app_id: &str, _auth_credentials: Option<&str>) -> Result<()> {
        warn!("Using fake authorisation for testing...");
        self.safe_conn = Some(create_app());
        Ok(())
    }

    // Connect to the SAFE Network using the provided app id and auth credentials
    #[cfg(not(feature = "fake-auth"))]
    fn connect(&mut self, app_id: &str, auth_credentials: Option<&str>) -> Result<()> {
        debug!("Connecting to SAFE Network...");

        let disconnect_cb = || {
            warn!("Connection with the SAFE Network was lost");
        };

        let app = match auth_credentials {
            Some(auth_credentials) => {
                let auth_granted = decode_ipc_msg(auth_credentials)?;
                match auth_granted {
                    AuthResponseType::Registered(authgranted) => {
                        App::registered(app_id.to_string(), authgranted, disconnect_cb)
                    }
                    AuthResponseType::Unregistered(config) => {
                        App::unregistered(disconnect_cb, Some(config))
                    }
                }
            }
            None => App::unregistered(disconnect_cb, None),
        }
        .map_err(|err| {
            Error::ConnectionError(format!("Failed to connect to the SAFE Network: {:?}", err))
        })?;

        self.safe_conn = Some(app);
        debug!("Successfully connected to the Network!!!");
        Ok(())
    }

    fn create_balance(
        &mut self,
        from_sk: Option<SecretKey>,
        new_balance_owner: PublicKey,
        amount: Coins,
    ) -> Result<XorName> {
        let safe_app: &App = self.get_safe_app()?;
        run(safe_app, move |client, _app_context| {
            let from_fullid = from_sk.map(ClientFullId::from);
            client
                .create_balance(
                    from_fullid.as_ref(),
                    SafeNdPublicKey::Bls(new_balance_owner),
                    amount,
                    None,
                )
                .map_err(SafeAppError)
        })
        .map_err(|err| {
            if let SafeAppFfiError(SafeAppError(SafeCoreError::DataError(
                SafeNdError::InsufficientBalance,
            ))) = err
            {
                Error::NotEnoughBalance(amount.to_string())
            } else {
                Error::NetDataError(format!("Failed to create a SafeKey: {:?}", err))
            }
        })?;

        let xorname = xorname_from_pk(new_balance_owner);
        Ok(xorname)
    }

    fn allocate_test_coins(&mut self, owner_sk: SecretKey, amount: Coins) -> Result<XorName> {
        info!("Creating test SafeKey with {} test coins", amount);
        let xorname = xorname_from_pk(owner_sk.public_key());
        test_create_balance(&ClientFullId::from(owner_sk), amount)
            .map_err(|e| Error::NetDataError(format!("Failed to allocate test coins: {:?}", e)))?;

        Ok(xorname)
    }

    fn get_balance_from_sk(&self, sk: SecretKey) -> Result<Coins> {
        let safe_app: &App = self.get_safe_app()?;
        let coins = run(safe_app, move |client, _app_context| {
            client
                .get_balance(Some(&ClientFullId::from(sk)))
                .map_err(SafeAppError)
        })
        .map_err(|e| Error::NetDataError(format!("Failed to retrieve balance: {:?}", e)))?;

        Ok(coins)
    }

    fn safecoin_transfer_to_xorname(
        &mut self,
        from_sk: Option<SecretKey>,
        to_xorname: XorName,
        tx_id: TransactionId,
        amount: Coins,
    ) -> Result<Transaction> {
        let safe_app: &App = self.get_safe_app()?;
        let tx = run(safe_app, move |client, _app_context| {
            let from_fullid = from_sk.map(ClientFullId::from);
            client
                .transfer_coins(from_fullid.as_ref(), to_xorname, amount, Some(tx_id))
                .map_err(SafeAppError)
        })
        .map_err(|err| match err {
            SafeAppFfiError(SafeAppError(SafeCoreError::DataError(
                SafeNdError::ExcessiveValue,
            )))
            | SafeAppFfiError(SafeAppError(SafeCoreError::DataError(
                SafeNdError::InsufficientBalance,
            ))) => Error::NotEnoughBalance(amount.to_string()),
            SafeAppFfiError(SafeAppError(SafeCoreError::DataError(
                SafeNdError::InvalidOperation,
            ))) => Error::InvalidAmount(amount.to_string()),
            other => Error::NetDataError(format!("Failed to transfer coins: {:?}", other)),
        })?;

        Ok(tx)
    }

    fn safecoin_transfer_to_pk(
        &mut self,
        from_sk: Option<SecretKey>,
        to_pk: PublicKey,
        tx_id: TransactionId,
        amount: Coins,
    ) -> Result<Transaction> {
        let to_xorname = xorname_from_pk(to_pk);
        self.safecoin_transfer_to_xorname(from_sk, to_xorname, tx_id, amount)
    }

    // TODO: Replace with SCL calling code
    fn get_transaction(&self, _tx_id: u64, _pk: PublicKey, _sk: SecretKey) -> Result<String> {
        Ok("Success(0)".to_string())
    }

    fn files_put_published_immutable(&mut self, data: &[u8], dry_run: bool) -> Result<XorName> {
        // TODO: allow this operation to work without a connection when it's a dry run
        let safe_app: &App = self.get_safe_app()?;

        let data_vec = data.to_vec();
        let idata = run(safe_app, move |client, _app_context| {
            let client2 = client.clone();
            if dry_run {
                immutable_data::gen_data_map(
                    client, &data_vec, /*published:*/ true, /*encryption_key:*/ None,
                )
            } else {
                immutable_data::create(
                    client, &data_vec, /*published:*/ true, /*encryption_key:*/ None,
                )
            }
            .and_then(move |data_map| {
                let address = *data_map.address();
                if dry_run {
                    futures::future::Either::A(futures::future::ok(address))
                } else {
                    futures::future::Either::B(client2.put_idata(data_map).map(move |_| address))
                }
            })
            .map_err(SafeAppError)
        })
        .map_err(|e| {
            Error::NetDataError(format!("Failed to PUT Published ImmutableData: {:?}", e))
        })?;

        Ok(*idata.name())
    }

    fn files_get_published_immutable(&self, xorname: XorName) -> Result<Vec<u8>> {
        debug!("Fetching immutable data: {:?}", &xorname);

        let safe_app: &App = self.get_safe_app()?;
        let immd_data_addr = IDataAddress::Pub(xorname);
        let data = run(safe_app, move |client, _app_context| {
            immutable_data::get_value(client, immd_data_addr, /*decryption_key:*/ None)
                .map_err(SafeAppError)
        })
        .map_err(|e| {
            Error::NetDataError(format!("Failed to GET Published ImmutableData: {:?}", e))
        })?;
        debug!(
            "Published ImmutableData data successfully retrieved from: {:?}",
            &xorname
        );

        Ok(data)
    }

    fn put_sequence(
        &mut self,
        values: Vec<Vec<u8>>,
        name: Option<XorName>,
        tag: u64,
        _permissions: Option<String>,
    ) -> Result<XorName> {
        debug!(
            "Putting Sequence w/ type tag: {:?}, xorname: {:?}",
            tag, name
        );

        let safe_app: &App = self.get_safe_app()?;
        let xorname = name.unwrap_or_else(rand::random);
        info!("Xorname for storage: {:?}", &xorname);

        let address = Address::Public { name: xorname, tag };
        let mut sequence = PublicSequence::new(xorname, tag);

        // TODO: setup permissions from props
        let mut access_list = BTreeMap::<User, PublicUserAccess>::new();
        let mut permissions = BTreeMap::<AccessType, bool>::new();
        permissions.insert(AccessType::Append, true);
        permissions.insert(AccessType::ModifyPermissions, true);
        let user_access = PublicUserAccess::new(permissions);
        let usr_app = User::Specific(SafeNdPublicKey::Bls(get_public_bls_key(safe_app)?));
        let _ = access_list.insert(usr_app, user_access);
        sequence
            .set_access_list(
                PublicAccessList {
                    access_list,
                    expected_data_version: 0,
                    expected_owners_version: 0,
                },
                0,
            )
            .map_err(|e| {
                Error::Unexpected(format!(
                    "Failed to set permissions for the Sequence: {:?}",
                    e
                ))
            })?;

        let user_account_owner = get_owner_pk(safe_app)?;
        let owner = Owner {
            public_key: user_account_owner,
            expected_data_version: 0,
            expected_access_list_version: 1,
        };
        sequence.set_owner(owner, 0).map_err(|e| {
            Error::Unexpected(format!("Failed to set owner of the Sequence: {:?}", e))
        })?;

        let append = AppendOperation::new(address, values, Some(0));

        run(safe_app, move |client, _app_context| {
            let append_client = client.clone();
            client
                .put_sequence(Sequence::Public(sequence.clone()))
                .and_then(move |_| append_client.append(append))
                .map_err(SafeAppError)
                .map(move |_| xorname)
        })
        .map_err(|e| Error::NetDataError(format!("Failed to PUT Sequence: {:?}", e)))
    }

    fn append_to_sequence(
        &mut self,
        values: Vec<Vec<u8>>,
        expected_version: u64,
        name: XorName,
        tag: u64,
    ) -> Result<u64> {
        let safe_app: &App = self.get_safe_app()?;
        run(safe_app, move |client, _app_context| {
            let address = Address::Public { name, tag };
            let append = AppendOperation::new(address, values, Some(expected_version));

            client.append(append).map_err(SafeAppError)
        })
        .map_err(|e| Error::NetDataError(format!("Failed to UPDATE Sequence: {:?}", e)))?;

        Ok(expected_version)
    }

    fn get_current_sequence_value(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<(u64, SequenceRawData)> {
        debug!("Getting current Sequence value for: {:?}", &name);

        let safe_app: &App = self.get_safe_app()?;
        let address = Address::Public { name, tag };

        debug!("Address for Sequence : {:?}", address);
        let data_version = self
            .get_current_sequence_version(name, tag)
            .map_err(|e| Error::NetDataError(format!("Failed to get Sequence: {:?}", e)))?;

        let data_entry = run(safe_app, move |client, _app_context| {
            client
                .get_sequence_current_entry(address)
                .map_err(SafeAppError)
        })
        .map_err(|e| Error::NetDataError(format!("Failed to get Sequence: {:?}", e)))?;

        Ok((data_version, data_entry.value))
    }

    fn get_current_sequence_version(&self, name: XorName, tag: u64) -> Result<u64> {
        debug!("Getting Sequence version for: {:?}", name);

        let safe_app: &App = self.get_safe_app()?;
        let address = Address::Public { name, tag };

        run(safe_app, move |client, _app_context| {
            client.get_sequence_indices(address).map_err(SafeAppError)
        })
        .map_err(|e| Error::NetDataError(format!("Failed to get Sequence version: {:?}", e)))
        .map(|versions| versions.data_version - 1)
    }

    fn get_sequence_value_at(
        &self,
        name: XorName,
        tag: u64,
        version: u64,
    ) -> Result<SequenceRawData> {
        debug!(
            "Getting Sequence value at version: {:?}, from: {:?}",
            version, name
        );

        let safe_app: &App = self.get_safe_app()?;
        let address = Address::Public { name, tag };

        let start = Version::FromStart(version);
        let end = Version::FromStart(version + 1);
        let data_entries = run(safe_app, move |client, _app_context| {
            client
                .get_sequence_range(address, (start, end))
                .map_err(SafeAppError)
        })
        .map_err(|err| {
            if let SafeAppFfiError(SafeAppError(SafeCoreError::DataError(
                SafeNdError::NoSuchEntry,
            ))) = err
            {
                Error::VersionNotFound(format!(
                    "Invalid version ({}) for Sequence found at XoR name {}",
                    version, name
                ))
            } else {
                Error::NetDataError(format!("Failed to get Sequence: {:?}", err))
            }
        })?;

        let value = data_entries[0].clone();
        Ok(value)
    }

    fn put_seq_mutable_data(
        &mut self,
        name: Option<XorName>,
        tag: u64,
        // _data: Option<String>,
        _permissions: Option<String>,
    ) -> Result<XorName> {
        let safe_app: &App = self.get_safe_app()?;
        let owner_key_option = get_owner_pk(safe_app)?;
        let owners = if let SafeNdPublicKey::Bls(owners) = owner_key_option {
            owners
        } else {
            return Err(Error::Unexpected(
                "Failed to retrieve public key.".to_string(),
            ));
        };

        let xorname = name.unwrap_or_else(rand::random);

        let permission_set = MDataPermissionSet::new()
            .allow(MDataAction::Read)
            .allow(MDataAction::Insert)
            .allow(MDataAction::Update)
            .allow(MDataAction::Delete)
            .allow(MDataAction::ManagePermissions);

        let mut permission_map = BTreeMap::new();
        let sign_pk = get_public_bls_key(safe_app)?;
        let app_pk = SafeNdPublicKey::Bls(sign_pk);
        permission_map.insert(app_pk, permission_set);

        let mdata = SeqMutableData::new_with_data(
            xorname,
            tag,
            BTreeMap::new(),
            permission_map,
            SafeNdPublicKey::Bls(owners),
        );

        run(safe_app, move |client, _app_context| {
            client
                .put_seq_mutable_data(mdata)
                .map_err(SafeAppError)
                .map(move |_| xorname)
        })
        .map_err(|err| Error::NetDataError(format!("Failed to put mutable data: {}", err)))
    }

    fn get_seq_mdata(&self, name: XorName, tag: u64) -> Result<SeqMutableData> {
        let safe_app: &App = self.get_safe_app()?;
        run(safe_app, move |client, _app_context| {
            client.get_seq_mdata(name, tag).map_err(SafeAppError)
        })
        .map_err(|e| Error::NetDataError(format!("Failed to get MD: {:?}", e)))
    }

    fn seq_mutable_data_insert(
        &mut self,
        name: XorName,
        tag: u64,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        let entry_actions = MDataSeqEntryActions::new();
        let entry_actions = entry_actions.ins(key.to_vec(), value.to_vec(), 0);
        self.mutate_seq_mdata_entries(name, tag, entry_actions, "Failed to insert to SeqMD")
    }

    fn seq_mutable_data_get_value(
        &self,
        name: XorName,
        tag: u64,
        key: &[u8],
    ) -> Result<MDataSeqValue> {
        let safe_app: &App = self.get_safe_app()?;
        let key_vec = key.to_vec();
        run(safe_app, move |client, _app_context| {
            client
                .get_seq_mdata_value(name, tag, key_vec)
                .map_err(SafeAppError)
        })
        .map_err(|err| match err {
            SafeAppFfiError(SafeAppError(SafeCoreError::DataError(SafeNdError::AccessDenied))) => {
                Error::AccessDenied(format!("Failed to retrieve a key: {:?}", key))
            }
            SafeAppFfiError(SafeAppError(SafeCoreError::DataError(SafeNdError::NoSuchData))) => {
                Error::ContentNotFound(format!(
                    "Sequenced MutableData not found at Xor name: {}",
                    xorname_to_hex(&name)
                ))
            }
            SafeAppFfiError(SafeAppError(SafeCoreError::DataError(SafeNdError::NoSuchEntry))) => {
                Error::EntryNotFound(format!(
                    "Entry not found in Sequenced MutableData found at Xor name: {}",
                    xorname_to_hex(&name)
                ))
            }
            err => Error::NetDataError(format!("Failed to retrieve a key. {:?}", err)),
        })
    }

    fn list_seq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<BTreeMap<Vec<u8>, MDataSeqValue>> {
        let safe_app: &App = self.get_safe_app()?;
        run(safe_app, move |client, _app_context| {
            client
                .list_seq_mdata_entries(name, tag)
                .map_err(SafeAppError)
        })
        .map_err(|err| match err {
            SafeAppFfiError(SafeAppError(SafeCoreError::DataError(SafeNdError::AccessDenied))) => {
                Error::AccessDenied(format!(
                    "Failed to get Sequenced MutableData at: {:?} (type tag: {})",
                    name, tag
                ))
            }
            SafeAppFfiError(SafeAppError(SafeCoreError::DataError(SafeNdError::NoSuchData))) => {
                Error::ContentNotFound(format!(
                    "Sequenced MutableData not found at Xor name: {} (type tag: {})",
                    xorname_to_hex(&name),
                    tag
                ))
            }
            SafeAppFfiError(SafeAppError(SafeCoreError::DataError(SafeNdError::NoSuchEntry))) => {
                Error::EntryNotFound(format!(
                    "Entry not found in Sequenced MutableData found at Xor name: {} (type tag: {})",
                    xorname_to_hex(&name),
                    tag
                ))
            }
            err => Error::NetDataError(format!("Failed to get Sequenced MutableData. {:?}", err)),
        })
    }

    fn seq_mutable_data_update(
        &mut self,
        name: XorName,
        tag: u64,
        key: &[u8],
        value: &[u8],
        version: u64,
    ) -> Result<()> {
        let entry_actions = MDataSeqEntryActions::new();
        let entry_actions = entry_actions.update(key.to_vec(), value.to_vec(), version);
        self.mutate_seq_mdata_entries(name, tag, entry_actions, "Failed to update SeqMD")
    }
}

// Helpers

fn get_owner_pk(safe_app: &App) -> Result<SafeNdPublicKey> {
    run(safe_app, move |client, _app_context| Ok(client.owner_key())).map_err(|err| {
        Error::Unexpected(format!("Failed to retrieve account's public key: {}", err))
    })
}

fn get_public_bls_key(safe_app: &App) -> Result<PublicKey> {
    run(safe_app, move |client, _app_context| {
        let pk = client
            .public_key()
            .bls()
            .ok_or_else(|| "It's not a BLS Public Key".to_string())?;
        Ok(pk)
    })
    .map_err(|err| {
        Error::Unexpected(format!(
            "Failed to retrieve account's public BLS key: {}",
            err
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Safe;

    #[test]
    fn test_put_and_get_immutable_data() {
        let mut safe = Safe::default();
        safe.connect("", Some("fake-credentials")).unwrap();

        let id1 = b"HELLLOOOOOOO".to_vec();

        let xorname = safe
            .safe_app
            .files_put_published_immutable(&id1, false)
            .unwrap();
        let data = safe
            .safe_app
            .files_get_published_immutable(xorname)
            .unwrap();
        let text = std::str::from_utf8(data.as_slice()).unwrap();
        assert_eq!(text.to_string(), "HELLLOOOOOOO");
    }

    #[test]
    fn test_put_get_update_sequence() {
        let mut safe = Safe::default();
        safe.connect("", Some("fake-credentials")).unwrap();

        let key1 = b"KEY1".to_vec();
        let val1 = b"VALUE1".to_vec();
        let data1 = vec![key1, val1];

        let type_tag = 12322;
        let xorname = safe
            .safe_app
            .put_sequence(data1, None, type_tag, None)
            .unwrap();

        let (this_version, data) = safe
            .safe_app
            .get_current_sequence_value(xorname, type_tag)
            .unwrap();

        assert_eq!(this_version, 0);

        //TODO: Properly unwrap data so this is clear (0 being version, 1 being data)
        assert_eq!(std::str::from_utf8(data.as_slice()).unwrap(), "KEY1");
        // assert_eq!(std::str::from_utf8(data_v1.as_slice()).unwrap(), "VALUE1");

        let key2 = b"KEY2".to_vec();
        let val2 = b"VALUE2".to_vec();
        let data2 = vec![key2, val2];
        let expected_version = 2;

        let updated_version = safe
            .safe_app
            .append_to_sequence(data2, expected_version, xorname, type_tag)
            .unwrap();
        let (the_latest_version, data_updated) = safe
            .safe_app
            .get_current_sequence_value(xorname, type_tag)
            .unwrap();

        assert_eq!(updated_version, the_latest_version);

        assert_eq!(
            std::str::from_utf8(data_updated.as_slice()).unwrap(),
            "KEY2"
        );
        // assert_eq!(
        //     std::str::from_utf8(data_updated_v1.as_slice()).unwrap(),
        //     "VALUE2"
        // );

        let first_version = 0;

        let first_data = safe
            .safe_app
            .get_sequence_value_at(xorname, type_tag, first_version)
            .unwrap();

        assert_eq!(std::str::from_utf8(first_data.as_slice()).unwrap(), "KEY1");
        // assert_eq!(
        //     std::str::from_utf8(first_data_v1.as_slice()).unwrap(),
        //     "VALUE1"
        // );

        let second_version = 1;
        let second_data = safe
            .safe_app
            .get_sequence_value_at(xorname, type_tag, second_version)
            .unwrap();

        assert_eq!(std::str::from_utf8(second_data.as_slice()).unwrap(), "KEY2");
        // assert_eq!(
        //     std::str::from_utf8(second_data_v1.as_slice()).unwrap(),
        //     "VALUE2"
        // );

        // test checking for versions that dont exist
        let nonexistant_version = 2;
        match safe
            .safe_app
            .get_sequence_value_at(xorname, type_tag, nonexistant_version)
        {
            Ok(_) => panic!("No error thrown when passing an outdated new version"),
            Err(Error::VersionNotFound(msg)) => assert!(msg.contains(&format!(
                "Invalid version ({}) for Sequenced Sequence found at XoR name {}",
                nonexistant_version, xorname
            ))),
            err => panic!(format!("Error returned is not the expected one: {:?}", err)),
        }
    }

    #[test]
    fn test_update_sequence_error() {
        let mut safe = Safe::default();
        safe.connect("", Some("fake-credentials")).unwrap();

        let key1 = b"KEY1".to_vec();
        let val1 = b"VALUE1".to_vec();
        let data1 = vec![key1, val1];

        let type_tag = 12322;
        let xorname = safe
            .safe_app
            .put_sequence(data1, None, type_tag, None)
            .unwrap();

        let (this_version, data) = safe
            .safe_app
            .get_current_sequence_value(xorname, type_tag)
            .unwrap();

        assert_eq!(this_version, 0);

        //TODO: Properly unwrap data so this is clear (0 being version, 1 being data)
        assert_eq!(std::str::from_utf8(data.as_slice()).unwrap(), "KEY1");
        //assert_eq!(std::str::from_utf8(data_v1.as_slice()).unwrap(), "VALUE1");

        let key2 = b"KEY2".to_vec();
        let val2 = b"VALUE2".to_vec();
        let data2 = vec![key2, val2];
        let wrong_new_version = 0;

        match safe
            .safe_app
            .append_to_sequence(data2, wrong_new_version, xorname, type_tag)
        {
            Ok(_) => panic!("No error thrown when passing an outdated new version"),
            Err(Error::NetDataError(msg)) => assert!(msg.contains("Invalid data successor")),
            _ => panic!("Error returned is not the expected one"),
        }
    }
}
