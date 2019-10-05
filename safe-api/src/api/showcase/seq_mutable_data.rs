// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::data::{get_owner_pk, get_public_bls_key};

use super::helpers::{create_random_xorname, xorname_from_pk, xorname_to_hex};
use super::{Error, ResultReturn as ReturnResult, SafeApp};
use futures::future::Future;
use log::{debug, info, warn};
use rand::rngs::OsRng;
use rand_core::RngCore;
use safe_app::{run, App as Session, AppError::CoreError as SessionError};
use safe_core::{CoreError as SafeCoreError};

#[cfg(not(feature = "fake-auth"))]
use super::helpers::decode_ipc_msg;
#[cfg(feature = "fake-auth")]
use safe_app::test_utils::create_app;
use safe_core::client::Client;
use safe_nd::{
    Error as SafeNdError, MDataAction, MDataPermissionSet, MDataSeqEntryActions as MDataTransaction,
    MDataSeqValue as Value, PublicKey as SafeNdPublicKey,
    SeqMutableData as SequencedMutableData, Transaction, TransactionId, XorName,
};

pub use threshold_crypto::{PublicKey, SecretKey};

use std::collections::BTreeMap;

const NOT_CONNECTED: &str = "Application is not connected to the network";

#[derive(Default)]
pub struct SeqMutableData {
    session: Option<Session>,
}

impl SeqMutableData {

    fn new(session: &Session) -> Self {
        Self { session: session }
    }

    // Private helper to obtain the Session instance
    fn get_session(&self) -> Result<&Session> {
        match &self.session {
            Some(session) => Ok(session),
            None => Err(Error::ConnectionError(NOT_CONNECTED.to_string())),
        }
    }

    fn update_with_tx(
        &self,
        name: XorName,
        tag: u64,
        tx: MDataTransaction,
        error_msg: &str,
    ) -> Result<()> {
        let session = self.get_session()?;
        let message = error_msg.to_string();
        run(session, move |client, _app_context| {
            client
                .mutate_seq_mdata_entries(name, tag, tx)
                .map_err(SessionError)
        })
        .map_err(|err| {
            if let SessionError(SafeCoreError::DataError(SafeNdError::InvalidEntryActions(_))) = err
            {
                Error::EntryExists(format!("{}: {}", message, err))
            } else {
                Error::NetDataError(format!("{}: {}", message, err))
            }
        })
    }
    
    fn create(
        &mut self,
        name: Option<XorName>,
        tag: u64,
        // _data: Option<String>,
        _permissions: Option<String>,
    ) -> Result<XorName> {
        let session: &Session = self.get_session()?;
        let owner_key_option = get_owner_pk(session)?;
        let owners = if let SafeNdPublicKey::Bls(owners) = owner_key_option {
            owners
        } else {
            return Err(Error::Unexpected(
                "Failed to retrieve public key.".to_string(),
            ));
        };

        let xorname = match name {
            Some(xorname) => xorname,
            None => {
                let mut rng = OsRng::new().map_err(|err| {
                    Error::Unexpected(format!("Failed to generate a random XOR name: {}", err))
                })?;
                let mut xorname = XorName::default();
                rng.fill_bytes(&mut xorname.0);
                xorname
            }
        };

        let permission_set = MDataPermissionSet::new()
            .allow(MDataAction::Read)
            .allow(MDataAction::Insert)
            .allow(MDataAction::Update)
            .allow(MDataAction::Delete)
            .allow(MDataAction::ManagePermissions);

        let mut permission_map = BTreeMap::new();
        let sign_pk = get_public_bls_key(session)?;
        let app_pk = SafeNdPublicKey::Bls(sign_pk);
        permission_map.insert(app_pk, permission_set);

        let mdata = SequencedMutableData::new_with_data(
            xorname,
            tag,
            BTreeMap::new(),
            permission_map,
            SafeNdPublicKey::Bls(owners),
        );

        run(session, move |client, _app_context| {
            client
                .put_seq_mutable_data(mdata)
                .map_err(SessionError)
                .map(move |_| xorname)
        })
        .map_err(|err| Error::NetDataError(format!("Failed to put Sequenced MutableData: {}", err)))
    }

    fn get(&self, name: XorName, tag: u64) -> Result<SeqMutableData> {
        let session: &Session = self.get_session()?;
        run(session, move |client, _app_context| {
            client.get_seq_mdata(name, tag).map_err(SessionError)
        })
        .map_err(|e| Error::NetDataError(format!("Failed to get Sequenced MutableData: {:?}", e)))
    }

    fn insert(
        &mut self,
        name: XorName,
        tag: u64,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        let tx = MDataTransaction::new();
        let tx = tx.ins(key.to_vec(), value.to_vec(), 0);
        self.mutate_seq_mdata_entries(name, tag, tx, "Failed to insert to Sequenced MutableData")
    }

    fn get_value(
        &self,
        name: XorName,
        tag: u64,
        key: &[u8],
    ) -> Result<Value> {
        let session: &Session = self.get_session()?;
        let key_vec = key.to_vec();
        run(session, move |client, _app_context| {
            client
                .get_seq_mdata_value(name, tag, key_vec)
                .map_err(SessionError)
        })
        .map_err(|err| match err {
            SessionError(SafeCoreError::DataError(SafeNdError::AccessDenied)) => {
                Error::AccessDenied(format!("Failed to retrieve a key: {:?}", key))
            }
            SessionError(SafeCoreError::DataError(SafeNdError::NoSuchData)) => {
                Error::ContentNotFound(format!(
                    "Sequenced MutableData not found at XOR name: {}",
                    xorname_to_hex(&name)
                ))
            }
            SessionError(SafeCoreError::DataError(SafeNdError::NoSuchEntry)) => {
                Error::EntryNotFound(format!(
                    "Entry not found in Sequenced MutableData found at XOR name: {}",
                    xorname_to_hex(&name)
                ))
            }
            err => Error::NetDataError(format!("Failed to retrieve a key. {:?}", err)),
        })
    }

    fn list(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<BTreeMap<Vec<u8>, Value>> {
        let session: &Session = self.get_session()?;
        run(session, move |client, _app_context| {
            client
                .list_seq_mdata_entries(name, tag)
                .map_err(SessionError)
        })
        .map_err(|err| {
            if let SessionError(SafeCoreError::DataError(SafeNdError::AccessDenied)) = err {
                Error::AccessDenied(format!("Failed to get Sequenced MutableData at: {:?}", name))
            } else {
                Error::NetDataError(format!("Failed to get Sequenced MutableData. {:?}", err))
            }
        })
    }

    fn update(
        &mut self,
        name: XorName,
        tag: u64,
        key: &[u8],
        value: &[u8],
        version: u64,
    ) -> Result<()> {
        let tx = MDataTransaction::new();
        let tx = tx.update(key.to_vec(), value.to_vec(), version);
        self.update_with_tx(name, tag, tx, "Failed to update Sequenced MutableData")
    }
}

// Unit tests
