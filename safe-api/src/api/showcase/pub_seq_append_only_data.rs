// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::data::{get_owner_pk, get_public_bls_key};

use super::helpers::{create_random_xorname, xorname_from_pk, xorname_to_hex};
use super::safe_net::AppendOnlyDataRawData;
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
    AData, ADataAddress, ADataAppendOperation, ADataEntry, ADataIndex, ADataOwner,
    ADataPubPermissionSet, ADataPubPermissions, ADataUser, AppendOnlyData,
    Error as SafeNdError, PubSeqAppendOnlyData, PublicKey as SafeNdPublicKey,
    Transaction, TransactionId, XorName,
};

pub use threshold_crypto::{PublicKey, SecretKey};

use std::collections::BTreeMap;

const NOT_CONNECTED: &str = "Application is not connected to the network";

#[derive(Default)]
pub struct PubSeqAppendOnlyData {
    session: Option<Session>,
}

impl PubSeqAppendOnlyData {

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

    fn put(
        &mut self,
        the_data: Vec<(Vec<u8>, Vec<u8>)>,
        name: Option<XorName>,
        tag: u64,
        _permissions: Option<String>,
    ) -> Result<XorName> {
        debug!(
            "Putting appendable data w/ type: {:?}, xorname: {:?}",
            tag, name
        );

        let session: &Session = self.get_session()?;
        let xorname = name.unwrap_or_else(create_random_xorname);
        info!("Xorname for storage: {:?}", &xorname);

        let append_only_data_address = ADataAddress::PubSeq { name: xorname, tag };
        let mut data = PubSeqAppendOnlyData::new(xorname, tag);

        // TODO: setup permissions from props
        let mut perms = BTreeMap::<ADataUser, ADataPubPermissionSet>::new();
        let set = ADataPubPermissionSet::new(true, true);
        let usr_app = ADataUser::Key(SafeNdPublicKey::Bls(get_public_bls_key(session)?));
        let _ = perms.insert(usr_app, set);
        data.append_permissions(
            ADataPubPermissions {
                permissions: perms,
                entries_index: 0,
                owners_index: 0,
            },
            0,
        )
        .map_err(|e| {
            Error::Unexpected(format!(
                "Failed to set permissions for the Sequenced Append Only Data: {:?}",
                e
            ))
        })?;

        let usr_acc_owner = get_owner_pk(session)?;
        let owner = ADataOwner {
            public_key: usr_acc_owner,
            entries_index: 0,
            permissions_index: 1,
        };
        data.append_owner(owner, 0).map_err(|e| {
            Error::Unexpected(format!(
                "Failed to set the owner to the Sequenced Append Only Data: {:?}",
                e
            ))
        })?;

        let entries_vec = the_data
            .iter()
            .map(|(k, v)| ADataEntry::new(k.to_vec(), v.to_vec()))
            .collect();
        let append = ADataAppendOperation {
            address: append_only_data_address,
            values: entries_vec,
        };

        run(session, move |client, _app_context| {
            let append_client = client.clone();
            client
                .put_adata(AData::PubSeq(data.clone()))
                .and_then(move |_| append_client.append_seq_adata(append, 0))
                .map_err(SessionError)
                .map(move |_| xorname)
        })
        .map_err(|e| {
            Error::NetDataError(format!("Failed to PUT Sequenced Append Only Data: {:?}", e))
        })
    }

    fn append(
        &mut self,
        the_data: Vec<(Vec<u8>, Vec<u8>)>,
        new_version: u64,
        name: XorName,
        tag: u64,
    ) -> Result<u64> {
        let session: &Session = self.get_session()?;
        run(session, move |client, _app_context| {
            let append_only_data_address = ADataAddress::PubSeq { name, tag };
            let entries_vec = the_data
                .iter()
                .map(|(k, v)| ADataEntry::new(k.to_vec(), v.to_vec()))
                .collect();
            let append = ADataAppendOperation {
                address: append_only_data_address,
                values: entries_vec,
            };

            client
                .append_seq_adata(append, new_version)
                .map_err(SessionError)
        })
        .map_err(|e| {
            Error::NetDataError(format!(
                "Failed to UPDATE Sequenced Append Only Data: {:?}",
                e
            ))
        })?;

        Ok(new_version)
    }

    fn get_last(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<(u64, AppendOnlyDataRawData)> {
        debug!("Getting latest seq_append_only_data for: {:?}", &name);

        let session: &Session = self.get_session()?;
        let append_only_data_address = ADataAddress::PubSeq { name, tag };

        debug!("Address for a_data : {:?}", append_only_data_address);

        let data_length = self
            .get_current_seq_append_only_data_version(name, tag)
            .map_err(|e| {
                Error::NetDataError(format!("Failed to get Sequenced Append Only Data: {:?}", e))
            })?;

        let data_entry = run(session, move |client, _app_context| {
            client
                .get_adata_last_entry(append_only_data_address)
                .map_err(SessionError)
        })
        .map_err(|e| {
            Error::NetDataError(format!("Failed to get Sequenced Append Only Data: {:?}", e))
        })?;

        let data = (data_entry.key, data_entry.value);
        Ok((data_length, data))
    }

    fn get_version(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<u64> {
        debug!("Getting seq appendable data, length for: {:?}", name);

        let session: &Session = self.get_session()?;
        let append_only_data_address = ADataAddress::PubSeq { name, tag };

        run(session, move |client, _app_context| {
            client
                .get_adata_indices(append_only_data_address)
                .map_err(SessionError)
        })
        .map_err(|e| {
            Error::NetDataError(format!(
                "Failed to get Sequenced Append Only Data indices: {:?}",
                e
            ))
        })
        .map(|data_returned| data_returned.entries_index() - 1)
    }

    fn get_at_version(
        &self,
        name: XorName,
        tag: u64,
        version: u64,
    ) -> Result<AppendOnlyDataRawData> {
        debug!(
            "Getting seq appendable data, version: {:?}, from: {:?}",
            version, name
        );

        let session: &Session = self.get_session()?;
        let append_only_data_address = ADataAddress::PubSeq { name, tag };

        let start = ADataIndex::FromStart(version);
        let end = ADataIndex::FromStart(version + 1);
        let data_entries = run(session, move |client, _app_context| {
            client
                .get_adata_range(append_only_data_address, (start, end))
                .map_err(SessionError)
        })
        .map_err(|err| {
            if let SessionError(SafeCoreError::DataError(SafeNdError::NoSuchEntry)) = err {
                Error::VersionNotFound(format!(
                    "Invalid version ({}) for Sequenced AppendOnlyData found at XoR name {}",
                    version, name
                ))
            } else {
                Error::NetDataError(format!(
                    "Failed to get Sequenced Append Only Data: {:?}",
                    err
                ))
            }
        })?;

        let this_version = data_entries[0].clone();
        Ok((this_version.key, this_version.value))
    }

}

// Unit tests

#[test]
fn test_put_get_update_seq_append_only_data() {
    use super::Safe;
    let mut safe = Safe::new("base32z");
    safe.connect("", Some("fake-credentials")).unwrap();

    let key1 = b"KEY1".to_vec();
    let val1 = b"VALUE1".to_vec();
    let data1 = [(key1, val1)].to_vec();

    let type_tag = 12322;
    let xorname = safe
        .session
        .put_seq_append_only_data(data1, None, type_tag, None)
        .unwrap();

    let (this_version, data) = safe
        .session
        .get_latest_seq_append_only_data(xorname, type_tag)
        .unwrap();

    assert_eq!(this_version, 0);

    //TODO: Properly unwrap data so this is clear (0 being version, 1 being data)
    assert_eq!(std::str::from_utf8(data.0.as_slice()).unwrap(), "KEY1");
    assert_eq!(std::str::from_utf8(data.1.as_slice()).unwrap(), "VALUE1");

    let key2 = b"KEY2".to_vec();
    let val2 = b"VALUE2".to_vec();
    let data2 = [(key2, val2)].to_vec();
    let new_version = 1;

    let updated_version = safe
        .session
        .append_seq_append_only_data(data2, new_version, xorname, type_tag)
        .unwrap();
    let (the_latest_version, data_updated) = safe
        .session
        .get_latest_seq_append_only_data(xorname, type_tag)
        .unwrap();

    assert_eq!(updated_version, the_latest_version);

    assert_eq!(
        std::str::from_utf8(data_updated.0.as_slice()).unwrap(),
        "KEY2"
    );
    assert_eq!(
        std::str::from_utf8(data_updated.1.as_slice()).unwrap(),
        "VALUE2"
    );

    let first_version = 0;

    let first_data = safe
        .session
        .get_seq_append_only_data(xorname, type_tag, first_version)
        .unwrap();

    assert_eq!(
        std::str::from_utf8(first_data.0.as_slice()).unwrap(),
        "KEY1"
    );
    assert_eq!(
        std::str::from_utf8(first_data.1.as_slice()).unwrap(),
        "VALUE1"
    );

    let second_version = 1;
    let second_data = safe
        .session
        .get_seq_append_only_data(xorname, type_tag, second_version)
        .unwrap();

    assert_eq!(
        std::str::from_utf8(second_data.0.as_slice()).unwrap(),
        "KEY2"
    );
    assert_eq!(
        std::str::from_utf8(second_data.1.as_slice()).unwrap(),
        "VALUE2"
    );

    // test checking for versions that dont exist
    let nonexistant_version = 2;
    match safe
        .session
        .get_seq_append_only_data(xorname, type_tag, nonexistant_version)
    {
        Ok(_) => panic!("No error thrown when passing an outdated new version"),
        Err(Error::VersionNotFound(msg)) => assert!(msg.contains(&format!(
            "Invalid version ({}) for Sequenced AppendOnlyData found at XoR name {}",
            nonexistant_version, xorname
        ))),
        err => panic!(format!("Error returned is not the expected one: {:?}", err)),
    }
}

#[test]
fn test_update_seq_append_only_data_error() {
    use super::Safe;
    let mut safe = Safe::new("base32z");
    safe.connect("", Some("fake-credentials")).unwrap();

    let key1 = b"KEY1".to_vec();
    let val1 = b"VALUE1".to_vec();
    let data1 = [(key1, val1)].to_vec();

    let type_tag = 12322;
    let xorname = safe
        .session
        .put_seq_append_only_data(data1, None, type_tag, None)
        .unwrap();

    let (this_version, data) = safe
        .session
        .get_latest_seq_append_only_data(xorname, type_tag)
        .unwrap();

    assert_eq!(this_version, 0);

    //TODO: Properly unwrap data so this is clear (0 being version, 1 being data)
    assert_eq!(std::str::from_utf8(data.0.as_slice()).unwrap(), "KEY1");
    assert_eq!(std::str::from_utf8(data.1.as_slice()).unwrap(), "VALUE1");

    let key2 = b"KEY2".to_vec();
    let val2 = b"VALUE2".to_vec();
    let data2 = [(key2, val2)].to_vec();
    let wrong_new_version = 0;

    match safe
        .session
        .append_seq_append_only_data(data2, wrong_new_version, xorname, type_tag)
    {
        Ok(_) => panic!("No error thrown when passing an outdated new version"),
        Err(Error::NetDataError(msg)) => assert!(msg.contains("Invalid data successor")),
        _ => panic!("Error returned is not the expected one"),
    }
}
