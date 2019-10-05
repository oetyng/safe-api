// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

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
    Error as SafeNdError, IDataAddress, PubImmutableData,
    PublicKey as SafeNdPublicKey,
    Transaction, TransactionId, XorName,
};

pub use threshold_crypto::{PublicKey, SecretKey};

use std::collections::BTreeMap;

const NOT_CONNECTED: &str = "Application is not connected to the network";

#[derive(Default)]
pub struct PubImmutableData {
    session: Option<Session>,
}

impl PubImmutableData {
    
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

    fn put(&mut self, data: &[u8]) -> Result<XorName> {
        let session: &Session = self.get_session()?;

        let the_idata = PubImmutableData::new(data.to_vec());
        let return_idata = the_idata.clone();
        run(session, move |client, _app_context| {
            client.put_idata(the_idata).map_err(SessionError)
        })
        .map_err(|e| {
            Error::NetDataError(format!("Failed to PUT Published ImmutableData: {:?}", e))
        })?;

        Ok(*return_idata.name())
    }

    fn get(&self, xorname: XorName) -> Result<Vec<u8>> {
        debug!("Fetching immutable data: {:?}", &xorname);

        let session: &Session = self.get_session()?;
        let immd_data_addr = IDataAddress::Pub(xorname);
        let data = run(session, move |client, _app_context| {
            client.get_idata(immd_data_addr).map_err(SessionError)
        })
        .map_err(|e| {
            Error::NetDataError(format!("Failed to GET Published ImmutableData: {:?}", e))
        })?;
        debug!("the_data: {:?}", &xorname);

        Ok(data.value().to_vec())
    }
}

// Unit tests

#[test]
fn test_put_and_get_immutable_data() {
    use super::Safe;
    let mut safe = Safe::new("base32z");
    safe.connect("", Some("fake-credentials")).unwrap();

    let id1 = b"HELLLOOOOOOO".to_vec();

    let xorname = safe.session.files_put_published_immutable(&id1).unwrap();
    let data = safe
        .session
        .files_get_published_immutable(xorname)
        .unwrap();
    let text = std::str::from_utf8(data.as_slice()).unwrap();
    assert_eq!(text.to_string(), "HELLLOOOOOOO");
}
