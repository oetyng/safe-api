// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use safe_app::{run, App as Session};
use super::super::{Error, ResultReturn as ReturnResult};
pub use threshold_crypto::{PublicKey, SecretKey};

use safe_nd::{
    PublicKey as SafeNdPublicKey,
};

use safe_core::client::Client;

pub fn get_owner_pk(session: &Session) -> ReturnResult<SafeNdPublicKey> {
    run(session, move |client, _app_context| Ok(client.owner_key())).map_err(|err| {
        Error::Unexpected(format!("Failed to retrieve account's public key: {}", err))
    })
}

pub fn get_public_bls_key(session: &Session) -> ReturnResult<PublicKey> {
    run(session, move |client, _app_context| {
        Ok(client.public_bls_key())
    })
    .map_err(|err| {
        Error::Unexpected(format!(
            "Failed to retrieve account's public BLS key: {}",
            err
        ))
    })
}

// Unit tests
