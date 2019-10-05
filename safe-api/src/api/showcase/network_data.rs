// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::SeqAppendOnlyData;
use super::SeqMutableData;
use super::PublishedImmutableData;

use futures::future::Future;
use log::{debug, info, warn};
use safe_app::{run, App as Session};

#[cfg(feature = "fake-auth")]
use safe_app::test_utils::create_app;
use safe_core::client::Client;

use std::collections::BTreeMap;

#[derive(Default)]
pub struct NetworkData {
    pub_seq_append_only_data: Option<PubSeqAppendOnlyData>,
    pub_immutable_data: Option<PubImmutableData>,
    seq_mutable_data: Option<SeqMutableData>,
}

impl NetworkData {
    fn new(session: &Session) -> Self {
        Self 
        { 
            pub_seq_append_only_data: PubSeqAppendOnlyData::new(session),
            pub_immutable_data: PubImmutableData::new(session),
            seq_mutable_data: SeqMutableData::new(session),
        }
    }
}