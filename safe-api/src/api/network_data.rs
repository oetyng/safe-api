// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::data_files::DataFiles;
use super::map::Map;
use super::versioned_data::VersionedData;

use safe_app::{App as Session};

#[cfg(feature = "fake-auth")]
use safe_app::test_utils::create_app;

//#[derive(Default)]
pub struct NetworkData {
    connection: Session,
}

impl NetworkData {
    fn new(session: Session) -> Self {
        Self { 
            connection: session
        }
    }

    pub fn files_api(self) -> DataFiles {
        DataFiles::new(self.connection)
    }

    pub fn map_api(self) -> Map {
        Map::new(self.connection)
    }

    pub fn versioned_data_api(self) -> VersionedData {
        VersionedData::new(self.connection)
    }
}