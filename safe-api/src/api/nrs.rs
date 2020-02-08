// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{
    constants::{CONTENT_ADDED_SIGN, CONTENT_DELETED_SIGN},
    helpers::get_subnames_host_path_and_version, // gen_timestamp_nanos
    nrs_map::NrsMap,
    xorurl::{SafeContentType, SafeDataType},
    Error,
    Result,
    Safe,
    SafeApp,
    XorUrl,
    XorUrlEncoder,
};
use log::{debug, info, warn};
use safe_nd::XorName;
use std::collections::BTreeMap;
use tiny_keccak::sha3_256;

// Type tag to use for the NrsMapContainer stored on AppendOnlyData
const NRS_MAP_TYPE_TAG: u64 = 1_500;

const ERROR_MSG_NO_NRS_MAP_FOUND: &str = "No NRS Map found at this address";

// Raw data stored in the SAFE native data type for a NRS Map Container
type NrsMapRawData = Vec<Vec<u8>>;

// List of public names uploaded with details if they were added, updated or deleted from NrsMaps
pub type ProcessedEntries = BTreeMap<String, (String, String)>;

#[allow(dead_code)]
impl Safe {
    pub fn parse_url(url: &str) -> Result<XorUrlEncoder> {
        let sanitised_url = sanitised_url(url);
        debug!("Attempting to decode url: {}", sanitised_url);
        XorUrlEncoder::from_url(&sanitised_url).or_else(|err| {
            info!(
                "Falling back to NRS. XorUrl decoding failed with: {:?}",
                err
            );

            let (sub_names, host_str, path, version) =
                get_subnames_host_path_and_version(&sanitised_url)?;
            let hashed_host = xorname_from_nrs_string(&host_str)?;

            let encoded_xor = XorUrlEncoder::new(
                hashed_host,
                NRS_MAP_TYPE_TAG,
                SafeDataType::PublishedSeqAppendOnlyData,
                SafeContentType::NrsMapContainer,
                Some(&path),
                Some(sub_names),
                version,
            )?;

            Ok(encoded_xor)
        })
    }

    // Parses a safe:// URL and returns all the info in a XorUrlEncoder instance.
    // It also returns a second XorUrlEncoder if the URL was resolved as NRS-URL,
    // this second XorUrlEncoder instance contains the information of the parsed NRS-URL.
    pub fn parse_and_resolve_url(
        &self,
        url: &str,
    ) -> Result<(XorUrlEncoder, Option<XorUrlEncoder>)> {
        let xorurl_encoder = Safe::parse_url(url)?;
        if xorurl_encoder.content_type() == SafeContentType::NrsMapContainer {
            let (_version, nrs_map) = self.nrs_map_container_get(&url).map_err(|_| {
                Error::InvalidInput(
                    "The location couldn't be resolved from the NRS URL provided".to_string(),
                )
            })?;
            let xorurl = nrs_map.resolve_for_subnames(xorurl_encoder.sub_names())?;
            Ok((XorUrlEncoder::from_url(&xorurl)?, Some(xorurl_encoder)))
        } else {
            Ok((xorurl_encoder, None))
        }
    }

    pub fn nrs_map_container_add(
        &mut self,
        name: &str,
        link: &str,
        default: bool,
        hard_link: bool,
        dry_run: bool,
    ) -> Result<(u64, XorUrl, ProcessedEntries, NrsMap)> {
        info!("Adding to NRS map...");
        // GET current NRS map from name's TLD
        let (xorurl_encoder, _) = validate_nrs_name(name)?;
        let xorurl = xorurl_encoder.to_string()?;
        let (version, mut nrs_map) = self.nrs_map_container_get(&xorurl)?;
        debug!("NRS, Existing data: {:?}", nrs_map);

        let link = nrs_map.nrs_map_update_or_create_data(name, link, default, hard_link)?;
        let mut processed_entries = ProcessedEntries::new();
        processed_entries.insert(name.to_string(), (CONTENT_ADDED_SIGN.to_string(), link));

        debug!("The new NRS Map: {:?}", nrs_map);
        if !dry_run {
            // Append new version of the NrsMap in the Published AppendOnlyData (NRS Map Container)
            let nrs_map_raw_data = gen_nrs_map_raw_data(&nrs_map)?;
            self.safe_app.append_to_sequence(
                nrs_map_raw_data,
                version + 1,
                xorurl_encoder.xorname(),
                xorurl_encoder.type_tag(),
            )?;
        }

        Ok((version + 1, xorurl, processed_entries, nrs_map))
    }

    /// # Create a NrsMapContainer.
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use rand::distributions::Alphanumeric;
    /// # use rand::{thread_rng, Rng};
    /// # use unwrap::unwrap;
    /// # use safe_api::Safe;
    /// # let mut safe = Safe::default();
    /// # safe.connect("", Some("fake-credentials")).unwrap();
    /// let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// let file_xorurl = safe.files_put_published_immutable(&vec![], None, false).unwrap();
    /// let (xorurl, _processed_entries, nrs_map_container) = safe.nrs_map_container_create(&rand_string, &file_xorurl, true, false, false).unwrap();
    /// assert!(xorurl.contains("safe://"))
    /// ```
    pub fn nrs_map_container_create(
        &mut self,
        name: &str,
        link: &str,
        default: bool,
        hard_link: bool,
        dry_run: bool,
    ) -> Result<(XorUrl, ProcessedEntries, NrsMap)> {
        info!("Creating an NRS map");
        let (_, nrs_url) = validate_nrs_name(name)?;
        if self.nrs_map_container_get(&nrs_url).is_ok() {
            Err(Error::ContentError(
                "NRS name already exists. Please use 'nrs add' command to add sub names to it"
                    .to_string(),
            ))
        } else {
            let mut nrs_map = NrsMap::default();
            let link = nrs_map.nrs_map_update_or_create_data(&name, link, default, hard_link)?;
            let mut processed_entries = ProcessedEntries::new();
            processed_entries.insert(name.to_string(), (CONTENT_ADDED_SIGN.to_string(), link));

            debug!("The new NRS Map: {:?}", nrs_map);
            if dry_run {
                Ok(("".to_string(), processed_entries, nrs_map))
            } else {
                let (_, public_name, _, _) = get_subnames_host_path_and_version(&nrs_url)?;
                let nrs_xorname = xorname_from_nrs_string(&public_name)?;
                debug!(
                    "XorName for \"{:?}\" is \"{:?}\"",
                    &public_name, &nrs_xorname
                );

                // Store the NrsMapContainer in a Published AppendOnlyData
                let nrs_map_raw_data = gen_nrs_map_raw_data(&nrs_map)?;
                let xorname = self.safe_app.put_sequence(
                    nrs_map_raw_data,
                    Some(nrs_xorname),
                    NRS_MAP_TYPE_TAG,
                    None,
                )?;

                let xorurl = XorUrlEncoder::encode(
                    xorname,
                    NRS_MAP_TYPE_TAG,
                    SafeDataType::PublishedSeqAppendOnlyData,
                    SafeContentType::NrsMapContainer,
                    None,
                    None,
                    None,
                    self.xorurl_base,
                )?;

                Ok((xorurl, processed_entries, nrs_map))
            }
        }
    }

    pub fn nrs_map_container_remove(
        &mut self,
        name: &str,
        dry_run: bool,
    ) -> Result<(u64, XorUrl, ProcessedEntries, NrsMap)> {
        info!("Removing from NRS map...");
        // GET current NRS map from &name TLD
        let (xorurl_encoder, _) = validate_nrs_name(name)?;
        let xorurl = xorurl_encoder.to_string()?;
        let (version, mut nrs_map) = self.nrs_map_container_get(&xorurl)?;
        debug!("NRS, Existing data: {:?}", nrs_map);

        let removed_link = nrs_map.nrs_map_remove_subname(name)?;
        let mut processed_entries = ProcessedEntries::new();
        processed_entries.insert(
            name.to_string(),
            (CONTENT_DELETED_SIGN.to_string(), removed_link),
        );

        debug!("The new NRS Map: {:?}", nrs_map);
        if !dry_run {
            // Append new version of the NrsMap in the Published AppendOnlyData (NRS Map Container)
            let nrs_map_raw_data = gen_nrs_map_raw_data(&nrs_map)?;
            self.safe_app.append_to_sequence(
                nrs_map_raw_data,
                version + 1,
                xorurl_encoder.xorname(),
                xorurl_encoder.type_tag(),
            )?;
        }

        Ok((version + 1, xorurl, processed_entries, nrs_map))
    }

    /// # Fetch an existing NrsMapContainer.
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use safe_api::Safe;
    /// # use rand::distributions::Alphanumeric;
    /// # use rand::{thread_rng, Rng};
    /// # let mut safe = Safe::default();
    /// # safe.connect("", Some("fake-credentials")).unwrap();
    /// let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
    /// let file_xorurl = safe.files_put_published_immutable(&vec![], Some("text/plain"), false).unwrap();
    /// let (xorurl, _processed_entries, _nrs_map) = safe.nrs_map_container_create(&rand_string, &file_xorurl, true, false, false).unwrap();
    /// let (version, nrs_map_container) = safe.nrs_map_container_get(&xorurl).unwrap();
    /// assert_eq!(version, 0);
    /// assert_eq!(nrs_map_container.get_default_link().unwrap(), file_xorurl);
    /// ```
    pub fn nrs_map_container_get(&self, url: &str) -> Result<(u64, NrsMap)> {
        debug!("Getting latest resolvable map container from: {:?}", url);
        let xorurl_encoder = Safe::parse_url(url)?;

        // Check if the URL specified a specific version of the content or simply the latest available
        let data = xorurl_encoder.content_version().map_or_else(
            || {
                self.safe_app
                    .get_current_sequence_value(xorurl_encoder.xorname(), NRS_MAP_TYPE_TAG)
            },
            |content_version| {
                let value = self
                    .safe_app
                    .get_sequence_value_at(
                        xorurl_encoder.xorname(),
                        NRS_MAP_TYPE_TAG,
                        content_version,
                    )
                    .map_err(|_| {
                        Error::VersionNotFound(format!(
                            "Version '{}' is invalid for NRS Map Container found at \"{}\"",
                            content_version, url,
                        ))
                    })?;
                Ok((content_version, value))
            },
        );

        match data {
            Ok((version, value)) => {
                debug!("Nrs map retrieved.... v{:?}, value {:?} ", &version, &value);
                // TODO: use RDF format and deserialise it
                let nrs_map = serde_json::from_str(&String::from_utf8_lossy(&value.as_slice()))
                    .map_err(|err| {
                        Error::ContentError(format!(
                            "Couldn't deserialise the NrsMap stored in the NrsContainer: {:?}",
                            err
                        ))
                    })?;
                Ok((version, nrs_map))
            }
            Err(Error::EmptyContent(_)) => {
                warn!("Nrs container found at {:?} was empty", &url);
                Ok((0, NrsMap::default()))
            }
            Err(Error::ContentNotFound(_)) => Err(Error::ContentNotFound(
                ERROR_MSG_NO_NRS_MAP_FOUND.to_string(),
            )),
            Err(Error::VersionNotFound(msg)) => Err(Error::VersionNotFound(msg)),
            Err(err) => Err(Error::NetDataError(format!(
                "Failed to get current version: {}",
                err
            ))),
        }
    }
}

fn validate_nrs_name(name: &str) -> Result<(XorUrlEncoder, String)> {
    let sanitised_url = sanitised_url(name);
    let xorurl_encoder = Safe::parse_url(&sanitised_url)?;
    if xorurl_encoder.content_version().is_some() {
        return Err(Error::InvalidInput(format!(
            "The NRS name/subname URL cannot cannot contain a version: {}",
            sanitised_url
        )));
    };
    Ok((xorurl_encoder, sanitised_url))
}

fn xorname_from_nrs_string(name: &str) -> Result<XorName> {
    let vec_hash = sha3_256(&name.to_string().into_bytes());
    let xorname = XorName(vec_hash);
    debug!("Resulting XorName for NRS \"{}\" is: {}", name, xorname);
    Ok(xorname)
}

fn sanitised_url(name: &str) -> String {
    // FIXME: make sure we remove the starting 'safe://'
    format!("safe://{}", name.replace("safe://", ""))
}

fn gen_nrs_map_raw_data(nrs_map: &NrsMap) -> Result<NrsMapRawData> {
    // The NrsMapContainer is an AppendOnlyData where each NRS Map version is an entry containing
    // the timestamp as the entry's key, and the serialised NrsMap as the entry's value
    // TODO: use RDF format
    let serialised_nrs_map = serde_json::to_string(nrs_map).map_err(|err| {
        Error::Unexpected(format!(
            "Couldn't serialise the NrsMap generated: {:?}",
            err
        ))
    })?;
    //let now = gen_timestamp_nanos();

    Ok(vec![serialised_nrs_map.as_bytes().to_vec()]) // now.into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nrs_map_container_create() {
        use crate::api::constants::FAKE_RDF_PREDICATE_LINK;
        use crate::nrs_map::DefaultRdf;
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};
        use unwrap::unwrap;

        let site_name: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();

        let mut safe = Safe::default();
        safe.connect("", Some("fake-credentials")).unwrap();

        let nrs_xorname = xorname_from_nrs_string(&site_name).unwrap();

        let (xor_url, _entries, nrs_map) = unwrap!(safe.nrs_map_container_create(
            &site_name,
            "safe://linked-from-<site_name>?v=0",
            true,
            false,
            false
        ));
        assert_eq!(nrs_map.sub_names_map.len(), 0);
        assert_eq!(
            unwrap!(nrs_map.get_default_link()),
            "safe://linked-from-<site_name>?v=0"
        );

        if let DefaultRdf::OtherRdf(def_data) = &nrs_map.default {
            assert_eq!(
                *def_data.get(FAKE_RDF_PREDICATE_LINK).unwrap(),
                "safe://linked-from-<site_name>?v=0".to_string()
            );
            assert_eq!(
                nrs_map.get_default().unwrap(),
                &DefaultRdf::OtherRdf(def_data.clone())
            );
        } else {
            panic!("No default definition map found...")
        }

        let decoder = XorUrlEncoder::from_url(&xor_url).unwrap();
        assert_eq!(nrs_xorname, decoder.xorname())
    }

    #[test]
    fn test_nrs_map_container_add() {
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};
        use unwrap::unwrap;

        let site_name: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();

        let mut safe = Safe::default();
        safe.connect("", Some("fake-credentials")).unwrap();

        let (_xor_url, _entries, nrs_map) = unwrap!(safe.nrs_map_container_create(
            &format!("b.{}", site_name),
            "safe://linked-from-<b.site_name>?v=0",
            true,
            false,
            false
        ));
        assert_eq!(nrs_map.sub_names_map.len(), 1);
        assert_eq!(
            unwrap!(nrs_map.get_default_link()),
            "safe://linked-from-<b.site_name>?v=0"
        );

        // add subname and set it as the new default too
        let (version, _xorurl, _entries, updated_nrs_map) = unwrap!(safe.nrs_map_container_add(
            &format!("a.b.{}", site_name),
            "safe://linked-from-<a.b.site_name>?v=0",
            true,
            false,
            false
        ));
        assert_eq!(version, 1);
        assert_eq!(updated_nrs_map.sub_names_map.len(), 1);
        assert_eq!(
            unwrap!(updated_nrs_map.get_default_link()),
            "safe://linked-from-<a.b.site_name>?v=0"
        );
    }

    #[test]
    fn test_nrs_map_container_add_or_remove_with_versioned_target() {
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};
        use unwrap::unwrap;

        let site_name: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();

        let mut safe = Safe::default();
        safe.connect("", Some("fake-credentials")).unwrap();

        let _ = unwrap!(safe.nrs_map_container_create(
            &format!("b.{}", site_name),
            "safe://linked-from-<b.site_name>?v=0",
            true,
            false,
            false
        ));

        let versioned_sitename = format!("safe://a.b.{}?v=6", site_name);
        match safe.nrs_map_container_add(
            &versioned_sitename,
            "safe://linked-from-<a.b.site_name>?v=0",
            true,
            false,
            false,
        ) {
            Ok(_) => panic!("Sync was unexpectdly successful"),
            Err(err) => assert_eq!(
                err,
                Error::InvalidInput(format!(
                    "The NRS name/subname URL cannot cannot contain a version: {}",
                    versioned_sitename
                ))
            ),
        };

        match safe.nrs_map_container_remove(&versioned_sitename, false) {
            Ok(_) => panic!("Sync was unexpectdly successful"),
            Err(err) => assert_eq!(
                err,
                Error::InvalidInput(format!(
                    "The NRS name/subname URL cannot cannot contain a version: {}",
                    versioned_sitename
                ))
            ),
        };
    }

    #[test]
    fn test_nrs_map_container_remove_one_of_two() {
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};
        use unwrap::unwrap;

        let site_name: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();

        let mut safe = Safe::default();
        safe.connect("", Some("fake-credentials")).unwrap();

        let (_xor_url, _entries, nrs_map) = unwrap!(safe.nrs_map_container_create(
            &format!("a.b.{}", site_name),
            "safe://linked-from-<a.b.site_name>?v=0",
            true,
            false,
            false
        ));
        assert_eq!(nrs_map.sub_names_map.len(), 1);

        let (_version, _xorurl, _entries, _updated_nrs_map) = unwrap!(safe.nrs_map_container_add(
            &format!("a2.b.{}", site_name),
            "safe://linked-from-<a2.b.site_name>?v=0",
            true,
            false,
            false
        ));

        // remove subname
        let (version, _xorurl, _entries, updated_nrs_map) =
            unwrap!(safe.nrs_map_container_remove(&format!("a.b.{}", site_name), false));
        assert_eq!(version, 2);
        assert_eq!(updated_nrs_map.sub_names_map.len(), 1);
        assert_eq!(
            unwrap!(updated_nrs_map.get_default_link()),
            "safe://linked-from-<a2.b.site_name>?v=0"
        );
    }

    #[test]
    fn test_nrs_map_container_remove_default_soft_link() {
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};
        use unwrap::unwrap;

        let site_name: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();

        let mut safe = Safe::default();
        safe.connect("", Some("fake-credentials")).unwrap();

        let (_xor_url, _entries, nrs_map) = unwrap!(safe.nrs_map_container_create(
            &format!("a.b.{}", site_name),
            "safe://linked-from-<a.b.site_name>?v=0",
            true,
            false,
            false
        ));
        assert_eq!(nrs_map.sub_names_map.len(), 1);

        // remove subname
        let (version, _xorurl, _entries, updated_nrs_map) =
            unwrap!(safe.nrs_map_container_remove(&format!("a.b.{}", site_name), false));
        assert_eq!(version, 1);
        assert_eq!(updated_nrs_map.sub_names_map.len(), 0);
        match updated_nrs_map.get_default_link() {
            Ok(_) => panic!("unexpectedly retrieved a default link"),
            Err(Error::ContentError(msg)) => assert_eq!(
                msg,
                "Default found for resolvable map (set to sub names 'a.b') cannot be resolved."
                    .to_string()
            ),
            Err(err) => panic!(format!("error returned is not the expected one: {}", err)),
        };
    }

    #[test]
    fn test_nrs_map_container_remove_default_hard_link() {
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};
        use unwrap::unwrap;

        let site_name: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();

        let mut safe = Safe::default();
        safe.connect("", Some("fake-credentials")).unwrap();

        let (_xor_url, _entries, nrs_map) = unwrap!(safe.nrs_map_container_create(
            &format!("a.b.{}", site_name),
            "safe://linked-from-<a.b.site_name>?v=0",
            true,
            true, // this sets the default to be a hard-link
            false
        ));
        assert_eq!(nrs_map.sub_names_map.len(), 1);

        // remove subname
        let (version, _xorurl, _entries, updated_nrs_map) =
            unwrap!(safe.nrs_map_container_remove(&format!("a.b.{}", site_name), false));
        assert_eq!(version, 1);
        assert_eq!(updated_nrs_map.sub_names_map.len(), 0);
        assert_eq!(
            unwrap!(updated_nrs_map.get_default_link()),
            "safe://linked-from-<a.b.site_name>?v=0"
        );
    }
}
