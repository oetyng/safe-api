// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#[cfg(feature = "app")]
use crate::{Error, Result};
use chrono::{DateTime, SecondsFormat, Utc};

use safe_network::types::{Error as SafeNdError, PublicKey, Token};
use std::{
    str::{self, FromStr},
    time,
};

/// The conversion from token to raw value
const TOKEN_TO_RAW_CONVERSION: u64 = 1_000_000_000;
/// The maximum amount of safetoken that can be represented by a single `Token`
const MAX_TOKENS_VALUE: u64 = (u32::max_value() as u64 + 1) * TOKEN_TO_RAW_CONVERSION - 1;

#[allow(dead_code)]
pub fn pk_from_hex(hex_str: &str) -> Result<PublicKey> {
    PublicKey::ed25519_from_hex(&hex_str)
        .or_else(|_| PublicKey::bls_from_hex(&hex_str))
        .map_err(|_| {
            Error::InvalidInput(format!(
                "Invalid (Ed25519/BLS) public key bytes: {}",
                hex_str
            ))
        })
}

pub fn parse_tokens_amount(amount_str: &str) -> Result<Token> {
    Token::from_str(amount_str).map_err(|err| {
        match err {
            SafeNdError::ExcessiveValue => Error::InvalidAmount(format!(
                "Invalid tokens amount '{}', it exceeds the maximum possible value '{}'",
                amount_str, Token::from_nano(MAX_TOKENS_VALUE)
            )),
            SafeNdError::LossOfPrecision => {
                Error::InvalidAmount(format!("Invalid tokens amount '{}', the minimum possible amount is one nano token (0.000000001)", amount_str))
            }
            SafeNdError::FailedToParse(msg) => {
                Error::InvalidAmount(format!("Invalid tokens amount '{}' ({})", amount_str, msg))
            },
            _ => Error::InvalidAmount(format!("Invalid tokens amount '{}'", amount_str)),
        }
    })
}

pub fn systemtime_to_rfc3339(t: time::SystemTime) -> String {
    let datetime: DateTime<Utc> = t.into();
    datetime.to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn gen_timestamp_secs() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}
