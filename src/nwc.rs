// Copyright (c) 2022-2023 Yuki Kishimoto
// Distributed under the MIT software license

//! NIP47
//!
//! <https://github.com/nostr-protocol/nips/blob/master/47.md>

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use nostr::nips::nip04;
use nostr::{key, Keys};
use secp256k1::{SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use url::form_urlencoded::byte_serialize;
use url::Url;

/// NIP47 error
#[derive(Debug)]
pub enum Error {
    /// Key error
    Key(key::Error),
    /// JSON error
    JSON(serde_json::Error),
    /// Url parse error
    Url(url::ParseError),
    /// Secp256k1 error
    Secp256k1(secp256k1::Error),
    /// NIP04 error
    NIP04(nip04::Error),
    /// Unsigned event error
    UnsignedEvent(nostr::event::unsigned::Error),
    /// Invalid request
    InvalidRequest,
    /// Too many/few params
    InvalidParamsLength,
    /// Unsupported method
    UnsupportedMethod(String),
    /// Invalid URI
    InvalidURI,
    /// Invalid URI scheme
    InvalidURIScheme,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(e) => write!(f, "{e}"),
            Self::JSON(e) => write!(f, "{e}"),
            Self::Url(e) => write!(f, "{e}"),
            Self::Secp256k1(e) => write!(f, "{e}"),
            Self::NIP04(e) => write!(f, "{e}"),
            Self::UnsignedEvent(e) => write!(f, "{e}"),
            Self::InvalidRequest => write!(f, "Invalid NIP47 Request"),
            Self::InvalidParamsLength => write!(f, "Invalid NIP47 Params length"),
            Self::UnsupportedMethod(e) => write!(f, "{e}"),
            Self::InvalidURI => write!(f, "Invalid NIP47 URI"),
            Self::InvalidURIScheme => write!(f, "Invalid NIP47 URI Scheme"),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::JSON(e)
    }
}

impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Self::Url(e)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}

impl From<key::Error> for Error {
    fn from(e: key::Error) -> Self {
        Self::Key(e)
    }
}

/// NIP47 Response Error codes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorCode {
    ///  The client is sending commands too fast.
    #[serde(rename = "RATE_LIMITED")]
    RateLimited,
    /// The command is not known of is intentionally not implemented
    #[serde(rename = "NOT_IMPLEMENTED")]
    NotImplemented,
    /// The wallet does not have enough funds to cover a fee reserve or the payment amount
    #[serde(rename = "INSUFFICIENT_BALANCE")]
    InsufficantBalance,
    /// The wallet has exceeded its spending quota
    #[serde(rename = "QUOTA_EXCEEDED")]
    QuotaExceeded,
    /// This public key is not allowed to do this operation
    #[serde(rename = "RESTRICTED")]
    Restricted,
    /// This public key has no wallet connected
    #[serde(rename = "UNAUTHORIZED")]
    Unauthorized,
    /// An internal error
    #[serde(rename = "INTERNAL")]
    Internal,
    /// Other error
    #[serde(rename = "OTHER")]
    Other,
}

/// NIP47 Error message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NIP47Error {
    /// Error Code
    pub code: ErrorCode,
    /// Human Readable error message
    pub message: String,
}

/// Method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Method {
    /// Pay Invoice
    #[serde(rename = "pay_invoice")]
    PayInvoice,
    /// Make Invoice
    #[serde(rename = "make_invoice")]
    MakeInvoice,
    /// Lookup Invoice
    #[serde(rename = "lookup_invoice")]
    LookupInvoice,
    /// Get Balance
    #[serde(rename = "get_balance")]
    GetBalance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestParams {
    PayInvoice(PayInvoiceRequestParams),
    MakeInvoice(MakeInvoiceRequestParams),
    LookupInvoice(LookupInvoiceRequestParams),
    GetBalance,
}

impl Serialize for RequestParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            RequestParams::PayInvoice(p) => p.serialize(serializer),
            RequestParams::MakeInvoice(p) => p.serialize(serializer),
            RequestParams::LookupInvoice(p) => p.serialize(serializer),
            RequestParams::GetBalance => serializer.serialize_none(),
        }
    }
}

/// Pay Invoice Request Params
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayInvoiceRequestParams {
    /// Request invoice
    pub invoice: String,
}

/// Make Invoice Request Params
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MakeInvoiceRequestParams {
    /// Amount in millisatoshis
    pub amount: i64,
    pub description: Option<String>,
    pub description_hash: Option<String>,
    pub expiry: Option<i64>,
}

/// Lookup Invoice Request Params
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LookupInvoiceRequestParams {
    /// Payment hash of invoice
    pub payment_hash: Option<String>,
    /// Bolt11 invoice
    pub bolt11: Option<String>,
}

/// NIP47 Request
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Request {
    /// Request method
    pub method: Method,
    /// Params
    pub params: RequestParams,
}

#[derive(Serialize, Deserialize)]
struct RequestTemplate {
    /// Request method
    method: Method,
    /// Params
    params: Value,
}

impl Request {
    /// Serialize [`Message`] as JSON string
    pub fn as_json(&self) -> String {
        json!(self).to_string()
    }

    /// Deserialize from JSON string
    pub fn from_json<S>(json: S) -> Result<Self, Error>
    where
        S: AsRef<str>,
    {
        let template: RequestTemplate = serde_json::from_str(json.as_ref())?;

        let params = match template.method {
            Method::PayInvoice => {
                let params: PayInvoiceRequestParams = serde_json::from_value(template.params)?;
                RequestParams::PayInvoice(params)
            }
            Method::MakeInvoice => {
                let params: MakeInvoiceRequestParams = serde_json::from_value(template.params)?;
                RequestParams::MakeInvoice(params)
            }
            Method::LookupInvoice => {
                let params: LookupInvoiceRequestParams = serde_json::from_value(template.params)?;
                RequestParams::LookupInvoice(params)
            }
            Method::GetBalance => RequestParams::GetBalance,
        };

        Ok(Self {
            method: template.method,
            params,
        })
    }
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from_json(
            Value::deserialize(deserializer)
                .unwrap()
                .to_string()
                .as_str(),
        )
        .unwrap())
    }
}

/// NIP47 Response Result
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PayInvoiceResponseResult {
    /// Response preimage
    pub preimage: String,
}

/// NIP47 Response Result
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MakeInvoiceResponseResult {
    /// Bolt 11 invoice
    pub invoice: String,
    /// Invoice's payment hash
    pub payment_hash: String,
}

/// NIP47 Response Result
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LookupInvoiceResponseResult {
    /// Bolt11 invoice
    pub invoice: String,
    /// If the invoice has been paid
    pub paid: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BudgetType {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

/// NIP47 Response Result
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GetBalanceResponseResult {
    /// Balance amount in sats
    pub balance: u64,
    /// Max amount payable within current budget
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<u64>,
    /// Budget renewal type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_renewal: Option<BudgetType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseResult {
    PayInvoice(PayInvoiceResponseResult),
    MakeInvoice(MakeInvoiceResponseResult),
    LookupInvoice(LookupInvoiceResponseResult),
    GetBalance(GetBalanceResponseResult),
}

impl Serialize for ResponseResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ResponseResult::PayInvoice(p) => p.serialize(serializer),
            ResponseResult::MakeInvoice(p) => p.serialize(serializer),
            ResponseResult::LookupInvoice(p) => p.serialize(serializer),
            ResponseResult::GetBalance(p) => p.serialize(serializer),
        }
    }
}

/// NIP47 Response
#[derive(Debug, Clone, Serialize)]
pub struct Response {
    /// Request Method
    pub result_type: Method,
    /// NIP47 Error
    pub error: Option<NIP47Error>,
    /// NIP47 Result
    pub result: Option<ResponseResult>,
}

/// NIP47 Response
#[derive(Debug, Clone, Deserialize)]
struct ResponseTemplate {
    /// Request Method
    pub result_type: Method,
    /// NIP47 Error
    pub error: Option<NIP47Error>,
    /// NIP47 Result
    pub result: Option<Value>,
}

impl Response {
    /// Serialize [`Response`] as JSON string
    pub fn as_json(&self) -> String {
        json!(self).to_string()
    }

    /// Deserialize from JSON string
    pub fn from_json<S>(json: S) -> Result<Self, Error>
    where
        S: AsRef<str>,
    {
        let template: ResponseTemplate = serde_json::from_str(json.as_ref())?;

        if let Some(result) = template.result {
            let result = match template.result_type {
                Method::PayInvoice => {
                    let result: PayInvoiceResponseResult = serde_json::from_value(result)?;
                    ResponseResult::PayInvoice(result)
                }
                Method::MakeInvoice => {
                    let result: MakeInvoiceResponseResult = serde_json::from_value(result)?;
                    ResponseResult::MakeInvoice(result)
                }
                Method::LookupInvoice => {
                    let result: LookupInvoiceResponseResult = serde_json::from_value(result)?;
                    ResponseResult::LookupInvoice(result)
                }
                Method::GetBalance => {
                    let result: GetBalanceResponseResult = serde_json::from_value(result)?;
                    ResponseResult::GetBalance(result)
                }
            };

            Ok(Self {
                result_type: template.result_type,
                error: template.error,
                result: Some(result),
            })
        } else {
            Ok(Self {
                result_type: template.result_type,
                error: template.error,
                result: None,
            })
        }
    }
}

impl<'de> Deserialize<'de> for Response {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from_json(
            Value::deserialize(deserializer)
                .unwrap()
                .to_string()
                .as_str(),
        )
        .unwrap())
    }
}

/// Nostr Wallet Connect Info
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NostrWalletConnectInfo {}

fn url_encode<T>(data: T) -> String
where
    T: AsRef<[u8]>,
{
    byte_serialize(data.as_ref()).collect()
}

/// NIP47 URI Scheme
pub const NOSTR_WALLET_CONNECT_URI_SCHEME: &str = "nostr+walletconnect";

/// Nostr Connect URI
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NostrWalletConnectURI {
    /// App Pubkey
    pub public_key: XOnlyPublicKey,
    /// URL of the relay of choice where the `App` is connected and the `Signer` must send and listen for messages.
    pub relay_url: Url,
    /// 32-byte randomly generated hex encoded string
    pub secret: SecretKey,
    /// A lightning address that clients can use to automatically setup the lud16 field on the user's profile if they have none configured.
    pub lud16: Option<String>,
}

impl NostrWalletConnectURI {
    /// Create new [`NostrWalletConnectURI`]
    pub fn new(
        public_key: XOnlyPublicKey,
        relay_url: Url,
        secret: Option<SecretKey>,
        lud16: Option<String>,
    ) -> Result<Self, Error> {
        let secret = match secret {
            Some(secret) => secret,
            None => {
                let keys = Keys::generate();
                keys.secret_key()?
            }
        };

        Ok(Self {
            public_key,
            relay_url,
            secret,
            lud16,
        })
    }
}

impl FromStr for NostrWalletConnectURI {
    type Err = Error;
    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(uri)?;

        if url.scheme() != NOSTR_WALLET_CONNECT_URI_SCHEME {
            return Err(Error::InvalidURIScheme);
        }

        if let Some(pubkey) = url.domain() {
            let public_key = XOnlyPublicKey::from_str(pubkey)?;

            let mut relay_url: Option<Url> = None;
            let mut secret: Option<SecretKey> = None;
            let mut lud16: Option<String> = None;

            for (key, value) in url.query_pairs() {
                match key {
                    Cow::Borrowed("relay") => {
                        let value = value.to_string();
                        relay_url = Some(Url::parse(&value)?);
                    }
                    Cow::Borrowed("secret") => {
                        let value = value.to_string();
                        secret = Some(SecretKey::from_str(&value)?);
                    }
                    Cow::Borrowed("lud16") => {
                        lud16 = Some(value.to_string());
                    }
                    _ => (),
                }
            }

            if let Some(relay_url) = relay_url {
                if let Some(secret) = secret {
                    return Ok(Self {
                        public_key,
                        relay_url,
                        secret,
                        lud16,
                    });
                }
            }
        }

        Err(Error::InvalidURI)
    }
}

impl fmt::Display for NostrWalletConnectURI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{NOSTR_WALLET_CONNECT_URI_SCHEME}://{}?relay={}&secret={}",
            self.public_key,
            url_encode(self.relay_url.to_string()),
            url_encode(self.secret.display_secret().to_string())
        )?;
        if let Some(lud16) = &self.lud16 {
            write!(f, "&lud16={}", url_encode(lud16))?;
        }
        Ok(())
    }
}
