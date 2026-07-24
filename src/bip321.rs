use bitcoin::Network;
use bitcoin_payment_instructions::hrn_resolution::DummyHrnResolver;
use bitcoin_payment_instructions::{
    ParseError, PaymentInstructions, PaymentMethod, PossiblyResolvedPaymentMethod,
};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::borrow::Cow;
use std::fmt;

pub const PAY_METHOD: &str = "pay";
pub const RECEIVE_METHOD: &str = "receive";

#[derive(Debug, Deserialize)]
pub struct PayRequestParams {
    pub payment: String,
    pub amount: Option<u64>,
    pub payer_note: Option<String>,
    #[serde(default, rename = "metadata")]
    pub _metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ReceiveRequestParams {
    pub amount: Option<u64>,
    pub description: Option<String>,
    #[serde(default, rename = "metadata")]
    pub _metadata: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct PayResponseResult {
    pub transaction_id: String,
    pub state: &'static str,
    pub instruction_type: &'static str,
    pub amount: u64,
    pub fees_paid: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer_proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ReceiveResponseResult {
    pub bip321: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

pub fn success_response<T: Serialize>(method: &str, result: T) -> Value {
    json!({
        "result_type": method,
        "error": null,
        "result": result,
    })
}

pub fn error_response(method: &str, code: &str, message: impl Into<String>) -> Value {
    json!({
        "result_type": method,
        "error": {
            "code": code,
            "message": message.into(),
        },
        "result": null,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentUriError {
    BadRequest(String),
    UnsupportedPaymentInstruction,
    UnsupportedNetwork,
}

impl PaymentUriError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::UnsupportedPaymentInstruction => "UNSUPPORTED_PAYMENT_INSTRUCTION",
            Self::UnsupportedNetwork => "UNSUPPORTED_NETWORK",
        }
    }
}

impl fmt::Display for PaymentUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest(message) => f.write_str(message),
            Self::UnsupportedPaymentInstruction => {
                f.write_str("No supported payment instruction found")
            }
            Self::UnsupportedNetwork => {
                f.write_str("The payment instruction is for a different Bitcoin network")
            }
        }
    }
}

pub async fn parse_payment_uri(
    payment: &str,
    expected_network: Network,
) -> Result<Bolt11Invoice, PaymentUriError> {
    let (scheme, _) = payment
        .split_once(':')
        .ok_or_else(|| bad_request("Invalid BIP-321 URI"))?;
    if payment.trim() != payment || !scheme.eq_ignore_ascii_case("bitcoin") {
        return Err(bad_request("Expected a bitcoin: BIP-321 URI"));
    }

    // We do not support opening proof-of-payment callbacks. BIP-321 allows an
    // optional `pop` callback to be ignored, while `req-pop` must still be
    // understood and honored. Remove only the optional form before parsing.
    let payment = without_optional_pop(payment);
    let instructions =
        PaymentInstructions::parse(&payment, expected_network, &DummyHrnResolver, false)
            .await
            .map_err(map_parse_error)?;

    match instructions {
        PaymentInstructions::FixedAmount(instructions) => {
            instructions
                .methods()
                .iter()
                .find_map(|method| match method {
                    PaymentMethod::LightningBolt11(invoice) => Some(invoice.clone()),
                    _ => None,
                })
        }
        PaymentInstructions::ConfigurableAmount(instructions) => {
            instructions.methods().find_map(|method| match method {
                PossiblyResolvedPaymentMethod::Resolved(PaymentMethod::LightningBolt11(
                    invoice,
                )) => Some(invoice.clone()),
                _ => None,
            })
        }
    }
    .ok_or(PaymentUriError::UnsupportedPaymentInstruction)
}

fn without_optional_pop(payment: &str) -> Cow<'_, str> {
    let Some((prefix, query)) = payment.split_once('?') else {
        return Cow::Borrowed(payment);
    };
    let (query, fragment) = query
        .split_once('#')
        .map_or((query, None), |(query, fragment)| (query, Some(fragment)));

    let mut removed = false;
    let retained = query
        .split('&')
        .filter(|parameter| {
            let name = parameter
                .split_once('=')
                .map_or(*parameter, |(name, _)| name);
            let keep = !name.eq_ignore_ascii_case("pop");
            removed |= !keep;
            keep
        })
        .collect::<Vec<_>>();

    if !removed {
        return Cow::Borrowed(payment);
    }

    let mut normalized = prefix.to_string();
    if !retained.is_empty() {
        normalized.push('?');
        normalized.push_str(&retained.join("&"));
    }
    if let Some(fragment) = fragment {
        normalized.push('#');
        normalized.push_str(fragment);
    }
    Cow::Owned(normalized)
}

pub fn payment_amount(
    invoice: &Bolt11Invoice,
    requested_amount: Option<u64>,
) -> Result<u64, PaymentUriError> {
    let amount = match (invoice.amount_milli_satoshis(), requested_amount) {
        (Some(invoice_amount), Some(requested_amount)) if invoice_amount != requested_amount => {
            return Err(bad_request(
                "Requested amount conflicts with the BOLT11 invoice",
            ));
        }
        (Some(invoice_amount), _) => invoice_amount,
        (None, Some(requested_amount)) => requested_amount,
        (None, None) => {
            return Err(bad_request(
                "An amount is required for an amountless BOLT11 invoice",
            ));
        }
    };

    if amount == 0 || amount > i64::MAX as u64 {
        return Err(bad_request("Payment amount is out of range"));
    }

    Ok(amount)
}

fn bad_request(message: impl Into<String>) -> PaymentUriError {
    PaymentUriError::BadRequest(message.into())
}

fn map_parse_error(error: ParseError) -> PaymentUriError {
    match error {
        ParseError::WrongNetwork => PaymentUriError::UnsupportedNetwork,
        ParseError::UnknownPaymentInstructions => PaymentUriError::UnsupportedPaymentInstruction,
        ParseError::UnknownRequiredParameter => {
            bad_request("Unknown or unsupported required BIP-321 parameter")
        }
        ParseError::InstructionsExpired => bad_request("Payment instruction has expired"),
        error => bad_request(format!("Invalid BIP-321 URI: {error:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};

    const SIGNET_OFFER: &str = "lno1qgs0v8hw8d368q9yw7sx8tejk2aujlyll8cp7tzzyh5h8xyppqqqqqqgqvqcdgq2qenxzatrv46pvggrv64u366d5c0rr2xjc3fq6vw2hh6ce3f9p7z4v4ee0u7avfynjw9q";

    fn invoice(currency: Currency, amount: u64) -> Bolt11Invoice {
        let secret_key = SecretKey::from_slice(&[42; 32]).unwrap();
        InvoiceBuilder::new(currency)
            .description("test invoice".to_string())
            .payment_hash(sha256::Hash::hash(&[1; 32]))
            .payment_secret(PaymentSecret([2; 32]))
            .amount_milli_satoshis(amount)
            .current_timestamp()
            .min_final_cltv_expiry_delta(144)
            .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(hash, &secret_key))
            .unwrap()
    }

    #[tokio::test]
    async fn parses_case_insensitive_lightning_instruction() {
        let expected = invoice(Currency::Bitcoin, 1_000_000);
        let uri = format!("BITCOIN:?LIGHTNING={}", expected.to_string().to_uppercase());
        let invoice = parse_payment_uri(&uri, Network::Bitcoin).await.unwrap();
        assert_eq!(invoice.amount_milli_satoshis(), Some(1_000_000));
    }

    #[tokio::test]
    async fn rejects_unknown_required_parameter() {
        let invoice = invoice(Currency::Bitcoin, 1_000_000);
        let uri = format!("bitcoin:?lightning={invoice}&req-future=1");
        let error = parse_payment_uri(&uri, Network::Bitcoin).await.unwrap_err();
        assert_eq!(error.code(), "BAD_REQUEST");
    }

    #[tokio::test]
    async fn rejects_required_proof_callback() {
        let invoice = invoice(Currency::Bitcoin, 1_000_000);
        let uri = format!("bitcoin:?lightning={invoice}&req-pop=myapp%3A");
        let error = parse_payment_uri(&uri, Network::Bitcoin).await.unwrap_err();
        assert_eq!(error.code(), "BAD_REQUEST");
    }

    #[tokio::test]
    async fn ignores_optional_proof_callback() {
        let expected = invoice(Currency::Bitcoin, 1_000_000);
        let uri = format!("bitcoin:?PoP=myapp%3A&lightning={expected}");

        let selected = parse_payment_uri(&uri, Network::Bitcoin).await.unwrap();

        assert_eq!(selected.payment_hash(), expected.payment_hash());
    }

    #[tokio::test]
    async fn rejects_wrong_network() {
        let invoice = invoice(Currency::Signet, 1_000_000);
        let uri = format!("bitcoin:?lightning={invoice}");
        let error = parse_payment_uri(&uri, Network::Bitcoin).await.unwrap_err();
        assert_eq!(error, PaymentUriError::UnsupportedNetwork);
    }

    #[test]
    fn rejects_conflicting_request_amount() {
        let invoice = invoice(Currency::Bitcoin, 1_000_000);
        let error = payment_amount(&invoice, Some(2_000_000)).unwrap_err();
        assert_eq!(error.code(), "BAD_REQUEST");
    }

    #[tokio::test]
    async fn accepts_hex_letters_in_percent_encoding() {
        let invoice = invoice(Currency::Bitcoin, 1_000_000);
        let uri = format!("bitcoin:?label=a%2Fb&lightning={invoice}");
        assert!(parse_payment_uri(&uri, Network::Bitcoin).await.is_ok());
    }

    #[tokio::test]
    async fn selects_bolt11_when_bolt12_is_also_present() {
        let parsed_offer = PaymentInstructions::parse(
            &format!("bitcoin:?lno={SIGNET_OFFER}"),
            Network::Signet,
            &DummyHrnResolver,
            false,
        )
        .await
        .unwrap();
        let offer_amount = match parsed_offer {
            PaymentInstructions::FixedAmount(instructions) => {
                instructions.ln_payment_amount().unwrap().milli_sats()
            }
            PaymentInstructions::ConfigurableAmount(_) => {
                panic!("test offer must have a fixed amount")
            }
        };
        let expected = invoice(Currency::Signet, offer_amount);
        let uri = format!("bitcoin:?lno={SIGNET_OFFER}&lightning={expected}");

        let selected = parse_payment_uri(&uri, Network::Signet).await.unwrap();

        assert_eq!(selected.payment_hash(), expected.payment_hash());
    }

    #[tokio::test]
    async fn rejects_bolt12_only_when_no_payable_method_exists() {
        let uri = format!("bitcoin:?lno={SIGNET_OFFER}");
        let error = parse_payment_uri(&uri, Network::Signet).await.unwrap_err();
        assert_eq!(error, PaymentUriError::UnsupportedPaymentInstruction);
    }

    #[test]
    fn serializes_extension_response_shape() {
        let response = success_response(
            PAY_METHOD,
            PayResponseResult {
                transaction_id: "hash".to_string(),
                state: "settled",
                instruction_type: "bolt11",
                amount: 1_000,
                fees_paid: 10,
                payment_hash: Some("hash".to_string()),
                preimage: Some("preimage".to_string()),
                payer_proof: None,
                txid: None,
                failure_reason: None,
                created_at: 1,
                settled_at: Some(2),
            },
        );

        assert_eq!(response["result_type"], "pay");
        assert!(response["error"].is_null());
        assert_eq!(response["result"]["instruction_type"], "bolt11");
        assert!(response["result"].get("payer_proof").is_none());
        assert!(response["result"].get("failure_reason").is_none());
    }
}
