#![allow(clippy::too_many_arguments)]

use crate::bip321::{
    error_response, parse_payment_uri, payment_amount, success_response, PayRequestParams,
    PayResponseResult, ReceiveRequestParams, ReceiveResponseResult, PAY_METHOD, RECEIVE_METHOD,
};
use crate::config::Config;
use crate::payments::PaymentTracker;
use anyhow::anyhow;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::SecretKey as Secp256k1SecretKey;
use clap::Parser;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use log::{debug, error, info};
use nostr::nips::nip04;
use nostr::nips::nip44;
use nostr::nips::nip47::*;
use nostr::{
    Event, EventBuilder, EventId, Filter, JsonUtil, Keys, Kind, SecretKey as NostrSecretKey, Tag,
    Timestamp,
};
use nostr_sdk::{Client, RelayPoolNotification};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::{create_dir_all, read, File};
use std::io::{BufReader, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{oneshot, Mutex, RwLock};
use tokio::{select, spawn};
use tonic_openssl_lnd::lnrpc::{
    htlc_attempt::HtlcStatus, payment::PaymentStatus, ChannelBalanceRequest, GetInfoRequest,
    GetInfoResponse as LndGetInfoResponse, Invoice, Payment, PaymentFailureReason, PaymentHash,
};
use tonic_openssl_lnd::routerrpc::{SendPaymentRequest, TrackPaymentRequest};
use tonic_openssl_lnd::{LndClient, LndLightningClient, LndRouterClient};

mod bip321;
mod config;
mod payments;

const PAYMENT_TIMEOUT_SECONDS: i32 = 45;
const KEYSEND_FINAL_CLTV_DELTA: i32 = 40;
/// How far back to fetch requests after a reconnect.
const RECONNECT_LOOKBACK_SECONDS: u64 = 5 * 60;
const ENCRYPTION_SCHEMES: &str = "nip44_v2 nip04";

const BAD_REQUEST: &str = "BAD_REQUEST";
const FEE_LIMIT_EXCEEDED: &str = "FEE_LIMIT_EXCEEDED";
const INSUFFICIENT_BALANCE: &str = "INSUFFICIENT_BALANCE";
const INTERNAL: &str = "INTERNAL";
const NOT_FOUND: &str = "NOT_FOUND";
const NOT_IMPLEMENTED: &str = "NOT_IMPLEMENTED";
const PAYMENT_FAILED: &str = "PAYMENT_FAILED";
const QUOTA_EXCEEDED: &str = "QUOTA_EXCEEDED";
const RESTRICTED: &str = "RESTRICTED";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::try_init()?;
    let config: Config = Config::parse();
    let keys = get_keys(&config.keys_file);

    let cert = hex::encode(read(config.cert_file())?);
    let macaroon = hex::encode(read(config.macaroon_file())?);
    let socket = format!("{}:{}", config.lnd_host, config.lnd_port);
    let mut lnd_client = tonic_openssl_lnd::connect(cert, macaroon, socket)
        .await
        .expect("failed to connect");

    let mut ln_client = lnd_client.lightning().clone();

    if !config.recv_only() {
        // get_info needs the info:read permission. A least-privilege macaroon
        // may not have it, so do not fail startup over it.
        match ln_client.get_info(GetInfoRequest {}).await {
            Ok(lnd_info) => {
                let lnd_info: LndGetInfoResponse = lnd_info.into_inner();
                info!("Connected to lnd: {}", lnd_info.identity_pubkey);
            }
            Err(e) => info!("Connected to lnd (get_info not permitted: {e})"),
        }
    } else {
        info!("Connected to lnd")
    }

    let uri = NostrWalletConnectURI::new(
        keys.server_keys().public_key(),
        vec![config.relay.parse()?],
        keys.user_key.clone(),
        None,
    );
    // Print the URI directly to the terminal, not through the logging
    // framework. The URI holds a secret and must not go to log appenders
    // or aggregators.
    println!("\n{uri}\n");

    debug!("server pubkey: {}", keys.user_keys().public_key());

    // Set up a oneshot channel to handle shutdown signal
    let (tx, rx) = oneshot::channel();

    // Spawn a task to listen for shutdown signals
    spawn(async move {
        let mut term_signal = signal(SignalKind::terminate())
            .map_err(|e| error!("failed to install TERM signal handler: {e}"))
            .unwrap();
        let mut int_signal = signal(SignalKind::interrupt())
            .map_err(|e| {
                error!("failed to install INT signal handler: {e}");
            })
            .unwrap();

        select! {
            _ = term_signal.recv() => {
                debug!("Received SIGTERM");
            },
            _ = int_signal.recv() => {
                debug!("Received SIGINT");
            },
        }

        let _ = tx.send(());
    });

    let active_requests = Arc::new(RwLock::new(HashSet::new()));
    let active_requests_clone = active_requests.clone();
    spawn(async move {
        if let Err(e) = event_loop(&config, keys, lnd_client, active_requests_clone).await {
            error!("Error: {e}");
        }
    });

    rx.await?;

    info!("Shutting down...");
    // wait for active requests to complete
    loop {
        let requests = active_requests.read().await;
        if requests.is_empty() {
            break;
        }
        debug!("Waiting for {} requests to complete...", requests.len());
        drop(requests);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

async fn event_loop(
    config: &Config,
    keys: Nip47Keys,
    mut lnd_client: LndClient,
    active_requests: Arc<RwLock<HashSet<EventId>>>,
) -> anyhow::Result<()> {
    let tracker = Arc::new(Mutex::new(PaymentTracker::new()));
    // Event IDs that were already processed. A relay can deliver the same
    // request more than once; a replayed pay_keysend would pay again because
    // each try creates a new random preimage.
    let handled_events = Arc::new(Mutex::new(HashMap::<EventId, Instant>::new()));
    let mut since = Timestamp::now();
    // loop in case we get disconnected
    loop {
        let client = Client::new(keys.server_keys());
        client.add_relay(config.relay.as_str()).await?;

        client.connect().await;

        // Publish the info event on every connection, in case the relay
        // dropped it.
        client.send_event(&info_event(config, &keys)?).await?;

        let subscription = Filter::new()
            .kinds(vec![Kind::WalletConnectRequest])
            .author(keys.user_keys().public_key())
            .pubkey(keys.server_keys().public_key())
            .since(since);

        client.subscribe(subscription, None).await?;

        info!("Listening for nip 47 requests...");

        let (tx, mut rx) = tokio::sync::watch::channel(());
        spawn(async move {
            tokio::time::sleep(Duration::from_secs(60 * 15)).await;
            tx.send_modify(|_| ())
        });

        let mut notifications = client.notifications();
        loop {
            select! {
                Ok(notification) = notifications.recv() => {
                    match notification {
                        RelayPoolNotification::Event { event, .. } => {
                            if event.kind == Kind::WalletConnectRequest
                                && event.pubkey == keys.user_keys().public_key()
                                && event.verify().is_ok()
                            {
                                // Drop events older than 24 hours. A newer
                                // event that was processed before is in the
                                // handled-events cache below, so an old event
                                // can only be a replay or a backdated event.
                                let cutoff = Timestamp::now().as_secs().saturating_sub(86_400);
                                if event.created_at.as_secs() < cutoff {
                                    debug!("Ignoring event older than 24h: {}", event.id);
                                    continue;
                                }

                                // NIP-40: the client no longer wants an
                                // expired request to be done.
                                if event.is_expired() {
                                    debug!("Ignoring expired request: {}", event.id);
                                    continue;
                                }

                                // Drop events that were handled before.
                                let mut handled = handled_events.lock().await;
                                handled
                                    .retain(|_, seen_at| seen_at.elapsed() < Duration::from_secs(86_400));
                                if handled.insert(event.id, Instant::now()).is_some() {
                                    debug!("Ignoring already handled event: {}", event.id);
                                    continue;
                                }
                                drop(handled);

                                debug!("Received event!");
                                let active_requests = active_requests.clone();
                                let keys = keys.clone();
                                let config = config.clone();
                                let client = client.clone();
                                let tracker = tracker.clone();
                                let lnd = lnd_client.lightning().clone();
                                let router = lnd_client.router().clone();

                                spawn(async move {
                                    let event_id = event.id;
                                    let mut ar = active_requests.write().await;
                                    ar.insert(event_id);
                                    drop(ar);

                                    match tokio::time::timeout(
                                        Duration::from_secs(60),
                                        handle_nwc_request(
                                            *event, keys, config, &client, tracker, lnd, router,
                                        ),
                                    )
                                    .await
                                    {
                                        Ok(Ok(_)) => {},
                                        Ok(Err(e)) => error!("Error processing request: {e}"),
                                        Err(e) => error!("Timeout error: {e}"),
                                    }

                                    // remove request from active requests
                                    let mut ar = active_requests.write().await;
                                    ar.remove(&event_id);
                                });
                            } else {
                                error!("Invalid event: {}", event.as_json());
                            }
                        }
                        RelayPoolNotification::Shutdown => {
                            info!("Relay pool shutdown");
                            break;
                        }
                        _ => {}
                    }
                }
                _ = rx.changed() => {
                    break;
                }
            }
        }

        client.disconnect().await;

        // A subscription that starts at "now" loses the requests that were
        // published while we reconnect. Look back a few minutes;
        // handled_events drops the requests that were already processed.
        since = Timestamp::from_secs(
            Timestamp::now()
                .as_secs()
                .saturating_sub(RECONNECT_LOOKBACK_SECONDS),
        );
    }
}

fn info_event(config: &Config, keys: &Nip47Keys) -> anyhow::Result<Event> {
    let content = advertised_methods(config).join(" ");
    Ok(EventBuilder::new(Kind::WalletConnectInfo, content)
        .tag(Tag::parse(["encryption", ENCRYPTION_SCHEMES])?)
        .sign_with_keys(&keys.server_keys())?)
}

#[derive(Debug, Clone, Copy)]
enum Encryption {
    Nip04,
    Nip44,
}

/// Decrypt a request and detect its encryption scheme. NIP-04 payloads
/// contain "?iv="; anything else is treated as NIP-44 v2.
fn decrypt_request_content(
    keys: &Nip47Keys,
    content: &str,
) -> anyhow::Result<(String, Encryption)> {
    let user_pubkey = keys.user_keys().public_key();
    if content.contains("?iv=") {
        let decrypted = nip04::decrypt(&keys.server_key, &user_pubkey, content)?;
        Ok((decrypted, Encryption::Nip04))
    } else {
        let decrypted = nip44::decrypt(&keys.server_key, &user_pubkey, content)?;
        Ok((decrypted, Encryption::Nip44))
    }
}

/// Encrypt a response with the same scheme that the request used.
fn encrypt_content(scheme: Encryption, keys: &Nip47Keys, content: &str) -> anyhow::Result<String> {
    let user_pubkey = keys.user_keys().public_key();
    match scheme {
        Encryption::Nip04 => Ok(nip04::encrypt(&keys.server_key, &user_pubkey, content)?),
        Encryption::Nip44 => Ok(nip44::encrypt(
            &keys.server_key,
            &user_pubkey,
            content,
            nip44::Version::V2,
        )?),
    }
}

async fn handle_nwc_request(
    event: Event,
    keys: Nip47Keys,
    config: Config,
    client: &Client,
    tracker: Arc<Mutex<PaymentTracker>>,
    lnd: LndLightningClient,
    router: LndRouterClient,
) -> anyhow::Result<()> {
    let (decrypted, scheme) = decrypt_request_content(&keys, &event.content)?;
    // From here on, every request gets a response, so the client does not
    // wait until it times out.
    let envelope: RequestEnvelope = match serde_json::from_str(&decrypted) {
        Ok(envelope) => envelope,
        Err(error) => {
            let content = error_response("", BAD_REQUEST, format!("Invalid request: {error}"));
            return send_json_response(&event, &keys, client, content, scheme, None).await;
        }
    };
    if matches!(envelope.method.as_str(), PAY_METHOD | RECEIVE_METHOD) {
        return handle_bip321_request(
            envelope.method,
            envelope.params,
            &event,
            &keys,
            &config,
            client,
            tracker,
            lnd,
            router,
            scheme,
        )
        .await;
    }

    if !Method::from_str(&envelope.method).is_ok_and(|method| METHODS.contains(&method)) {
        let content = error_response(
            &envelope.method,
            NOT_IMPLEMENTED,
            format!("Method not implemented: {}", envelope.method),
        );
        return send_json_response(&event, &keys, client, content, scheme, None).await;
    }

    let req: Request = match Request::from_json(&decrypted) {
        Ok(req) => req,
        Err(error) => {
            let content = error_response(
                &envelope.method,
                BAD_REQUEST,
                format!("Invalid params: {error}"),
            );
            return send_json_response(&event, &keys, client, content, scheme, None).await;
        }
    };

    debug!("Request params: {:?}", req.params);

    // split up the multis into their parts
    match req.params {
        RequestParams::MultiPayInvoice(params) => {
            for inv in params.invoices {
                let params = RequestParams::PayInvoice(inv);
                let lnd = lnd.clone();
                let router = router.clone();
                let tracker = tracker.clone();
                let keys = keys.clone();
                let config = config.clone();
                let client = client.clone();
                let event = event.clone();
                spawn(async move {
                    handle_nwc_params(
                        params, req.method, &event, &keys, &config, &client, tracker, lnd, router,
                        scheme,
                    )
                    .await
                })
                .await??;
            }

            Ok(())
        }
        RequestParams::MultiPayKeysend(params) => {
            for inv in params.keysends {
                let params = RequestParams::PayKeysend(inv);
                let lnd = lnd.clone();
                let router = router.clone();
                let tracker = tracker.clone();
                let keys = keys.clone();
                let config = config.clone();
                let client = client.clone();
                let event = event.clone();
                spawn(async move {
                    handle_nwc_params(
                        params, req.method, &event, &keys, &config, &client, tracker, lnd, router,
                        scheme,
                    )
                    .await
                })
                .await??;
            }

            Ok(())
        }
        params => {
            handle_nwc_params(
                params, req.method, &event, &keys, &config, client, tracker, lnd, router, scheme,
            )
            .await
        }
    }
}

#[derive(Debug, Deserialize)]
struct RequestEnvelope {
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct ExtendedGetInfoResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey: Option<String>,
    network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_hash: Option<String>,
    methods: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notifications: Vec<String>,
}

async fn handle_bip321_request(
    method: String,
    params: Value,
    event: &Event,
    keys: &Nip47Keys,
    config: &Config,
    client: &Client,
    tracker: Arc<Mutex<PaymentTracker>>,
    mut lnd: LndLightningClient,
    mut router: LndRouterClient,
    scheme: Encryption,
) -> anyhow::Result<()> {
    let allowed = method == RECEIVE_METHOD || (method == PAY_METHOD && !config.recv_only());
    let content = if !allowed {
        error_response(&method, "RESTRICTED", "Method not allowed.")
    } else if method == PAY_METHOD {
        match serde_json::from_value::<PayRequestParams>(params) {
            Ok(params) => handle_bip321_pay(params, config, tracker, &mut router).await,
            Err(error) => error_response(PAY_METHOD, "BAD_REQUEST", error.to_string()),
        }
    } else {
        match serde_json::from_value::<ReceiveRequestParams>(params) {
            Ok(params) => handle_bip321_receive(params, config, &mut lnd).await,
            Err(error) => error_response(RECEIVE_METHOD, "BAD_REQUEST", error.to_string()),
        }
    };

    send_json_response(event, keys, client, content, scheme, None).await
}

async fn handle_bip321_pay(
    params: PayRequestParams,
    config: &Config,
    tracker: Arc<Mutex<PaymentTracker>>,
    router: &mut LndRouterClient,
) -> Value {
    if params
        .payer_note
        .as_deref()
        .is_some_and(|note| !note.is_empty())
    {
        return error_response(
            PAY_METHOD,
            "BAD_REQUEST",
            "BOLT11 does not support payer-provided notes",
        );
    }

    let invoice = match parse_payment_uri(&params.payment, config.network).await {
        Ok(invoice) => invoice,
        Err(error) => return error_response(PAY_METHOD, error.code(), error.to_string()),
    };
    if invoice.is_expired() {
        return error_response(PAY_METHOD, BAD_REQUEST, "Invoice has expired.");
    }
    let amount = match payment_amount(&invoice, params.amount) {
        Ok(amount) => amount,
        Err(error) => return error_response(PAY_METHOD, error.code(), error.to_string()),
    };

    let limit_error = {
        let mut tracker = tracker.lock().await;
        if config.max_amount > 0 && amount > config.max_amount.saturating_mul(1_000) {
            Some("Payment amount too high.")
        } else if config.daily_limit > 0
            && tracker.sum_payments().saturating_add(amount)
                > config.daily_limit.saturating_mul(1_000)
        {
            Some("Daily limit exceeded.")
        } else {
            tracker.add_payment(amount);
            None
        }
    };
    if let Some(message) = limit_error {
        return error_response(PAY_METHOD, "QUOTA_EXCEEDED", message);
    }

    let created_at = Timestamp::now().as_secs();
    let payment_hash = hex::encode(invoice.payment_hash().to_byte_array());
    let request = SendPaymentRequest {
        payment_request: invoice.to_string(),
        amt_msat: if invoice.amount_milli_satoshis().is_none() {
            amount as i64
        } else {
            0
        },
        timeout_seconds: PAYMENT_TIMEOUT_SECONDS,
        fee_limit_msat: fee_limit_msat(config.max_fee, params.max_fee),
        no_inflight_updates: true,
        allow_self_payment: false,
        ..Default::default()
    };
    let result = match send_payment(router, request).await {
        Ok(response) if response.status() == PaymentStatus::Succeeded => Ok(response),
        Ok(response) => Err(payment_failure(&response, params.max_fee.is_some())),
        Err(error) => Err(send_payment_error(&error, "Failed to pay invoice")),
    };
    let response = match result {
        Ok(response) => response,
        Err(error) => {
            tracker.lock().await.remove_payment(amount);
            return error_response(PAY_METHOD, error.code, error.message);
        }
    };

    let settled_at = Timestamp::now().as_secs();
    let fees_paid = response.fee_msat.max(0) as u64;
    let preimage = (!response.payment_preimage.is_empty()).then_some(response.payment_preimage);

    success_response(
        PAY_METHOD,
        PayResponseResult {
            transaction_id: payment_hash.clone(),
            state: "settled",
            instruction_type: "bolt11",
            amount,
            fees_paid,
            payment_hash: Some(payment_hash),
            preimage,
            payer_proof: None,
            txid: None,
            failure_reason: None,
            created_at,
            settled_at: Some(settled_at),
        },
    )
}

async fn handle_bip321_receive(
    params: ReceiveRequestParams,
    config: &Config,
    lnd: &mut LndLightningClient,
) -> Value {
    if params
        .amount
        .is_some_and(|amount| amount == 0 || amount > i64::MAX as u64)
    {
        return error_response(
            RECEIVE_METHOD,
            "BAD_REQUEST",
            "Invoice amount is out of range",
        );
    }

    let invoice = Invoice {
        memo: params.description.unwrap_or_default(),
        value_msat: params.amount.unwrap_or(0) as i64,
        expiry: 86_400,
        private: config.route_hints,
        ..Default::default()
    };
    let response = match lnd.add_invoice(invoice).await {
        Ok(response) => response.into_inner(),
        Err(error) => {
            return error_response(
                RECEIVE_METHOD,
                "INTERNAL",
                format!("Failed to create invoice: {error}"),
            );
        }
    };
    let transaction_id = hex::encode(response.r_hash);

    success_response(
        RECEIVE_METHOD,
        ReceiveResponseResult {
            bip321: format!("bitcoin:?lightning={}", response.payment_request),
            transaction_id: Some(transaction_id),
        },
    )
}

async fn send_json_response(
    event: &Event,
    keys: &Nip47Keys,
    client: &Client,
    content: Value,
    scheme: Encryption,
    d_tag: Option<Tag>,
) -> anyhow::Result<()> {
    let encrypted = encrypt_content(scheme, keys, &content.to_string())?;
    let mut tags = vec![Tag::public_key(event.pubkey), Tag::event(event.id)];
    tags.extend(d_tag);
    let response = EventBuilder::new(Kind::WalletConnectResponse, encrypted)
        .tags(tags)
        .sign_with_keys(&keys.server_keys())?;
    client.send_event(&response).await?;
    Ok(())
}

/// An NWC error response.
#[derive(Debug)]
struct NwcError {
    code: &'static str,
    message: String,
}

impl NwcError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        NwcError {
            code,
            message: message.into(),
        }
    }
}

fn lnd_error(context: &str, status: tonic::Status) -> NwcError {
    NwcError::new(INTERNAL, format!("{context}: {}", status.message()))
}

fn is_permission_denied(status: &tonic::Status) -> bool {
    // LND reports a missing macaroon permission as an unknown error.
    status.code() == tonic::Code::PermissionDenied
        || status
            .message()
            .to_ascii_lowercase()
            .contains("permission denied")
}

fn is_invoice_not_found(status: &tonic::Status) -> bool {
    status.code() == tonic::Code::NotFound
        || status
            .message()
            .to_ascii_lowercase()
            .contains("unable to locate invoice")
}

async fn get_info_response(
    config: &Config,
    lnd: &mut LndLightningClient,
) -> Result<Value, NwcError> {
    let lnd_info = if config.recv_only() {
        None
    } else {
        match lnd.get_info(GetInfoRequest {}).await {
            Ok(info) => Some(info.into_inner()),
            // A least-privilege macaroon may not have info:read. Answer
            // without the node fields.
            Err(status) if is_permission_denied(&status) => {
                debug!("get_info not permitted: {status}");
                None
            }
            Err(status) => return Err(lnd_error("Failed to get node info", status)),
        }
    };
    Ok(success_response(
        Method::GetInfo.as_str(),
        ExtendedGetInfoResult {
            alias: lnd_info.as_ref().map(|info| info.alias.clone()),
            color: lnd_info.as_ref().map(|info| info.color.clone()),
            pubkey: lnd_info.as_ref().map(|info| info.identity_pubkey.clone()),
            network: config.nwc_network_name().to_string(),
            block_height: lnd_info.as_ref().map(|info| info.block_height),
            block_hash: lnd_info.as_ref().map(|info| info.block_hash.clone()),
            methods: advertised_methods(config),
            notifications: Vec::new(),
        },
    ))
}

async fn handle_nwc_params(
    params: RequestParams,
    method: Method,
    event: &Event,
    keys: &Nip47Keys,
    config: &Config,
    client: &Client,
    tracker: Arc<Mutex<PaymentTracker>>,
    mut lnd: LndLightningClient,
    mut router: LndRouterClient,
    scheme: Encryption,
) -> anyhow::Result<()> {
    let d_tag = match &params {
        RequestParams::PayInvoice(params) => params.id.clone().map(Tag::identifier),
        RequestParams::PayKeysend(params) => params.id.clone().map(Tag::identifier),
        _ => None,
    };

    let content = if !check_nwc_permissions(config, method) {
        error_response(method.as_str(), RESTRICTED, "Method not allowed.")
    } else {
        match nwc_response(params, method, config, tracker, &mut lnd, &mut router).await {
            Ok(content) => content,
            Err(error) => error_response(method.as_str(), error.code, error.message),
        }
    };

    send_json_response(event, keys, client, content, scheme, d_tag).await
}

async fn nwc_response(
    params: RequestParams,
    method: Method,
    config: &Config,
    tracker: Arc<Mutex<PaymentTracker>>,
    lnd: &mut LndLightningClient,
    router: &mut LndRouterClient,
) -> Result<Value, NwcError> {
    let result = match params {
        RequestParams::PayInvoice(params) => {
            let invoice = Bolt11Invoice::from_str(&params.invoice)
                .map_err(|_| NwcError::new(BAD_REQUEST, "Failed to parse invoice"))?;
            let msats = invoice
                .amount_milli_satoshis()
                .or(params.amount)
                .unwrap_or(0);

            reserve_payment(config, &tracker, msats).await?;
            match pay_invoice(invoice, router, config.max_fee).await {
                Ok(result) => result,
                Err(error) => {
                    tracker.lock().await.remove_payment(msats);
                    return Err(error);
                }
            }
        }
        RequestParams::PayKeysend(params) => {
            let msats = params.amount;
            // Validate the request before any budget is reserved. A bad
            // request must not hold the reserved amount for a day.
            let pubkey = bitcoin::secp256k1::PublicKey::from_str(&params.pubkey).map_err(|_| {
                NwcError::new(BAD_REQUEST, format!("Invalid pubkey: {}", params.pubkey))
            })?;
            let request = keysend_request(
                &pubkey,
                params.preimage,
                params.tlv_records,
                msats,
                config.max_fee,
            )
            .map_err(|e| NwcError::new(BAD_REQUEST, e.to_string()))?;

            reserve_payment(config, &tracker, msats).await?;
            match pay_keysend(request, &pubkey, msats, router).await {
                Ok(result) => result,
                Err(error) => {
                    tracker.lock().await.remove_payment(msats);
                    return Err(error);
                }
            }
        }
        RequestParams::MakeInvoice(params) => {
            let amount = params.amount;
            let expiry = params.expiry.unwrap_or(86_400);
            let description = params.description;
            let description_hash_hex = params.description_hash;
            let description_hash: Vec<u8> = match &description_hash_hex {
                None => vec![],
                Some(value) => FromHex::from_hex(value)
                    .map_err(|_| NwcError::new(BAD_REQUEST, "Invalid description_hash"))?,
            };
            let inv = Invoice {
                memo: description.clone().unwrap_or_default(),
                description_hash,
                value_msat: amount as i64,
                expiry: expiry as i64,
                private: config.route_hints,
                ..Default::default()
            };
            let created_at = Timestamp::now();
            let res = lnd
                .add_invoice(inv)
                .await
                .map_err(|e| lnd_error("Failed to create invoice", e))?
                .into_inner();

            info!("Created invoice: {}", res.payment_request);

            ResponseResult::MakeInvoice(MakeInvoiceResponse {
                invoice: res.payment_request,
                payment_hash: Some(::hex::encode(res.r_hash)),
                description,
                description_hash: description_hash_hex,
                preimage: None,
                amount: Some(amount),
                created_at: Some(created_at),
                expires_at: Some(Timestamp::from_secs(
                    created_at.as_secs().saturating_add(expiry),
                )),
            })
        }
        RequestParams::LookupInvoice(params) => {
            let mut invoice: Option<Bolt11Invoice> = None;
            let payment_hash: Vec<u8> = match params.payment_hash {
                None => match params.invoice {
                    None => {
                        return Err(NwcError::new(
                            BAD_REQUEST,
                            "Missing payment_hash or invoice",
                        ))
                    }
                    Some(bolt11) => {
                        let inv = Bolt11Invoice::from_str(&bolt11)
                            .map_err(|_| NwcError::new(BAD_REQUEST, "Failed to parse invoice"))?;
                        let hash = inv.payment_hash().to_byte_array().to_vec();
                        invoice = Some(inv);
                        hash
                    }
                },
                Some(str) => <[u8; 32]>::from_hex(&str)
                    .map_err(|_| NwcError::new(BAD_REQUEST, "Invalid payment_hash"))?
                    .to_vec(),
            };

            let lookup = lnd
                .lookup_invoice(PaymentHash {
                    r_hash: payment_hash.clone(),
                    ..Default::default()
                })
                .await;
            let response = match lookup {
                Ok(res) => {
                    let res = res.into_inner();
                    info!("Looked up invoice: {}", res.payment_request);
                    incoming_lookup_response(res, &payment_hash, invoice.as_ref())
                }
                Err(status) if is_invoice_not_found(&status) => {
                    // Not one of our invoices; it can be a payment we sent.
                    // A receive-only node has no outgoing payments.
                    let payment = if config.recv_only() {
                        None
                    } else {
                        lookup_payment(router, &payment_hash).await?
                    };
                    match payment {
                        Some(payment) => outgoing_lookup_response(&payment),
                        None => return Err(NwcError::new(NOT_FOUND, "Invoice not found")),
                    }
                }
                Err(status) => return Err(lnd_error("Failed to look up invoice", status)),
            };

            ResponseResult::LookupInvoice(response)
        }
        RequestParams::GetBalance => {
            let balance: u64 = if config.recv_only() {
                // fetch local balance from lnd
                let channel_balance_response = lnd
                    .channel_balance(ChannelBalanceRequest {})
                    .await
                    .map_err(|e| lnd_error("Failed to get balance", e))?
                    .into_inner();
                let channel_balance = channel_balance_response
                    .local_balance
                    .unwrap_or_default()
                    .sat;
                (channel_balance * 1_000) as u64
            } else {
                // calculate remaining balance based on daily limit
                let tracker = tracker.lock().await.sum_payments();
                (config.daily_limit * 1_000).saturating_sub(tracker)
            };

            info!("Current balance: {balance} msats");

            ResponseResult::GetBalance(GetBalanceResponse { balance })
        }
        RequestParams::GetInfo => return get_info_response(config, lnd).await,
        _ => return Err(NwcError::new(NOT_IMPLEMENTED, "Method not implemented")),
    };

    let response = Response {
        result_type: method,
        error: None,
        result: Some(result),
    };
    serde_json::to_value(response).map_err(|e| NwcError::new(INTERNAL, e.to_string()))
}

/// Atomically check the payment limits and reserve the amount.
async fn reserve_payment(
    config: &Config,
    tracker: &Mutex<PaymentTracker>,
    msats: u64,
) -> Result<(), NwcError> {
    let mut tracker = tracker.lock().await;
    if config.max_amount > 0 && msats > config.max_amount.saturating_mul(1_000) {
        Err(NwcError::new(QUOTA_EXCEEDED, "Invoice amount too high."))
    } else if config.daily_limit > 0
        && tracker.sum_payments().saturating_add(msats) > config.daily_limit.saturating_mul(1_000)
    {
        Err(NwcError::new(QUOTA_EXCEEDED, "Daily limit exceeded."))
    } else {
        tracker.add_payment(msats);
        Ok(())
    }
}

fn invoice_description(invoice: &Bolt11Invoice) -> (Option<String>, Option<String>) {
    match invoice.description() {
        Bolt11InvoiceDescriptionRef::Direct(desc) => (Some(desc.to_string()), None),
        Bolt11InvoiceDescriptionRef::Hash(hash) => (None, Some(hash.0.to_string())),
    }
}

fn incoming_lookup_response(
    res: Invoice,
    payment_hash: &[u8],
    invoice: Option<&Bolt11Invoice>,
) -> LookupInvoiceResponse {
    let (description, description_hash) = invoice.map(invoice_description).unwrap_or_default();

    let preimage = if res.r_preimage.is_empty() {
        None
    } else {
        Some(hex::encode(res.r_preimage))
    };

    let settled_at = if res.settle_date == 0 {
        None
    } else {
        Some(Timestamp::from_secs(res.settle_date as u64))
    };
    let state = match res.state {
        1 => Some(TransactionState::Settled),
        2 => Some(TransactionState::Expired),
        _ => Some(TransactionState::Pending),
    };

    LookupInvoiceResponse {
        transaction_type: Some(TransactionType::Incoming),
        state,
        invoice: Some(res.payment_request),
        description,
        description_hash,
        preimage,
        payment_hash: hex::encode(payment_hash),
        amount: res.value_msat as u64,
        fees_paid: 0,
        created_at: Timestamp::from_secs(res.creation_date as u64),
        expires_at: Some(Timestamp::from_secs(
            (res.creation_date + res.expiry) as u64,
        )),
        settled_at,
        metadata: Default::default(),
    }
}

/// Look up an outgoing payment. Returns `None` if no payment with this hash
/// exists.
async fn lookup_payment(
    router: &mut LndRouterClient,
    payment_hash: &[u8],
) -> Result<Option<Payment>, NwcError> {
    // The first update holds the current state. Do not set
    // no_inflight_updates: for a pending payment, the first update would
    // then only come when the payment resolves.
    let request = TrackPaymentRequest {
        payment_hash: payment_hash.to_vec(),
        no_inflight_updates: false,
    };
    let first_update = match router.track_payment_v2(request).await {
        Ok(updates) => updates.into_inner().message().await,
        Err(status) => Err(status),
    };
    match first_update {
        Ok(payment) => Ok(payment),
        Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
        Err(status) => Err(lnd_error("Failed to look up payment", status)),
    }
}

fn nanos_to_timestamp(nanos: i64) -> Timestamp {
    Timestamp::from_secs(nanos.max(0) as u64 / 1_000_000_000)
}

fn outgoing_lookup_response(payment: &Payment) -> LookupInvoiceResponse {
    let state = match payment.status() {
        PaymentStatus::Succeeded => TransactionState::Settled,
        PaymentStatus::Failed => TransactionState::Failed,
        _ => TransactionState::Pending,
    };

    let invoice = Some(payment.payment_request.clone()).filter(|inv| !inv.is_empty());
    let parsed = invoice
        .as_deref()
        .and_then(|inv| Bolt11Invoice::from_str(inv).ok());
    let (description, description_hash) =
        parsed.as_ref().map(invoice_description).unwrap_or_default();

    // LND returns an all-zero preimage for payments that did not settle.
    let preimage = Some(payment.payment_preimage.clone())
        .filter(|preimage| preimage.bytes().any(|b| b != b'0'));

    let settled_at = if state == TransactionState::Settled {
        payment
            .htlcs
            .iter()
            .filter(|htlc| htlc.status() == HtlcStatus::Succeeded)
            .map(|htlc| htlc.resolve_time_ns)
            .max()
            .filter(|nanos| *nanos > 0)
            .map(nanos_to_timestamp)
    } else {
        None
    };

    LookupInvoiceResponse {
        transaction_type: Some(TransactionType::Outgoing),
        state: Some(state),
        invoice,
        description,
        description_hash,
        preimage,
        payment_hash: payment.payment_hash.clone(),
        amount: payment.value_msat.max(0) as u64,
        fees_paid: payment.fee_msat.max(0) as u64,
        created_at: nanos_to_timestamp(payment.creation_time_ns),
        expires_at: parsed
            .and_then(|inv| inv.expires_at())
            .map(|expires_at| Timestamp::from_secs(expires_at.as_secs())),
        settled_at,
        metadata: None,
    }
}

/// The routing fee limit: the configured limit in sats, lowered to the
/// limit the client requested in msats, if any.
fn fee_limit_msat(max_fee_sats: u64, requested_max_fee_msat: Option<u64>) -> i64 {
    let limit = max_fee_sats.saturating_mul(1_000);
    let limit = requested_max_fee_msat.map_or(limit, |requested| limit.min(requested));
    limit.min(i64::MAX as u64) as i64
}

fn payment_failure_message(payment: &Payment) -> &'static str {
    match payment.failure_reason() {
        PaymentFailureReason::FailureReasonTimeout => "Payment timed out.",
        PaymentFailureReason::FailureReasonNoRoute => "No payment route was found.",
        PaymentFailureReason::FailureReasonError => "Payment failed with a non-recoverable error.",
        PaymentFailureReason::FailureReasonIncorrectPaymentDetails => {
            "The payment details are incorrect."
        }
        PaymentFailureReason::FailureReasonInsufficientBalance => "Insufficient local balance.",
        PaymentFailureReason::FailureReasonCanceled => "Payment was canceled.",
        PaymentFailureReason::FailureReasonNone => "Payment failed.",
    }
}

/// The error for a failed payment. Failures where LND did not send an HTLC
/// get a specific code, so the client knows that nothing was sent.
/// `fee_limited` is true if the client set a fee limit.
fn payment_failure(payment: &Payment, fee_limited: bool) -> NwcError {
    let attempted = !payment.htlcs.is_empty();
    let code = match payment.failure_reason() {
        PaymentFailureReason::FailureReasonInsufficientBalance if !attempted => {
            INSUFFICIENT_BALANCE
        }
        PaymentFailureReason::FailureReasonNoRoute if fee_limited && !attempted => {
            FEE_LIMIT_EXCEEDED
        }
        _ => PAYMENT_FAILED,
    };
    let message = if code == FEE_LIMIT_EXCEEDED {
        "No route was found within the fee limit."
    } else {
        payment_failure_message(payment)
    };
    NwcError::new(code, message)
}

/// The error for a payment that LND did not finish. LND rejects some
/// payments before it routes them; these get a specific code. Any other
/// error keeps PAYMENT_FAILED, because the payment state is not known.
fn send_payment_error(error: &anyhow::Error, context: &str) -> NwcError {
    let code = error
        .downcast_ref::<tonic::Status>()
        .and_then(pre_routing_error_code)
        .unwrap_or(PAYMENT_FAILED);
    NwcError::new(code, format!("{context}: {error}"))
}

fn pre_routing_error_code(status: &tonic::Status) -> Option<&'static str> {
    let message = status.message().to_ascii_lowercase();
    if message.contains("insufficient") && message.contains("balance") {
        Some(INSUFFICIENT_BALANCE)
    } else if message.contains("invoice expired")
        || message.contains("already paid")
        || message.contains("payment is in transition")
        || status.code() == tonic::Code::InvalidArgument
    {
        Some(BAD_REQUEST)
    } else {
        None
    }
}

async fn send_payment(
    router: &mut LndRouterClient,
    request: SendPaymentRequest,
) -> anyhow::Result<Payment> {
    let mut updates = router.send_payment_v2(request).await?.into_inner();

    while let Some(payment) = updates.message().await? {
        if matches!(
            payment.status(),
            PaymentStatus::Succeeded | PaymentStatus::Failed
        ) {
            return Ok(payment);
        }
    }

    Err(anyhow!(
        "payment update stream ended before a terminal status"
    ))
}

async fn pay_invoice(
    ln_invoice: Bolt11Invoice,
    router: &mut LndRouterClient,
    max_fee_sats: u64,
) -> Result<ResponseResult, NwcError> {
    debug!("paying invoice: {ln_invoice}");

    if ln_invoice.is_expired() {
        return Err(NwcError::new(BAD_REQUEST, "Invoice has expired."));
    }

    let req = SendPaymentRequest {
        payment_request: ln_invoice.to_string(),
        timeout_seconds: PAYMENT_TIMEOUT_SECONDS,
        fee_limit_msat: fee_limit_msat(max_fee_sats, None),
        no_inflight_updates: true,
        allow_self_payment: false,
        ..Default::default()
    };

    let response = send_payment(router, req)
        .await
        .map_err(|e| send_payment_error(&e, "Failed to pay invoice"))?;
    if response.status() != PaymentStatus::Succeeded {
        return Err(payment_failure(&response, false));
    }

    info!("paid invoice: {}", ln_invoice.payment_hash());
    Ok(ResponseResult::PayInvoice(PayInvoiceResponse {
        preimage: response.payment_preimage,
        fees_paid: Some(response.fee_msat.max(0) as u64),
    }))
}

async fn pay_keysend(
    request: SendPaymentRequest,
    pubkey: &bitcoin::secp256k1::PublicKey,
    amount_msats: u64,
    router: &mut LndRouterClient,
) -> Result<ResponseResult, NwcError> {
    debug!("paying keysend to {pubkey} for {amount_msats}msats");

    let response = send_payment(router, request)
        .await
        .map_err(|e| send_payment_error(&e, "Failed to pay keysend"))?;
    if response.status() != PaymentStatus::Succeeded {
        return Err(payment_failure(&response, false));
    }

    info!("paid keysend to {pubkey} for {amount_msats}msats");
    Ok(ResponseResult::PayKeysend(PayKeysendResponse {
        preimage: response.payment_preimage,
        fees_paid: Some(response.fee_msat.max(0) as u64),
    }))
}

fn keysend_request(
    pubkey: &bitcoin::secp256k1::PublicKey,
    preimage: Option<String>,
    tlv_records: Vec<KeysendTLVRecord>,
    amount_msats: u64,
    max_fee_sats: u64,
) -> anyhow::Result<SendPaymentRequest> {
    let mut dest_custom_records = tlv_records
        .into_iter()
        .map(|rec| Ok((rec.tlv_type, FromHex::from_hex(&rec.value)?)))
        .collect::<Result<HashMap<u64, Vec<u8>>, anyhow::Error>>()?;

    let payment_hash: Vec<u8> = match preimage {
        None => match dest_custom_records.get(&5482373484) {
            None => {
                let preimage = Secp256k1SecretKey::new(&mut OsRng).secret_bytes();
                dest_custom_records.insert(5482373484, preimage.to_vec());
                sha256::Hash::hash(&preimage).to_byte_array().to_vec()
            }
            Some(preimage) => sha256::Hash::hash(preimage).to_byte_array().to_vec(),
        },
        Some(preimage) => {
            let preimage: [u8; 32] = FromHex::from_hex(&preimage)?;
            dest_custom_records.insert(5482373484, preimage.to_vec());
            sha256::Hash::hash(&preimage).to_byte_array().to_vec()
        }
    };

    Ok(SendPaymentRequest {
        dest: pubkey.serialize().to_vec(),
        amt_msat: i64::try_from(amount_msats)
            .map_err(|_| anyhow!("keysend amount is out of range"))?,
        final_cltv_delta: KEYSEND_FINAL_CLTV_DELTA,
        timeout_seconds: PAYMENT_TIMEOUT_SECONDS,
        fee_limit_msat: fee_limit_msat(max_fee_sats, None),
        dest_custom_records,
        no_inflight_updates: true,
        allow_self_payment: false,
        payment_hash,
        ..Default::default()
    })
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Nip47Keys {
    #[serde(serialize_with = "serialize_secret_key")]
    server_key: NostrSecretKey,
    #[serde(serialize_with = "serialize_secret_key")]
    user_key: NostrSecretKey,
}

fn serialize_secret_key<S>(secret_key: &NostrSecretKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&secret_key.to_secret_hex())
}

impl Nip47Keys {
    fn generate() -> Self {
        let server_key = Keys::generate();
        let user_key = Keys::generate();

        Nip47Keys {
            server_key: server_key.secret_key().clone(),
            user_key: user_key.secret_key().clone(),
        }
    }

    fn server_keys(&self) -> Keys {
        Keys::new(self.server_key.clone())
    }

    fn user_keys(&self) -> Keys {
        Keys::new(self.user_key.clone())
    }
}

fn get_keys(keys_file: &str) -> Nip47Keys {
    let path = Path::new(keys_file);
    match File::open(path) {
        Ok(file) => {
            warn_on_permissive_keys_file(keys_file, &file);
            let reader = BufReader::new(file);
            serde_json::from_reader(reader).expect("Could not parse JSON")
        }
        Err(_) => {
            let keys = Nip47Keys::generate();
            write_keys(keys, path)
        }
    }
}

// The keys file holds the full NWC secret. Warn if other users can read it.
#[cfg(unix)]
fn warn_on_permissive_keys_file(keys_file: &str, file: &File) {
    use std::os::unix::fs::MetadataExt;

    if let Ok(metadata) = file.metadata() {
        if metadata.mode() & 0o077 != 0 {
            error!("{keys_file} is readable by other users; run: chmod 600 {keys_file}");
        }
    }
}

#[cfg(not(unix))]
fn warn_on_permissive_keys_file(_keys_file: &str, _file: &File) {}

fn write_keys(keys: Nip47Keys, path: &Path) -> Nip47Keys {
    let json_str = serde_json::to_string(&keys).expect("Could not serialize data");

    if let Some(parent) = path.parent() {
        create_dir_all(parent).expect("Could not create directory");
    }

    let mut options = File::options();
    options.write(true).create(true).truncate(true);
    // The file holds the full NWC secret; only the owner may read or write it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).expect("Could not create file");
    file.write_all(json_str.as_bytes())
        .expect("Could not write to file");

    keys
}

const METHODS: [Method; 8] = [
    Method::GetInfo,
    Method::MakeInvoice,
    Method::GetBalance,
    Method::LookupInvoice,
    Method::PayInvoice,
    Method::MultiPayInvoice,
    Method::PayKeysend,
    Method::MultiPayKeysend,
];

const RECV_ONLY_METHODS: [Method; 4] = [
    Method::GetInfo,
    Method::MakeInvoice,
    Method::GetBalance,
    Method::LookupInvoice,
];

fn methods(config: &Config) -> Vec<Method> {
    if config.recv_only() {
        RECV_ONLY_METHODS.to_vec()
    } else {
        METHODS.to_vec()
    }
}

fn advertised_methods(config: &Config) -> Vec<String> {
    let mut methods = methods(config)
        .into_iter()
        .map(|method| method.to_string())
        .collect::<Vec<_>>();
    if !config.recv_only() {
        methods.push(PAY_METHOD.to_string());
    }
    methods.push(RECEIVE_METHOD.to_string());
    methods
}

fn check_nwc_permissions(config: &Config, method: Method) -> bool {
    methods(config).contains(&method)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertises_bip321_methods_according_to_permissions() {
        let config = Config::try_parse_from(["nwc-lnd", "--relay", "wss://relay.example"]).unwrap();
        assert_eq!(config.max_fee, 1_000);
        let advertised = advertised_methods(&config);
        assert!(advertised.contains(&PAY_METHOD.to_string()));
        assert!(advertised.contains(&RECEIVE_METHOD.to_string()));

        let recv_only = Config::try_parse_from([
            "nwc-lnd",
            "--relay",
            "wss://relay.example",
            "--invoice-macaroon-file",
            "invoice.macaroon",
        ])
        .unwrap();
        let advertised = advertised_methods(&recv_only);
        assert!(!advertised.contains(&PAY_METHOD.to_string()));
        assert!(advertised.contains(&RECEIVE_METHOD.to_string()));
    }

    #[test]
    fn builds_lnd_021_keysend_request_with_preimage_tlv_and_limits() {
        let pubkey = bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let preimage = [1_u8; 32];

        let request =
            keysend_request(&pubkey, Some(hex::encode(preimage)), Vec::new(), 42_000, 7).unwrap();

        assert_eq!(request.amt_msat, 42_000);
        assert_eq!(request.timeout_seconds, PAYMENT_TIMEOUT_SECONDS);
        assert_eq!(request.fee_limit_msat, 7_000);
        assert_eq!(request.final_cltv_delta, KEYSEND_FINAL_CLTV_DELTA);
        assert!(request.no_inflight_updates);
        assert_eq!(
            request.dest_custom_records.get(&5482373484),
            Some(&preimage.to_vec())
        );
        assert_eq!(
            request.payment_hash,
            sha256::Hash::hash(&preimage).to_byte_array()
        );
    }

    #[test]
    fn rejects_keysend_amounts_that_do_not_fit_lnd_request() {
        let pubkey = bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();

        let error = keysend_request(&pubkey, None, Vec::new(), u64::MAX, 1).unwrap_err();
        assert_eq!(error.to_string(), "keysend amount is out of range");
    }

    #[test]
    fn lowers_fee_limit_to_requested_max_fee() {
        assert_eq!(fee_limit_msat(7, None), 7_000);
        assert_eq!(fee_limit_msat(7, Some(1_500)), 1_500);
        assert_eq!(fee_limit_msat(7, Some(9_000)), 7_000);
        assert_eq!(fee_limit_msat(u64::MAX, None), i64::MAX);
    }

    fn failed_payment(reason: PaymentFailureReason, attempted: bool) -> Payment {
        Payment {
            status: PaymentStatus::Failed as i32,
            failure_reason: reason as i32,
            htlcs: if attempted {
                vec![Default::default()]
            } else {
                Vec::new()
            },
            ..Default::default()
        }
    }

    #[test]
    fn uses_pre_routing_codes_only_when_no_htlc_was_sent() {
        let insufficient = PaymentFailureReason::FailureReasonInsufficientBalance;
        let no_route = PaymentFailureReason::FailureReasonNoRoute;

        let error = payment_failure(&failed_payment(insufficient, false), false);
        assert_eq!(error.code, INSUFFICIENT_BALANCE);
        let error = payment_failure(&failed_payment(insufficient, true), false);
        assert_eq!(error.code, PAYMENT_FAILED);

        let error = payment_failure(&failed_payment(no_route, false), true);
        assert_eq!(error.code, FEE_LIMIT_EXCEEDED);
        let error = payment_failure(&failed_payment(no_route, false), false);
        assert_eq!(error.code, PAYMENT_FAILED);
        let error = payment_failure(&failed_payment(no_route, true), true);
        assert_eq!(error.code, PAYMENT_FAILED);

        let timeout = PaymentFailureReason::FailureReasonTimeout;
        let error = payment_failure(&failed_payment(timeout, true), true);
        assert_eq!(error.code, PAYMENT_FAILED);
    }

    #[test]
    fn maps_lnd_send_errors_to_codes() {
        let code = |status: tonic::Status| send_payment_error(&status.into(), "Failed").code;

        assert_eq!(
            code(tonic::Status::already_exists("invoice is already paid")),
            BAD_REQUEST
        );
        assert_eq!(
            code(tonic::Status::already_exists("payment is in transition")),
            BAD_REQUEST
        );
        assert_eq!(
            code(tonic::Status::unknown(
                "invoice expired. Valid until 2026-01-01 00:00:00 +0000 UTC"
            )),
            BAD_REQUEST
        );
        assert_eq!(
            code(tonic::Status::unknown("insufficient local balance")),
            INSUFFICIENT_BALANCE
        );
        assert_eq!(
            code(tonic::Status::unavailable("transport error")),
            PAYMENT_FAILED
        );
        assert_eq!(
            send_payment_error(&anyhow!("stream ended"), "Failed").code,
            PAYMENT_FAILED
        );
    }

    #[test]
    fn detects_lnd_lookup_and_permission_errors() {
        assert!(is_invoice_not_found(&tonic::Status::not_found(
            "unable to locate invoice"
        )));
        assert!(is_invoice_not_found(&tonic::Status::unknown(
            "unable to locate invoice"
        )));
        assert!(!is_invoice_not_found(&tonic::Status::unavailable("down")));

        assert!(is_permission_denied(&tonic::Status::unknown(
            "permission denied"
        )));
        assert!(!is_permission_denied(&tonic::Status::unavailable("down")));
    }

    #[test]
    fn builds_outgoing_lookup_response() {
        let settled = Payment {
            payment_hash: "ab".repeat(32),
            value_msat: 21_000,
            fee_msat: 1_000,
            payment_preimage: "cd".repeat(32),
            status: PaymentStatus::Succeeded as i32,
            creation_time_ns: 1_700_000_000_500_000_000,
            htlcs: vec![tonic_openssl_lnd::lnrpc::HtlcAttempt {
                status: HtlcStatus::Succeeded as i32,
                resolve_time_ns: 1_700_000_010_000_000_000,
                ..Default::default()
            }],
            ..Default::default()
        };

        let response = outgoing_lookup_response(&settled);
        assert_eq!(response.transaction_type, Some(TransactionType::Outgoing));
        assert_eq!(response.state, Some(TransactionState::Settled));
        assert_eq!(response.payment_hash, "ab".repeat(32));
        assert_eq!(response.preimage, Some("cd".repeat(32)));
        assert_eq!(response.amount, 21_000);
        assert_eq!(response.fees_paid, 1_000);
        assert_eq!(response.created_at, Timestamp::from_secs(1_700_000_000));
        assert_eq!(
            response.settled_at,
            Some(Timestamp::from_secs(1_700_000_010))
        );
        assert_eq!(response.invoice, None);

        let failed = Payment {
            payment_preimage: "0".repeat(64),
            status: PaymentStatus::Failed as i32,
            ..Default::default()
        };
        let response = outgoing_lookup_response(&failed);
        assert_eq!(response.state, Some(TransactionState::Failed));
        assert_eq!(response.preimage, None);
        assert_eq!(response.settled_at, None);

        let pending = Payment {
            status: PaymentStatus::InFlight as i32,
            ..Default::default()
        };
        let response = outgoing_lookup_response(&pending);
        assert_eq!(response.state, Some(TransactionState::Pending));
    }

    #[test]
    fn info_event_advertises_encryption_schemes() {
        let config = Config::try_parse_from(["nwc-lnd", "--relay", "wss://relay.example"]).unwrap();
        let keys = Nip47Keys::generate();

        let event = info_event(&config, &keys).unwrap();

        assert_eq!(event.kind, Kind::WalletConnectInfo);
        assert!(event
            .tags
            .iter()
            .any(|tag| tag.as_slice() == ["encryption", "nip44_v2 nip04"]));
    }

    #[test]
    fn detects_request_encryption_scheme() {
        let keys = Nip47Keys::generate();
        let user_pubkey = keys.user_keys().public_key();
        let content = r#"{"method":"get_balance","params":{}}"#;

        let encrypted = nip04::encrypt(&keys.server_key, &user_pubkey, content).unwrap();
        let (decrypted, scheme) = decrypt_request_content(&keys, &encrypted).unwrap();
        assert_eq!(decrypted, content);
        assert!(matches!(scheme, Encryption::Nip04));

        let encrypted =
            nip44::encrypt(&keys.server_key, &user_pubkey, content, nip44::Version::V2).unwrap();
        let (decrypted, scheme) = decrypt_request_content(&keys, &encrypted).unwrap();
        assert_eq!(decrypted, content);
        assert!(matches!(scheme, Encryption::Nip44));
    }

    #[test]
    fn encrypts_responses_with_the_request_scheme() {
        let keys = Nip47Keys::generate();
        let content = r#"{"result_type":"get_balance"}"#;

        for scheme in [Encryption::Nip04, Encryption::Nip44] {
            let encrypted = encrypt_content(scheme, &keys, content).unwrap();
            let (decrypted, detected) = decrypt_request_content(&keys, &encrypted).unwrap();
            assert_eq!(decrypted, content);
            assert!(matches!(
                (scheme, detected),
                (Encryption::Nip04, Encryption::Nip04) | (Encryption::Nip44, Encryption::Nip44)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn writes_keys_file_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("nwc-keys-test-{}", std::process::id()));
        let path = dir.join("keys.json");
        write_keys(Nip47Keys::generate(), &path);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_legacy_key_files_with_sent_info() {
        let expected = Nip47Keys::generate();
        let mut legacy = serde_json::to_value(&expected).unwrap();
        legacy["sent_info"] = Value::Bool(true);

        let actual: Nip47Keys = serde_json::from_value(legacy).unwrap();

        assert_eq!(
            actual.server_key.to_secret_hex(),
            expected.server_key.to_secret_hex()
        );
        assert_eq!(
            actual.user_key.to_secret_hex(),
            expected.user_key.to_secret_hex()
        );
    }
}
