use crate::config::Config;
use crate::payments::PaymentTracker;
use anyhow::anyhow;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha256, Hash};
use clap::Parser;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription};
use nostr::nips::nip47::{
    ErrorCode, GetBalanceResponseResult, LookupInvoiceResponseResult, MakeInvoiceResponseResult,
    Method, NIP47Error, NostrWalletConnectURI, PayInvoiceResponseResult, Request, RequestParams,
    Response, ResponseResult,
};
use nostr::prelude::*;
use nostr::Keys;
use nostr_sdk::{Client, RelayPoolNotification};
use secp256k1::rand::rngs::OsRng;
use secp256k1::{SecretKey, ThirtyTwoByteHash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::io::{BufReader, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{oneshot, Mutex};
use tokio::{select, spawn};
use tonic_openssl_lnd::lnrpc::{GetInfoRequest, GetInfoResponse, Invoice, PaymentHash};
use tonic_openssl_lnd::{LndClient, LndLightningClient};

mod config;
mod payments;

const METHODS: [Method; 6] = [
    Method::GetInfo,
    Method::MakeInvoice,
    Method::GetBalance,
    Method::LookupInvoice,
    Method::PayInvoice,
    Method::PayKeysend,
];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config: Config = Config::parse();
    let keys = get_keys(&config.keys_file);

    let mut lnd_client = tonic_openssl_lnd::connect(
        config.lnd_host.clone(),
        config.lnd_port,
        config.cert_file(),
        config.macaroon_file(),
    )
    .await
    .expect("failed to connect");

    let mut ln_client = lnd_client.lightning().clone();
    let lnd_info: GetInfoResponse = ln_client
        .get_info(GetInfoRequest {})
        .await
        .expect("Failed to get lnd info")
        .into_inner();

    println!("Connected to lnd: {}", lnd_info.identity_pubkey);

    let uri = NostrWalletConnectURI::new(
        keys.server_keys().public_key(),
        config.relay.parse()?,
        keys.user_key.into(),
        None,
    );
    println!("\n{uri}\n");

    println!("server pubkey: {}", keys.user_keys().public_key());

    // Set up a oneshot channel to handle shutdown signal
    let (tx, rx) = oneshot::channel();

    // Spawn a task to listen for shutdown signals
    spawn(async move {
        let mut term_signal = signal(SignalKind::terminate())
            .map_err(|e| eprintln!("failed to install TERM signal handler: {e}"))
            .unwrap();
        let mut int_signal = signal(SignalKind::interrupt())
            .map_err(|e| {
                eprintln!("failed to install INT signal handler: {e}");
            })
            .unwrap();

        select! {
            _ = term_signal.recv() => {
                println!("Received SIGTERM");
            },
            _ = int_signal.recv() => {
                println!("Received SIGINT");
            },
        }

        let _ = tx.send(());
    });

    let active_requests = Arc::new(Mutex::new(vec![]));
    let active_requests_clone = active_requests.clone();
    spawn(async move {
        if let Err(e) = event_loop(config, keys, lnd_client, active_requests_clone).await {
            eprintln!("Error: {e}");
        }
    });

    rx.await?;

    println!("Shutting down...");
    // wait for active requests to complete
    loop {
        let active_requests = active_requests.clone();
        let requests = active_requests.lock().await;
        if requests.is_empty() {
            break;
        }
        println!("Waiting for {} requests to complete...", requests.len());
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

async fn event_loop(
    config: Config,
    mut keys: Nip47Keys,
    mut lnd_client: LndClient,
    active_requests: Arc<Mutex<Vec<EventId>>>,
) -> anyhow::Result<()> {
    let tracker = Arc::new(Mutex::new(PaymentTracker::new()));
    // loop in case we get disconnected
    loop {
        let client = Client::new(&keys.server_keys());
        client.add_relay(config.relay.as_str()).await?;

        client.connect().await;

        // broadcast info event
        if !keys.sent_info {
            let content: String = METHODS
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            let info = EventBuilder::new(Kind::WalletConnectInfo, content, [])
                .to_event(&keys.server_keys())?;
            client.send_event(info).await?;

            keys.sent_info = true;
            write_keys(keys.clone(), Path::new(&config.keys_file));
        }

        let subscription = Filter::new()
            .kinds(vec![Kind::WalletConnectRequest])
            .author(keys.user_keys().public_key())
            .pubkey(keys.server_keys().public_key())
            .since(Timestamp::now());

        client.subscribe(vec![subscription]).await;

        println!("Listening for nip 47 requests...");

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
                                println!("Received event!");
                                let active_requests = active_requests.clone();
                                let keys = keys.clone();
                                let config = config.clone();
                                let client = client.clone();
                                let tracker = tracker.clone();
                                let lnd = lnd_client.lightning().clone();

                                tokio::task::spawn(async move {
                                    let event_id = event.id;
                                    let mut ar = active_requests.lock().await;
                                    ar.push(event_id);
                                    drop(ar);

                                    if let Err(e) = tokio::time::timeout(
                                        Duration::from_secs(60),
                                        handle_nwc_request(event, &keys, &config, &client, tracker, lnd),
                                    )
                                    .await
                                    {
                                        eprintln!("Error: {e}");
                                    }

                                    // remove request from active requests
                                    let mut ar = active_requests.lock().await;
                                    ar.retain(|id| *id != event_id);
                                });
                            } else {
                                eprintln!("Invalid event: {}", event.as_json());
                            }
                        }
                        RelayPoolNotification::Shutdown => {
                            println!("Relay pool shutdown");
                            break;
                        }
                        _ => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(3600)) => {
                    break;
                }
            }
        }

        client.disconnect().await?;
    }
}

async fn handle_nwc_request(
    event: Event,
    keys: &Nip47Keys,
    config: &Config,
    client: &Client,
    tracker: Arc<Mutex<PaymentTracker>>,
    mut lnd: LndLightningClient,
) -> anyhow::Result<()> {
    let decrypted = nip04::decrypt(
        &keys.server_key.into(),
        &keys.user_keys().public_key(),
        &event.content,
    )?;
    let req: Request = Request::from_json(&decrypted)?;

    let content = match req.params {
        RequestParams::PayInvoice(params) => {
            let invoice = Bolt11Invoice::from_str(&params.invoice)
                .map_err(|_| anyhow!("Failed to parse invoice"))?;
            let msats = invoice
                .amount_milli_satoshis()
                .or(params.amount)
                .unwrap_or(0);

            let error_msg = if msats > config.max_amount * 1_000 {
                Some("Invoice amount too high.")
            } else if tracker.lock().await.sum_payments() + msats > config.daily_limit * 1_000 {
                Some("Daily limit exceeded.")
            } else {
                None
            };

            // verify amount, convert to msats
            match error_msg {
                None => {
                    match pay_invoice(invoice, lnd).await {
                        Ok(content) => {
                            // add payment to tracker
                            tracker.lock().await.add_payment(msats);
                            content
                        }
                        Err(e) => {
                            eprintln!("Error paying invoice: {e}");

                            Response {
                                result_type: Method::PayInvoice,
                                error: Some(NIP47Error {
                                    code: ErrorCode::InsufficientBalance,
                                    message: format!("Failed to pay invoice: {e}"),
                                }),
                                result: None,
                            }
                        }
                    }
                }
                Some(err_msg) => Response {
                    result_type: Method::PayInvoice,
                    error: Some(NIP47Error {
                        code: ErrorCode::QuotaExceeded,
                        message: err_msg.to_string(),
                    }),
                    result: None,
                },
            }
        }
        RequestParams::PayKeysend(params) => {
            let msats = params.amount;
            let error_msg = if msats > config.max_amount * 1_000 {
                Some("Invoice amount too high.")
            } else if tracker.lock().await.sum_payments() + msats > config.daily_limit * 1_000 {
                Some("Daily limit exceeded.")
            } else {
                None
            };

            // verify amount, convert to msats
            match error_msg {
                None => {
                    let pubkey = secp256k1::PublicKey::from_str(&params.pubkey)?;
                    match pay_keysend(pubkey, params.preimage, params.tlv_records, msats, lnd).await
                    {
                        Ok(content) => {
                            // add payment to tracker
                            tracker.lock().await.add_payment(msats);
                            content
                        }
                        Err(e) => {
                            eprintln!("Error paying invoice: {e}");

                            Response {
                                result_type: Method::PayInvoice,
                                error: Some(NIP47Error {
                                    code: ErrorCode::InsufficientBalance,
                                    message: format!("Failed to pay invoice: {e}"),
                                }),
                                result: None,
                            }
                        }
                    }
                }
                Some(err_msg) => Response {
                    result_type: Method::PayInvoice,
                    error: Some(NIP47Error {
                        code: ErrorCode::QuotaExceeded,
                        message: err_msg.to_string(),
                    }),
                    result: None,
                },
            }
        }
        RequestParams::MakeInvoice(params) => {
            let description_hash: Vec<u8> = match params.description_hash {
                None => vec![],
                Some(str) => FromHex::from_hex(&str)?,
            };
            let inv = Invoice {
                memo: params.description.unwrap_or_default(),
                description_hash,
                value_msat: params.amount as i64,
                expiry: params.expiry.unwrap_or(86_400) as i64,
                ..Default::default()
            };
            let res = lnd.add_invoice(inv).await?.into_inner();
            Response {
                result_type: Method::MakeInvoice,
                error: None,
                result: Some(ResponseResult::MakeInvoice(MakeInvoiceResponseResult {
                    invoice: res.payment_request,
                    payment_hash: ::hex::encode(res.r_hash),
                })),
            }
        }
        RequestParams::LookupInvoice(params) => {
            let mut invoice: Option<Bolt11Invoice> = None;
            let payment_hash: Vec<u8> = match params.payment_hash {
                None => match params.bolt11 {
                    None => return Err(anyhow!("Missing payment_hash or bolt11")),
                    Some(bolt11) => {
                        let inv = Bolt11Invoice::from_str(&bolt11)
                            .map_err(|_| anyhow!("Failed to parse invoice"))?;
                        invoice = Some(inv.clone());
                        inv.payment_hash().into_32().to_vec()
                    }
                },
                Some(str) => FromHex::from_hex(&str)?,
            };

            let res = lnd
                .lookup_invoice(PaymentHash {
                    r_hash: payment_hash.clone(),
                    ..Default::default()
                })
                .await?
                .into_inner();

            let (description, description_hash) = match invoice {
                Some(inv) => match inv.description() {
                    Bolt11InvoiceDescription::Direct(desc) => (Some(desc.to_string()), None),
                    Bolt11InvoiceDescription::Hash(hash) => (None, Some(hash.0.to_string())),
                },
                None => (None, None),
            };

            let preimage = if res.r_preimage.is_empty() {
                None
            } else {
                Some(hex::encode(res.r_preimage))
            };

            let settled_at = if res.settle_date == 0 {
                None
            } else {
                Some(res.settle_date as u64)
            };

            Response {
                result_type: Method::LookupInvoice,
                error: None,
                result: Some(ResponseResult::LookupInvoice(LookupInvoiceResponseResult {
                    transaction_type: None,
                    invoice: Some(res.payment_request),
                    description,
                    description_hash,
                    preimage,
                    payment_hash: hex::encode(payment_hash),
                    amount: res.value_msat as u64,
                    fees_paid: 0,
                    created_at: res.creation_date as u64,
                    expires_at: (res.creation_date + res.expiry) as u64,
                    settled_at,
                    metadata: Default::default(),
                })),
            }
        }
        RequestParams::GetBalance => {
            let tracker = tracker.lock().await.sum_payments();
            let remaining_msats = (config.daily_limit * 1_000 - tracker) / 1_000;
            Response {
                result_type: Method::GetBalance,
                error: None,
                result: Some(ResponseResult::GetBalance(GetBalanceResponseResult {
                    balance: remaining_msats * 1_000,
                })),
            }
        }
        RequestParams::GetInfo => {
            let lnd_info: GetInfoResponse = lnd.get_info(GetInfoRequest {}).await?.into_inner();
            Response {
                result_type: Method::GetBalance,
                error: None,
                result: Some(ResponseResult::GetInfo(GetInfoResponseResult {
                    alias: lnd_info.alias,
                    color: lnd_info.color,
                    pubkey: lnd_info.identity_pubkey,
                    network: "".to_string(),
                    block_height: lnd_info.block_height,
                    block_hash: lnd_info.block_hash,
                    methods: METHODS.iter().map(|i| i.to_string()).collect(),
                })),
            }
        }
        _ => {
            return Err(anyhow!("Command not supported"));
        }
    };

    let encrypted = nip04::encrypt(
        &keys.server_key.into(),
        &keys.user_keys().public_key(),
        content.as_json(),
    )?;
    let p_tag = Tag::public_key(event.pubkey);
    let e_tag = Tag::event(event.id);
    let response = EventBuilder::new(Kind::WalletConnectResponse, encrypted, [p_tag, e_tag])
        .to_event(&keys.server_keys())?;

    client.send_event(response).await?;

    Ok(())
}

async fn pay_invoice(
    ln_invoice: Bolt11Invoice,
    mut lnd: LndLightningClient,
) -> anyhow::Result<Response> {
    println!("paying invoice: {ln_invoice}");

    let req = tonic_openssl_lnd::lnrpc::SendRequest {
        payment_request: ln_invoice.to_string(),
        allow_self_payment: false,
        ..Default::default()
    };

    let response = lnd.send_payment_sync(req).await?.into_inner();

    let payment_error = if response.payment_error.is_empty() {
        None
    } else {
        Some(response.payment_error)
    };

    let response = match payment_error {
        None => {
            println!("paid invoice: {}", ln_invoice.payment_hash());

            let preimage = ::hex::encode(response.payment_preimage);
            Response {
                result_type: Method::PayInvoice,
                error: None,
                result: Some(ResponseResult::PayInvoice(PayInvoiceResponseResult {
                    preimage,
                })),
            }
        }
        Some(error_msg) => Response {
            result_type: Method::PayInvoice,
            error: Some(NIP47Error {
                code: ErrorCode::PaymentFailed,
                message: error_msg,
            }),
            result: None,
        },
    };

    Ok(response)
}

async fn pay_keysend(
    pubkey: secp256k1::PublicKey,
    preimage: Option<String>,
    tlv_records: Vec<KeysendTLVRecord>,
    amount_msats: u64,
    mut lnd: LndLightningClient,
) -> anyhow::Result<Response> {
    println!("paying keysend to {pubkey} for {amount_msats}msats");

    let mut dest_custom_records = tlv_records
        .into_iter()
        .map(|rec| Ok((rec.tlv_type, FromHex::from_hex(&rec.value)?)))
        .collect::<Result<HashMap<u64, Vec<u8>>, anyhow::Error>>()?;

    let payment_hash: sha256::Hash = match preimage {
        None => match dest_custom_records.get(&5482373484) {
            None => {
                let preimage = SecretKey::new(&mut OsRng).secret_bytes();
                dest_custom_records.insert(5482373484, preimage.to_vec());
                sha256::Hash::hash(&preimage)
            }
            Some(preimage) => sha256::Hash::hash(preimage),
        },
        Some(preimage) => {
            let preimage: [u8; 32] = FromHex::from_hex(&preimage)?;
            dest_custom_records.insert(5482373484, preimage.to_vec());
            sha256::Hash::hash(&preimage)
        }
    };

    let req = tonic_openssl_lnd::lnrpc::SendRequest {
        dest: pubkey.serialize().to_vec(),
        amt_msat: amount_msats as i64,
        allow_self_payment: false,
        payment_hash: payment_hash.into_32().to_vec(),
        ..Default::default()
    };

    let response = lnd.send_payment_sync(req).await?.into_inner();

    let payment_error = if response.payment_error.is_empty() {
        None
    } else {
        Some(response.payment_error)
    };

    let response = match payment_error {
        None => {
            println!("paid keysend to {pubkey} for {amount_msats}msats");

            let preimage = ::hex::encode(response.payment_preimage);
            Response {
                result_type: Method::PayKeysend,
                error: None,
                result: Some(ResponseResult::PayKeysend(PayKeysendResponseResult {
                    preimage,
                })),
            }
        }
        Some(error_msg) => Response {
            result_type: Method::PayKeysend,
            error: Some(NIP47Error {
                code: ErrorCode::PaymentFailed,
                message: error_msg,
            }),
            result: None,
        },
    };

    Ok(response)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Nip47Keys {
    server_key: secp256k1::SecretKey,
    user_key: secp256k1::SecretKey,
    #[serde(default)]
    sent_info: bool,
}

impl Nip47Keys {
    fn generate() -> Self {
        let server_key = Keys::generate();
        let user_key = Keys::generate();

        Nip47Keys {
            server_key: **server_key.secret_key().unwrap(),
            user_key: **user_key.secret_key().unwrap(),
            sent_info: false,
        }
    }

    fn server_keys(&self) -> Keys {
        Keys::new(self.server_key.into())
    }

    fn user_keys(&self) -> Keys {
        Keys::new(self.user_key.into())
    }
}

fn get_keys(keys_file: &str) -> Nip47Keys {
    let path = Path::new(keys_file);
    match File::open(path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            serde_json::from_reader(reader).expect("Could not parse JSON")
        }
        Err(_) => {
            let keys = Nip47Keys::generate();
            write_keys(keys, path)
        }
    }
}

fn write_keys(keys: Nip47Keys, path: &Path) -> Nip47Keys {
    let json_str = serde_json::to_string(&keys).expect("Could not serialize data");

    if let Some(parent) = path.parent() {
        create_dir_all(parent).expect("Could not create directory");
    }

    let mut file = File::create(path).expect("Could not create file");
    file.write_all(json_str.as_bytes())
        .expect("Could not write to file");

    keys
}
