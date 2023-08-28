use crate::config::Config;
use crate::payments::PaymentTracker;
use anyhow::anyhow;
use bitcoin::hashes::hex::{FromHex, ToHex};
use clap::Parser;
use lightning_invoice::Bolt11Invoice;
use nostr::nips::nip47::{
    BudgetType, ErrorCode, GetBalanceResponseResult, LookupInvoiceResponseResult,
    MakeInvoiceResponseResult, Method, NIP47Error, NostrWalletConnectURI, PayInvoiceResponseResult,
    Request, RequestParams, Response, ResponseResult,
};
use nostr::prelude::*;
use nostr::Keys;
use nostr_sdk::{Client, RelayPoolNotification};
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, File};
use std::io::{BufReader, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::sync::Mutex;
use tonic_openssl_lnd::lnrpc::invoice::InvoiceState;
use tonic_openssl_lnd::lnrpc::{
    ChannelBalanceRequest, GetInfoRequest, GetInfoResponse, Invoice, PaymentHash,
};
use tonic_openssl_lnd::LndLightningClient;

mod config;
mod payments;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config: Config = Config::parse();
    let mut keys = get_keys(&config.keys_file);
    let tracker = Arc::new(Mutex::new(PaymentTracker::new()));

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

    let mut broadcasted_info = keys.sent_info;

    let uri = NostrWalletConnectURI::new(
        keys.server_keys().public_key(),
        config.relay.parse()?,
        Some(keys.user_key),
        None,
    )?;
    println!("\n{uri}\n");

    // loop in case we get disconnected
    loop {
        let client = Client::new(&keys.server_keys());
        client.add_relay(config.relay.as_str(), None).await?;

        client.connect().await;

        // broadcast info event
        if !broadcasted_info {
            let info = EventBuilder::new(
                Kind::WalletConnectInfo,
                "pay_invoice make_invoice lookup_invoice get_balance".to_string(),
                &[],
            )
            .to_event(&keys.server_keys())?;
            client.send_event(info).await?;

            broadcasted_info = true;
            keys.sent_info = true;
            write_keys(keys.clone(), Path::new(&config.keys_file));
        }

        let subscription = Filter::new()
            .kinds(vec![Kind::WalletConnectRequest])
            .author(keys.user_keys().public_key().to_hex())
            .pubkey(keys.server_keys().public_key())
            .since(Timestamp::now());

        client.subscribe(vec![subscription]).await;

        println!("Listening for nip 47 requests...");

        let mut notifications = client.notifications();
        loop {
            select! {
                Ok(notification) = notifications.recv() => {
                    match notification {
                        RelayPoolNotification::Event(_url, event) => {
                            if event.kind == Kind::WalletConnectRequest
                                && event.pubkey == keys.user_keys().public_key()
                                && event.verify().is_ok()
                            {
                                let keys = keys.clone();
                                let config = config.clone();
                                let client = client.clone();
                                let tracker = tracker.clone();
                                let lnd = lnd_client.lightning().clone();
                                tokio::task::spawn(async move {
                                    if let Err(e) = tokio::time::timeout(
                                        Duration::from_secs(60),
                                        handle_nwc_request(event, &keys, &config, &client, tracker, lnd),
                                    )
                                    .await
                                    {
                                        eprintln!("Error: {e}");
                                    }
                                });
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
    let decrypted = decrypt(
        &keys.server_key,
        &keys.user_keys().public_key(),
        &event.content,
    )?;
    let req: Request = Request::from_json(&decrypted)?;

    let content = match req.params {
        RequestParams::PayInvoice(params) => {
            let invoice = Bolt11Invoice::from_str(&params.invoice)
                .map_err(|_| anyhow!("Failed to parse invoice"))?;
            let msats = invoice.amount_milli_satoshis().unwrap_or(0);

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
        RequestParams::MakeInvoice(params) => {
            let description_hash: Vec<u8> = match params.description_hash {
                None => vec![],
                Some(str) => FromHex::from_hex(&str)?,
            };
            let inv = Invoice {
                memo: params.description.unwrap_or_default(),
                description_hash,
                value_msat: params.amount,
                expiry: params.expiry.unwrap_or(86_400),
                ..Default::default()
            };
            let res = lnd.add_invoice(inv).await?.into_inner();
            Response {
                result_type: Method::MakeInvoice,
                error: None,
                result: Some(ResponseResult::MakeInvoice(MakeInvoiceResponseResult {
                    invoice: res.payment_request,
                    payment_hash: res.r_hash.to_hex(),
                })),
            }
        }
        RequestParams::LookupInvoice(params) => {
            let payment_hash: Vec<u8> = match params.payment_hash {
                None => match params.bolt11 {
                    None => return Err(anyhow!("Missing payment_hash or bolt11")),
                    Some(bolt11) => {
                        let invoice = Bolt11Invoice::from_str(&bolt11)
                            .map_err(|_| anyhow!("Failed to parse invoice"))?;
                        invoice.payment_hash().to_vec()
                    }
                },
                Some(str) => FromHex::from_hex(&str)?,
            };

            let res = lnd
                .lookup_invoice(PaymentHash {
                    r_hash: payment_hash,
                    ..Default::default()
                })
                .await?
                .into_inner();
            Response {
                result_type: Method::LookupInvoice,
                error: None,
                result: Some(ResponseResult::LookupInvoice(LookupInvoiceResponseResult {
                    invoice: res.payment_request,
                    paid: InvoiceState::from_i32(res.state) == Some(InvoiceState::Settled),
                })),
            }
        }
        RequestParams::GetBalance => {
            let res = lnd
                .channel_balance(ChannelBalanceRequest::default())
                .await?
                .into_inner();
            let tracker = tracker.lock().await.sum_payments();
            let remaining_msats = (config.daily_limit * 1_000 - tracker) / 1_000;
            let max = remaining_msats.max(config.max_amount);
            Response {
                result_type: Method::GetBalance,
                error: None,
                result: Some(ResponseResult::GetBalance(GetBalanceResponseResult {
                    balance: res.local_balance.unwrap_or_default().sat,
                    max_amount: Some(max),
                    budget_renewal: Some(BudgetType::Daily),
                })),
            }
        }
    };

    let encrypted = encrypt(
        &keys.server_key,
        &keys.user_keys().public_key(),
        content.as_json(),
    )?;
    let p_tag = Tag::PubKey(event.pubkey, None);
    let e_tag = Tag::Event(event.id, None, None);
    let response = EventBuilder::new(Kind::WalletConnectResponse, encrypted, &[p_tag, e_tag])
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
            println!("paid invoice: {}", ln_invoice.payment_hash().to_hex());

            let preimage = response.payment_preimage.to_hex();
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
                code: ErrorCode::InsufficientBalance,
                message: error_msg,
            }),
            result: None,
        },
    };

    Ok(response)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Nip47Keys {
    server_key: SecretKey,
    user_key: SecretKey,
    #[serde(default)]
    sent_info: bool,
}

impl Nip47Keys {
    fn generate() -> Self {
        let server_key = Keys::generate();
        let user_key = Keys::generate();

        Nip47Keys {
            server_key: server_key.secret_key().unwrap(),
            user_key: user_key.secret_key().unwrap(),
            sent_info: false,
        }
    }

    fn server_keys(&self) -> Keys {
        Keys::new(self.server_key)
    }

    fn user_keys(&self) -> Keys {
        Keys::new(self.user_key)
    }
}

fn get_keys(keys_file: &str) -> Nip47Keys {
    let path = Path::new(keys_file);
    match File::open(path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            from_reader(reader).expect("Could not parse JSON")
        }
        Err(_) => {
            let keys = Nip47Keys::generate();
            write_keys(keys, path)
        }
    }
}

fn write_keys(keys: Nip47Keys, path: &Path) -> Nip47Keys {
    let json_str = to_string(&keys).expect("Could not serialize data");

    if let Some(parent) = path.parent() {
        create_dir_all(parent).expect("Could not create directory");
    }

    let mut file = File::create(path).expect("Could not create file");
    file.write_all(json_str.as_bytes())
        .expect("Could not write to file");

    keys
}
