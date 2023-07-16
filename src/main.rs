use crate::config::Config;
use crate::payments::PaymentTracker;
use anyhow::anyhow;
use bitcoin::hashes::hex::ToHex;
use clap::Parser;
use lightning_invoice::Invoice;
use nostr::nips::nip47::{
    ErrorCode, Method, NIP47Error, NostrWalletConnectURI, Request, Response, ResponseResult,
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
use tokio::sync::Mutex;
use tonic_openssl_lnd::lnrpc::{GetInfoRequest, GetInfoResponse};
use tonic_openssl_lnd::LndLightningClient;

mod config;
mod payments;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config: Config = Config::parse();
    let keys = get_keys(&config.keys_file);
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

    let mut broadcasted_info = false;

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
        client.add_relay(&config.relay, None).await?;

        client.connect().await;

        // broadcast info event
        if !broadcasted_info {
            let info = EventBuilder::new(Kind::WalletConnectInfo, "pay_invoice".to_string(), &[])
                .to_event(&keys.server_keys())?;
            client.send_event(info).await?;

            broadcasted_info = true;
        }

        let subscription = Filter::new()
            .kinds(vec![Kind::WalletConnectRequest])
            .author(keys.user_keys().public_key().to_hex())
            .pubkey(keys.server_keys().public_key())
            .since(Timestamp::now());

        client.subscribe(vec![subscription]).await;

        println!("Listening for nip 47 requests...");

        let mut notifications = client.notifications();
        while let Ok(notification) = notifications.recv().await {
            if let RelayPoolNotification::Event(_url, event) = notification {
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
                        if let Err(e) =
                            handle_nwc_request(event, &keys, &config, &client, tracker, lnd).await
                        {
                            eprintln!("Error: {e}");
                        }
                    });
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
    lnd: LndLightningClient,
) -> anyhow::Result<()> {
    let decrypted = decrypt(
        &keys.server_key,
        &keys.user_keys().public_key(),
        &event.content,
    )?;
    let req: Request = Request::from_json(&decrypted)?;

    // only pay invoice requests
    if req.method != Method::PayInvoice {
        return Ok(());
    }

    let invoice =
        Invoice::from_str(&req.params.invoice).map_err(|_| anyhow!("Failed to parse invoice"))?;
    let msats = invoice.amount_milli_satoshis().unwrap_or(0);

    let error_msg = if msats > config.max_amount * 1_000 {
        Some("Invoice amount too high.")
    } else if tracker.lock().await.sum_payments() + msats > config.daily_limit * 1_000 {
        Some("Daily limit exceeded.")
    } else {
        None
    };

    // verify amount, convert to msats
    let content = match error_msg {
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
                            code: ErrorCode::InsufficantBalance,
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

async fn pay_invoice(ln_invoice: Invoice, mut lnd: LndLightningClient) -> anyhow::Result<Response> {
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
                result: Some(ResponseResult { preimage }),
            }
        }
        Some(error_msg) => Response {
            result_type: Method::PayInvoice,
            error: Some(NIP47Error {
                code: ErrorCode::InsufficantBalance,
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
}

impl Nip47Keys {
    fn generate() -> Self {
        let server_key = Keys::generate();
        let user_key = Keys::generate();

        Nip47Keys {
            server_key: server_key.secret_key().unwrap(),
            user_key: user_key.secret_key().unwrap(),
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
            let json_str = to_string(&keys).expect("Could not serialize data");

            if let Some(parent) = path.parent() {
                create_dir_all(parent).expect("Could not create directory");
            }

            let mut file = File::create(path).expect("Could not create file");
            file.write_all(json_str.as_bytes())
                .expect("Could not write to file");

            keys
        }
    }
}
