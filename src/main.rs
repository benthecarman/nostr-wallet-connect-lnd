use std::fs::{create_dir_all, File};
use std::io::{BufReader, Write};
use std::path::Path;
use bitcoin::hashes::hex::ToHex;
use clap::Parser;
use lightning_invoice::Invoice;
use nostr::Keys;
use tonic_openssl_lnd::lnrpc::payment::PaymentStatus;
use nostr::prelude::*;
use nostr_sdk::Client;
use nostr_sdk::relay::pool::RelayPoolNotification::*;
use serde_json::json;
use tonic_openssl_lnd::LndRouterClient;
use tonic_openssl_lnd::lnrpc::{GetInfoRequest, GetInfoResponse, PaymentFailureReason};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::nip47::Nip47Request;

mod config;
mod nip47;

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

	let client = Client::new(&keys.server_keys());
	client.add_relay(&config.relay, None).await?;

	client.connect().await;

	// broadcast info event
	let info = EventBuilder::new(Kind::Custom(13194), "pay_invoice".to_string(), &[]).to_event(&keys.server_keys())?;

	client.send_event(info).await?;
	let nip47_request_kind = Kind::Custom(23194);
	let subscription = Filter::new()
		.kinds(vec![nip47_request_kind])
		.author(keys.user_keys().public_key())
		.pubkey(keys.server_keys().public_key())
		.since(Timestamp::now());

	client.subscribe(vec![subscription]).await;

	println!("Listening for nip 47 requests...");
	println!();
	let encoded_relay = urlencoding::encode(&config.relay);
	println!("nostr+walletconnect:{}?relay={}&secret={}", keys.server_keys().public_key().to_hex(), &encoded_relay, keys.user_key.secret_bytes().to_hex());


	let mut notifications = client.notifications();
	while let Ok(notification) = notifications.recv().await {
		if let Event(_url, event) = notification {
			if event.kind == nip47_request_kind && event.pubkey == keys.user_keys().public_key() {
				let decrypted = decrypt(&keys.server_key, &keys.user_keys().public_key(), &event.content).unwrap();
				let req: Nip47Request = serde_json::from_str(&decrypted).unwrap();

				let amount = req.params.invoice.amount_milli_satoshis().unwrap_or(0);

				// verify amount, convert to msats
				if amount <= config.max_amount * 1_000 {
					print!("Paying invoice: {}...", req.params.invoice);
					let router_client = lnd_client.router().clone();
					if let Err(e) = pay_invoice(req.params.invoice, keys.user_keys().public_key(), event.id, &keys.server_keys(), &client, router_client).await {
						eprintln!("failed to pay invoice: {e}");
					}
				} else {
					println!("Invoice amount too high: {}", amount);

					let content = json!({
						"result_type": "pay_invoice",
						"result": {
							"code": "QUOTA_EXCEEDED",
							"error": "Invoice amount too high."
						}
					});
					let encrypted = encrypt(&keys.server_key, &keys.user_keys().public_key(), &content.to_string()).unwrap();
					let p_tag = Tag::PubKey(event.pubkey, None);
					let e_tag = Tag::Event(event.id, None, None);
					let response = EventBuilder::new(Kind::Custom(23195), encrypted, &[p_tag, e_tag])
						.to_event(&keys.server_keys())?;

					client.send_event(response).await?;
				}
			}
		}
	}

	Ok(())
}

async fn pay_invoice(
	ln_invoice: Invoice,
	user_key: XOnlyPublicKey,
	event_id: EventId,
	server_keys: &Keys,
	client: &Client,
	mut router: LndRouterClient,
) -> anyhow::Result<()> {
	println!("paying invoice: {ln_invoice}");

	let req = tonic_openssl_lnd::routerrpc::SendPaymentRequest {
		payment_request: ln_invoice.to_string(),
		no_inflight_updates: true,
		time_pref: 0.9,
		..Default::default()
	};

	let mut stream = router.send_payment_v2(req).await?.into_inner();

	if let Some(payment) = stream.message().await.ok().flatten() {
		let content = if let Some(PaymentStatus::Succeeded) = PaymentStatus::from_i32(payment.status) {
			println!("paid invoice: {}", ln_invoice.payment_hash().to_hex());

			let preimage = payment.payment_preimage;
			let json = json!({
				"result_type": "pay_invoice",
				"result": {
					"preimage": preimage
				}
			});

			json.to_string()
		} else {
			let error_msg = match PaymentFailureReason::from_i32(payment.failure_reason) {
				Some(PaymentFailureReason::FailureReasonNone) => "No error?",
				Some(PaymentFailureReason::FailureReasonTimeout) => "Payment timeout.",
				Some(PaymentFailureReason::FailureReasonNoRoute) => "No route found.",
				Some(PaymentFailureReason::FailureReasonError) => "A non-recoverable error has occurred.",
				Some(PaymentFailureReason::FailureReasonIncorrectPaymentDetails) => "Incorrect payment details.",
				Some(PaymentFailureReason::FailureReasonInsufficientBalance) => "Insufficient balance.",
				None => "Unknown error.",
			};
			let json = json!({
				"result_type": "pay_invoice",
				"error": {
					"code": "INSUFFICIENT_BALANCE",
					"message": error_msg
				}
			});

			json.to_string()
		};

		let encrypted = encrypt(&server_keys.secret_key().unwrap(), &user_key, &content).unwrap();
		let p_tag = Tag::PubKey(user_key, None);
		let e_tag = Tag::Event(event_id, None, None);
		let response = EventBuilder::new(Kind::Custom(23195), encrypted, &[p_tag, e_tag])
			.to_event(server_keys)?;

		client.send_event(response).await?;
		return Ok(());
	}

	Err(anyhow!("Failed to handle invoice"))
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
			serde_json::from_reader(reader).expect("Could not parse JSON")
		}
		Err(_) => {
			let keys = Nip47Keys::generate();
			let json_str = serde_json::to_string(&keys).expect("Could not serialize data");

			if let Some(parent) = path.parent() {
				create_dir_all(parent).expect("Could not create directory");
			}

			let mut file = File::create(path).expect("Could not create file");
			file.write_all(json_str.as_bytes()).expect("Could not write to file");

			keys
		}
	}
}
