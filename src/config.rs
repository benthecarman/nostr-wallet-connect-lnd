use bitcoin::Network;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(version, author, about)]
/// A NIP 47 tool
pub struct Config {
    #[clap(default_value_t = String::from("keys.json"), long)]
    /// Location of keys file
    pub keys_file: String,
    #[clap(long)]
    /// Relay to use for communicating
    pub relay: String,
    /// Max invoice payment amount, in satoshis
    #[clap(default_value_t = 100_000, long)]
    pub max_amount: u64,
    /// Max payment amount per day, in satoshis
    #[clap(default_value_t = 100_000, long)]
    pub daily_limit: u64,
    #[clap(default_value_t = String::from("127.0.0.1"), long)]
    /// Host of the GRPC server for lnd
    pub lnd_host: String,
    #[clap(default_value_t = 10009, long)]
    /// Port of the GRPC server for lnd
    pub lnd_port: u32,
    #[clap(default_value_t = Network::Bitcoin, short, long)]
    /// Network lnd is running on ["bitcoin", "testnet", "signet, "regtest"]
    pub network: Network,
    #[clap(long)]
    /// Path to tls.cert file for lnd
    cert_file: Option<String>,
    #[clap(long)]
    /// Path to admin.macaroon file for lnd
    macaroon_file: Option<String>,
}

impl Config {
    pub fn macaroon_file(&self) -> String {
        self.macaroon_file
            .clone()
            .unwrap_or_else(|| default_macaroon_file(&self.network))
    }

    pub fn cert_file(&self) -> String {
        self.cert_file.clone().unwrap_or_else(default_cert_file)
    }
}

fn home_directory() -> String {
    let buf = home::home_dir().expect("Failed to get home dir");
    let str = format!("{}", buf.display());

    // to be safe remove possible trailing '/' and
    // we can manually add it to paths
    match str.strip_suffix('/') {
        Some(stripped) => stripped.to_string(),
        None => str,
    }
}

pub fn default_cert_file() -> String {
    format!("{}/.lnd/tls.cert", home_directory())
}

pub fn default_macaroon_file(network: &Network) -> String {
    let network_str = match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    };

    format!(
        "{}/.lnd/data/chain/bitcoin/{}/admin.macaroon",
        home_directory(),
        network_str
    )
}
