# Nostr Wallet Connect for LND

This lets you use nostr wallet connect with your LND node.

## Install

```bash
cargo build --release
cargo install --path .
```

## Usage

```bash
nostr-wallet-connect-lnd --relay wss://relay.damus.io --lnd-host localhost --lnd-port 10009 --macaroon-file ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon --cert-file ~/.lnd/tls.cert
```

This will print a wallet connect uri to the console. Scan this with your wallet connect enabled wallet.
You may need to use a tool to turn the uri into a QR code.

## BIP-321 support

The service advertises and supports the optional NWC `pay` and `receive` methods from
[NWC-321](https://github.com/nostr-wallet-connect/nwc/pull/2).

- `pay` selects and pays a BOLT11 `lightning` instruction from a BIP-321 URI.
- `receive` creates a `bitcoin:?lightning=...` BIP-321 URI.

BOLT12 `lno` instructions are not supported by this LND backend.
