# Nostr Wallet Connect for LND

This lets you use nostr wallet connect with your LND node.

## Install

```bash
cargo build --release
cargo install --path .
```

## Usage

```bash
nostr-wallet-connect-lnd --relay wss://relay.damus.io --lnd-host localhost --lnd-port 10009 --macaroon-file ~/.lnd/nwc.macaroon --cert-file ~/.lnd/tls.cert
```

This will print a wallet connect uri to the console. Scan this with your wallet connect enabled wallet.
You may need to use a tool to turn the uri into a QR code.

Outgoing payments use a maximum routing fee of 1,000 satoshis by default. Set a
different limit with `--max-fee <SATS>`.

## Macaroon permissions

Do not use `admin.macaroon`. It gives full control of your node. Bake a custom
macaroon that has only the permissions this tool needs:

```bash
lncli bakemacaroon --save_to=~/.lnd/nwc.macaroon \
  uri:/lnrpc.Lightning/GetInfo \
  uri:/lnrpc.Lightning/AddInvoice \
  uri:/lnrpc.Lightning/LookupInvoice \
  uri:/lnrpc.Lightning/ChannelBalance \
  uri:/routerrpc.Router/SendPaymentV2 \
  uri:/routerrpc.Router/TrackPaymentV2
```

`TrackPaymentV2` lets `lookup_invoice` find outgoing payments.

For a receive-only setup, use `--invoice-macaroon-file` with the `invoice.macaroon`
that lnd creates. Send permissions are then disabled.

## BIP-321 support

The service advertises and supports the optional NWC `pay` and `receive` methods from
[NWC-321](https://github.com/nostr-wallet-connect/nwc/pull/2).

- `pay` selects and pays a BOLT11 `lightning` instruction from a BIP-321 URI.
- `receive` creates a `bitcoin:?lightning=...` BIP-321 URI.

BOLT12 `lno` instructions are not supported by this LND backend.
