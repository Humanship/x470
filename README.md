# x470 Proof-of-Human Required

A minimal HTTP-native protocol for verifying that a request was made by a human before serving protected data.



## HTTP status code

470 Proof-of-Human Required



When a client requests a protected resource, the server can respond with `470` and a JSON challenge describing how to prove humanness (e.g., signing a message with an attested key).

Once the client completes the challenge, it retries the request with the `Proof-Of-Human` header containing the proof object. 

If the proof is valid, the server grants access.

## Running it

First make sure to be running the server

```
cd server
npm i
node index.js
```

Then open the HTML file at `client/index.html`

## How does verification work?

We rely on Humanship ID's open protocol to generate Proof-Of-Human signatures, but can be expanded to any Proof-Of-Human protocol.

[Humanship ID](https://humanship.id) lets users verify their personhood through their phone in a trustless and decentralized way. Currently on closed beta, you can reach out on [@humanship_id](https://x.com/humanship_id) to get access to the Testflight app.

## Verification Construction

Verification part is working, but dummy at the moment, until the Humanship ID protocol is fully implemented in it, where we need to verify that a signature comes from a verified pubkey.

There are two ways to create the proof's signature:

- Either the proof was linked to a Solana wallet, having the wallet to sign the challenge
- Or the proof lives on the user's phone, where a challenge needs to be completed through a QR code scan (an ephemeral keypair can be generated, to keep signing challenges for a certain period of time)

## Humanship ID's SDK

This leads the starting point to generate QR codes and retrieve someone's proof from their device: [SDK](https://github.com/Humanship/sdk).
