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
