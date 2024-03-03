# Crunch

Lots of important Web2 data cannot be used on-chain because is private or access-controlled, which makes it impossible to access via traditional solutions like oracles. Normal Web2 clients trust the origin of this data because it is requested via HTTPS, but this is not enough to prove provenance to a third-party because the TLS client has enough information to forge the response.

# TLS Session Verification

Crunch is a research project and proof-of-concept addressing scalability shortcomings of existing MPC-based TLS verification schemes like TLSNotary and zkPass. Existing schemes are based on 2-party MPC protocols, limited to TLS 1.2's deprecated, non-AEAD ciphersuites. TLS verification requires an MPC ceremony which completes rapidly enough to prevent server timeouts, imposing a hard boundary on how far MPC-only techniques can scale.

Blockchain technology can easily produce groups of disinterested, economically-disincentivized-to-collude parties to participare in an MPC protocol, but the trustability of any MPC computation is limited by the number of parties who can efficiently participate. Our efforts are focused on reducing the cost of the MPC required, allowing more participants and therefore greater security. To do this, Crunch shifts as much of the security burden as possible from the MPC component to zero-knowledge Risc0 proofs.

## Structure

Crunch separates the proof process into a relatively lightweight MPC ceremony during the TLS session, followed a client-generated Risc0 proof. The MPC process handles handles just enough of the TLS 1.3 key schedule to allow the client to complete the session handshake and allow it to send an HTTP request. After receiving the response, but before receiving the keys to decrypt it, the client submits its hash for notarization and receives the remaining key material.

- `crunch` is a fake-it-till-you-make-it TLS client. It is capable of establishing a TLS handshake with a minimum of key material and collecting the data needed for the MPC ceremony as the session proceeds.
- `uncrunch` is a real TLS client with full key material over the session transcripts created by `crunch`. It runs as a Risc0 guest, proving that the TLS protocol was followed and hashing the plaintext data. 

`uncrunch` creates a Risc0 receipt with commitments to the server certificate, client request, and server response, but discloses no other information about the session. With this information, a simple parser can verify the plaintext data and disclose whichever properties about it are desired -- for example, disclosing the response body but keeping authentication tokens in the headers private. `uncrunch` executes in approximately 5 million cycles for a simple message. 

## Technical Details

Crunch's MPC component is designed for easy portability between MPC protocols and extension to various party sizes. This flexibility is possible because most computation is offloaded from the MPC domain to the `uncrunch` proof generated later by the client. A 3-party, maliciously-secure honest-majority implementation takes approximately 2.5 seconds to complete on an i7-10875H at 2.3GHz; greater security properties and larger party sizes are available with moderate latency increases.

Crunch targets TLS 1.3 with X25519 key exchange and the AES_128_GCM_SHA256 ciphersuite, which is a combination supported by most web servers. Our proof-of-concept implementation faithfully recreates the official sample TLS session transcript described in [RFC 8448 Section 3](https://datatracker.ietf.org/doc/html/rfc8448#autoid-3), and generates identical key information via an MPC computation implemented using the [MP-SPDZ](https://eprint.iacr.org/2020/521.pdf) toolkit. Crunch contains original implementations of AES128 and GHASH primitives in Rust, adopting the [Boyar/Peralta 2011](https://eprint.iacr.org/2011/332.pdf) optimized AES S-Box equations and compiled into to Bristol Fashion boolean circuits using the `garble_lang` crate.

## Future Work

Significant feature improvements and optimizations are still possible. In particular, leveraging Risc0 proofs could enable the use of MPC protocols with lower security requirements (and thus much better performance). Because the goal of the MPC ceremony is to merely delay the client's knowledge of the full key material until commitments are made, the client can its this eventual knowledge to prove that the MPC protocol was executed honestly, without requiring traditional maliciously-secure MPC.

In addition, our current implementation uses no preprocessing stage. Almost all of the computational cost of the MPC component can be offloaded to a preprocessing phase which generates Beaver triples. This can traditionally be an extremely expensive task, in both time and communications bandwidth, when malicious security guarantees are required. In our model, however, an additional Risc0 proof could prove the honesty of the preprocessing phase after the fact, enabling pre-selected groups of notaries to complete most of the computational load before the client even comes online.
