# IKEv2 foundation

The parser uses the 28-byte header, packed version, correct exchange codes, generic payload chains and a single Nonce type. The response bit is distinct from the exchange type. Initial exchange ID/SPI/role constraints are checked; subsequent IDs require session correlation, provided for the fixed childless handshake described below. Reserved bits are ignored on receive. Unsupported exchanges and encrypted fragmentation fail explicitly.

Messages are capped at 65,535 bytes and 64 payloads. Certificates and AUTH bodies are capped at 16 KiB, KE at 16 KiB, vendor bodies at 1 KiB, proposals at 16, transforms at 32 per proposal and attributes at 32 per transform. Known singleton duplicates fail. Unknown critical payloads fail; unknown noncritical payloads remain bounded opaque data. SK is terminal in the outer chain, with its inner type preserved but ciphertext never parsed as plaintext.

Proposal syntax validates nesting, lengths, SPI sizes, numbering and transform chains. It is not negotiation; a well-formed numeric transform ID is not evidence of support. Certificate, AUTH, EAP and configuration bodies still need semantic/profile verification. Traffic-selector basic ranges are validated but not authorized against policy.

Unconfigured processors and legacy `connect`/`process` APIs still fail explicitly. Configured processors expose the authenticated childless session API below. An optional single CHILD_SA with exact host authorization and single-peer UDP transport is described below.

Hybrid architecture follows initial classical KE, encrypted intermediate additional KE, then AUTH with intermediate transcript binding. ML-KEM public key and ciphertext must be role-specific protocol messages, not independently generated per packet. The current draft revision is recorded in [STANDARDS.md](../STANDARDS.md) and must be rechecked before implementation.

## Isolated PSK AUTH primitive (2026-09-18)

`ike::auth::PskAuth` computes and verifies 32-byte Authentication Data using PRF_HMAC_SHA2_256 and the PSK construction in [RFC 7296 §2.15](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.15). It streams the retained IKE_SA_INIT wire message, opposite peer's nonce and keyed identity digest. Role selection chooses SK_pi or SK_pr; reserved and unknown noncritical wire bytes remain authenticated. Identity input excludes only the generic payload header and retains its reserved bytes. This primitive imposes a local 4,096-byte identity-body limit and uses constant-time HMAC tag verification.

The caller must supply the latest successful exchange after any retries, correlate its keys/nonces, provision a high-entropy PSK and authorize the identity. Structural validation cannot establish these properties. This API returns authentication data only, not a complete AUTH payload. The primitive alone does not enable negotiation or install SAs; the session layer below supplies correlation and identity policy. Intermediate transcript binding remains unsupported. Owned secret intermediates are zeroized; HMAC dependency state is not guaranteed erased.

## Configured childless sessions

Create `PskPolicy::new(local_key_id, expected_peer_key_id, psk)` and pass it to `IkeProcessor::with_psk(role, policy, lifetime)`. Both identities are distinct opaque byte strings (1–1024 bytes); the PSK is a dedicated 32-byte high-entropy secret. The library does not load credentials from disk. `start()` emits the initiator's first message, and `receive()` returns an optional response to forward to the peer. Inputs begin at the IKE header; the caller owns UDP framing and peer routing.

The fixed proposal selects X25519 group 31 ([RFC 8031](https://www.rfc-editor.org/rfc/rfc8031.html)), HMAC-SHA256 PRF and AES-256-GCM-16. Ephemeral scalars, nonces and SPIs use OS randomness; noncontributory DH results fail. SK protects the full header and SK header as AAD ([RFC 5282](https://www.rfc-editor.org/rfc/rfc5282.html)). Keys cannot be imported/exported through this API. AUTH uses IV zero. Optional CREATE_CHILD_SA messages reserve IVs from one upward before sealing; failed attempts cannot reuse a reserved IV. Retries reuse exact cached ciphertext.

The responder advertises [experimental RFC 6023 childless support](https://www.rfc-editor.org/rfc/rfc6023.html); without it the initiator refuses to send childless AUTH. The initial exchange installs no CHILD_SA; a separately configured CREATE_CHILD_SA exchange can follow as described below. State transitions are `Initial → InitSent → AuthSent → Authenticated` for the initiator and `Initial → AwaitingAuth → Authenticated` for the responder. Authentication requires the expected SPI pair, role, exchange and message ID, valid GCM, PSK AUTH over retained transcripts, and the configured identity. The responder authenticates the initiator before emitting its own AUTH; it cannot know whether that response was delivered.

Rejected packets preserve state and cached responses. Up to three accepted inbound messages (INIT, AUTH, optional CHILD) are cached per session. `retransmit()` returns the last outbound message; transport scheduling and rate limits remain the application's responsibility. `close()` drops keys and credentials permanently. Lifetime is monotonic, absolute from creation, at most one hour. Call `expire()` periodically to release secrets during inactivity; all packet/retransmission operations also enforce expiry. There is no persistence, restart/resume, rekey, liveness exchange or multi-session listener. This is a library handshake profile, not a working VPN or a full IKE implementation.

## UDP handshake command

`ike-handshake` runs one authentication attempt over UDP. Supply the same dedicated PSK to both peers as 64 hex digits on stdin, optionally followed by a newline, then EOF. Credentials are not accepted as command-line arguments or written by the command. Input and decoded buffers are zeroized on drop; this does not erase shell, terminal or secret-provider copies. The handshake deadline begins after credential input and socket setup.

Build with `cargo build -p quantum-ipsec-cli --locked`. In two terminals, start the responder first. `PSK_HEX_FILE` below is the path to an already securely provisioned file containing the same secret on both sides; it is not the secret itself.

```sh
# Terminal 1: responder
./target/debug/quantum-ipsec ike-handshake \
  --role responder --bind 127.0.0.1:15000 --peer 127.0.0.1:15001 \
  --local-id server --peer-id client --psk-stdin --timeout-secs 10 \
  --output-format json < "$PSK_HEX_FILE"

# Terminal 2: initiator
./target/debug/quantum-ipsec ike-handshake \
  --role initiator --bind 127.0.0.1:15001 --peer 127.0.0.1:15000 \
  --local-id client --peer-id server --psk-stdin --timeout-secs 10 \
  --output-format json < "$PSK_HEX_FILE"
```

Without inner-host flags this remains an IKE-only probe. The initiator retries at 250 ms with exponential backoff capped at two seconds (or the configured timeout if shorter). The responder only replies to received requests, following the retransmission roles in [RFC 7296 §2.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.1). After authenticating, it remains available for one additional timeout interval to resend cached responses; duplicates never extend that interval. Use the same timeout on both peers, and start the initiator before the responder's initial deadline. Each invocation consumes at most 256 datagrams and accepts at most 4,096 bytes per datagram. Foreign endpoints, oversize and invalid packets count against the budget and never extend deadlines.

Success reports `authenticated-childless-handshake`, matching SPI metadata and transport counters, with `tunnel_established: false` and `session_retained: false`. The command closes its session before returning. It does not forward ESP traffic or modify `status`. This increment has been tested between two local processes, including deliberate loss of the first request and final AUTH response; it is not independent IKE-daemon interoperability evidence.

Library callers can use `ike::udp::handshake(socket, peer, role, policy, options)`. It consumes a bound UDP socket and returns the socket, authenticated `PskSession` and counters on success. It is a blocking, single-peer runner. The caller owns the returned session's remaining lifetime and must close/expire it. No NAT detection, UDP encapsulation marker, port 4500, migration or multi-session admission service is implemented.

## Single CHILD_SA and ESP packet protection

Configure `ChildPolicy::new(local_inner_ipv4, peer_inner_ipv4)` before starting a `PskSession`, then call `start_child()` on the original initiator after mutual AUTH. Alternatively, `ike::udp::handshake_with_child` performs both exchanges under the same deadline and datagram budget. It returns only after the configured CHILD_SA has been installed locally; loss of its final response is handled by the same response cache/grace period.

The profile implements one CREATE_CHILD_SA request/response at message ID 2, with SA, fresh nonce, TSi and TSr inside SK. The ESP proposal selects AES-256-GCM-16 with 256-bit keys and no ESN. The peer's selected SPI is used for outbound ESP. KEYMAT is `prf+(SK_d, Ni | Nr)`, split into initiator-to-responder and responder-to-initiator 32-byte keys plus 4-byte salts, following [RFC 7296 §§1.3.1 and 2.17](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.17). There is no additional CHILD DH exchange; this profile does not add per-child DH forward secrecy beyond the initial IKE exchange.

TSi/TSr must exactly match the configured two IPv4 hosts, all protocols and ports. No narrowing, wildcard address ranges, transport mode, rekey or multiple children are accepted. Policy is immutable and scoped to the session's configured PSK identity pair. Both directional SAs are built privately and published together; duplicate requests return cached ciphertext, never derive/reinstall SAs. Keys and SAs cannot be extracted or cloned through the session API. `child_metadata()` exposes public SPI/provenance/counter metadata only.

`encrypt_ipv4()` accepts a complete IPv4 datagram and returns raw ESP bytes. `decrypt_ipv4()` verifies ESP and the inbound inner-host policy before committing replay/counters or returning plaintext. IPv4 options and fragments are unsupported. Closing/expiring the parent session disables and drops both SAs; normal SA packet/byte/age limits also apply. These APIs do not send ESP on the network, install kernel SAs or configure routes/TUN.

For the CLI commands above, add these flags to both sides:

```sh
# Initiator
--local-inner-ip 10.0.0.1 --peer-inner-ip 10.0.0.2
# Responder
--local-inner-ip 10.0.0.2 --peer-inner-ip 10.0.0.1
```

Success then reports `authenticated-child-sa`, `child_sa_established: true` and complementary `child_inbound_spi`/`child_outbound_spi`. The command remains a finite negotiation probe: it closes the session/pair before exit and reports `tunnel_established: false`. Keeping a routed tunnel alive requires a separate persistent data-plane integration.
