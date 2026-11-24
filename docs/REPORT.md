# Secure Messaging over TLS 1.3 with End-to-End Encryption: Handshake and Overhead Analysis

**Group F · BCS 5H** — Saad Soail (24K-0549), Taha Anwar (24K-3033), Muhammad Abdullah (24K-0977)
Computer Networks · Project #2 · November 2026

> **How to finish this report.** The text below is complete except for the measured numbers. Run
> `sudo bash scripts/run_all.sh` on the routed topology, then paste the output of
> `python3 -m bench.report_tables` into §6.1–§6.2, the figures from `results/plots/` into §6, and the
> capture-derived numbers from `python3 -m bench.analyze_overhead` into §7. Sections marked **[MEASURED]** need your numbers; everything else is final.
> Section authorship follows the tracks: §3.1, §5, §6 Abdullah (N) · §2.2, §3.2, §7 Saad (S) · §3.3, §8 Taha (C).

## Abstract

We build a small secure messaging system (two clients and a relay) and measure what each security layer costs. Every connection is protected by
TLS 1.3 hop-by-hop, and messages are additionally sealed end-to-end with NaCl `Box` (X25519 + XSalsa20-Poly1305), so the relay forwards only
ciphertext. The system runs across a routed topology of five Linux network namespaces (two routers, four subnets, static routes) where delay and
loss are injected on the router link with `tc netem`. We compare plain TCP, TLS 1.2, TLS 1.3 (full and resumed) and TLS 1.3 + E2EE on handshake
time, round trips, byte overhead and end-to-end message latency under five network conditions with five runs each, backed by packet captures, and we demonstrate
the defences against a forged certificate, a malicious relay substituting public keys, and ciphertext tampering.

## 1. Introduction and objectives

Transport security (TLS) protects a connection between two endpoints, but in a messaging service the relay is itself an endpoint, so TLS alone does not
keep messages from the service. End-to-end encryption (E2EE) removes the relay from the trust base for message content. We therefore ask:

1. **Round trips.** How many round trips does a TLS 1.3 handshake need compared with TLS 1.2, and does session resumption change that?
2. **Bytes.** How many extra bytes does each layer (TLS records, E2EE, our framing, TCP/IP) add, and how does that depend on message size?
3. **Latency.** What do TLS and E2EE add to end-to-end message latency, and how do delay and loss change it?
4. **Security.** Which attacks does each layer stop, and what remains (key substitution, replay)?

**Hypotheses** (stated before measuring; the proposal's resumption claim was corrected, see §3.2):
(H1) TLS 1.3 completes its handshake in one RTT after TCP; TLS 1.2 needs two. (H2) A resumed TLS 1.3 handshake needs the **same** one RTT but fewer bytes and less time
(no certificate exchange or signature) — only 0-RTT early data would remove the round trip, and Python's `ssl` cannot send it, so 0-RTT is out of scope.
(H3) The E2EE overhead is a fixed 40 bytes, proportionally large for small messages and negligible for large ones. (H4) Total wire overhead exceeds
E2EE + TLS-record overhead because TCP/IP headers, ACKs and segmentation add on top. (H5) Loss increases variance and produces explainable outliers (retransmission timeouts).
(H6) The cost of encryption is small relative to network delay at these RTTs — to be measured, not assumed.

## 2. Background

### 2.1 Handshakes and round trips (after the TCP 3-way handshake, ≈ 1 RTT)

| Handshake | Round trips | Flights |
|---|---|---|
| TLS 1.2 full | 2 | ClientHello → ServerHello + Certificate + ServerHelloDone → ClientKeyExchange + Finished → Finished |
| TLS 1.3 full | 1 | ClientHello + key_share → ServerHello + {Certificate, CertificateVerify, Finished} → Finished |
| TLS 1.3 resumed (PSK) | 1 | ClientHello + PSK → ServerHello + {Finished} (no certificate) → Finished — same RTT count, fewer bytes |
| TLS 1.3 + 0-RTT | ≈ 0 | application data in the first flight (out of scope) |

In TLS 1.3 everything after the ServerHello — including the certificate — is encrypted, so a capture shows handshake fields only when decrypted with the key log
(`SSLContext.keylog_filename`). The outer record layer keeps version 0x0303 for middlebox compatibility; the real version is in the `supported_versions` extension (0x0304).

### 2.2 Why two layers of encryption

TLS secures the hop between a client and the relay; anyone sniffing that link sees nothing, but the relay decrypts. E2EE seals the message for the recipient's
key before it reaches the relay. X25519 gives two parties a shared secret from each other's public key without sending it; `Box` derives a key from it and uses XSalsa20-Poly1305
authenticated encryption, so tampering is detected. Every `Box` ciphertext carries a 24-byte nonce and a 16-byte MAC: **40 bytes, independent of message size**.
Because the relay hands out public keys, a dishonest relay could substitute its own; a **fingerprint** (here the first 16 bytes of SHA-256 of the key, shown as 8 groups of 4 hex digits)
lets users compare keys out-of-band.

## 3. System design

### 3.1 Network (N track)

Five network namespaces (`clientA`, `clientB`, `r1`, `r2`, `relay`) joined by veth pairs; routers have `ip_forward=1`; addressing and routes as in `docs/ARCHITECTURE.md` and Figure 1.
Subnets: LAN-A 10.0.1.0/24, LAN-B 10.0.2.0/24 (relay), LAN-C 10.0.3.0/24, LAN-T 10.0.12.0/29 (transit). Routing is static; `traceroute` from clientA to the relay shows the two
intermediate hops `10.0.1.1 → 10.0.12.2`. Impairments are applied with `tc netem` on both router-side interfaces of LAN-T so that every message crosses them:
delay is split evenly (RTT/2 per direction) and **loss is applied on one direction only** (R1 egress), so that the nominal 2 % / 5 % is the loss each packet in that
direction experiences, which keeps the condition interpretable; the actual values are verified independently with `ping` (§5.3).

![Figure 1 — routed topology](architecture.svg)

### 3.2 Transport security (S track)

The relay accepts TLS 1.3 on 8443 (TLS 1.2 only when started with `--allow-tls12`, for the comparison) and plain TCP on 8080 (baseline). Certificates come from a private
CA created with `openssl`; the relay certificate carries `subjectAltName = DNS:relay.local, IP:10.0.2.10, IP:127.0.0.1` because clients connect by address and Python verifies the IP SAN, and the CA
certificate has `basicConstraints`/`keyUsage` (Python ≥ 3.13 verifies in strict mode). Each client connection is handshaked in its own thread so a stalled handshake cannot block others (tested with a hanging
`nc` connection and a 10 s timeout).

**Session resumption.** TLS 1.3 sends `NewSessionTicket` *after* the handshake, so a client that reads `.session` immediately may find nothing usable and silently perform a full handshake. Our client therefore does one application round
trip first, then reuses the saved session on a new TCP connection with the same `SSLContext`; the run records `session_reused` and the capture analysis checks for the `pre_shared_key` extension in the ServerHello, so a "resumed" connection is verified, not assumed.
(The original proposal predicted that resumption would reduce round trips; that is incorrect without 0-RTT and was corrected to the hypotheses H2 above.)

**Thread-safety.** The relay and clients read a TLS socket on one thread while others write it; a blocking `SSLSocket` is not safe for that, so all TLS sockets go through `tlsutil.SafeTLS`, which serialises each SSL call and waits for readiness outside the lock.

### 3.3 Client, E2EE and modes (C track)

A single code path supports three modes: **tcp** (plain, baseline), **tls** (TLS 1.3, application data in clear), **e2ee** (TLS 1.3 + `Box`). Frames are `[4-byte length][1-byte type][payload]` (types REGISTER, LOOKUP, MESSAGE, ERROR, PUBLISH);
fixed-width fields keep the byte accounting exact. A client generates an X25519 key pair on first use, publishes the public key, and caches the first key seen for each peer (a changed key is reported). `--trust NAME=FINGERPRINT` pins a fingerprint so a substituted key is refused before encryption.

## 4. Implementation notes

Python 3, standard-library `ssl`, PyNaCl; no cloud or paid components. Tools: `ip netns`, `tc`, tcpdump/tshark, Wireshark for annotation. Code layout and stage map are in the README. 15 automated tests cover TLS 1.3/1.2, resumption, wrong-CA refusal,
E2EE round trip, tamper rejection, fingerprint pinning and the capture analyser (on a capture synthesised from a real TLS conversation).

## 5. Methodology

### 5.1 Conditions

| Set | RTT (added) | Loss |
|---|---|---|
| A-1 / B-1 | 20 ms | 0 % |
| A-2 | 100 ms | 0 % |
| A-3 | 200 ms | 0 % |
| B-2 | 20 ms | 2 % |
| B-3 | 20 ms | 5 % |

Five distinct points across two sweeps, 5 runs each (the requirement is ≥ 3 conditions × ≥ 3 runs).

### 5.2 Metrics and where each number comes from

| Metric | Definition | Source |
|---|---|---|
| TCP handshake time | SYN sent → connect() returns | client timer (`perf_counter_ns`), cross-checked against SYN/ACK timestamps in the pcap |
| TLS handshake time | ClientHello → `do_handshake()` returns | client timer, cross-checked in the pcap |
| Time to first data | connection start → first application reply | client timer |
| RTTs to first data | time to first data ÷ measured RTT | derived; pcap flight count |
| Handshake bytes | TLS records up to the client's Finished, per direction | `bench.analyze_overhead` |
| E2EE overhead | ciphertext − plaintext = 40 B | application instrumentation |
| Framing overhead | frame − body = 6 B + name | application instrumentation |
| TLS record overhead | 5 B header + 1 B inner type + 16 B tag = 22 B per record | pcap |
| Total wire overhead | captured L3 bytes − plaintext | pcap |
| Message latency | sender timestamp (before encryption) → receiver timestamp (after decryption) | application instrumentation, same host clock |

### 5.3 Procedure and validity

Per condition: apply netem → **verify** (200 pings: configured vs measured RTT and loss) → handshake matrix (20 sequential connections × {TCP, TLS 1.2, TLS 1.3, TLS 1.3 resumed} × 5 runs, configuration order shuffled each run)
→ latency matrix (100 messages A→B × {tcp, tls, e2ee} × {64 B, 1 KiB, 16 KiB} × 5 runs, order shuffled each run, 10 ms pacing so sender queueing is not counted) → clear. Statistics: per-run means, then mean ± standard deviation across the 5 runs; min / median / p95 / max retained;
no run or outlier is dropped (a lost SYN costs a ≈ 1 s retransmission, which is an explainable outlier, not noise). Key discovery (one LOOKUP round trip) is performed before timing starts so it is not folded into per-message latency.
Threats to validity: a shared laptop adds scheduling jitter (mitigated by repetition, shuffling and reporting σ); netem loss is a statistical model, hence the measured-vs-configured check; all namespaces share one clock, which makes one-way latency measurable but means there is no clock skew to emulate.

## 6. Results [MEASURED]

> Paste the generated tables and figures here: `python3 -m bench.report_tables > /tmp/tables.md`, figures from `results/plots/`.
> `results/sample_loopback/` is a laptop smoke test with emulated delay and **must not** be reported as the result.

### 6.1 Handshake (ms, mean ± σ across 5 runs) [MEASURED]

*(insert table: TCP / TLS 1.2 / TLS 1.3 / TLS 1.3 resumed × the five conditions; figures `handshake_tls_ms_rtt.png`, `handshake_tls_ms_loss.png`, `handshake_ttfd_ms_*.png`)*

What to check against the hypotheses: TLS handshake time ÷ RTT should be ≈ 2 for TLS 1.2 and ≈ 1 for TLS 1.3 and TLS 1.3 resumed (H1, H2); resumed should be slightly faster than full TLS 1.3 at 0 % loss but **not** a full RTT faster.

### 6.2 Message latency (ms) [MEASURED]

*(insert table: {tcp, tls, e2ee} × {64 B, 1 KiB, 16 KiB} × conditions; figures `latency_rtt.png`, `latency_loss.png`)*

Expected shape (H6): latency ≈ RTT/2 + small constant; `tls` ≈ `tcp`; `e2ee` adds the Box seal/open time (microseconds to ≈ 1 ms), more visible for 16 KiB payloads; at 2 % and 5 % loss, means rise and σ grows with occasional retransmission-timeout outliers.

### 6.3 Effect of loss [MEASURED]

*(discuss variance, p95 and max, explain any ≈ 200 ms / 1 s outliers by RTO; compare measured loss from the verification pings with the configured 2 % / 5 %.)*

## 7. Byte overhead (S track) [MEASURED]

`bench.analyze_overhead` reads a capture (pure-Python pcap/pcapng parser; no dependencies) and reports per TCP connection: SYN/ACK timing, ClientHello/ServerHello sizes, negotiated version (ServerHello `supported_versions`),
whether the server selected a PSK (resumption), handshake bytes per direction, and a **layered accounting** of an application exchange (client → server):

```
total wire (L3) = plaintext + E2EE (40 B × msgs) + app framing ((6 + name) × msgs) + TLS records (22 B × app records)
                  + TCP/IP headers (all packets incl. pure ACKs) + retransmissions + handshake records + (control frames, close_notify)
```

Insert one worked example (e.g. 100 × 64-byte messages) and a table of handshake bytes for TLS 1.2 vs TLS 1.3 vs TLS 1.3 resumed; the server → client side of the resumed handshake should be markedly smaller (no certificate chain), which is the real benefit of resumption.
Note that in a TLS 1.3 capture handshake and data records are indistinguishable without the key log (all are type 23 after the ServerHello), so the boundary is placed at the client's first encrypted record (its Finished), which is exact when there is no client certificate; post-handshake `NewSessionTicket` records may fall on either side of that boundary, which we mention wherever it matters.
**Expected result (H3, H4):** E2EE adds 40 B (≈ 62 % of a 64-byte message, ≈ 4 % of 1 KiB, ≈ 0.2 % of 16 KiB); total overhead is larger than E2EE + TLS records because of TCP/IP headers and ACKs; for 16 KiB payloads TLS splits data into two records (max record plaintext 16 384 B).

## 8. Security evaluation (C and S tracks)

All scenarios are in `attacks/demo_attacks.py` (CLI and dashboard) and `scripts/attack_demo.sh` (inside the topology, with captures).

| Scenario | Attack | Result |
|---|---|---|
| Forged certificate | R1 (compromised) redirects :8443 to a proxy presenting a certificate from the attacker's CA | client aborts: *unable to get local issuer certificate*; attacker receives an `unknown_ca` alert, 0 application frames exposed |
| Key substitution, pinned | malicious relay answers Alice's lookup for Bob with its own key | Alice's pinned fingerprint mismatches; she refuses before encrypting; relay intercepted 0 messages |
| Key substitution, not pinned | same, nobody compares fingerprints | **succeeds silently**: relay decrypts and re-encrypts; only the visibly different fingerprints reveal it — why out-of-band verification matters |
| Tampering | one ciphertext byte flipped | Poly1305 check fails; message dropped, never shown |
| Trusted rogue CA, TLS only | victim tricked into trusting the attacker's CA | attacker reads every message in clear: TLS alone is not end-to-end |
| Trusted rogue CA, TLS + E2EE | same worst case | attacker sees only NaCl ciphertext: E2EE still protects the content |
| Passive eavesdropper | tap on the link, no keys | plain TCP leaks the message; TLS and TLS + E2EE show only record headers and opaque bytes |

**Out of scope / residual risks.** Replay: `Box` gives confidentiality and integrity but not ordering, so a captured message can be replayed to its recipient; a per-sender sequence number in the plaintext (+8 B) would close it.
Metadata (who talks to whom, message sizes and timing) is visible to the relay and to anyone observing the link. Trust-on-first-use of keys: the first key seen for a peer is kept, so a relay that lies from the first lookup is only caught by fingerprint comparison.

## 9. Discussion and limitations

* TLS 1.3 gains over TLS 1.2 come from one fewer round trip, which grows linearly with RTT — the 200 ms condition shows the largest absolute gap. Resumption is valuable for bytes and CPU, not for round trips.
* E2EE's fixed 40 B is a poor trade for tiny messages but trivial for large ones; its CPU cost is small next to network delay at these RTTs (H6, measured in §6.2).
* The relay is the key directory, so E2EE is only as trustworthy as the fingerprint check; automating that check (e.g. a transparency log) is future work.
* Python's `ssl` cannot do TLS 1.3 0-RTT, so we cannot measure the zero-round-trip case; this is a limitation of the tooling, not of the protocol.
* Single host: all namespaces share CPU and clock; absolute times include scheduler jitter.

## 10. Conclusion

[MEASURED] Summarise: TLS 1.3 vs 1.2 round trips, what resumption saves, the E2EE overhead curve, the effect of loss, and the defences demonstrated. State the one-sentence answer to each of the four questions in §1.

## Appendix A — reproduction

See `README.md` §2: `sudo bash scripts/run_all.sh` reproduces the topology, captures, attack demos, experiments, plots and overhead analysis on a clean Ubuntu machine; `python3 ui/server.py` browses the results.

## Appendix B — AI-use disclosure

See `docs/AI_USE_DISCLOSURE.md`.
