# Live demo script (≈ 5 minutes)

Prepare once (≈ 10 s): `sudo bash topology.sh up`, `python3 certs_tool.py`, and have Wireshark open with
`evidence/captures/e2ee_transit.pcapng` and its `.keylog` configured (*Edit → Preferences → Protocols → TLS*).
Three terminals in the repo folder, plus the dashboard (`python3 ui/server.py --open`) for visuals.

## 1. Prove the routed topology (45 s)

```bash
ip netns list
for n in r1 r2; do echo "== $n"; sudo ip -n $n route; done
sudo ip netns exec clientA traceroute -n 10.0.2.10      # 10.0.1.1 -> 10.0.12.2 -> 10.0.2.10
```
Say: two routers, four subnets, static routes; exactly two intermediate hops.

## 2. Start the system and exchange messages (60 s)

```bash
# terminal 1
sudo ip netns exec relay python3 relay.py --host 10.0.2.10 --tls --allow-tls12 --plain-port 8080
# terminal 2
sudo ip netns exec clientA python3 client.py alice --host 10.0.2.10 --mode e2ee
# terminal 3
sudo ip netns exec clientB python3 client.py bob   --host 10.0.2.10 --mode e2ee
```
Type `bob: hello` in Alice's terminal, `alice: hi back` in Bob's. Point at the relay log: it prints
`forward sender=alice to=bob size=… head=<hex>` — ciphertext only (size = message length + 40 bytes).
Both clients print the same fingerprints for each other's keys.

## 3. Show the decrypted capture (60 s)

Open `e2ee_transit.pcapng` in Wireshark. On the wire: `ClientHello` (SNI relay.local, `supported_versions` 0x0304,
`key_share` x25519), `ServerHello`, then encrypted records. With the key log loaded, Wireshark decrypts them: handshake messages
appear (`Certificate`, `Finished`), and the application data is our binary frame whose body is opaque NaCl ciphertext.
Open `e2ee_relay_side.pcapng`: the relay's own view — same ciphertext. Mention the outer record version is 0x0303 for compatibility, not a bug.

## 4. Apply a delay live (45 s)

```bash
sudo ip netns exec clientA python3 -m bench.probe tls13 --host 10.0.2.10   # baseline: ~1 ms
sudo bash scripts/impair.sh set --rtt-ms 100
sudo ip netns exec clientA python3 -m bench.probe tls13 --host 10.0.2.10   # tls ≈ 100 ms: one round trip
sudo ip netns exec clientA python3 -m bench.probe tls12 --host 10.0.2.10   # tls ≈ 200 ms: two round trips
sudo bash scripts/impair.sh clear
```
Say: TLS 1.3 needs one round trip, TLS 1.2 needs two; `bench.probe resumed` shows resumption keeps one round trip but
shrinks the handshake (no Certificate).

## 5. Security demos (60 s)

```bash
sudo bash scripts/attack_demo.sh all
```
* **Forged certificate**: R1 redirects `:8443` to an attacker proxy; the client aborts with `certificate verify failed`; the attacker saw only an `unknown_ca` alert.
* **Key substitution**: a malicious relay answers Alice's lookup with its own key; her client shows a fingerprint that differs from Bob's real one. Without pinning, the relay reads everything; with `--trust "bob=<fingerprint>"` Alice refuses before encrypting.

The dashboard's **Attack lab** runs the same scenarios in one click, and **Live lab** shows plain TCP → TLS → E2EE with the eavesdropper and relay views side by side.

## If something goes wrong

* `sudo bash topology.sh down && sudo bash topology.sh up` resets the network.
* `sudo bash scripts/impair.sh clear` removes any leftover delay or loss.
* Pre-recorded captures and results are in `evidence/` and `results/`; the dashboard's *Evidence* tab lists them.
