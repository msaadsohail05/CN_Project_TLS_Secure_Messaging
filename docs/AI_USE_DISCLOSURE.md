# AI-use disclosure

> Template completed from the repository's history of work. **The team must review and edit this page so it states
> exactly what each member did, in the wording required by the course policy.** Replace the bracketed items.

## Tools used

* An AI coding / writing assistant (**[tool name and version, as required by the course policy]**) was used during development.

## What the AI assistant was used for

| Area | Use |
|---|---|
| Planning | explaining the project requirements, checking the proposal against the specification, reviewing the build plan |
| Environment help | troubleshooting VirtualBox networking, SSH / VS Code Remote-SSH, netplan and git problems |
| Code | drafting and reviewing boilerplate: the relay / client refactor, benchmark runners, capture analysis, attack demonstrations, test suite, the dashboard (`ui/`), shell scripts |
| Documentation | drafting the README, architecture notes, demo script and the structure of the technical report |

## What was written, run and verified by the team itself

* **[Fill in]** — the design decisions (protocol, topology, addressing, experiment matrix) are the team's, taken from the submitted proposal.
* **[Fill in]** — every experiment on the routed topology, every packet capture, and every number in the report must be produced by the team's own runs (`scripts/run_all.sh`), not by the assistant.
* **[Fill in]** — each member read, ran and can explain the code of their own track (S: transport security, C: client / E2EE, N: network / experiments).
* Unit tests (`python3 -m unittest discover -s tests`) and the attack demonstrations were executed to confirm the behaviour described in the report.

## Limits of AI involvement

* AI output was treated as a draft: it was run, tested and compared against captures before being relied on.
* Measured results (handshake times, latencies, packet counts) come from runs of `scripts/run_all.sh` on the team's Ubuntu VM and are stored in `results/` and `evidence/`.
