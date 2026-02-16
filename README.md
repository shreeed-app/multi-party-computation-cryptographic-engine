# Multi-Party Computation Engine

This document describes the setup and prerequisites for the Multi-Party Computation (MPC) Engine.
This engine is designed to securely manage key shares and perform signing operations in a distributed manner.

## Compatibility

| OS                 | Status |
| ------------------ | ------ |
| macOS              | ✅     |
| Linux              | ✅     |
| Windows (via WSL2) | ✅     |
| Native Windows     | ✅     |

## Prerequisites

- [Docker](https://www.docker.com) and Docker Compose
- [Act](https://github.com/nektos/act) for local GitHub Actions testing
- [Rust](https://www.rust-lang.org) and Cargo

## Key Generation Protocol Overview

The following sequence diagram illustrates the interactions between the orchestrator and multiple peers during a key generation session using the MPC Engine.

The orchestrator coordinates the session, managing rounds of communication and finalizing the key generation. Each peer operates independently, executing the same protocol steps to collaboratively generate a key share.

```mermaid
sequenceDiagram
    autonumber

    participant Orchestrator
    box Peers × N
        participant Peer as Peer n
    end

    Note over Peer: Represents N independent peers<br/>All peers execute the same protocol.

    Orchestrator->>Peer: StartKeyGenerationSession(key_id, algorithm, threshold, participants)

    Peer-->>Orchestrator: StartSessionResponse(round = 0, payload)

    loop Rounds
        Orchestrator->>Peer: SubmitRound(from?, to?, payload)
        Peer-->>Orchestrator: SubmitRoundResponse(new_round, payload)
    end

    Orchestrator->>Peer: FinalizeSession
    Peer->>Peer: StoreKeyShare
    Peer-->>Orchestrator: FinalizeSessionResponse(public_key)

    Orchestrator-->>Orchestrator: PublishPublicKey
```

## Signing Protocol Overview

The following sequence diagram illustrates the interactions between the orchestrator and multiple peers during a signing session using the MPC Engine.

Each peer operates independently, executing the same protocol steps to collaboratively generate a signature. The orchestrator coordinates the session, managing rounds of communication and finalizing the signature.

```mermaid
sequenceDiagram
    autonumber

    participant Orchestrator
    box Peers (× N)
        participant Peer as Peer n
    end

    Note over Peer: It represents N independent peers<br />All peers execute the same protocol.

    Orchestrator->>Peer: StartSigningSession(key_id, algorithm, threshold, participants, message)
    Peer-->>Orchestrator: StartSessionResponse(round=0, payload)

    loop Rounds
        Orchestrator->>Peer: SubmitRound(from?, to?, payload)
        Peer-->>Orchestrator: SubmitRoundResponse(new_round, payload)
    end

    Orchestrator->>Peer: FinalizeSession
    Peer-->>Orchestrator: FinalizeSessionResponse(signature)

    Orchestrator-->>Orchestrator: CombineSignatures(signatures[])
    Orchestrator-->>Orchestrator: VerifySignature(public_key, message, signature)
```
