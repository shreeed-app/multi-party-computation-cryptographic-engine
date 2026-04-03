# Multi-Party Computation Cryptographic Engine

This document outlines the setup and prerequisites for the multi-party computation cryptographic engine, a distributed system responsible for secure key generation and threshold signing using protocols such as FROST and CGGMP24. The engine coordinates multiple nodes to manage key shares, execute cryptographic state machines, and produce signatures without ever reconstructing private keys.

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

## Key Generation Protocols

## FROST Key Generation Protocol

The following sequence diagram illustrates the interactions between the controller and multiple nodes during a FROST distributed key generation session.

The controller coordinates the session across three rounds, routing packages between nodes. Each node independently executes the same distributed key generation steps and stores its own key share in Vault.

```mermaid
sequenceDiagram
    autonumber

    participant Controller
    box Nodes × N
        participant Node as Node n
    end

    Note over Node: N independent nodes. Each executes <br /> the same distributed key generation <br /> steps and stores its own key share.

    Note over Controller,Node: Round 0: Session startup and distributed <br /> key generation round 1

    Controller->>Node: StartKeyGenerationSession
    Note over Node: Runs distributed key generation part1(), <br /> generates Round1SecretPackage and <br /> Round1Package
    Node-->>Controller: StartSessionResponse

    Note over Controller,Node: Round 1: Broadcast all <br /> Round1Packages to each node

    Note over Controller: Aggregates all Round1Packages <br /> into a single distributed key generationRound1Packages batch
    Controller->>Node: SubmitRound
    Note over Node: Runs distributed key generation part2(), <br /> generates Round2SecretPackage and <br /> Round2Packages for each recipient node
    Node-->>Controller: SubmitRoundResponse

    Note over Controller,Node: Round 2: Deliver each <br /> node's Round2Packages

    Note over Controller: Routes each Round2Package <br /> to its intended recipient node
    Controller->>Node: SubmitRound
    Note over Node: Runs distributed key generation part3(), <br /> produces KeyPackage and PublicKeyPackage

    Note over Controller,Node: Finalization: Store key shares <br /> and collect public key

    Controller->>Node: FinalizeSession
    Note over Node: Serializes KeyPackage and PublicKeyPackage <br /> into FrostStoredKey (rkyv) and stores in Vault
    Node-->>Controller: FinalizeSessionResponse

    Note over Controller: Verifies all nodes returned identical <br /> public_key and public_key_package, <br /> and publishes public key
```

## FROST Signing Protocol

The following sequence diagram illustrates the interactions between the controller and multiple nodes during a FROST threshold signing session.

The controller aggregates commitments from all nodes, builds the signing package, and collects signature shares. Each node independently verifies the message and produces a signature share using its key share.

```mermaid
sequenceDiagram
    autonumber

    participant Controller
    box Nodes × N
        participant Node as Node n
    end

    Note over Node: N independent nodes. Each loads its key share <br /> from Vault and participates in threshold signing.

    Note over Controller,Node: Round 0: Session startup <br /> and commitment generation

    Controller->>Node: StartSigningSession
    Note over Node: Loads FrostStoredKey from Vault, deserializes <br /> KeyPackage (postcard) and runs commit(): <br /> nonces and SigningCommitments
    Node-->>Controller: StartSessionResponse

    Note over Controller,Node: Round 1: Broadcast SigningPackage <br /> and collect SignatureShares

    Note over Controller: Aggregates all SigningCommitments <br /> and builds SigningPackage
    Controller->>Node: SubmitRound
    Note over Node: Verifies message matches init and own  <br /> commitments present, consumes nonces (single  <br /> use) and runs sign(): SignatureShare
    Node-->>Controller: SubmitRoundResponse

    Note over Controller,Node: Finalization: Aggregate signature shares

    Controller->>Node: FinalizeSession
    Node-->>Controller: FinalizeSessionResponse

    Note over Controller: Calls frost_core::aggregate and <br /> verifies aggregated signature
    Controller-->>Controller: FinalSignature
```

## CGGMP24 Key Generation Protocol

The following sequence diagram illustrates the interactions between the controller and multiple nodes during a CGGMP24 key generation session, comprising two phases: distributed key generation and auxiliary information generation.

Each node runs a dedicated worker thread executing the CGGMP24 state machine. The controller routes messages between nodes across all rounds and finalizes each phase independently.

```mermaid
sequenceDiagram
    autonumber

    participant Controller
    box Nodes × N
        participant Node as Node n
    end

    Note over Node: N independent nodes. Each runs a <br /> CGGMP24 state machine worker in a <br /> dedicated OS thread.

    Note over Controller,Node: Phase 1: Distributed Key Generation

    Controller->>Node: StartKeyGenerationSession
    Note over Node: Spawns KeyGenerationWorker thread <br /> and produces distributed key generation  <br /> round 1 package
    Node-->>Controller: StartSessionResponse

    loop Key generation rounds
        Controller->>Node: SubmitRound
        Note over Node: Worker receives via incoming channel <br /> and produces outgoing messages
        Node-->>Controller: CollectRound
    end

    Note over Node: Produces IncompleteKeyShare
    Node-->>Controller: CollectRound

    Controller->>Node: FinalizeSession
    Note over Node: Stores IncompleteKeyShare in Vault
    Node-->>Controller: FinalizeSessionResponse

    Note over Controller: Verifies all nodes produced <br /> identical public_key

    Note over Controller,Node: Phase 2: Auxiliary Information Generation

    Controller->>Node: StartAuxiliaryInformationGenerationSession
    Note over Node: Pre-generates Paillier safe primes and <br /> spawns AuxiliaryInformationGenerationWorker <br /> thread abd generates π_mod, π_fac ZK proofs
    Node-->>Controller: StartSessionResponse

    loop Auxiliary information generation rounds
        Controller->>Node: SubmitRound
        Note over Node: ZK proofs: π_enc, π_aff, π_fac <br /> Paillier moduli + Pedersen params
        Node-->>Controller: CollectRound
    end

    Note over Node: AuxiliaryInformation complete, combines <br /> IncompleteKeyShare and AuxInfo: complete <br /> KeyShare<Cggmp24SecurityLevel>
    Node-->>Controller: CollectRound(done=true)

    Controller->>Node: FinalizeSession
    Note over Node: Stores complete KeyShare in Vault
    Node-->>Controller: FinalizeSessionResponse
```

## CGGMP24 Signing Protocol

The following sequence diagram illustrates the interactions between the controller and multiple nodes during a CGGMP24 threshold signing session.

The controller starts sessions on all nodes. Each node independently derives the same deterministic signer subset from the key identifier. The CGGMP24 state machine executes the MtA protocol across multiple rounds to produce a threshold ECDSA signature.

```mermaid
sequenceDiagram
    autonumber

    participant Controller
    box Nodes × N
        participant Node as Node n
    end

    Note over Node: N independent nodes. Controller starts sessions <br /> on all nodes with a deterministic subset of <br /> threshold nodes participates in signing.

    Note over Controller,Node: Session startup: Deterministic <br /> signer selection

    Controller->>Node: StartSigningSession
    Note over Node: Loads KeyShare from Vault, computes parties <br /> deterministically, validates local node is in <br /> parties and spawns SigningWorker thread
    Node-->>Controller: StartSessionResponse

    Note over Controller,Node: Signing rounds: State <br /> machine message routing

    loop Signing rounds
        Controller->>Node: SubmitRound
        Note over Node: Worker delivers to state machine via incoming <br /> channel, state machine: π_enc(K), π_aff(χ,γ), <br /> MtA protocol, δ=γk, σ=χk
        Node-->>Controller: CollectRound
    end

    Note over Node: State machine produces <br /> partial ECDSA signature (r, s)
    Node-->>Controller: CollectRound

    Note over Controller,Node: Finalization: Reconstruct and <br /> verify signature

    Controller->>Node: FinalizeSession
    Note over Node: Extracts r, s scalars, reconstructs <br /> K256Signature, computes recovery_identifier <br /> via trial recovery and returns EcdsaSignature{r, s, v}
    Node-->>Controller: FinalizeSessionResponse

    Note over Controller: Takes first valid signature (all <br /> threshold nodes produce identical output) <br /> Returns FinalSignature::Ecdsa{r, s, v}
```
