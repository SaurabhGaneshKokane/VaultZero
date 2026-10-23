# VaultZero: End-to-End Hybrid Cryptographic Vault

A modern, enterprise-grade, client-side zero-knowledge cryptographic web application built with **React**, **TypeScript**, **Tailwind CSS**, and the browser's native **Web Crypto API (`window.crypto.subtle`)**.

Developed for the **Cryptography & Network Security (CNS) Micro-Project — Stage 2** at **Shah & Anchor Kutchhi Engineering College**.

---

## 🛡️ Key Features

### 1. Core Vault (`VaultTab.tsx`)
- **Hybrid Cryptography**: Combines the raw speed of symmetric **AES-256-GCM** (authenticated encryption) with the security of asymmetric **RSA-OAEP-2048** key wrapping.
- **Zero External Dependencies**: Implemented entirely via native browser `window.crypto.subtle` (BoringSSL/NSS) with hardware-accelerated **AES-NI** CPU instructions.
- **Client-Side Processing**: Plaintext files never leave the browser unencrypted.
- **Streamlined User Experience**:
  - Segmented control toggling between **Send Protected File** and **Unlock Received File**.
  - Expandable **My Security Keys** identity drawer with 1-click public address copying.
  - Automatic `sessionStorage` master key persistence for zero-friction unlocking.
  - **Dual Terminology Modes**: Toggle between **Simple Mode** (approachable, human-friendly terms) and **Cryptographic Audit Mode** (deep telemetry, byte offsets, and hex digests).

### 2. Adversarial Lab (`AdversarialLab.tsx`)
*Implements Stage 1 Objective 5 (Tamper and Misuse Detection)*:
- **Scenario A (In-Transit 1-Bit Mutation Attack)**:
  - Injects a single-bit XOR flip (`tamperedBytes[offset] ^= 0x01`) inside the ciphertext body.
  - Demonstrates how the 128-bit **AES-GCM GMAC** authentication tag detects tampering and throws `OperationError`, rejecting corrupted files before any plaintext is released.
  - Features an interactive **Hex Diff Card** showing the mutated byte, binary bit-flips, and memory context window.
- **Scenario B (Key Mismatch / Unauthorized Identity)**:
  - Attempts to unwrap the 256-byte session key header using an unauthorized rogue RSA-2048 private key.
  - Demonstrates **RSA-OAEP** plaintext-aware padding rejection (MGF1 with SHA-256).
- **Security Audit Telemetry Console**: Embedded live terminal logging cryptographic engine decisions.

### 3. Performance Benchmark Suite (`BenchmarkTab.tsx`)
*Implements Stage 1 Objective 7 (Performance Measurement)*:
- Automated micro-benchmark suite measuring encryption and decryption across 4 tiers:
  - **12 KB**: Text / Configuration payload
  - **50 KB**: Document payload
  - **2 MB**: Media / Image payload
  - **10 MB**: Stress test payload
- **Literature Comparison**: Real-time comparison against baseline metrics from *Elumalaivasan et al. (2025)* (legacy CFB mode).
- **Throughput & Speedup Visualizer**: Real-time MB/s calculations and dual-bar latency charts demonstrating up to **170× speedup** via hardware-level vector instructions.
- Explains why parallel counter mode (CTR) and hardware CLMUL outperform sequential Cipher Feedback (CFB) mode while guaranteeing non-malleability.

---

## 📦 Binary Package Layout (`.vault`)

Each protected file is packed into a unified binary buffer:
```
+-------------------------------------------------------------------------------------------------+
| Offset    | Size (Bytes) | Description                                                          |
+-------------------------------------------------------------------------------------------------+
| 0         | 256          | Encrypted AES Session Key (RSA-OAEP 2048-bit with SHA-256)         |
| 256       | 12           | AES-GCM Initialization Vector (IV)                                   |
| 268       | 4            | Metadata Length (uint32 big-endian)                                  |
| 272       | N            | Metadata JSON (UTF-8 encoded: fileName, fileType, plaintext hash)   |
| 272 + N   | Remainder    | AES-256-GCM Ciphertext + 16-byte Authentication Tag (GMAC)           |
+-------------------------------------------------------------------------------------------------+
```

---

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) (v18 or higher recommended)
- [npm](https://www.npmjs.com/)

### Installation
```bash
git clone https://github.com/SaurabhGaneshKokane/VaultZero.git
cd VaultZero
npm install
```

### Development Server
```bash
npm run dev
```
Open `http://localhost:5173` in your browser.

### Production Build
```bash
npm run build
npm run preview
```

---

## 🏛️ Academic Citation
**Shah & Anchor Kutchhi Engineering College**  
*Cryptography & Network Security (CNS) Micro-Project — Stage 2*  
Topic: Client-Side Zero-Knowledge Hybrid Encryption Vault
