# Hide

[![Go Report Card](https://goreportcard.com/badge/github.com/andresmejia3/hide)](https://goreportcard.com/report/github.com/andresmejia3/hide)
[![Go](https://github.com/andresmejia3/hide/actions/workflows/test.yml/badge.svg)](https://github.com/andresmejia3/hide/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/andresmejia3/hide)](https://go.dev/)

**Hide** is a high-performance, production-grade steganography tool engineered in Go. It securely conceals data within images using advanced encoding strategies, military-grade encryption, and fault-tolerant error correction.

Unlike simple LSB tools, **Hide** is built for reliability and security, featuring Reed-Solomon error correction to handle data corruption and support for both symmetric (AES) and asymmetric (RSA) encryption.

## Features

*   **Multiple Encoding Strategies**:
    *   **LSB (Least Significant Bit)**: High capacity, standard steganography.
    *   **LSB Matching**: Improved security against statistical analysis (histogram attacks).
    *   **DCT (Discrete Cosine Transform)**: Embeds data in the frequency domain, offering robustness against minor image alterations.
*   **Strong Encryption**:
    *   **AES-256**: Encrypt messages with a passphrase.
    *   **RSA**: Asymmetric encryption using public/private keys for secure message sharing.
*   **Reliability**:
    *   **Reed-Solomon Error Correction**: Automatically adds parity data to recover messages even if parts of the image are corrupted.
    *   **Compression**: Automatically compresses data (Zlib) before embedding to maximize storage space.
*   **Analysis Tools**:
    *   **Capacity Calculator**: Check exactly how much data fits in an image before starting.
    *   **Steganalysis**: Compare original and stego images to calculate PSNR (Peak Signal-to-Noise Ratio) and generate difference heatmaps.
    *   **Integrity Verification**: Verify hidden messages without fully extracting them.
*   **Performance**: Uses concurrent processing for computationally intensive tasks like DCT embedding.
*   **Stealth Engineering**:
    *   **HVS Optimization**: Exploits the Human Visual System's low sensitivity to the blue color spectrum. When operating in single-channel mode, **Hide** automatically targets the Blue channel to ensure that data embedding creates the least amount of visible noise.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Visual Demo](#visual-demo)
- [Strategies Explained](#strategies-explained)
- [Testing](#testing)
- [License](#license)

## Installation

### Using Go Install

If you have Go installed and just want the binary:

```bash
go install github.com/andresmejia3/hide/cmd/hide@latest
```

### From Source

Ensure you have [Go](https://go.dev/) installed (1.21+ recommended).

```bash
git clone https://github.com/andresmejia3/hide.git
cd hide
go build -o hide ./cmd/hide
```

## Usage

### Hiding Data (`conceal`)

Hide a text message or a file inside an image.

**Basic Usage (Passphrase):**
```bash
./hide conceal -i input.png -o output.png -m "Secret Message" -p "my-secret-password"
```

**Hide a File:**
```bash
./hide conceal -i input.png -o output.png -f secret.pdf -p "my-secret-password"
```

**Using RSA Encryption:**
First, generate keys (see below), then encrypt for the recipient using their public key.
```bash
./hide conceal -i input.png -f secret.txt -k public.pem
```

**Advanced Options:**
*   `-n 2`: Use 2 bits per channel (higher capacity, slightly more visible artifacts).
*   `--dry-run`: Check if the data fits without actually writing the file.
*   `-c 3`: Specify number of RGBA channels to use (1-4).
*   `-z false`: Disable Zlib compression (enabled by default).
*   `-w 4`: Set specific number of concurrent workers (defaults to CPU count).

### Extracting Data (`reveal`)

Recover the hidden message or file.

**Basic Usage:**
```bash
./hide reveal -i output.png -p "my-secret-password"
```

**Save to File:**
```bash
./hide reveal -i output.png -p "my-secret-password" -o recovered_secret.pdf
```

**Using RSA Decryption:**
```bash
./hide reveal -i output.png -k private.pem -o recovered.txt
```

### Analysis & Utilities

**Check Capacity:**
See how many bytes you can hide in an image using different strategies.
```bash
./hide capacity input.png
```

**Inspect Header:**
View metadata (strategy, channels used, compression status) without decoding the payload.
```bash
./hide info stego_image.png
```

**Verify Integrity:**
Check if a hidden message is intact using Reed-Solomon checks without extracting the full payload.
```bash
./hide verify -i stego_image.png -p "my-secret-password"
```

**Analyze Differences:**
Compare an original image with a stego image to see how much it changed (MSE/PSNR) and generate a heatmap.
```bash
./hide analyze -o original.png -s stego.png -d heatmap.png
```

### Key Generation (`keys`)

Generate RSA public/private key pairs for asymmetric encryption.

```bash
./hide keys -o ./keys -b 2048
```

## Visual Demo

Below is a demonstration of concealing a **64KB Lorem Ipsum PDF** into a standard PNG carrier using the default DCT strategy.

| Original Image | Stego Image (Hidden PDF) | Difference Heatmap |
| :---: | :---: | :---: |
| ![Original](/assets/original.jpg) | ![Stego](/assets/stego.png) | ![Heatmap](/assets/heatmap.png) |
| **Clean** | **Encrypted & Compressed** | **Modified Pixels** |

### Analysis Results
After running `./hide analyze -o original.png -s stego.png`, the tool generated the following metrics:

* **MSE (Mean Squared Error):** 0.0842
* **PSNR (Peak Signal-to-Noise Ratio):** 48.87 dB 
    * *(Values >40dB are considered excellent quality and virtually invisible to the human eye).*



### Stego Header Info
Using `./hide info stego.png`, we can see the internal metadata used for recovery:

```text
Stego Header Information:
-------------------------
Version:          1.0.0
Strategy:         DCT (Discrete Cosine Transform)
Encryption:       AES-256-GCM
Compression:      Zlib (Level 6)
Error Correction: Reed-Solomon (Parity: 10%)
Channels:         3 (RGB)
Payload Size:     65,536 bytes

## Strategies Explained

*   **LSB (Least Significant Bit)**: Replaces the lowest bits of pixel color values. It offers the highest storage capacity but is fragile to image editing (resizing, compression).
*   **LSB Matching**: Similar to LSB but randomly adds or subtracts 1 to match the target bit. This alters the statistical footprint less than standard replacement, making it harder to detect via histogram analysis.
*   **DCT**: Embeds data into the frequency domain of 8x8 pixel blocks. This is computationally intensive but allows the message to potentially survive mild lossy compression or format conversion.
*   **Adaptive Channel Selection**: To maximize stealth, the algorithms default to using the Blue channel (when channel limits are applied) because the human eye has the lowest spatial resolution for blue light, making artifacts virtually invisible.

## Testing

To run the test suite:

```bash
go test ./...
```

## License

MIT
