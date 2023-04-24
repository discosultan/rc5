# rc5

A Rust implementation of the RC5 encryption algorithm. RC5 is a symmetric key block cipher designed
by Ronald Rivest in 1994. It is characterized by its simplicity and flexibility, with variable block
size, key size, and number of rounds.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
  - [Basic Example](#basic-example)

## Features

- Written in pure Rust
- Compatible with stable Rust
- Supports `no_std` environment
- Customizable block size, key size, and number of rounds

## Getting Started

To get started with the Rust RC5 encryption algorithm, follow the steps below.

### Prerequisites

- Rust (tested with stable version 1.69)

### Installation

Add the following to your `Cargo.toml` file:

```toml
[dependencies]
rc5 = { git = "https://github.com/discosultan/rc5.git" }
```

## Usage

### Basic Example

Here's a basic example to help you get started with encrypting and decrypting data using the RC5
algorithm:

```rs
use rc5::RC5;

fn main() {
    let key = [0x00, 0x01, 0x02, 0x03];
    let plaintext = [0x00, 0x01];
    let ciphertext = [0x21, 0x2A];

    // RC5-8/12/4
    let rc5 = RC5::<8, 12, 4, 1, 2, 26, 4>::new(key);

    assert_eq!(rc5.encrypt(plaintext), ciphertext);
    assert_eq!(rc5.decrypt(ciphertext), plaintext);
}
```
