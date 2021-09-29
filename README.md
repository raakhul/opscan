# opscan - Open Port Scanner

A simple port scanner written using rust.

## Installation

git clone https://github.com/raakhul/opscan

cd scan

cargo build --release

## Usage

sudo ./target/release/opscan -S syn -P unused_port target_ip

For now only Syn Scan is working.
