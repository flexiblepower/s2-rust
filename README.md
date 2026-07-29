# The S2 standard for Rust: `s2energy`
<div align="center">
    <a href="https://s2standard.org"><img src="./Logo-S2.svg" width="200" height="200" /></a>
    <div>
        <a href="https://crates.io/crates/s2energy"><img src="https://img.shields.io/crates/v/s2energy" /></a>
        <a href="https://docs.rs/s2energy"><img src="https://img.shields.io/docsrs/s2energy" /></a>
        <a href="https://discord.com/invite/NyFMEPmuDw"><img src="https://img.shields.io/discord/1351281839913832510"></a>
    </div>
</div>
<br />

This crate provides type definitions and utilities for working with the [S2 energy flexibility standard](https://s2standard.org) in Rust. S2 is a communication standard for energy flexibility and energy management in homes and buildings, designed to simplify the use of energy flexibility of smart devices. To learn more about the S2 standard:
- [Read the `s2energy` crate documentation](https://docs.rs/s2energy/latest/s2energy/) to learn about this crate
- [Read the S2 standard's documentation](https://docs.s2standard.org/) for a detailed explanation of S2
- [Visit the website](https://s2standard.org) for a high-level explanation of S2
- [Read the whitepaper](https://ecostandard.org/wp-content/uploads/2024/05/20240521_DSF_PositionPaper.pdf) to learn why it's important to expose and utilise energy flexibility

## Crate contents
This crate provides Rust types for all types specified by S2. It also provides utilities that help you manage an S2 connection over websockets with JSON as the format, including functions to easily set up a WebSocket server/client to send/receive S2 messages.

JSON over WebSockets is a common and recommended way to implement S2, but you're free to choose a different format and communication protocol. In that case, the types in this crate should still be useful but you may wish to disable the `websockets-json` feature.

## Installing dependencies

These crates require the avahi client libraries on linux. On debian or debian-like systems such as Ubuntu, these can be installed with
```sh
sudo apt install libavahi-client-dev
```

The discovery examples also require a running mDNS stack. On Debian-like systems this typically means installing and starting Avahi and D-Bus:
```sh
sudo apt install avahi-daemon dbus
sudo service dbus start
sudo service avahi-daemon start
```

## Running full client and server examples

The full-client and full-server examples provide complete examples of an s2-connect client and server. Both examples assume local running, which means that the server example needs certificates for the hostname of the machine it is being run on. To generate this, run
```sh
cd s2energy-connection/testdata
./gen_cert <hostname>.local
```

After generating the certificates, the server can be run with
```sh
cargo run --example full-server -- <hostname>
```
and the client with
```sh
cargo run --example full-client
```

Note: the full examples use `.local` hostnames such as `https://<hostname>.local:8000`. On WSL this hostname often does not resolve by default. If `https://localhost.local:8000` times out even though the server is running, add a hosts entry such as:
```sh
sudo sh -c 'printf "\n127.0.0.1 localhost.local\n::1 localhost.local\n" >> /etc/hosts'
```
Alternatively, configure mDNS resolution in WSL so `.local` names resolve through Avahi.

## Documentation
You can find the crate documentation at [docs.rs](https://docs.rs/s2energy). The crate documentation assumes that you are familiar with S2; if this is not the case, it may be useful to refer to [the S2 documentation website](https://docs.s2standard.org/docs/welcome/). That documentation explains S2 concepts in more detail, and contains a reference of all messages and types in the S2 specification.
