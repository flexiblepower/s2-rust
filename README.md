# The S2 standard for Rust: `s2energy`
<div align="center">
    <a href="https://s2standard.org"><img src="./Logo-S2.svg" width="200" height="200" /></a>
    <div>
        <a href="https://crates.io/crates/s2energy"><img src="https://img.shields.io/crates/v/s2energy" /></a>
        <a href="https://docs.rs/s2energy"><img src="https://img.shields.io/docsrs/s2energy" /></a>
    </div>
</div>
<br />

This crate provides type definitions and utilities for working with the [S2 energy flexibility standard](https://s2standard.org) in Rust. S2 is a communication standard for energy flexibility and energy management in homes and buildings, designed to simplify the use of energy flexibility of smart devices. To learn more about the S2 standard:
- [Read the documentation](https://docs.s2standard.org/) for a detailed explanation of S2
- [Visit the website](https://s2standard.org) for a high-level explanation of S2
- [Read the whitepaper](https://ecostandard.org/wp-content/uploads/2024/05/20240521_DSF_PositionPaper.pdf) to learn why it's important to expose and utilise energy flexibility

## Crate contents
This crate provides Rust types for all types specified by S2. It also provides utilities that help you manage an S2 connection over websockets with JSON as the format, including functions to easily set up a WebSocket server/client to send/receive S2 messages.

JSON over WebSockets is a common and recommended way to implement S2, but you're free to choose a different format and communication protocol. In that case, the types in this crate should still be useful but you may wish to disable the `websockets-json` feature.

## Documentation
You can find the crate documentation at [docs.rs](https://docs.rs/s2energy). The crate documentation assumes that you are familiar with S2; if this is not the case, you may want to refer to the [GitHub wiki](https://github.com/flexiblepower/s2-ws-json/wiki) for the S2 JSON schema. That documentation explains S2 concepts in more detail.
