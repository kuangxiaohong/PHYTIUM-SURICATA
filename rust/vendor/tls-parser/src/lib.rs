//! # TLS Parser
//!
//! A TLS parser, implemented with the [nom](https://github.com/Geal/nom)
//! parser combinator framework.
//!
//! The goal of this parser is to implement TLS messages analysis, for example
//! to use rules from a network IDS, for ex during the TLS handshake.
//!
//! It implements structures and parsing functions for records and messages, but
//! need additional code to handle fragmentation, or to fully inspect messages.
//! Parsing some TLS messages requires to know the previously selected parameters.
//! See [the rusticata TLS parser](https://github.com/rusticata/rusticata/blob/master/src/tls.rs)
//! for a full example.
//!
//! The code is available on [Github](https://github.com/rusticata/tls-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//! ## Parsing records
//!
//! The main parsing functions are located in the [tls.rs](src/tls.rs) file. The entry functions are:
//! - `parse_tls_plaintext`: parses a record as plaintext
//! - `parse_tls_encrypted`: read an encrypted record. The parser has no crypto or decryption features, so the content
//!   will be left as opaque data.
//!
//! # Examples
//!
//! ```rust
//! extern crate nom;
//! extern crate tls_parser;
//!
//! use nom::{Err, IResult};
//! use tls_parser::parse_tls_plaintext;
//!
//! # fn main() {
//! let bytes : &[u8]= include_bytes!("../assets/client_hello_dhe.bin");
//! // [ 0x16, 0x03, 0x01 ... ];
//! let res = parse_tls_plaintext(&bytes);
//! match res {
//!     Ok((rem,record)) => {
//!         // rem is the remaining data (not parsed)
//!         // record is an object of type TlsRecord
//!     },
//!     Err(Err::Incomplete(needed)) => {
//!         eprintln!("Defragmentation required (TLS record)");
//!     },
//!     Err(e) => { eprintln!("parse_tls_record_with_header failed: {:?}",e); }
//! }
//! # }
//! ```
//!
//! Note that knowing if a record is plaintext or not is the responsibility of the caller.
//!
//! As reading TLS records may imply defragmenting records, some functions are
//! provided to only read the record as opaque data (which ensures the record is
//! complete and gives the record header) and then reading messages from data.
//!
//! Here is an example of two-steps parsing:
//!
//! ```rust
//! # extern crate nom;
//! # extern crate tls_parser;
//! # use nom::{Err, IResult};
//! # use tls_parser::{parse_tls_raw_record, parse_tls_record_with_header};
//!
//! # fn main() {
//! # let bytes : &[u8]= include_bytes!("../assets/client_hello_dhe.bin");
//! // [ 0x16, 0x03, 0x01 ... ];
//! match parse_tls_raw_record(bytes) {
//!     Ok((rem, ref r)) => {
//!         match parse_tls_record_with_header(r.data, &r.hdr) {
//!             Ok((rem2,ref msg_list)) => {
//!                 for msg in msg_list {
//!                     // msg has type TlsMessage
//!                 }
//!             }
//!             Err(Err::Incomplete(needed)) => { eprintln!("incomplete record") }
//!             Err(_) => { eprintln!("error while parsing record") }
//!         }
//!     }
//!     Err(Err::Incomplete(needed)) => { eprintln!("incomplete record header") }
//!     Err(_) => { eprintln!("error while parsing record header") }
//! }
//! # }
//! ```
//!
//! Some additional work is required if reading packets from the network, to support
//! reassembly of TCP segments and reassembly of TLS records.
//!
//! For a complete example of a TLS parser supporting defragmentation and states, see the
//! [rusticata/src/tls.rs](https://github.com/rusticata/rusticata/blob/master/src/tls.rs) file of
//! the [rusticata](https://github.com/rusticata/rusticata) crate.
//!
//! ## State machine
//!
//! A TLS state machine is provided in [tls_states.rs](src/tls_states.rs). The state machine is separated from the
//! parsing functions, and is almost independent.
//! It is implemented as a table of transitions, mainly for the handshake phase.
//!
//! After reading a TLS message using the previous functions, the TLS state can be
//! updated using the `tls_state_transition` function. If the transition succeeds,
//! it returns `Ok(new_state)`, otherwise it returns `Err(error_state)`.
//!
//! ```rust
//! # extern crate nom;
//! # extern crate tls_parser;
//! # use nom::{Err, IResult};
//! # use tls_parser::{tls_state_transition, TlsMessage, TlsState};
//!
//! struct ParseContext {
//!     state: TlsState,
//! }
//!
//! # fn update_state_machine(msg: &TlsMessage, ctx: &mut ParseContext, to_server:bool) -> Result<(),&'static str> {
//! match tls_state_transition(ctx.state, msg, to_server) {
//!     Ok(s)  => { ctx.state = s; Ok(()) }
//!     Err(_) => {
//!         ctx.state = TlsState::Invalid;
//!         Err("Invalid state")
//!     }
//! }
//! # }
//! ```
//!
//! # Implementation notes
//!
//! When parsing messages, if a field is an integer corresponding to an enum of known values,
//! it is not parsed as an enum type, but as an integer. While this complicates accesses,
//! it allows to read invalid values and continue parsing (for an IDS, it's better to read
//! values than to get a generic parse error).

#![deny(/*missing_docs,*/unsafe_code,
        unstable_features,
        /*unused_import_braces,*/ unused_qualifications)]

#[macro_use]
extern crate enum_primitive;

#[macro_use]
extern crate nom;

extern crate phf;

#[macro_use]
extern crate rusticata_macros;

#[cfg(feature = "serialize")]
extern crate cookie_factory;

pub use tls_alert::*;
/// TLS alerts
#[macro_use]
pub mod tls_alert;
pub use tls_ciphers::*;
/// TLS ciphersuites definitions and parameters
pub mod tls_ciphers;
pub use tls_dh::*;
/// Diffie-Hellman parameters
pub mod tls_dh;
pub use tls_ec::*;
/// Elliptic curves
pub mod tls_ec;
pub use tls_extensions::*;
/// TLS extensions
#[macro_use]
pub mod tls_extensions;
pub use tls_sign_hash::*;
/// TLS signature schemes
pub mod tls_sign_hash;
pub use tls_states::*;
/// TLS state machine
pub mod tls_states;
pub use tls::*;
/// TLS parser structures and functions
pub mod tls;

mod tls_debug;

pub mod tls_serialize;
pub use tls_serialize::*;
