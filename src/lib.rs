//! netpeek internals, exposed as a library so the binary, the test suite and
//! throwaway examples share one implementation. See [`ntstat`] for the kernel
//! control protocol and [`model`] for the aggregation engine.

pub mod app;
pub mod dns;
pub mod format;
pub mod model;
pub mod ntstat;
pub mod services;
pub mod ui;
