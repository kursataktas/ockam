//! The ockam_abac crate is responsible for performing attribute based authorization
//! control on messages within an Ockam worker system.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
extern crate core;

mod env;
mod error;
mod eval;
mod policy;
mod types;

#[cfg(feature = "std")]
mod parser;

pub mod expr;
pub mod resource;

mod abac;
mod boolean_expr;
mod policy_expr;

pub use abac::*;

pub use boolean_expr::*;
pub use env::Env;
pub use error::{EvalError, ParseError};
pub use eval::eval;
pub use expr::Expr;
pub use policy::{
    storage::*, Policies, PolicyAccessControl, ResourcePolicy, ResourceTypePolicy, Resources,
};
pub use policy_expr::*;
pub use resource::{Resource, ResourceType};
pub use types::{Action, ResourceName, Subject};

#[cfg(feature = "std")]
pub use parser::parse;

#[cfg(not(feature = "std"))]
pub use ockam_executor::tokio;

#[cfg(feature = "std")]
pub use tokio;

/// This is a temporary workaround until the fixes done
/// in https://github.com/launchbadge/sqlx/pull/3298 are released
#[cfg(feature = "std")]
extern crate sqlx_etorreborre as sqlx;
