//! blvm-miniscript — Miniscript descriptor and PSBT analysis module
//!
//! Overrides core JSON-RPC methods `getdescriptorinfo` and `analyzepsbt` via the
//! module override system.  The `bitcoin` / `miniscript` crates are isolated entirely
//! to this module binary; `blvm-node` itself has no dependency on them.
//!
//! ## How it works
//!
//! 1. Node spawns this binary (or it's loaded manually with `loadmodule blvm-miniscript`).
//! 2. Module connects to the node IPC socket and performs handshake.
//! 3. `setup` closure calls `NodeAPI::register_core_rpc_override` for each method it owns.
//! 4. Node routes `getdescriptorinfo` / `analyzepsbt` JSON-RPC calls to this module
//!    as `InvocationMessage` over IPC (`InvocationType::Rpc`).
//! 5. `dispatch_rpc` computes the result (pure Rust, no node state needed) and returns JSON.
//! 6. On unload / crash, node calls `unregister_all_for_module` and reverts to the
//!    built-in "module not loaded" error response.

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn};

mod rpc;

use blvm_node::module::traits::{EventType, ModuleError};
use blvm_sdk::module::{ModuleBootstrap, ModuleDb};

const MODULE_NAME: &str = "blvm-miniscript";

// ── Module struct + proc-macro generated dispatch ────────────────────────────

#[derive(Clone)]
pub struct MiniscriptModule;

#[blvm_sdk_macros::rpc_methods]
impl MiniscriptModule {
    #[rpc_method(name = "getdescriptorinfo")]
    pub fn rpc_getdescriptorinfo(
        &self,
        params: &serde_json::Value,
        _db: &Arc<dyn blvm_node::storage::database::Database>,
    ) -> Result<serde_json::Value, ModuleError> {
        Ok(rpc::get_descriptor_info(params))
    }

    #[rpc_method(name = "analyzepsbt")]
    pub fn rpc_analyzepsbt(
        &self,
        params: &serde_json::Value,
        _db: &Arc<dyn blvm_node::storage::database::Database>,
    ) -> Result<serde_json::Value, ModuleError> {
        Ok(rpc::analyze_psbt(params))
    }
}

// `#[command]` generates `cli_spec()` and `dispatch_cli()` from `#[command(name=...)]` methods.
#[blvm_sdk_macros::command]
impl MiniscriptModule {
    #[command(name = "help")]
    fn cmd_help(&self, _args: &[String]) -> Result<String, ModuleError> {
        Ok("blvm-miniscript: provides getdescriptorinfo and analyzepsbt RPC methods.\n\
            Use bitcoin-cli getdescriptorinfo <descriptor>\n\
            Use bitcoin-cli analyzepsbt <psbt_base64>"
            .to_string())
    }
}

impl MiniscriptModule {
    pub fn event_types() -> Vec<EventType> {
        vec![]
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let bootstrap = ModuleBootstrap::init_module(MODULE_NAME);
    // No persistent storage needed; open a temp db to satisfy the run_module! macro signature.
    let db = ModuleDb::open_or_temp(&bootstrap.data_dir, MODULE_NAME)?;

    let setup = |node_api: Arc<dyn blvm_node::module::traits::NodeAPI>,
                 _db: Arc<dyn blvm_node::storage::database::Database>,
                 _data_dir: &std::path::Path| {
        async move {
            // Register core RPC overrides so the node routes these method names to us.
            for method in &["getdescriptorinfo", "analyzepsbt"] {
                match node_api
                    .register_core_rpc_override(
                        method.to_string(),
                        format!("Miniscript implementation of {}", method),
                    )
                    .await
                {
                    Ok(()) => info!("Registered core RPC override: {}", method),
                    Err(e) => warn!(
                        "Failed to register core RPC override '{}': {}",
                        method, e
                    ),
                }
            }

            let module = MiniscriptModule;
            Ok((module.clone(), module))
        }
    };

    blvm_sdk::run_module! {
        bootstrap: &bootstrap,
        module_name: MODULE_NAME,
        module_type: MiniscriptModule,
        cli_type: MiniscriptModule,
        db: db.as_db(),
        setup: setup,
        event_types: MiniscriptModule::event_types(),
    }?;

    warn!("Event receiver closed, module shutting down");
    Ok(())
}
