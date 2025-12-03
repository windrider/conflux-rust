use crate::{
    builtin::Builtin,
    executive_observer::TracerTrait,
    machine::Machine,
    stack::CallStackInfo,
    state::State,
    substate::Substate,
};
use cfx_statedb::Result as DbResult;
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, H256, U256,
};
use cfx_vm_types::{self as vm, ActionParams, Env, Spec};

/// The internal contracts need to access the context parameter directly, e.g.,
/// `foo(env, spec)`. But `foo(context.env(), context.spec())` will incur
/// lifetime issue. The `InternalRefContext` contains the parameters required by
/// the internal contracts.
pub struct InternalRefContext<'a> {
    pub env: &'a Env,
    pub spec: &'a Spec,
    pub callstack: &'a mut CallStackInfo,
    pub state: &'a mut State,
    pub substate: &'a mut Substate,
    pub tracer: &'a mut dyn TracerTrait,
    pub static_flag: bool,
    pub depth: usize,
    /// Reference to the Machine so internal contracts can access builtins.
    pub machine: &'a Machine,
}

// The following implementation is copied from `executive/context.rs`. I know
// it is not a good idea to implement the context interface again. We put it
// here temporarily.
impl<'a> InternalRefContext<'a> {
    pub fn log(
        &mut self, params: &ActionParams, spec: &Spec, topics: Vec<H256>,
        data: Vec<u8>,
    ) -> vm::Result<()> {
        use primitives::log_entry::LogEntry;

        if self.static_flag || self.callstack.in_reentrancy(spec) {
            return Err(vm::Error::MutableCallInStaticContext);
        }

        let address = params.address;
        self.substate.logs.push(LogEntry {
            address,
            topics,
            data,
            space: params.space,
        });

        Ok(())
    }

    pub fn set_storage(
        &mut self, params: &ActionParams, key: Vec<u8>, value: U256,
    ) -> vm::Result<()> {
        let receiver = params.address.with_space(params.space);
        self.state
            .set_storage(
                &receiver,
                key,
                value,
                params.storage_owner,
                self.substate,
            )
            .map_err(|e| e.into())
    }

    pub fn storage_at(
        &mut self, params: &ActionParams, key: &[u8],
    ) -> DbResult<U256> {
        let receiver = params.address.with_space(params.space);
        self.state.storage_at(&receiver, key).map_err(|e| e.into())
    }

    pub fn is_contract_address(&self, address: &Address) -> vm::Result<bool> {
        Ok(address.is_contract_address())
    }

    /// Call a builtin precompile directly from an internal contract.
    /// This uses the same builtin lookup and execution logic as normal EVM calls,
    /// but bypasses bytecode and directly invokes the native implementation.
    pub fn call_builtin(
        &mut self, address: &Address, input: &[u8],
    ) -> vm::Result<Vec<u8>> {
        use cfx_bytes::BytesRef;

        let addr_with_space = address.with_space(self.env.space);
        let block_number = self.env.number;

        let builtin = self
            .machine
            .builtin(&addr_with_space, block_number)
            .ok_or_else(|| {
                vm::Error::InternalContract("Builtin not found at address".into())
            })?;

        let cost = builtin.cost(input, self.spec);
        // For internal contract calls, we rely on outer gas accounting. Here we only
        // validate that builtin itself is well-defined; gas exhaustion will be
        // handled at higher layers if needed.
        let mut out_buf = Vec::new();
        let mut out_ref = BytesRef::Flexible(&mut out_buf);
        builtin
            .execute(input, &mut out_ref)
            .map_err(|e| vm::Error::BuiltIn(e.0))?;
        Ok(out_buf)
    }
}
