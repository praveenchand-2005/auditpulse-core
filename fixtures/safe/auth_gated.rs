//! Safe fixture: authorization ordering that must NOT be flagged by
//! AP-AUTH-001. Expected findings: none.
//!
//! Every sensitive operation executes after an auth check in the same
//! function. No storage writes and no external-call patterns without
//! boundaries, so the other rules stay silent as well.

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct GatedVault;

#[contractimpl]
impl GatedVault {
    /// Auth before a token transfer with amount check.
    pub fn withdraw(env: Env, token: Address, to: Address, amount: i128) {
        env.require_auth(&to);
        assert!(amount > 0);
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// Auth for explicit args before a token burn with amount check.
    pub fn burn_rewards(env: Env, token: Address, holder: Address, amount: i128) {
        env.require_auth_for_args(&holder, &(holder.clone(), amount.clone()));
        assert!(amount > 0);
        let client = token::Client::new(&env, &token);
        client.burn(&holder, &amount);
    }

    /// Receiver-form auth before a storage write.
    pub fn set_fee(env: Env, admin: Address, fee: u32) {
        admin.require_auth();
        env.storage().instance().set(&KEY_FEE, &fee);
        env.storage().instance().extend_ttl(&KEY_FEE, 100, 200);
    }
}
