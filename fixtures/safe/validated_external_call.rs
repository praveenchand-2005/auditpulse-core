//! Safe fixture: cross-contract calls that must NOT be flagged by
//! AP-CALL-001. Expected findings: none.
//!
//! Both entrypoints carry env.require_auth; withdraw also shows the
//! authenticated pattern, sweep shows a validated token id argument.

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct SafeBridge;

#[contractimpl]
impl SafeBridge {
    /// Authenticated transfer: require_auth is the boundary.
    pub fn withdraw(env: Env, token: Address, to: Address, amount: i128) {
        env.require_auth(&to);
        assert!(amount > 0);
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// Validated token id plus auth: both boundaries present.
    pub fn sweep(env: Env, token_id: Address, to: Address, amount: i128) {
        env.require_auth(&to);
        assert!(amount > 0);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
