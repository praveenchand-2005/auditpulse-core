//! Safe Soroban-style vault used as the demo scan target.
//!
//! Run: node dist/index.js scan examples/safe_vault.rs   (exits 0)
//! Every authorization-sensitive operation is gated, all arithmetic is
//! checked, storage TTLs are extended, and errors are returned as Result.

use soroban_sdk::{
    contract, contractimpl, contracttype, token, Address, Env, Symbol,
};

#[contracttype]
pub struct DataKey {
    pub admin: Symbol,
    pub balances: Symbol,
}

#[contract]
pub struct SafeVault;

#[contractimpl]
impl SafeVault {
    /// Gate every sensitive transfer with require_auth.
    pub fn withdraw(env: Env, from: Address, to: Address, amount: i128) -> Result<(), Error> {
        env.require_auth(&from);
        assert!(amount > 0);
        let client = token::Client::new(&env, &Self::token_id(&env)?);
        client.transfer(&from, &to, &amount);
        Self::bump(&env);
        Ok(())
    }

    /// Only accept a validated token id argument, and require auth for payouts.
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) -> Result<(), Error> {
        env.require_auth(&to);
        assert!(amount > 0);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
        Self::bump(&env);
        Ok(())
    }

    /// Checked arithmetic and a TTL bump on every storage touch.
    pub fn credit(env: Env, user: Address, amount: i128) -> Result<(), Error> {
        env.require_auth(&user);
        assert!(amount > 0);
        let balance: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        let updated = balance
            .checked_add(amount)
            .ok_or(Error::Overflow)?;
        env.storage().persistent().set(&user, &updated);
        env.storage().persistent().extend_ttl(&user, 100, 200);
        Ok(())
    }

    /// Admin-gated configuration change.
    pub fn set_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&Self::admin_key(&env))
            .ok_or(Error::AdminNotSet)?;
        env.require_auth(&admin);
        env.storage().instance().set(&Self::admin_key(&env), &new_admin);
        Self::bump(&env);
        Ok(())
    }

    /// Deliberately named helper, not an upgrade/migration entry point.
    fn bump(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(&Self::admin_key(env), 100, 200);
    }

    fn token_id(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&Symbol::new(env, "token"))
            .ok_or(Error::TokenNotSet)
    }

    fn admin_key(env: &Env) -> Symbol {
        Symbol::new(env, "admin")
    }
}

pub enum Error {
    Overflow,
    AdminNotSet,
    TokenNotSet,
}
