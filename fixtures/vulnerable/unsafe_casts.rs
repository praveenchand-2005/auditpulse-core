use soroban_sdk::{contractimpl, Address, Env};

pub struct CastVault;

#[contractimpl]
impl CastVault {
    pub fn process_stake(env: Env, user: Address, amount: i128) {
        env.require_auth();
        assert!(amount > 0);
        // Vulnerable: raw narrowing cast on amount-like identifier
        let stake_u64 = amount as u64;
        let fee_u32 = fee as u32;
        env.storage().persistent().set(&user, &stake_u64);
    }
}
