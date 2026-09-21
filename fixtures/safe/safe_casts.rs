use soroban_sdk::{contractimpl, Address, Env};

pub struct SafeCastVault;

#[contractimpl]
impl SafeCastVault {
    pub fn process_stake(env: Env, user: Address, amount: i128) -> Result<(), ()> {
        env.require_auth(&user);
        assert!(amount > 0);
        // Safe: using try_into and checked conversion
        let stake_u64: u64 = amount.try_into().map_err(|_| ())?;
        env.storage().persistent().set(&user, &stake_u64);
        env.storage().persistent().extend_ttl(&user, 100, 200);
        Ok(())
    }
}
