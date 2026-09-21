use soroban_sdk::{contractimpl, Address, Env};

pub struct BoundedVault;

#[contractimpl]
impl BoundedVault {
    pub fn deposit(env: Env, from: Address, amount: i128) {
        env.require_auth();
        assert!(amount > 0, "amount must be positive");
        let client = token::Client::new(&env, &token_id);
        client.transfer(&from, &env.current_contract_address(), &amount);
    }
}
