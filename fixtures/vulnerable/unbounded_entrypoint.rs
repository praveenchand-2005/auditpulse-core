use soroban_sdk::{contractimpl, Address, Env};

pub struct UnboundedVault;

#[contractimpl]
impl UnboundedVault {
    pub fn deposit(env: Env, from: Address, amount: i128) {
        env.require_auth();
        // Vulnerable: no bound check on amount (e.g. assert!(amount > 0))
        let client = token::Client::new(&env, &token_id);
        client.transfer(&from, &env.current_contract_address(), &amount);
    }
}
