mod test_hashing;

use array::ArrayTrait;
use starknet::{class_hash::Felt252TryIntoClassHash, ContractAddress, SyscallResultTrait};
use eth_stark_resolver::{EthStarkResolver, EthStarkResolver::InternalImpl, interface::IEnsMigrator};
use traits::TryInto;
use debug::PrintTrait;

#[test]
#[available_gas(20000000000)]
fn test_write_eth_domain() {
    let mut unsafe_state = EthStarkResolver::unsafe_new_contract_state();

    let domain = array![('alp', 'h', 'a'), ('bravo', 0, 0)];
    let output = EthStarkResolver::InternalImpl::concat_eth_domain(@unsafe_state, domain.span());

    assert(
        output == array!['a', 'l', 'p', 'h', 'a', '.', 'b', 'r', 'a', 'v', 'o', '.', 'e', 't', 'h'],
        'unexpected result'
    );
}
