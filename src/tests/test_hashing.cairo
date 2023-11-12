use core::traits::TryInto;
use core::option::OptionTrait;
use core::array::ArrayTrait;
use starknet::testing;
use debug::PrintTrait;
use starknet::{ContractAddress, contract_address_const};

use eth_stark_resolver::EthStarkResolver;
use eth_stark_resolver::EthStarkResolver::InternalImpl;


#[test]
#[available_gas(20000000000)]
fn test_hash() {
    let mut unsafe_state = EthStarkResolver::unsafe_new_contract_state();

    let receiver_addr: ContractAddress = contract_address_const::<
        0x01c744953f1d671673f46a9179a58a7e58d9299499b1e076cdb908e7abffe69f
    >();

    let hash = InternalImpl::get_message_hash(
        @unsafe_state, array![('riton', 0, 0)].span(), receiver_addr
    );

    hash.print();
// let test: felt252 = hash.try_into().unwrap();
// test.print();
}
