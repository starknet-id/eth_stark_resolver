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
// assert(
//     hash == u256 {
//         low: 0xbf559c27341fa72061a0b7756f6211cd, high: 0x31da66731ad95669df4e3be9ff19a8da
//     },
//     'unexpected result'
// )
}

#[test]
#[available_gas(20000000000)]
fn test_claim() {
    let mut unsafe_state = EthStarkResolver::unsafe_new_contract_state();
    let unicode_domain = ('riton', 0, 0);
    let msg_hash: u256 = 0xd90ea27cafdcfd6b14f85560c11b84f834f808010de102c0b45b81b815847011;
    let signature: (u32, u256, u256) = (
        28,
        u256 {
            low: 261931949998748776939267404548129803226,
            high: 13201864247169148976061489895718339987
        },
        u256 {
            low: 137716299578801269734426610133052649767,
            high: 7791505619358039735595296269689348135
        },
    );
}

