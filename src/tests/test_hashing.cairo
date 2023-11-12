use eth_stark_resolver::interface::IEnsMigrator;
use core::traits::TryInto;
use core::option::OptionTrait;
use core::array::ArrayTrait;
use starknet::testing;
use debug::PrintTrait;
use starknet::{ContractAddress, contract_address_const};
use starknet::testing::set_contract_address;

use eth_stark_resolver::EthStarkResolver;
use eth_stark_resolver::EthStarkResolver::InternalImpl;


#[test]
#[available_gas(20000000000)]
fn test_hash() {
    let mut unsafe_state = EthStarkResolver::unsafe_new_contract_state();

    let receiver_addr: ContractAddress = contract_address_const::<
        0x01c744953f1d671673f46a9179a58a7e58d9299499b1e076cdb908e7abffe69f
    >();
    let msg_hash: u256 = 0xd90ea27cafdcfd6b14f85560c11b84f834f808010de102c0b45b81b815847011;
    let hash = InternalImpl::get_message_hash(
        @unsafe_state, array![('riton', 0, 0)].span(), receiver_addr
    );
    assert(hash == msg_hash, 'unexpected result');
}

#[test]
#[available_gas(20000000000)]
fn test_claim() {
    let mut unsafe_state = EthStarkResolver::unsafe_new_contract_state();
    let unicode_domain = array![('riton', 0, 0)];
    let msg_hash: u256 = 0xd90ea27cafdcfd6b14f85560c11b84f834f808010de102c0b45b81b815847011;
    let signature: (u32, u256, u256) = (
        28,
        u256 {
            low: 264458328843289448807540486485984279057,
            high: 175010475074688131746407571080189183465
        },
        u256 {
            low: 71637454079598667298175776862993069603,
            high: 158880397047593632344396121506762609741
        },
    );
    let receiver_addr: ContractAddress = contract_address_const::<
        0x01c744953f1d671673f46a9179a58a7e58d9299499b1e076cdb908e7abffe69f
    >();
    set_contract_address(receiver_addr);

    unsafe_state.claim(unicode_domain.span(), msg_hash, signature, 0);
}

