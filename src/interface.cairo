use starknet::{ContractAddress, ClassHash};
use starknet::secp256k1::Signature;

#[starknet::interface]
trait IEnsMigrator<TContractState> {
    fn claim(
        ref self: TContractState,
        unicode_domain: Span<(u128, u128, u128)>,
        msg_hash: u256,
        signature: Signature,
        herodotus_proof : felt252
    );

    fn set_resolving(
        ref self: TContractState, domain: Span<felt252>, field: felt252, data: felt252
    );
}
