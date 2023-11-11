mod interface;

#[starknet::contract]
mod EthStarkResolver {
    use option::OptionTrait;
    use starknet::ContractAddress;
    use starknet::contract_address::ContractAddressZeroable;
    use starknet::{get_caller_address, get_contract_address, get_block_timestamp};
    use storage_read::{main::storage_read_component, interface::IStorageRead};
    use naming::interface::resolver::{IResolver, IResolverDispatcher, IResolverDispatcherTrait};
    use eth_stark_resolver::interface::IEnsMigrator;
    use starknet::secp256k1::Signature;

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        StorageReadEvent: storage_read_component::Event
    }

    #[derive(Drop, starknet::Event)]
    struct DomainMint {
        #[key]
        domain: felt252,
        owner: u128,
        expiry: u64
    }

    #[storage]
    struct Storage {
        #[substorage(v0)]
        storage_read: storage_read_component::Storage,
    }

    component!(path: storage_read_component, storage: storage_read, event: StorageReadEvent);

    #[abi(embed_v0)]
    impl StorageReadComponent = storage_read_component::StorageRead<ContractState>;

    #[external(v0)]
    impl ResolverImpl of IResolver<ContractState> {
        fn resolve(
            self: @ContractState, domain: Span<felt252>, field: felt252, hint: Span<felt252>
        ) -> felt252 {
            // todo: read the resolving set by the controler
            1
        }
    }

    #[external(v0)]
    impl IEnsMigratorImpl of IEnsMigrator<ContractState> {
        fn claim(
            ref self: ContractState,
            unicode_domain: Span<(felt252, felt252)>,
            msg_hash: u256,
            signature: Signature,
            herodotus_proof: felt252
        ) { // todo:
        // assert msg_hash is hash('redeem .eth domain', eth_domain, caller_address)
        // verify that signature corresponds to the hash
        // extract ethereum address from signature (using recover_public_key and derivating address?)
        // validate herodotus proof
        //  onverts domain from unicode_domain
        // write caller_address as controller of domain
        // emits an event saying that caller_address claimed domain
        }

        fn set_resolving(
            ref self: ContractState, domain: Span<felt252>, field: felt252, data: felt252
        ) { // ensure caller is controller
        // sets mapping read by resolve
        }
    }


    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn get_message_hash(
            self: @ContractState,
            unicode_domain: Span<(felt252, felt252)>,
            receiver: ContractAddress
        ) -> felt252 {
            1
        }

        fn build_eth_domain(unicode_domain: Span<(felt252, felt252)>) -> Array<felt252> {
            Default::default()
        }
    }
}

