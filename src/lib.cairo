mod interface;
#[cfg(test)]
mod tests;

#[starknet::contract]
mod EthStarkResolver {
    use core::array::ArrayTrait;
    use core::array::SpanTrait;
    use option::OptionTrait;
    use starknet::ContractAddress;
    use starknet::contract_address::ContractAddressZeroable;
    use starknet::{get_caller_address, get_contract_address, get_block_timestamp};
    use storage_read::{main::storage_read_component, interface::IStorageRead};
    use encoder::{main::encoder_component, interface::IEncoder};
    use naming::interface::resolver::{IResolver, IResolverDispatcher, IResolverDispatcherTrait};
    use eth_stark_resolver::interface::IEnsMigrator;
    use starknet::secp256k1::Signature;
    use core::keccak::cairo_keccak;
    use traits::{Into, TryInto};
    use alexandria_math::keccak256::keccak256;

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        StorageReadEvent: storage_read_component::Event,
        EncoderEvent: encoder_component::Event
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
        #[substorage(v0)]
        encoder_storage: encoder_component::Storage,
    }

    component!(path: storage_read_component, storage: storage_read, event: StorageReadEvent);
    component!(path: encoder_component, storage: encoder_storage, event: EncoderEvent);

    #[abi(embed_v0)]
    impl StorageReadComponent = storage_read_component::StorageRead<ContractState>;
    #[abi(embed_v0)]
    impl encoderImpl = encoder_component::Encoder<ContractState>;

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
        ) { // eth_address 
        // signature = (u256, u256, u256) - r, s, v from eth Signature 
        // todo: message hash to recreate 

        // let mut eth_domain = array![];
        // let mut unicode_domain = unicode_domain;
        // loop {
        //     match unicode_domain.pop_front() {
        //         Option::Some(domain) => { eth_domain.append(self.encode(*domain)); },
        //         Option::None => { break; }
        //     }
        // };
        // todo:
        // assert msg_hash is hash('redeem .eth domain', eth_domain, caller_address)
        // verify that signature corresponds to the hash
        // extract ethereum address from signature (using recover_public_key and derivating address?)
        // validate herodotus proof
        //  converts domain from unicode_domain
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
            unicode_domain: Span<(u128, u128, u128)>,
            receiver: ContractAddress
        ) -> u256 {
            // let domain_hash: felt252 =
            //     a025b1a217bc84e4b217654aa94a85ca673637b23f990016df89f0acd7ca8834;

            // val1 = 363a2f63f018f6691a4a91be3738af9474dfa08915515d488bbbe44023073b0b
            // keccak(ethereum_domain)
            // riton.eth
            // 57c49d6978302dafb27c1af60e9f6d5aa710f2547867b8637239efdac1f55577

            // let receiver_felt: felt252 = receiver.into();
            // let receiver_u256: u256 = receiver_felt.try_into().unwrap();
            // let hashed_receiver = keccak_u256s_le_inputs(vec![receiver_u256]);
            // keccak(receiver)
            // let hash = keccak_u256s_le_inputs();

            // let receiver_felt: felt252 = receiver.into();
            // let receiver_u256: u256 = receiver_felt.into();
            // let hashed_receiver = keccak256(array![1].span());
            let mut eth_domain = ArrayTrait::new();
            self.write_eth_domain(ref eth_domain, unicode_domain);
            let hashed_domain = keccak256(eth_domain.span());
            hashed_domain
        }

        fn concat_eth_domain(
            self: @ContractState, mut unicode_domain: Span<(u128, u128, u128)>
        ) -> Array<felt252> {
            let mut bytes_stream = Default::default();
            loop {
                match unicode_domain.pop_front() {
                    Option::Some(x) => {
                        let (first, second, third) = *x;
                        self.rec_add_chars(ref bytes_stream, 16, first);
                        self.rec_add_chars(ref bytes_stream, 16, second);
                        self.rec_add_chars(ref bytes_stream, 16, third);
                        bytes_stream.append('.');
                    },
                    Option::None => { break; }
                }
            };
            bytes_stream.append('e');
            bytes_stream.append('t');
            bytes_stream.append('h');
            bytes_stream
        }

        fn rec_add_chars(
            self: @ContractState, ref arr: Array<felt252>, str_len: felt252, str: u128
        ) {
            if str_len == 0 {
                return;
            }
            let (str, char) = DivRem::div_rem(str, 256_u128.try_into().unwrap());
            self.rec_add_chars(ref arr, str_len - 1, str);
            if char != 0 {
                arr.append(char.into());
            }
        }
    }
}

