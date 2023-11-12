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
    use starknet::secp256_trait::{signature_from_vrs, recover_public_key};
    use starknet::eth_signature::verify_eth_signature;
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
            unicode_domain: Span<(u128, u128, u128)>,
            msg_hash: u256,
            signature: (u32, u256, u256), // (v: u32, r: u256, s: u256)
            herodotus_proof: felt252
        ) {
            // Assert message hashes match
            let hash = self.get_message_hash(unicode_domain, get_contract_address());
            assert(hash == msg_hash, 'Hashes do not match');

            // verify that signature corresponds to the hash
            let (v, r, s) = signature;
            let sig = signature_from_vrs(v, r, s);
        // Extract eth address from signature
        // match recover_public_key(msg_hash, sig) {
        //     Option::Some(eth_addr) => {
        //         // verify_eth_signature(msg_hash, sig, eth_addr)
        //     },
        //     Option::None => { panic('Could not recover public key'); }
        // };
        // todo:
        // assert msg_hash is hash('redeem .eth domain', eth_domain, caller_address)
        // verify that signature corresponds to the hash
        // signature_from_vrs
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
            // Compute the Keccak of the eth domain 
            let mut eth_domain = self.concat_eth_domain(unicode_domain);
            let mut eth_domain_bytes: Array::<u8> = ArrayTrait::new();
            loop {
                match eth_domain.pop_front() {
                    Option::Some(x) => { eth_domain_bytes.append(x.try_into().unwrap()); },
                    Option::None => { break; }
                }
            };
            let hashed_domain = keccak256(eth_domain_bytes.span());

            // Compute the keccak of the receiver address
            let receiver_arr = self.addr_to_dec_chars(receiver);
            let hashed_receiver = keccak256(receiver_arr.span());

            // Compute structHash
            // struct_hash = keccak(0x + 363a2f63f018f6691a4a91be3738af9474dfa08915515d488bbbe44023073b0b + hashed_domain + hashed_receiver)
            let concatenated_hashes = self
                .concat_hashes(
                    (
                        0x363a2f63f018f6691a4a91be3738af9474dfa08915515d488bbbe44023073b0b,
                        hashed_domain,
                        hashed_receiver,
                        0
                    )
                );
            let struct_hashes = keccak256(concatenated_hashes.span());

            // Compute message_hash
            // message_hash = 0x + keccak("0x1901${domain_hash}${struct_hash}")
            let concatenated_msg_hash = self
                .concat_hashes(
                    (
                        '1901',
                        0xa025b1a217bc84e4b217654aa94a85ca673637b23f990016df89f0acd7ca8834,
                        struct_hashes,
                        0
                    )
                );
            let message_hash = keccak256(concatenated_msg_hash.span());

            struct_hashes
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

        fn addr_to_bytes(self: @ContractState, addr: ContractAddress) -> Array<u8> {
            let felted: felt252 = addr.into();
            let byte_size: NonZero<u256> = 256_u256.try_into().unwrap();
            let to_add = self.div_rec(felted.into(), byte_size);
            to_add
        }

        fn div_rec(self: @ContractState, value: u256, divider: NonZero<u256>) -> Array<u8> {
            let (value, digit) = DivRem::div_rem(value, divider);
            let mut output = if value == 0 {
                Default::default()
            } else {
                self.div_rec(value, divider)
            };
            output.append(digit.try_into().unwrap());
            output
        }

        fn addr_to_dec_chars(self: @ContractState, addr: ContractAddress) -> Array<u8> {
            let felted: felt252 = addr.into();
            let ten: NonZero<u256> = 10_u256.try_into().unwrap();
            let to_add = self.ascii_div_rec(felted.into(), ten);
            to_add
        }

        fn ascii_div_rec(self: @ContractState, value: u256, divider: NonZero<u256>) -> Array<u8> {
            let (value, digit) = DivRem::div_rem(value, divider);
            let mut output = if value == 0 {
                Default::default()
            } else {
                self.ascii_div_rec(value, divider)
            };
            output.append(48 + digit.try_into().unwrap());
            output
        }

        fn concat_hashes(self: @ContractState, hashes: (u256, u256, u256, u256)) -> Array<u8> {
            let mut output = array!['0', 'x'];
            let (a, b, c, d) = hashes;
            let byte_size: NonZero<u256> = 256_u256.try_into().unwrap();
            self.append_div_rec(ref output, a, byte_size, 32);
            self.append_div_rec(ref output, b, byte_size, 32);
            self.append_div_rec(ref output, c, byte_size, 32);
            self.append_div_rec(ref output, d, byte_size, 32);
            output
        }

        fn append_div_rec(
            self: @ContractState,
            ref output: Array<u8>,
            value: u256,
            divider: NonZero<u256>,
            i: felt252
        ) {
            if i == 0 {
                return;
            }
            let (value, digit) = DivRem::div_rem(value, divider);
            self.append_div_rec(ref output, value, divider, i - 1);
            output.append(digit.try_into().unwrap());
        }
    }
}

