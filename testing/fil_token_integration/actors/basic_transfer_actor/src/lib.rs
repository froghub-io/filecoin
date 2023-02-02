use cid::{multihash::Code, Cid};
use ethabi::ethereum_types::{H160, U256};
use ethabi::Token;
use frc42_dispatch::{match_method, method_hash};
use frc46_token::receiver::{FRC46TokenReceived, FRC46_TOKEN_TYPE};
use frc46_token::token::types::TransferParams;
use fvm_actor_utils::receiver::UniversalReceiverParams;
use fvm_ipld_blockstore::Block;
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_ipld_encoding::{de::DeserializeOwned, RawBytes, DAG_CBOR};
use fvm_sdk as sdk;
use fvm_shared::bigint::{BigInt, Sign};
use fvm_shared::IPLD_RAW;
use fvm_shared::{address::Address, bigint::Zero, econ::TokenAmount, error::ExitCode};
use sdk::NO_DATA_BLOCK_ID;

/// Grab the incoming parameters and convert from RawBytes to deserialized struct
pub fn deserialize_params<O: DeserializeOwned>(params: u32) -> O {
    let params = sdk::message::params_raw(params).unwrap().unwrap();
    let params = RawBytes::new(params.data);
    params.deserialize().unwrap()
}

#[derive(Serialize_tuple, Deserialize_tuple)]
struct TransferActorState {
    operator_address: Option<Address>,
    token_address: Option<Address>,
}

impl TransferActorState {
    fn load(cid: &Cid) -> Self {
        let data = sdk::ipld::get(cid).unwrap();
        fvm_ipld_encoding::from_slice::<Self>(&data).unwrap()
    }

    fn save(&self) -> Cid {
        let serialized = fvm_ipld_encoding::to_vec(self).unwrap();
        let block = Block { codec: DAG_CBOR, data: serialized };
        sdk::ipld::put(Code::Blake2b256.into(), 32, block.codec, block.data.as_ref()).unwrap()
    }
}

/// Implements a simple actor that can hold and transfer tokens
///
/// First operator to send it tokens will be saved and tokens from other operators will be rejected
///
/// Address of the token actor is also saved as this identifies the token type
///
/// After receiving some tokens, it does nothing until the Forward method is called by the initial operator
/// When Forward method is invoked, it will transfer the entire balance it holds to a given address
///
/// Forward requires the same operator to initiate transfer and will abort if the operator address doesn't match,
/// or if the receiver hook rejects the transfer
#[no_mangle]
fn invoke(input: u32) -> u32 {
    std::panic::set_hook(Box::new(|info| {
        sdk::vm::abort(ExitCode::USR_ASSERTION_FAILED.value(), Some(&format!("{info}")))
    }));

    let method_num = sdk::message::method_number();
    match_method!(method_num, {
        "Constructor" => {
            let initial_state = TransferActorState { operator_address: None, token_address: None };
            let cid = initial_state.save();
            sdk::sself::set_root(&cid).unwrap();

            NO_DATA_BLOCK_ID
        },
        "Receive" => {
            let mut state = TransferActorState::load(&sdk::sself::root().unwrap());
            // Received is passed a TokenReceivedParams
            let params: UniversalReceiverParams = deserialize_params(input);

            // reject if not an FRC46 token
            // we don't know how to inspect other payloads here
            if params.type_ != FRC46_TOKEN_TYPE {
                panic!("invalid token type, rejecting transfer");
            }

            // get token transfer data
            let token_params: FRC46TokenReceived = params.payload.deserialize().unwrap();

            // check the address, we'll remember the first operator and reject others later
            match state.operator_address {
                Some(operator) => {
                    let actor_id = sdk::actor::resolve_address(&operator).unwrap();
                    if actor_id != token_params.operator {
                        panic!("cannot accept from this operator");
                    }
                }
                None => {
                    state.operator_address = Some(Address::new_id(token_params.operator));
                    state.token_address = Some(Address::new_id(sdk::message::caller()));
                    let cid = state.save();
                    sdk::sself::set_root(&cid).unwrap();
                }
            }

            // all good, don't need to return anything
            NO_DATA_BLOCK_ID
        },
        "Forward" => {
            let state = TransferActorState::load(&sdk::sself::root().unwrap());

            let target: Address = deserialize_params(input);

            // match sender address to the one who operated the last transfer
            // if there's no address set, abort because we're expecting a transfer first
            match state.operator_address {
                Some(operator) => {
                    let actor_id = sdk::actor::resolve_address(&operator).unwrap();
                    if actor_id != sdk::message::caller() {
                        panic!("cannot accept from this operator");
                    }
                }
                None => panic!("no operator id set"),
            }

            // get our balance
            let self_address = Address::new_id(sdk::message::receiver());
            let balance_ret = sdk::send::send(&state.token_address.unwrap(), method_hash!("BalanceOf"),
                IpldBlock::serialize_cbor(&self_address).unwrap(), TokenAmount::zero()).unwrap();
            if !balance_ret.exit_code.is_success() {
                panic!("unable to get balance");
            }
            let balance = balance_ret.return_data.unwrap().deserialize::<TokenAmount>().unwrap();

            // transfer to target address
            // let params = TransferParams {
            //     to: target,
            //     amount: balance, // send everything
            //     operator_data: RawBytes::default(),
            // };
            // let transfer_ret = sdk::send::send(&state.token_address.unwrap(), method_hash!("Transfer"),
            //     IpldBlock::serialize_cbor(&params).unwrap(), TokenAmount::zero()).unwrap();
            // if !transfer_ret.exit_code.is_success() {
            //     panic!("transfer call failed");
            // }

            // transfer to target address
            let target_actor_id = sdk::actor::resolve_address(&target).unwrap();
            let bytes = ethabi::encode(&[Token::Address(address_to_h160(Address::new_id(target_actor_id)))
                    , Token::Uint(token_amount_to_u256(balance))]);
            let transfer_ret = sdk::send::send(&state.token_address.unwrap(), 0xa9059cbb,
                Some(IpldBlock{
                    data: bytes,
                    codec: DAG_CBOR,
                }), TokenAmount::zero()).unwrap();
            if !transfer_ret.exit_code.is_success() {
                panic!("transfer call failed");
            }

            // we could return the balance sent or something like that
            // but the test we run from is checking that already so no need to do it here
            NO_DATA_BLOCK_ID
        }
        _ => {
            sdk::vm::abort(
                ExitCode::USR_UNHANDLED_MESSAGE.value(),
                Some("Unknown method number"),
            );
        }
    })
}

fn h160_to_address(addr: H160) -> Address {
    let id = addr.to_low_u64_be();
    Address::new_id(id)
}

fn address_to_h160(addr: Address) -> H160 {
    H160::from_low_u64_be(addr.id().unwrap())
}

fn token_amount_to_u256(amount: TokenAmount) -> U256 {
    let (_, amount) = amount.atto().to_bytes_be();
    U256::from_big_endian(amount.as_slice())
}

fn u256_to_token_amount(amount: U256) -> TokenAmount {
    let mut big_endian = [0u8; 32];
    amount.to_big_endian(&mut big_endian);
    let amount = BigInt::from_bytes_be(Sign::Plus, &big_endian);
    TokenAmount::from_atto(amount)
}
