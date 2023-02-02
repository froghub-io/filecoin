use std::env;

use basic_token_actor::MintParams;
use cid::Cid;
use ethers::abi::{AbiDecode, AbiEncode, ParamType, Token as ETHToken};
use ethers::types::{BigEndianHash, H256, U256};
use ethers::utils::keccak256;
use frc42_dispatch::method_hash;
use frc46_token::token::{state::TokenState, types::MintReturn};
use fvm::executor::{ApplyKind, Executor};
use fvm_integration_tests::bundle;
use fvm_integration_tests::dummy::DummyExterns;
use fvm_integration_tests::tester::{Account, Tester};
use fvm_ipld_blockstore::MemoryBlockstore;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use fvm_shared::bigint::{BigInt, Sign, Zero};
use fvm_shared::econ::TokenAmount;
use fvm_shared::message::Message;
use fvm_shared::state::StateTreeVersion;
use fvm_shared::version::NetworkVersion;

const BASIC_TOKEN_ACTOR_WASM: &str =
    "../../target/debug/wbuild/basic_token_actor/basic_token_actor.compact.wasm";
const BASIC_RECEIVER_ACTOR_WASM: &str =
    "../../target/debug/wbuild/basic_receiving_actor/basic_receiving_actor.compact.wasm";

#[test]
fn it_mints_tokens() {
    let blockstore = MemoryBlockstore::default();
    let bundle_root = bundle::import_bundle(&blockstore, actors_v10::BUNDLE_CAR).unwrap();
    let mut tester =
        Tester::new(NetworkVersion::V15, StateTreeVersion::V4, bundle_root, blockstore.clone())
            .unwrap();

    let minter: [Account; 1] = tester.create_accounts().unwrap();

    // Get wasm bin
    let wasm_path =
        env::current_dir().unwrap().join(BASIC_TOKEN_ACTOR_WASM).canonicalize().unwrap();
    let wasm_bin = std::fs::read(wasm_path).expect("Unable to read token actor file");
    let rcvr_path =
        env::current_dir().unwrap().join(BASIC_RECEIVER_ACTOR_WASM).canonicalize().unwrap();
    let rcvr_bin = std::fs::read(rcvr_path).expect("Unable to read receiver actor file");

    // Set actor state
    let actor_state = TokenState::new(&blockstore).unwrap(); // TODO: this should probably not be exported from the package
    let state_cid = tester.set_state(&actor_state).unwrap();

    let token_actor_id = 10000;
    let actor_address = Address::new_id(token_actor_id);
    let receive_actor_id = 10010;
    let receive_address = Address::new_id(receive_actor_id);
    tester.set_actor_from_bin(&wasm_bin, state_cid, actor_address, TokenAmount::zero()).unwrap();
    tester
        .set_actor_from_bin(&rcvr_bin, Cid::default(), receive_address, TokenAmount::zero())
        .unwrap();

    // Instantiate machine
    tester.instantiate_machine(DummyExterns).unwrap();

    // Helper to simplify sending messages
    let mut sequence = 0u64;
    let mut call_method = |from, to, method_num, params| {
        let message = Message {
            from,
            to,
            gas_limit: 99999999,
            method_num,
            sequence,
            params: if let Some(params) = params { params } else { RawBytes::default() },
            ..Message::default()
        };
        sequence += 1;
        tester
            .executor
            .as_mut()
            .unwrap()
            .execute_message(message, ApplyKind::Explicit, 100)
            .unwrap()
    };

    // Construct the token actor
    let ret_val = call_method(minter[0].1, actor_address, method_hash!("Constructor"), None);
    println!("token actor constructor return data: {:#?}", &ret_val);

    let ret_val = call_method(minter[0].1, receive_address, method_hash!("Constructor"), None);
    println!("receiving actor constructor return data: {:#?}", &ret_val);

    // Mint some tokens
    let mint_params = MintParams {
        initial_owner: receive_address,
        amount: TokenAmount::from_atto(100),
        operator_data: RawBytes::default(),
    };
    let params = RawBytes::serialize(mint_params).unwrap();
    let ret_val = call_method(minter[0].1, actor_address, method_hash!("Mint"), Some(params));
    println!("mint return data {:#?}", &ret_val);
    let return_data = ret_val.msg_receipt.return_data;
    if return_data.is_empty() {
        println!("return data was empty");
    } else {
        let mint_result: MintReturn = return_data.deserialize().unwrap();
        println!("new total supply: {:?}", &mint_result.supply);
    }

    // Transfer some tokens
    let params =
        (ethers::types::Address::from_low_u64_be(receive_actor_id), U256::from(0)).encode();
    let params = RawBytes::new(params);
    let method_num = u32::from_be_bytes(
        keccak256(b"transfer(address,uint256)")[..4]
            .try_into()
            .expect("bytes was not at least length 4"),
    );
    let ret_val = call_method(minter[0].1, actor_address, method_num as u64, Some(params));
    println!("transfer return data {:#?}", &ret_val);
    let return_data = ret_val.msg_receipt.return_data;
    if return_data.is_empty() {
        println!("return data was empty");
    } else {
        let result = bool::decode(return_data.bytes()).unwrap();
        println!("transfer: {}", result);
    }

    // Check balance(ERC20)
    let params = RawBytes::new(ethers::types::Address::from_low_u64_be(receive_actor_id).encode());
    let method_num = u32::from_be_bytes(
        keccak256(b"balanceOf(address)")[..4].try_into().expect("bytes was not at least length 4"),
    );
    let ret_val = call_method(minter[0].1, actor_address, method_num as u64, Some(params));
    println!("balanceOf return data {:#?}", &ret_val);
    let return_data = ret_val.msg_receipt.return_data;
    if return_data.is_empty() {
        println!("return data was empty");
    } else {
        let result = ethers::types::U256::decode(return_data.bytes()).unwrap();
        println!("balanceOf: {}", result);

        println!("balanceOf: {:?}", u256_to_token_amount(result));
    }

    // Check balance
    // let params = RawBytes::serialize(receive_address).unwrap();
    // let ret_val = call_method(minter[0].1, actor_address, method_hash!("BalanceOf"), Some(params));
    // println!("balance return data {:#?}", &ret_val);

    // let return_data = ret_val.msg_receipt.return_data;
    // let balance: TokenAmount = return_data.deserialize().unwrap();
    // println!("balance: {balance:?}");
}

fn u256_to_token_amount(amount: U256) -> TokenAmount {
    let mut big_endian = [0u8; 32];
    amount.to_big_endian(&mut big_endian);
    let amount = BigInt::from_bytes_be(Sign::Plus, &big_endian);
    TokenAmount::from_atto(amount)
}
