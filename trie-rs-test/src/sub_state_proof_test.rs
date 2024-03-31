#![allow(unused_imports)]
#![allow(dead_code)]

use std::str::FromStr;

use codec::{Decode, Encode};
use ibc_proto::protobuf::Protobuf;
use sp_core::H256;

use hex_literal::hex;
use sp_core::sp_std;
use sp_trie::{LayoutV0, StorageProof, Trie, TrieDBBuilder, LayoutV1, NodeCodec};
use trie_db::{node::OwnedNode, NibbleSlice};
use tendermint::Time;
use ibc::core::{
		ics02_client::{client_type::ClientType, height::Height,consensus_state::ConsensusState,},
		ics03_connection::connection::ConnectionEnd,
		ics04_channel::{
			channel::ChannelEnd,
			commitment::{
				AcknowledgementCommitment as IbcAcknowledgementCommitment,
				PacketCommitment as IbcPacketCommitment,
			},
			packet::{Receipt, Sequence},
		},
		ics24_host::{
			identifier::{ChannelId, ClientId, ConnectionId, PortId},
			path::{
				AcksPath, ChannelEndsPath, ClientConsensusStatePath, ClientStatePath,
				ClientTypePath, CommitmentsPath, ConnectionsPath, ReceiptsPath, SeqAcksPath,
				SeqRecvsPath, SeqSendsPath,
			},
		},
        

	};
use ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensueState;
use ibc_proto::ibc::lightclients::tendermint::v1::ConsensusState as RawConsensusState;
// use ibc_relayer::consensus_state::AnyConsensusState;

#[tokio::test]
pub async fn timestamp_state_proof() -> Result<(), Box<dyn std::error::Error>> {
     // data soure: https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Frococo-rpc.polkadot.io#/explorer
    // number: 5,310,899
    // block hash: 0x6ba6142dd1848d98975b329219204f95382d50febefc3a2007c231d87a1efd93
    // block header stateRoot: 0x3b903e9947f26c4455f213b648661d0ef9b30018da7fa7be76bb5af2f5f75735
    let state_root = H256::from(hex!(
        "3b903e9947f26c4455f213b648661d0ef9b30018da7fa7be76bb5af2f5f75735"
    ));

    // module: timestamp 
    // method: now
    // encoded storage key: 0xf0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb
    let encode_storage_key = hex!("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb").to_vec();
    // expected value : 1,683,620,592,000
    let expected_value:u64 = 1683620592000;
    let proof = vec![
        hex!("80250280e63ff4b1e709ddffd66713e719eb07ed14c3aaad9300f107b71fb9084abf7bd4800745b13a8c766390f40cb9ca8613b923a26ec1e907ee258901e601c8efecd6128013091af7728a82797701a74ad422b19ebc8a9ebd067d03af98d3417216175ff98022a699b2cc90a6654c84163d2a498506b192afe7cd9777227e5288e8ff069c0f").to_vec(),
        hex!("80ffff80fe86a6cb12b2233729f7834ff614d56c968207d9ae09266cd3835e32fc7bbdba80ee3fa56aef90d79d5a7c8e5f6e85252288631533a5a8ebf405846bdc3cedcaf38019c7f105c5c4278d8f4b5a67adb644c0d4b056b6affbe8721df8ce54865e8fe8800b223e5d94298635855f517e49a2e925d4e39de3e27ff1af06b658de5a2e8280804165dde7158903211dc880ebc441e6fc3ef9f8a1c5f99fd261178c4e97206805808dcd7a042792b39ad7fcbd97e77273b3d0b250c3203398f7290a7d3e0d7cc20c807c3fac76e1315865f8e8fcda6748711a415fc87187794acba9584b2c151b956080091b6db629efcf3857b17a2df2fa8b296c5aedc80db088f4e6a560053c7ce890803e5026745b944d7fa9a39c6f08292b88efbaec1e1041ccd78348053881c1bf86800451959b47e46ecdb0edd2df37445db0a629898058bae12a73ad88379a130fe080f52d9d5dfa99ec1762f86ca9b229e11e8f7910633e1032ece9c89e28892397a4805e6def858a456048697cbdb9af83fc447c671b0cf283f1409400f3a6c506321f80f8093e29566bd8ebec39521f87c10156d1c424a767aadecd231adf5c55f5f538806075e1c36fcba711bb56da63b85b31fdf481041a0acb93b035a6ebb9987734f4808f0cfeb4e4785d0fcb162883963e55e8cbc49c2398f1f275cfe5d2484bac2f9780b063dd4a5cd6b883c54ff93751d114e20e99e2e05eff766ddcca317b67d4f08a").to_vec(),
        hex!("9ec365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb2080799bff87010000").to_vec(),
        
    ];
    let db = StorageProof::new(proof).into_memory_db::<sp_runtime::traits::BlakeTwo256>();
    // type LayoutV0 = LayoutV0<Blake2Hasher>;
    let trie =
        TrieDBBuilder::<LayoutV0<sp_runtime::traits::BlakeTwo256>>::new(&db, &state_root).build();

    // let trie = sp_trie::TrieDB::<sp_trie::LayoutV0<Blake2Hasher>>::new(&db, &state_root)
    //     .unwrap();

    let value = trie.get_with(&encode_storage_key, |v: &[u8]| v.to_vec()).unwrap().unwrap(); // actually gets the value from the trie proof
    println!("the key value: {:?}", value);

   

    let timestamp: u64 = codec::Decode::decode(&mut &value[..]).unwrap();
    println!("timestamp from proof: {}", timestamp);
    assert_eq!(timestamp,expected_value);

    use sp_std::time::Duration;
    let duration = Duration::from_millis(timestamp);
    println!(" duration = {:?}", duration);

    let tm_timestamp =
        Time::from_unix_timestamp(duration.as_secs() as i64, duration.subsec_nanos());
    println!("tm_timestamp = {:?}", tm_timestamp);

    let timestamp_str = tm_timestamp.unwrap().to_rfc3339();
    println!("timestamp_str = {:?}", timestamp_str);
    

    Ok(())

}

#[tokio::test]
pub async fn parachain_header_state_proof() -> Result<(), Box<dyn std::error::Error>> {
    // data soure: https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Frococo-rpc.polkadot.io#/explorer
    // number: 5,310,899
    // block hash: 0x6ba6142dd1848d98975b329219204f95382d50febefc3a2007c231d87a1efd93
    // block header stateRoot: 0x3b903e9947f26c4455f213b648661d0ef9b30018da7fa7be76bb5af2f5f75735
    let state_root = H256::from(hex!(
        "3b903e9947f26c4455f213b648661d0ef9b30018da7fa7be76bb5af2f5f75735"
    ));

    // module: paras 
    // method: heads
    // encoded storage key: 0xcd710b30bd2eab0352ddcc26417aa1941b3c252fcb29d88eff4f3de5de4476c3b6ff6f7d467b87a9e8030000
    let encode_storage_key = hex!("cd710b30bd2eab0352ddcc26417aa1941b3c252fcb29d88eff4f3de5de4476c3b6ff6f7d467b87a9e8030000").to_vec();
    // paras.heads: Option<Bytes>
    // 0x116a2811eaaa372fcd8c769b5f433d3995872b21c468dcfc6270e1f9fa07167eaa4c7c00f5f981c0b4dafe3c1029e70fb290294fc21f040197ac00f209dbf659a97bd83f7dc3fc42e985905ea2313b2551b72692510e9744493bd525055e27e295948a110806617572612092d55c08000000000561757261010116fd4fedb8ecd8eba0d907b7bd534b260bc0b86a0e9a1fd8f18cb85e9073f442a6a9f5460bfb2443bce67b8fdba17bbd2927bdad8fc6ae021c03e2c8b3e33e89
    let encode_parachain_header = hex!("116a2811eaaa372fcd8c769b5f433d3995872b21c468dcfc6270e1f9fa07167eaa4c7c00f5f981c0b4dafe3c1029e70fb290294fc21f040197ac00f209dbf659a97bd83f7dc3fc42e985905ea2313b2551b72692510e9744493bd525055e27e295948a110806617572612092d55c08000000000561757261010116fd4fedb8ecd8eba0d907b7bd534b260bc0b86a0e9a1fd8f18cb85e9073f442a6a9f5460bfb2443bce67b8fdba17bbd2927bdad8fc6ae021c03e2c8b3e33e89").to_vec();
    println!("encode_parachain_header:{:?}", encode_parachain_header);

    let proof = vec![
        hex!("36ff6f7d467b87a9e803000021590f48b11891aee1f281f856256f37a20f8abc5d027434f89dd2decab922fe").to_vec(),
        hex!("800464801861be085002d2b0498ea992b13cfb1ca6b5e05a7ca54f6180dcc1bcd10a9f0680f6f6801e4b41e2e6d8ec194dba122bfb9eb33feb2545ef5144cea79551f7cc5280f6370779a48f025599265f348f955ee0b12eeb99238950c07f5562091f2186d48043e819b824d89dc6e744b5342c963829d44a93a1bdad2405615856f67945c9e0").to_vec(),
        hex!("80cf93807b212eaf64882b542230cc1fa87d9505181a516c0dfd67ac55d3158cd753f8ad80862c9aecf51563f0b4f54f6d2a325bec9afdf62a66f595e150203fd9a144b1e580c2fb34bc8b88011ab509fd52c25b3469bbc9353f472a05decd83449af1e3677d80ecbe9453c51b405848014efabda8a0cde4b9458e7c26a4d9eeb589c52bdb5eb1809c43b10cb7509edfd059982f30f20ba7368bbd82786184cf0a5be813cd07490a8088d755e63972295bd4772b7322e27adb3358090fc2f16c66e65341de0d9bd22980891eac33e3ee82a64283ab12370710911e866576869040634657bcc78a1385a180a4c9385e359a9977574174c4d31beab6206a569ad15ef435bf784f16623e1d21802e89324e6a5e0be929b37bb44bdbf6619e6af80cbdebc9bd67a44c8aa072ef3980d8eabbfa85a6309a2ff6dac1a06e6a6d214faba34887e6f8e14c0d0d1858711e").to_vec(),
        hex!("80ffff80fe86a6cb12b2233729f7834ff614d56c968207d9ae09266cd3835e32fc7bbdba80ee3fa56aef90d79d5a7c8e5f6e85252288631533a5a8ebf405846bdc3cedcaf38019c7f105c5c4278d8f4b5a67adb644c0d4b056b6affbe8721df8ce54865e8fe8800b223e5d94298635855f517e49a2e925d4e39de3e27ff1af06b658de5a2e8280804165dde7158903211dc880ebc441e6fc3ef9f8a1c5f99fd261178c4e97206805808dcd7a042792b39ad7fcbd97e77273b3d0b250c3203398f7290a7d3e0d7cc20c807c3fac76e1315865f8e8fcda6748711a415fc87187794acba9584b2c151b956080091b6db629efcf3857b17a2df2fa8b296c5aedc80db088f4e6a560053c7ce890803e5026745b944d7fa9a39c6f08292b88efbaec1e1041ccd78348053881c1bf86800451959b47e46ecdb0edd2df37445db0a629898058bae12a73ad88379a130fe080f52d9d5dfa99ec1762f86ca9b229e11e8f7910633e1032ece9c89e28892397a4805e6def858a456048697cbdb9af83fc447c671b0cf283f1409400f3a6c506321f80f8093e29566bd8ebec39521f87c10156d1c424a767aadecd231adf5c55f5f538806075e1c36fcba711bb56da63b85b31fdf481041a0acb93b035a6ebb9987734f4808f0cfeb4e4785d0fcb162883963e55e8cbc49c2398f1f275cfe5d2484bac2f9780b063dd4a5cd6b883c54ff93751d114e20e99e2e05eff766ddcca317b67d4f08a").to_vec(),
        hex!("9e710b30bd2eab0352ddcc26417aa1945fcb801998fc2315e4329c3d3c59ff787fef52f1707abcf997f8114a016594b6716ce8803a5b05f6d48162e04748dce0050d00025c0d51a4845ea2119f66952522b2cd2b80549fd5090d980b3ae9b1b61196d5f617c57b2f4e5eb5f2e51e4c5c857429363180196a38280fc3af7f724552363e4833e604127b44cb46271dd28151765bb91cf0505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f03c716fb8fff3de61a883bb76adb34a2040080ae1c868ee54941861f121640db72e895211b6748da302cc4ddf39f715c76e7528052e248e38ba2e7f604c09c090bfb8abc6bc68c2f92f34f454606b4a63102e58a8026a2dd112b0ca67351d4abb723dc41978d5865dd4b208b37eed5200bbc0ba0f4807bd51e23ee41e85d99c3985aa8b0f859f70f20fa783b7055b5161adfc69e2d5180a6a96fae992961a174ea36d7e23e69c08d45ecacc82e14fbc3546b8d60ceae48").to_vec(),
        hex!("9f0b3c252fcb29d88eff4f3de5de4476c3ffff8076bed1a9045e1937ab7ad7cff6e667c66351022b28103771310fa09e0a07708f808ff91cb4e274aa25177bbea2d77d5693f3da34820ecb82d6a06529de8bc0beb580b51c90d98a3cc501566107ce9b89e91609de184f72c521efe2e2486beb095dc280af5427f678c5055f4039369c53aaa785a3767ba10cf2e42b5cc9b625d8021bca8044ea5b04397b504579d34a01419b6f0fb0c4f3003b3e6e0b99687cc88f398670803d46b9972edc81cd44df296d227eafde0abd880a53ea37632ddb558e913315e68010a7cfabb7bf234b6efd0fba3d30758e762ec52d14d329e0b9ebd5c84ec7752680c9b8e0f77483284d53f3ccb7ca3a217faa9b50a819cfa557438cfa9813306910809bb471046c73d5edf5683b4e3408714f428ecdf8c447e80f8335b4049e555c2e80fd2a0bea95ba513ddd672bdd9d9fbfd1c9588731d06e9afa5004332250054ea180263061f7d953b0fba1d98b9c6529ce6c1d78af0012180caccb388c4921216de1803543b7e854863de08e6ce77ac171ecec6b64d419e58d6171fe654ee279b5f8c28061cd0a2e641fbce3fd78bad7f2b298918a187aca625491c1a1898763705840fa807aa5071686a8d5d83f8db3531aaaa181ea3843746bfc7917193b1dfcfbb0c49b8065ad311a5eb95c25f400fd199f1005a4ba6f62a7049117e9466dba91c1df949d80aa704996ec32908132b67245030b4d8456c46415837150ef58898df6b9b0ce5e").to_vec(),
        hex!("e902116a2811eaaa372fcd8c769b5f433d3995872b21c468dcfc6270e1f9fa07167eaa4c7c00f5f981c0b4dafe3c1029e70fb290294fc21f040197ac00f209dbf659a97bd83f7dc3fc42e985905ea2313b2551b72692510e9744493bd525055e27e295948a110806617572612092d55c08000000000561757261010116fd4fedb8ecd8eba0d907b7bd534b260bc0b86a0e9a1fd8f18cb85e9073f442a6a9f5460bfb2443bce67b8fdba17bbd2927bdad8fc6ae021c03e2c8b3e33e89").to_vec(),
        
    ];
    let db = StorageProof::new(proof).into_memory_db::<sp_runtime::traits::BlakeTwo256>();
    // type LayoutV0 = LayoutV0<Blake2Hasher>;
    let trie =
        TrieDBBuilder::<LayoutV1<sp_runtime::traits::BlakeTwo256>>::new(&db, &state_root).build();

    // let trie = sp_trie::TrieDB::<sp_trie::LayoutV0<Blake2Hasher>>::new(&db, &state_root)
    //     .unwrap();

    let value = trie.get_with(&encode_storage_key, |v: &[u8]| v.to_vec()).unwrap().unwrap(); // actually gets the value from the trie proof
    println!("The encoded Value from trie :\n{:?}", value);
    
    let decode_value :Vec<u8>= codec::Decode::decode(&mut &value[..]).unwrap();
    
    println!("get decode header bytes from trie proof value:\n0x{}", hex::encode(decode_value.clone()));
    println!("expected header:\n{}", "0x116a2811eaaa372fcd8c769b5f433d3995872b21c468dcfc6270e1f9fa07167eaa4c7c00f5f981c0b4dafe3c1029e70fb290294fc21f040197ac00f209dbf659a97bd83f7dc3fc42e985905ea2313b2551b72692510e9744493bd525055e27e295948a110806617572612092d55c08000000000561757261010116fd4fedb8ecd8eba0d907b7bd534b260bc0b86a0e9a1fd8f18cb85e9073f442a6a9f5460bfb2443bce67b8fdba17bbd2927bdad8fc6ae021c03e2c8b3e33e89");
    
    let decoded_para_header_from_value = beefy_light_client::header::Header::decode(&mut &decode_value[..]);
    println!("decode header from trie proof value:\n{:?}", decoded_para_header_from_value);

    let decoded_para_header_from_expected_header = beefy_light_client::header::Header::decode(&mut &encode_parachain_header[..]);
    println!("decode header from expected header:\n{:?}", decoded_para_header_from_expected_header);

    Ok(())

}

#[tokio::test]
pub async fn parachain_header_state_proof2() -> Result<(), Box<dyn std::error::Error>> {
    // data soure: https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Frococo-rpc.polkadot.io#/explorer
    // number: 6,052,239
    // block hash: 0x18794d76be12de8ff859963081df8946f4b674572c08db059857bfe94e9879ff
    // block header stateRoot: 0xf6405bbc56e570e30373774e3612ba4e31b9421f464466cabb96c2cdf968ba79
    let state_root = H256::from(hex!(
        "f6405bbc56e570e30373774e3612ba4e31b9421f464466cabb96c2cdf968ba79"
    ));

    // module: paras 
    // method: heads
    // encoded storage key: 0xcd710b30bd2eab0352ddcc26417aa1941b3c252fcb29d88eff4f3de5de4476c3b86e75077b23ad2427080000
    let encode_storage_key = hex!("cd710b30bd2eab0352ddcc26417aa1941b3c252fcb29d88eff4f3de5de4476c3b86e75077b23ad2427080000").to_vec();
    // paras.heads: Option<Bytes>
    // 0xf5cc6e5cb9c5d861c3768b86421447b9a49780e8f3ed1420ca2ea66df7cd0c268ee224002e00ace14671f012576ad3b52c3d5e98e9199ac1e14ac4fe3c483181cfd7975385b8b954db36dd9c6fe0cfb697ab5c50cb4d1a4f7f171e0dff25b4ad5d6f387e08066175726120d5a362080000000005617572610101280caaa023d363143255b40d1170bac7bb9868ef8b3eac234feba8058a69c5414669285628ec02ce8ef1a024569c5a4345329d99f18df3682b8655b620930c8d
    let encode_parachain_header = hex!("f5cc6e5cb9c5d861c3768b86421447b9a49780e8f3ed1420ca2ea66df7cd0c268ee224002e00ace14671f012576ad3b52c3d5e98e9199ac1e14ac4fe3c483181cfd7975385b8b954db36dd9c6fe0cfb697ab5c50cb4d1a4f7f171e0dff25b4ad5d6f387e08066175726120d5a362080000000005617572610101280caaa023d363143255b40d1170bac7bb9868ef8b3eac234feba8058a69c5414669285628ec02ce8ef1a024569c5a4345329d99f18df3682b8655b620930c8d").to_vec();
    
    let proof = vec![
        hex!("366e75077b23ad24270800002e8cf31bfda889c6281a3ead5652cde8e11078f19875f6e9e50bc5c332682737").to_vec(),
        hex!("80046480ee248f69a5e36eb931f0cc6c0c51a6b1cceb26cc6572066bce8a48030e6ca4c480f6f6801e4b41e2e6d8ec194dba122bfb9eb33feb2545ef5144cea79551f7cc5280d12fc1fb34e638246870f1f98cc2b869700a08adbc51bf82889b2240abe2f673802bcf7334dde1fc91ba1f2ace460faa1d7b4dcd203366ee9c32556a69fff91028").to_vec(),
        hex!("80df93807b212eaf64882b542230cc1fa87d9505181a516c0dfd67ac55d3158cd753f8ad8063bcaeda2d98508a0bfcbc72f25a8e174fada86ce52b9998886d07e526357b4780b85903bb55c64e789b55c45c6b5229c710621705385150fa36932406376c6e0f8026ebeb0ec3e26c09a5ed5b3e836725ceb71a1413dafbcea4229341ef1611c9f08092dcc61945e09c15a64c9c57bbddb4fc86af0a7be86638f9bf62e99905a3f3e9805da8d888e78fa7ab9a5136810db0efce0f36ea0e604ea04b882ed66714a47caf804ba6e5c17475d4e38fbf7529471f130e81f9b20aca43dd946e202bb1a3c9a1298003f777a0be892d6a55f4dad8735ccc356dc739277c1e240b0137b25bfa068f2780a4c9385e359a9977574174c4d31beab6206a569ad15ef435bf784f16623e1d21802e89324e6a5e0be929b37bb44bdbf6619e6af80cbdebc9bd67a44c8aa072ef3980d8eabbfa85a6309a2ff6dac1a06e6a6d214faba34887e6f8e14c0d0d1858711e").to_vec(),
        hex!("80ffff80e63ce9aa88c5f25dfc4bea1daf703cb06b34997a84c601f43b3f885f76188ed88066132b6dd8983aee1ba4cd65b00a18311217c391f51ee4b4e3cf18b4fe87c469801e9f4f8885b3f6849811ac34f310833ff67c448e18f3ac717c8e1313e69effe380f1bfe97d960b2fedef1977f836ea57207a58fb0150d3f782d0e318d45f8ed21180fc7ee77b9bbb85c301d324fe7b39d89afb78a74370a10d0e5a398b7480134fa4800553aac624c42769697f91e98ea31a81f8514988e042087a960009bae8a5b479802c667e3a0f956d63f9620e73bd32f5768e5960f5ff975529d36e1d1bb118ed3380783ca39367ee05176cad2a3e75c6f000afcf34c54aec188183aa1425d5fb2ece80b36449960f591b1920dba6afa908f36454c55756e9f707562df027a4e020527c802608f2de9b0eb912aab118b34df5fba04ca086ed74374619c9e097908575030a80f7e0959e667574aa3bc957e8684429dd9337a78fac5224d8ec753355c376d70680f6b85eee123b42ee5f35ea5c46f3e4adb96e3582dded73e7b28df73b1cf4e88780bc9af8323c55f4ece4b98ac7066bb692a085f3a259a37ea143f5e9a39351d9d780a0f7dd8c15eb85a93b0030cd654239dccbc82273fdf838df52348c5f8ba5fec1802e2b3d142ce50c9b12dfc5443aede38b61673a56836c0ed61bc766d708763319807624a491af238f8ab86917f96e77c584fb53405102e9b42c31de4f9541748328").to_vec(),
        hex!("9e710b30bd2eab0352ddcc26417aa1945fc38025dd1399b0256baf015c4979beb645d180e219d18fb78b7122622112921cf0dc80b41d1871c96a572ae48fa851e3d16bbc3e0750bc52143c2f482ff3b302159bdd80bd38e5b6ee9b65acbd6fba1109cb578afbbd19ced9f8218dba82900bf3fcfc0880cbcf57d9b7e6faccab65309ed2f9ca60bb9c12e315f0cddac0104dd77868566a505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f03c716fb8fff3de61a883bb76adb34a2040080b4802a3eec96052442fae89c828e1415a1c3710ed77d412b115278d89fa092d84c5f0f4993f016e2d2f8e5f43be7bb25948604008096825408e9c7a05ff831bf138ba2198bd5117d3aa6d548365582f02e61b4765380b37001a49139edc052156d416b6d6dbc0adec086a8210e99b5bc33ab275ddd10").to_vec(),
        hex!("9f0b3c252fcb29d88eff4f3de5de4476c3ffff808c071193821f1b1fb787a4074e08a89053a8693710db6f3ab6823703a5803c11808ff91cb4e274aa25177bbea2d77d5693f3da34820ecb82d6a06529de8bc0beb580eeca7f4dd6313664dbf896817c6c7d5a8d7978620c91e5443872d440253c634680c11471b0edd5d9192a5b5910c86622f6a51df7886d0f9754e85c7e2989a3240c8044ea5b04397b504579d34a01419b6f0fb0c4f3003b3e6e0b99687cc88f398670809a22ed96f3c12639d5efe939eea76dd7a5e1aa1acce886f76246f0e52478295d80d7b6a2b89723314a732718ce4e574ed200f2738cccdb4e4b5bbf0957f2373adf809b76f05127f0e324266d58771e7d524d3163ff4d3edf0cb6aa571f7e9b894afa80a0ba6c1d968ee48c7bcb2b2e01a1ceb499c912c9a97b507ef4fb607532ce55f8803f87aebfa93bf7c4f67e6ec5538b01f871741f7022b8a60aa9157fa389c4346980a5c893ee2782000a6cb652d24bc90ed628143ada512eb826b84bf641b6847f5780830b428847372150d3c1901589a8ebfae2cb37bd6f7e053ef117c89f2d78271180a3e5a6a7a3ca15cba1a49a2255ecac287fa2998987ad3ef4509478ed1aea3b1780f32db2a2472b146b4532182fcd327eb435ceda937f20dcecf1177ddef5ecca108065ad311a5eb95c25f400fd199f1005a4ba6f62a7049117e9466dba91c1df949d807f9c90d7a65312165fa8bd0d237891ba809e3035ee8749385c98a3b3ed9bec5b").to_vec(),
        hex!("e902f5cc6e5cb9c5d861c3768b86421447b9a49780e8f3ed1420ca2ea66df7cd0c268ee224002e00ace14671f012576ad3b52c3d5e98e9199ac1e14ac4fe3c483181cfd7975385b8b954db36dd9c6fe0cfb697ab5c50cb4d1a4f7f171e0dff25b4ad5d6f387e08066175726120d5a362080000000005617572610101280caaa023d363143255b40d1170bac7bb9868ef8b3eac234feba8058a69c5414669285628ec02ce8ef1a024569c5a4345329d99f18df3682b8655b620930c8d").to_vec(),
        
    ];
    let db = StorageProof::new(proof).into_memory_db::<sp_runtime::traits::BlakeTwo256>();
    // type LayoutV0 = LayoutV0<Blake2Hasher>;
    let trie =
        TrieDBBuilder::<LayoutV1<sp_runtime::traits::BlakeTwo256>>::new(&db, &state_root).build();

    // let trie = sp_trie::TrieDB::<sp_trie::LayoutV0<Blake2Hasher>>::new(&db, &state_root)
    //     .unwrap();

    let value = trie.get_with(&encode_storage_key, |v: &[u8]| v.to_vec()).unwrap().unwrap(); // actually gets the value from the trie proof
    println!("The Key Value:\n{:?}", value);
    
    let decode_value :Vec<u8>= codec::Decode::decode(&mut &value[..]).unwrap();
    
    println!("get header from trie proof value:\n0x{}", hex::encode(decode_value.clone()));
    println!("expected header:\n{}", "0xf5cc6e5cb9c5d861c3768b86421447b9a49780e8f3ed1420ca2ea66df7cd0c268ee224002e00ace14671f012576ad3b52c3d5e98e9199ac1e14ac4fe3c483181cfd7975385b8b954db36dd9c6fe0cfb697ab5c50cb4d1a4f7f171e0dff25b4ad5d6f387e08066175726120d5a362080000000005617572610101280caaa023d363143255b40d1170bac7bb9868ef8b3eac234feba8058a69c5414669285628ec02ce8ef1a024569c5a4345329d99f18df3682b8655b620930c8d");
    
    let decoded_para_header_from_value = beefy_light_client::header::Header::decode(&mut &decode_value[..]);
    println!("decode header from trie proof value:\n{:?}", decoded_para_header_from_value);

    let decoded_para_header_from_expected_header = beefy_light_client::header::Header::decode(&mut &encode_parachain_header[..]);
    println!("decode header from expected header:\n{:?}", decoded_para_header_from_expected_header);

    Ok(())

}

#[tokio::test]
pub async fn decode_node_using_substrate() -> Result<(), Box<dyn std::error::Error>> {
    let data = hex!("e902116a2811eaaa372fcd8c769b5f433d3995872b21c468dcfc6270e1f9fa07167eaa4c7c00f5f981c0b4dafe3c1029e70fb290294fc21f040197ac00f209dbf659a97bd83f7dc3fc42e985905ea2313b2551b72692510e9744493bd525055e27e295948a110806617572612092d55c08000000000561757261010116fd4fedb8ecd8eba0d907b7bd534b260bc0b86a0e9a1fd8f18cb85e9073f442a6a9f5460bfb2443bce67b8fdba17bbd2927bdad8fc6ae021c03e2c8b3e33e89");
    let node = OwnedNode::new::<NodeCodec<sp_runtime::traits::BlakeTwo256>>(data)?;

    println!("Trie:\n{:?}", node);

    Ok(())
}

#[tokio::test]
pub async fn test_consensus_state_proof() -> Result<(), Box<dyn std::error::Error>> {
   
	// pub type ConsensusStates<T: Config> = StorageMap<_, Blake2_128Concat, ClientConsensusStatePath, Vec<u8>>;
    
    // key: ClientConsensusStatePath
    // pub struct ClientConsensusStatePath {
        //     pub client_id: ClientId,
        //     pub epoch: u64,
        //     pub height: u64,
        // }
    // #[display(fmt = "clients/{client_id}/consensusStates/{epoch}-{height}")]
    // eg, ClientConsensusStatePath { client_id: ClientId("07-tendermint-0"), epoch: 0, height: 169 }
    
    // value: ConsensusState pb encode_vec
    // pub struct ConsensusState {
    //     pub timestamp: Time,
    //     pub root: CommitmentRoot,
    //     pub next_validators_hash: Hash,
    // }
    
   
    // let state_root_bytes:[u8;32] = [
    //     10, 35, 47, 105, 98, 99, 46, 99, 111, 114, 101, 46, 99, 108, 105, 101, 110, 116, 46, 118,
    //     49, 46, 77,10, 35, 47, 105, 98, 99, 46, 99, 111,  
    // ];
    // let state_root = H256::from(state_root_bytes);
    let state_root = H256::from(hex!(
        "a011d1b2220b7a6c17a74fe992a8b7b428ca5e73638c0458af25e66c5212d97e"
    ));
    
    let ccsp = ClientConsensusStatePath { 
        client_id: ClientId::from_str("07-tendermint-0").unwrap(), 
        epoch: 0, 
        height: 169 };
    println!("ClientConsensusStatePath :\n{:?}", ccsp);
    // key: ClientConsensusStatePath
    // encoded_key = `twox_128("Ibc") ++ twox_128("ConsensusStates") ++ Blake2_128(encode(ClientConsensusStatePath)) ++ encode(ClientConsensusStatePath)`
    let mut encoded_key = Vec::new();
    encoded_key.extend(sp_core_hashing::twox_128("Ibc".as_bytes()));
    encoded_key.extend(sp_core_hashing::twox_128("ConsensusStates".as_bytes()));
    let encoded_ccsp = ccsp.encode();
    encoded_key.extend(sp_core_hashing::blake2_128(&encoded_ccsp));
    encoded_key.extend(encoded_ccsp);
    println!("build storage key:\n{:?}", encoded_key);
    let encoded_storage_key:Vec<u8>=  vec![101, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 60, 246, 65, 203, 244, 62, 245, 89, 235, 169, 34, 250, 219, 137, 199, 6, 170, 17, 126, 122, 142, 148, 165, 251, 232, 152, 181, 244, 235, 170, 161, 217, 60, 48, 55, 45, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 45, 48, 0, 0, 0, 0, 0, 0, 0, 0, 169, 0, 0, 0, 0, 0, 0, 0];
    println!("get storage key from substrate:\n{:?}", encoded_storage_key);
    let encoded_consensuse_state_path = encoded_storage_key[48..].to_vec();
    let consensuse_state_path = ClientConsensusStatePath::decode(&mut &*encoded_consensuse_state_path).unwrap();
    println!("get ClientConsensusStatePath from storage key:\n{:?}", consensuse_state_path);

    // value: ConsensusState.encode_vec()
    let expected_pbencoded_value:Vec<u8> =  vec![10, 46, 47, 105, 98, 99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110, 116, 115, 46, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 46, 118, 49, 46, 67, 111, 110, 115, 101, 110, 115, 117, 115, 83, 116, 97, 116, 101, 18, 83, 10, 11, 8, 171, 245, 164, 165, 6, 16, 196, 166, 174, 32, 18, 34, 10, 32, 71, 49, 250, 139, 211, 232, 130, 203, 55, 114, 131, 156, 33, 54, 186, 81, 40, 43, 238, 93, 139, 99, 69, 19, 107, 195, 108, 57, 168, 219, 201, 126, 26, 32, 176, 214, 254, 204, 43, 161, 28, 204, 147, 237, 120, 197, 147, 100, 83, 164, 120, 232, 85, 98, 58, 192, 101, 229, 93, 149, 168, 95, 238, 253, 95, 205];
    use bytes::Buf;
    use core::ops::Deref;
    use prost::Message;
    // let tm_consensue_state = TmConsensueState::decode_vec(&expected_pbencoded_value).unwrap();
    // let tm_consensue_state: Result<TmConsensueState, ibc_proto::protobuf::Error> = Protobuf::<RawConsensusState>::decode_vec(&expected_pbencoded_value);
    // let tm_consensue_state = RawConsensusState::decode(expected_pbencoded_value.deref());
    // let tm_consensue_state = TmConsensueState::decode(expected_pbencoded_value.deref());
    // let any_consensus_state =  AnyConsensusState::decode_vec(&expected_pbencoded_value);
    // println!("decoded pb tm_consensue_state :\n{:?}", any_consensus_state);

    let proofs: Vec<Vec<u8>>= vec![
        vec![21, 2, 10, 46, 47, 105, 98, 99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110, 116, 115, 46, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 46, 118, 49, 46, 67, 111, 110, 115, 101, 110, 115, 117, 115, 83, 116, 97, 116, 101, 18, 83, 10, 11, 8, 171, 245, 164, 165, 6, 16, 196, 166, 174, 32, 18, 34, 10, 32, 71, 49, 250, 139, 211, 232, 130, 203, 55, 114, 131, 156, 33, 54, 186, 81, 40, 43, 238, 93, 139, 99, 69, 19, 107, 195, 108, 57, 168, 219, 201, 126, 26, 32, 176, 214, 254, 204, 43, 161, 28, 204, 147, 237, 120, 197, 147, 100, 83, 164, 120, 232, 85, 98, 58, 192, 101, 229, 93, 149, 168, 95, 238, 253, 95, 205],
        vec![63, 64, 10, 17, 126, 122, 142, 148, 165, 251, 232, 152, 181, 244, 235, 170, 161, 217, 60, 48, 55, 45, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 45, 48, 0, 0, 0, 0, 0, 0, 0, 0, 169, 0, 0, 0, 0, 0, 0, 0, 24, 161, 201, 207, 207, 205, 217, 132, 221, 61, 44, 102, 4, 205, 129, 61, 186, 141, 220, 165, 207, 173, 101, 138, 118, 95, 162, 189, 44, 130, 82, 59], 
        vec![128, 168, 21, 128, 55, 92, 36, 190, 155, 31, 216, 140, 77, 72, 159, 87, 116, 23, 200, 119, 47, 164, 112, 211, 69, 65, 75, 124, 130, 170, 193, 146, 97, 120, 235, 199, 128, 236, 70, 193, 126, 170, 169, 60, 141, 167, 146, 151, 213, 5, 59, 147, 255, 49, 32, 90, 195, 178, 105, 209, 134, 195, 169, 159, 118, 68, 220, 52, 49, 128, 167, 80, 60, 9, 242, 55, 155, 253, 158, 34, 247, 241, 17, 176, 253, 1, 101, 249, 172, 79, 37, 152, 61, 114, 185, 90, 140, 224, 83, 75, 128, 220, 128, 123, 54, 37, 121, 53, 201, 167, 241, 147, 32, 255, 154, 250, 154, 27, 132, 37, 247, 11, 98, 51, 104, 96, 97, 47, 82, 157, 162, 173, 16, 177, 143, 128, 7, 252, 233, 77, 152, 160, 180, 150, 177, 174, 169, 91, 252, 121, 210, 32, 38, 62, 58, 92, 30, 176, 163, 221, 178, 228, 89, 55, 7, 229, 18, 206, 128, 81, 119, 54, 240, 89, 55, 154, 228, 116, 2, 207, 155, 93, 147, 6, 215, 50, 179, 165, 115, 98, 242, 54, 144, 218, 23, 76, 154, 206, 45, 22, 132], 
        vec![128, 255, 255, 128, 145, 224, 204, 210, 244, 106, 56, 159, 40, 100, 112, 179, 162, 241, 206, 71, 27, 8, 5, 52, 115, 23, 173, 47, 48, 128, 154, 156, 161, 108, 27, 63, 128, 147, 115, 125, 38, 83, 127, 136, 221, 65, 179, 213, 88, 34, 15, 107, 248, 25, 52, 46, 27, 204, 83, 211, 122, 77, 88, 11, 60, 198, 111, 249, 7, 128, 24, 253, 178, 154, 210, 186, 13, 60, 229, 161, 176, 115, 247, 33, 50, 52, 25, 180, 176, 95, 180, 207, 119, 238, 29, 46, 231, 154, 235, 240, 197, 97, 128, 78, 237, 59, 91, 35, 198, 150, 113, 239, 107, 129, 204, 114, 45, 174, 249, 34, 236, 5, 219, 215, 181, 133, 119, 185, 117, 31, 174, 206, 45, 133, 246, 128, 144, 55, 163, 181, 171, 98, 196, 117, 4, 162, 87, 252, 124, 110, 190, 47, 197, 166, 255, 59, 31, 126, 24, 151, 185, 104, 220, 16, 187, 70, 204, 16, 128, 2, 49, 9, 164, 107, 183, 50, 109, 90, 15, 82, 114, 71, 127, 147, 54, 192, 158, 88, 157, 242, 184, 30, 103, 252, 90, 188, 97, 151, 188, 220, 38, 128, 147, 238, 161, 161, 155, 66, 148, 113, 212, 158, 210, 3, 205, 34, 212, 57, 109, 174, 128, 5, 32, 198, 85, 14, 214, 168, 111, 43, 145, 154, 194, 153, 128, 91, 104, 33, 50, 197, 41, 8, 112, 85, 38, 5, 127, 115, 171, 127, 204, 171, 74, 246, 215, 42, 152, 5, 99, 77, 216, 211, 204, 83, 241, 48, 209, 128, 194, 212, 77, 55, 30, 95, 193, 245, 2, 39, 215, 73, 26, 214, 90, 208, 73, 99, 3, 97, 206, 251, 74, 177, 132, 72, 49, 35, 118, 9, 240, 131, 128, 178, 60, 55, 0, 228, 223, 159, 27, 125, 22, 214, 19, 63, 222, 140, 102, 166, 241, 47, 146, 242, 97, 60, 247, 120, 89, 78, 7, 39, 55, 176, 4, 128, 28, 144, 98, 41, 102, 83, 66, 97, 1, 187, 37, 80, 78, 32, 86, 249, 8, 153, 147, 209, 72, 94, 111, 102, 175, 95, 80, 229, 68, 25, 159, 18, 128, 53, 109, 10, 73, 17, 120, 20, 230, 150, 43, 42, 224, 52, 223, 56, 76, 76, 111, 220, 164, 38, 250, 200, 85, 36, 198, 29, 242, 76, 60, 228, 84, 128, 126, 156, 226, 42, 227, 74, 223, 96, 159, 15, 37, 242, 194, 213, 209, 124, 230, 215, 80, 250, 208, 35, 167, 115, 14, 101, 206, 64, 11, 0, 53, 234, 128, 89, 219, 254, 158, 101, 83, 237, 1, 219, 208, 36, 118, 42, 164, 227, 136, 129, 33, 43, 112, 239, 20, 165, 229, 1, 228, 179, 169, 122, 1, 112, 115, 128, 107, 253, 187, 240, 224, 190, 220, 185, 147, 182, 92, 156, 234, 30, 146, 154, 86, 215, 138, 59, 123, 197, 61, 27, 124, 166, 252, 72, 142, 34, 149, 238, 128, 138, 29, 218, 127, 14, 86, 184, 208, 126, 28, 35, 136, 135, 101, 131, 192, 42, 28, 0, 236, 109, 197, 71, 214, 35, 12, 249, 5, 90, 238, 112, 114], 
        vec![158, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 253, 166, 104, 95, 10, 188, 245, 27, 222, 65, 138, 14, 86, 107, 122, 75, 66, 31, 59, 242, 32, 1, 0, 0, 0, 0, 0, 0, 0, 128, 139, 146, 138, 165, 173, 89, 71, 236, 122, 160, 59, 225, 183, 30, 51, 12, 75, 152, 131, 237, 215, 218, 66, 141, 176, 146, 30, 58, 115, 235, 130, 234, 128, 221, 243, 225, 145, 202, 23, 18, 213, 76, 63, 204, 85, 144, 159, 96, 233, 84, 221, 152, 113, 19, 179, 254, 220, 182, 71, 101, 84, 46, 214, 127, 197, 80, 95, 14, 123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41, 8, 0, 0, 128, 35, 37, 52, 31, 168, 0, 99, 172, 60, 90, 35, 120, 13, 241, 64, 191, 138, 68, 39, 90, 173, 86, 241, 236, 195, 199, 209, 76, 113, 115, 241, 156, 104, 95, 8, 242, 131, 232, 130, 12, 246, 179, 105, 215, 10, 187, 160, 190, 136, 229, 32, 126, 0, 0, 0, 0, 0, 0, 0, 104, 95, 13, 175, 218, 65, 33, 225, 150, 51, 237, 160, 123, 37, 248, 10, 100, 93, 32, 1, 0, 0, 0, 0, 0, 0, 0, 128, 19, 13, 180, 184, 218, 229, 181, 215, 253, 169, 122, 204, 184, 19, 62, 142, 96, 117, 142, 158, 69, 31, 133, 140, 93, 155, 88, 89, 23, 84, 113, 165, 128, 249, 78, 132, 18, 176, 156, 41, 182, 0, 97, 58, 141, 7, 203, 16, 211, 41, 19, 80, 109, 25, 224, 157, 139, 8, 111, 116, 1, 101, 144, 158, 189, 128, 9, 68, 187, 63, 91, 170, 177, 195, 177, 72, 162, 250, 200, 19, 118, 145, 219, 189, 237, 215, 65, 17, 228, 107, 29, 93, 217, 77, 102, 93, 114, 126, 128, 12, 217, 18, 201, 129, 201, 97, 218, 54, 223, 240, 18, 118, 52, 138, 206, 180, 39, 102, 32, 109, 74, 148, 75, 9, 188, 91, 87, 159, 99, 134, 52],
        vec![159, 12, 246, 65, 203, 244, 62, 245, 89, 235, 169, 34, 250, 219, 137, 199, 6, 128, 6, 128, 37, 101, 82, 32, 15, 4, 129, 211, 194, 2, 74, 228, 185, 111, 11, 81, 146, 68, 78, 239, 152, 215, 12, 106, 21, 54, 42, 214, 82, 125, 182, 250, 128, 161, 195, 102, 81, 99, 17, 248, 65, 2, 253, 48, 225, 170, 24, 10, 51, 237, 231, 200, 107, 2, 64, 91, 96, 71, 84, 122, 20, 253, 50, 204, 106, 128, 140, 212, 73, 117, 114, 20, 63, 197, 194, 0, 199, 252, 109, 0, 7, 41, 81, 245, 115, 17, 49, 238, 213, 92, 38, 226, 28, 241, 202, 125, 172, 201],
    ];
    let db = StorageProof::new(proofs.clone()).into_memory_db::<sp_runtime::traits::BlakeTwo256>();
    // type LayoutV0 = LayoutV0<Blake2Hasher>;
    let trie =
        TrieDBBuilder::<LayoutV1<sp_runtime::traits::BlakeTwo256>>::new(&db, &state_root).build();

    let scale_encoded_value = trie.get_with(&encoded_storage_key, |v: &[u8]| v.to_vec()).unwrap().unwrap(); // actually gets the value from the trie proof
    println!("get encoded Value from trie:\n{:?}", scale_encoded_value);
    
    let scale_decode_value :Vec<u8>= codec::Decode::decode(&mut &scale_encoded_value[..]).unwrap();

    println!("get decoded value from trie:\n0x{}", hex::encode(scale_decode_value.clone()));
    println!("expected_value:\n0x{}", hex::encode(expected_pbencoded_value.clone()));
    assert_eq!(scale_decode_value,expected_pbencoded_value);

    // encode pb vec
    let expected_sclae_encoded_value = codec::Encode::encode(&expected_pbencoded_value);
    println!("encoded_expected_value:\n{:?}", expected_sclae_encoded_value);
    let result = sp_trie::verify_trie_proof::<LayoutV1<sp_runtime::traits::BlakeTwo256>, _, _, _>(
        &state_root,
        &proofs,
        &[(encoded_storage_key, Some(expected_sclae_encoded_value))]
    );
    println!("sp_trie::verify_trie_proof result:\n{:?}", result);
    // assert!(result.is_ok());

    Ok(())
}

#[tokio::test]
pub async fn test_client_state_proof() -> Result<(), Box<dyn std::error::Error>> {
   
	// pub type ClientStates<T: Config> = StorageMap<_, Blake2_128Concat, ClientStatePath, Vec<u8>>;
    
    // key: ClientStatePath
    // pub struct ClientStatePath(pub ClientId);
    // #[display(fmt = "clients/{_0}/clientState")]
    // eg,ClientStatePath(ClientId("07-tendermint-0"))
    // value: clientState pb encode_vec
    
    // let state_root_bytes:[u8;32] = [
    //     10, 35, 47, 105, 98, 99, 46, 99, 111, 114, 101, 46, 99, 108, 105, 101, 110, 116, 46, 118,
    //     49, 46, 77,10, 35, 47, 105, 98, 99, 46, 99, 111,  
    // ];
    // let state_root = H256::from(state_root_bytes);
    let state_root = H256::from(hex!(
        "3733855370a26d34a8c8bc4c67a3d220fedab64ebef37842069820875bb20a4c"
    ));
    
    // key: ClientStatePath encoded
    let encoded_storage_key:Vec<u8>=  vec![101, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 83, 132, 145, 119, 250, 48, 85, 212, 116, 56, 227, 154, 243, 42, 226, 177, 224, 142, 83, 8, 253, 79, 246, 169, 127, 189, 254, 217, 171, 176, 63, 44, 60, 48, 55, 45, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 45, 48];
    // value: clientState.encode_vec()
    let expected_pbencoded_value:Vec<u8> =  vec![10, 43, 47, 105, 98, 99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110, 116, 115, 46, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 46, 118, 49, 46, 67, 108, 105, 101, 110, 116, 83, 116, 97, 116, 101, 18, 123, 10, 7, 101, 97, 114, 116, 104, 45, 48, 18, 4, 8, 1, 16, 3, 26, 4, 8, 128, 234, 73, 34, 4, 8, 128, 223, 110, 42, 2, 8, 22, 50, 0, 58, 3, 16, 173, 11, 66, 25, 10, 9, 8, 1, 24, 1, 32, 1, 42, 1, 0, 18, 12, 10, 2, 0, 1, 16, 33, 24, 4, 32, 12, 48, 1, 66, 25, 10, 9, 8, 1, 24, 1, 32, 1, 42, 1, 0, 18, 12, 10, 2, 0, 1, 16, 32, 24, 1, 32, 1, 48, 1, 74, 7, 117, 112, 103, 114, 97, 100, 101, 74, 16, 117, 112, 103, 114, 97, 100, 101, 100, 73, 66, 67, 83, 116, 97, 116, 101, 80, 1, 88, 1];
    let proofs: Vec<Vec<u8>>= vec![
        vec![63, 64, 3, 132, 145, 119, 250, 48, 85, 212, 116, 56, 227, 154, 243, 42, 226, 177, 224, 142, 83, 8, 253, 79, 246, 169, 127, 189, 254, 217, 171, 176, 63, 44, 60, 48, 55, 45, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 45, 48, 0, 73, 30, 52, 80, 40, 168, 120, 187, 66, 237, 49, 92, 173, 138, 242, 143, 76, 244, 247, 205, 141, 204, 250, 227, 230, 249, 187, 62, 192, 45, 229], 
        vec![128, 168, 21, 128, 55, 92, 36, 190, 155, 31, 216, 140, 77, 72, 159, 87, 116, 23, 200, 119, 47, 164, 112, 211, 69, 65, 75, 124, 130, 170, 193, 146, 97, 120, 235, 199, 128, 78, 116, 54, 110, 33, 89, 174, 138, 153, 189, 91, 211, 172, 240, 59, 152, 78, 162, 7, 126, 179, 231, 86, 190, 184, 109, 129, 160, 245, 107, 123, 237, 128, 167, 80, 60, 9, 242, 55, 155, 253, 158, 34, 247, 241, 17, 176, 253, 1, 101, 249, 172, 79, 37, 152, 61, 114, 185, 90, 140, 224, 83, 75, 128, 220, 128, 123, 54, 37, 121, 53, 201, 167, 241, 147, 32, 255, 154, 250, 154, 27, 132, 37, 247, 11, 98, 51, 104, 96, 97, 47, 82, 157, 162, 173, 16, 177, 143, 128, 7, 252, 233, 77, 152, 160, 180, 150, 177, 174, 169, 91, 252, 121, 210, 32, 38, 62, 58, 92, 30, 176, 163, 221, 178, 228, 89, 55, 7, 229, 18, 206, 128, 81, 119, 54, 240, 89, 55, 154, 228, 116, 2, 207, 155, 93, 147, 6, 215, 50, 179, 165, 115, 98, 242, 54, 144, 218, 23, 76, 154, 206, 45, 22, 132], 
        vec![128, 255, 255, 128, 231, 68, 15, 197, 146, 143, 188, 100, 174, 99, 250, 201, 146, 170, 133, 1, 39, 250, 38, 58, 202, 235, 103, 168, 155, 206, 87, 85, 148, 150, 89, 131, 128, 132, 29, 217, 17, 94, 136, 26, 104, 1, 148, 150, 8, 25, 31, 135, 241, 84, 207, 62, 164, 198, 23, 225, 147, 217, 24, 106, 124, 205, 14, 34, 4, 128, 142, 30, 52, 167, 38, 86, 6, 141, 121, 104, 132, 113, 201, 28, 204, 101, 162, 16, 140, 37, 68, 198, 204, 40, 253, 242, 130, 195, 232, 7, 200, 143, 128, 200, 232, 211, 200, 96, 12, 49, 191, 22, 228, 90, 190, 57, 118, 82, 11, 209, 200, 185, 208, 42, 109, 241, 21, 14, 41, 224, 51, 83, 144, 194, 127, 128, 172, 171, 85, 0, 173, 66, 190, 174, 83, 137, 23, 80, 16, 228, 85, 90, 94, 248, 32, 221, 100, 38, 236, 41, 26, 166, 112, 86, 253, 251, 32, 0, 128, 196, 215, 121, 7, 17, 164, 223, 123, 20, 14, 184, 250, 81, 211, 226, 100, 40, 112, 69, 3, 185, 201, 32, 253, 187, 137, 173, 185, 209, 173, 182, 166, 128, 138, 7, 241, 20, 113, 203, 221, 148, 172, 13, 142, 118, 133, 87, 4, 34, 9, 1, 26, 224, 55, 163, 209, 4, 153, 73, 48, 73, 242, 253, 176, 232, 128, 91, 104, 33, 50, 197, 41, 8, 112, 85, 38, 5, 127, 115, 171, 127, 204, 171, 74, 246, 215, 42, 152, 5, 99, 77, 216, 211, 204, 83, 241, 48, 209, 128, 194, 212, 77, 55, 30, 95, 193, 245, 2, 39, 215, 73, 26, 214, 90, 208, 73, 99, 3, 97, 206, 251, 74, 177, 132, 72, 49, 35, 118, 9, 240, 131, 128, 105, 115, 94, 183, 132, 195, 15, 22, 205, 95, 199, 177, 61, 111, 196, 97, 199, 178, 18, 81, 201, 142, 21, 245, 71, 8, 117, 92, 114, 243, 167, 208, 128, 15, 55, 104, 161, 88, 195, 96, 67, 2, 226, 149, 33, 72, 136, 202, 35, 154, 26, 21, 176, 84, 136, 102, 163, 167, 3, 9, 137, 129, 141, 223, 55, 128, 141, 105, 25, 58, 70, 190, 193, 167, 206, 2, 101, 233, 128, 220, 208, 21, 206, 107, 78, 208, 112, 21, 17, 212, 119, 75, 174, 167, 33, 73, 240, 13, 128, 177, 206, 239, 41, 134, 239, 34, 224, 200, 204, 8, 103, 177, 214, 10, 224, 225, 185, 37, 72, 93, 76, 76, 115, 107, 203, 221, 202, 53, 118, 52, 116, 128, 157, 72, 36, 214, 255, 213, 59, 81, 59, 16, 26, 24, 150, 199, 157, 7, 32, 128, 109, 74, 226, 223, 183, 35, 31, 140, 249, 42, 183, 109, 50, 10, 128, 107, 253, 187, 240, 224, 190, 220, 185, 147, 182, 92, 156, 234, 30, 146, 154, 86, 215, 138, 59, 123, 197, 61, 27, 124, 166, 252, 72, 142, 34, 149, 238, 128, 189, 80, 185, 210, 193, 165, 136, 246, 11, 68, 58, 136, 194, 121, 177, 199, 6, 39, 140, 90, 231, 194, 99, 164, 182, 40, 86, 178, 151, 11, 234, 77], 
        vec![158, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 253, 166, 104, 95, 10, 188, 245, 27, 222, 65, 138, 14, 86, 107, 122, 75, 66, 31, 59, 242, 32, 1, 0, 0, 0, 0, 0, 0, 0, 128, 139, 146, 138, 165, 173, 89, 71, 236, 122, 160, 59, 225, 183, 30, 51, 12, 75, 152, 131, 237, 215, 218, 66, 141, 176, 146, 30, 58, 115, 235, 130, 234, 128, 14, 128, 168, 84, 245, 128, 38, 223, 221, 84, 86, 86, 191, 162, 183, 87, 162, 229, 129, 208, 87, 76, 202, 94, 151, 88, 139, 37, 83, 183, 240, 49, 80, 95, 14, 123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41, 8, 0, 0, 128, 162, 138, 27, 179, 178, 173, 136, 43, 131, 100, 29, 52, 248, 4, 9, 58, 75, 176, 85, 34, 255, 188, 76, 141, 175, 213, 66, 110, 112, 210, 232, 234, 104, 95, 8, 242, 131, 232, 130, 12, 246, 179, 105, 215, 10, 187, 160, 190, 136, 229, 32, 242, 0, 0, 0, 0, 0, 0, 0, 104, 95, 13, 175, 218, 65, 33, 225, 150, 51, 237, 160, 123, 37, 248, 10, 100, 93, 32, 1, 0, 0, 0, 0, 0, 0, 0, 128, 138, 173, 10, 164, 38, 250, 26, 70, 46, 177, 228, 224, 58, 62, 93, 214, 41, 83, 25, 11, 37, 216, 0, 164, 16, 49, 251, 118, 142, 96, 251, 47, 128, 197, 67, 136, 106, 81, 230, 216, 248, 107, 230, 33, 245, 79, 54, 124, 87, 196, 212, 43, 160, 49, 199, 73, 100, 164, 132, 210, 39, 13, 191, 217, 81, 128, 9, 68, 187, 63, 91, 170, 177, 195, 177, 72, 162, 250, 200, 19, 118, 145, 219, 189, 237, 215, 65, 17, 228, 107, 29, 93, 217, 77, 102, 93, 114, 126, 128, 175, 233, 199, 106, 161, 18, 153, 183, 250, 223, 172, 51, 90, 50, 39, 127, 8, 30, 250, 132, 11, 199, 143, 142, 91, 159, 171, 90, 84, 146, 68, 118], 
        vec![169, 2, 10, 43, 47, 105, 98, 99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110, 116, 115, 46, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 46, 118, 49, 46, 67, 108, 105, 101, 110, 116, 83, 116, 97, 116, 101, 18, 123, 10, 7, 101, 97, 114, 116, 104, 45, 48, 18, 4, 8, 1, 16, 3, 26, 4, 8, 128, 234, 73, 34, 4, 8, 128, 223, 110, 42, 2, 8, 22, 50, 0, 58, 3, 16, 173, 11, 66, 25, 10, 9, 8, 1, 24, 1, 32, 1, 42, 1, 0, 18, 12, 10, 2, 0, 1, 16, 33, 24, 4, 32, 12, 48, 1, 66, 25, 10, 9, 8, 1, 24, 1, 32, 1, 42, 1, 0, 18, 12, 10, 2, 0, 1, 16, 32, 24, 1, 32, 1, 48, 1, 74, 7, 117, 112, 103, 114, 97, 100, 101, 74, 16, 117, 112, 103, 114, 97, 100, 101, 100, 73, 66, 67, 83, 116, 97, 116, 101, 80, 1, 88, 1]    
    ];
    
    let db = StorageProof::new(proofs.clone()).into_memory_db::<sp_runtime::traits::BlakeTwo256>();
    // type LayoutV0 = LayoutV0<Blake2Hasher>;
    let trie =
        TrieDBBuilder::<LayoutV1<sp_runtime::traits::BlakeTwo256>>::new(&db, &state_root).build();

    let scale_encoded_value = trie.get_with(&encoded_storage_key, |v: &[u8]| v.to_vec()).unwrap().unwrap(); // actually gets the value from the trie proof
    println!("get encoded Value from trie:\n{:?}", scale_encoded_value);
    
    let scale_decode_value :Vec<u8>= codec::Decode::decode(&mut &scale_encoded_value[..]).unwrap();

    println!("get decoded value from trie:\n0x{}", hex::encode(scale_decode_value.clone()));
    println!("expected_pbencoded_value:\n0x{}", hex::encode(expected_pbencoded_value.clone()));
    assert_eq!(scale_decode_value,expected_pbencoded_value);

    // encode pb vec
    let expected_sclae_encoded_value = codec::Encode::encode(&expected_pbencoded_value);
    println!("expected_sclae_encoded_value:\n{:?}", expected_sclae_encoded_value);
    let result = sp_trie::verify_trie_proof::<LayoutV1<sp_runtime::traits::BlakeTwo256>, _, _, _>(
        &state_root,
        &proofs,
        &[(encoded_storage_key, Some(expected_sclae_encoded_value))]
    );
    println!("sp_trie::verify_trie_proof result:\n{:?}", result);
    // assert!(result.is_ok());

    Ok(())
}

#[tokio::test]
pub async fn test_connection_state_proof() -> Result<(), Box<dyn std::error::Error>> {
   
	// pub type Connections<T: Config> =
    // StorageMap<_, Blake2_128Concat, ConnectionsPath, ConnectionEnd>;
    // key: ConnectionsPath
    // #[display(fmt = "connections/{_0}")]
    // pub struct ConnectionsPath(pub ConnectionId);
    // eg, ConnectionsPath(ConnectionId("connection-0"))
    // value: ConnectionEnd
    // pub struct ConnectionEnd {
    //     pub state: State,
    //     client_id: ClientId,
    //     counterparty: Counterparty,
    //     versions: Vec<Version>,
    //     delay_period: Duration,
    // }
    // eg:
    // ConnectionEnd { 
    //     state: TryOpen,
    //     client_id: ClientId("07-tendermint-0"), 
    //     counterparty: Counterparty { client_id: ClientId("10-grandpa-0"), 
    //                   connection_id: Some(ConnectionId("connection-0")), 
    //                   prefix: CommitmentPrefix { bytes: [105, 98, 99] } }, 
    //     versions: [Version { identifier: "1", 
    //     features: ["ORDER_ORDERED", "ORDER_UNORDERED"] }], 
    //     delay_period_secs: 0, 
    //     delay_period_nanos: 0 
    // }


    // let state_root_bytes:[u8;32] = [
    //     10, 35, 47, 105, 98, 99, 46, 99, 111, 114, 101, 46, 99, 108, 105, 101, 110, 116, 46, 118,
    //     49, 46, 77,10, 35, 47, 105, 98, 99, 46, 99, 111,  
    // ];
    // let state_root = H256::from(state_root_bytes);
    let state_root = H256::from(hex!(
        "3733855370a26d34a8c8bc4c67a3d220fedab64ebef37842069820875bb20a4c"
    ));
    
    // key: ConnectionsPath
    let encoded_storage_key:Vec<u8>= vec![101, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 47, 99, 99, 80, 87, 249, 175, 51, 232, 228, 192, 128, 156, 156, 52, 197, 83, 68, 105, 160, 53, 236, 227, 28, 226, 64, 250, 25, 185, 226, 109, 66, 48, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 45, 48];
    // value: scale encode(ConnectionEnd)
    let expected_scale_encoded_value:Vec<u8> =  vec![2, 60, 48, 55, 45, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 45, 48, 48, 49, 48, 45, 103, 114, 97, 110, 100, 112, 97, 45, 48, 1, 48, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 45, 48, 12, 105, 98, 99, 4, 4, 49, 8, 52, 79, 82, 68, 69, 82, 95, 79, 82, 68, 69, 82, 69, 68, 60, 79, 82, 68, 69, 82, 95, 85, 78, 79, 82, 68, 69, 82, 69, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let proofs: Vec<Vec<u8>>= vec![
        vec![2, 60, 48, 55, 45, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 45, 48, 48, 49, 48, 45, 103, 114, 97, 110, 100, 112, 97, 45, 48, 1, 48, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 45, 48, 12, 105, 98, 99, 4, 4, 49, 8, 52, 79, 82, 68, 69, 82, 95, 79, 82, 68, 69, 82, 69, 68, 60, 79, 82, 68, 69, 82, 95, 85, 78, 79, 82, 68, 69, 82, 69, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 
        vec![63, 58, 15, 99, 99, 80, 87, 249, 175, 51, 232, 228, 192, 128, 156, 156, 52, 197, 83, 68, 105, 160, 53, 236, 227, 28, 226, 64, 250, 25, 185, 226, 109, 66, 48, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 45, 48, 199, 205, 37, 244, 76, 101, 179, 6, 128, 239, 209, 55, 32, 164, 28, 89, 130, 146, 56, 211, 200, 112, 13, 59, 80, 33, 212, 55, 90, 192, 194, 174], 
        vec![128, 168, 21, 128, 55, 92, 36, 190, 155, 31, 216, 140, 77, 72, 159, 87, 116, 23, 200, 119, 47, 164, 112, 211, 69, 65, 75, 124, 130, 170, 193, 146, 97, 120, 235, 199, 128, 78, 116, 54, 110, 33, 89, 174, 138, 153, 189, 91, 211, 172, 240, 59, 152, 78, 162, 7, 126, 179, 231, 86, 190, 184, 109, 129, 160, 245, 107, 123, 237, 128, 167, 80, 60, 9, 242, 55, 155, 253, 158, 34, 247, 241, 17, 176, 253, 1, 101, 249, 172, 79, 37, 152, 61, 114, 185, 90, 140, 224, 83, 75, 128, 220, 128, 123, 54, 37, 121, 53, 201, 167, 241, 147, 32, 255, 154, 250, 154, 27, 132, 37, 247, 11, 98, 51, 104, 96, 97, 47, 82, 157, 162, 173, 16, 177, 143, 128, 7, 252, 233, 77, 152, 160, 180, 150, 177, 174, 169, 91, 252, 121, 210, 32, 38, 62, 58, 92, 30, 176, 163, 221, 178, 228, 89, 55, 7, 229, 18, 206, 128, 81, 119, 54, 240, 89, 55, 154, 228, 116, 2, 207, 155, 93, 147, 6, 215, 50, 179, 165, 115, 98, 242, 54, 144, 218, 23, 76, 154, 206, 45, 22, 132], 
        vec![128, 255, 255, 128, 231, 68, 15, 197, 146, 143, 188, 100, 174, 99, 250, 201, 146, 170, 133, 1, 39, 250, 38, 58, 202, 235, 103, 168, 155, 206, 87, 85, 148, 150, 89, 131, 128, 132, 29, 217, 17, 94, 136, 26, 104, 1, 148, 150, 8, 25, 31, 135, 241, 84, 207, 62, 164, 198, 23, 225, 147, 217, 24, 106, 124, 205, 14, 34, 4, 128, 142, 30, 52, 167, 38, 86, 6, 141, 121, 104, 132, 113, 201, 28, 204, 101, 162, 16, 140, 37, 68, 198, 204, 40, 253, 242, 130, 195, 232, 7, 200, 143, 128, 200, 232, 211, 200, 96, 12, 49, 191, 22, 228, 90, 190, 57, 118, 82, 11, 209, 200, 185, 208, 42, 109, 241, 21, 14, 41, 224, 51, 83, 144, 194, 127, 128, 172, 171, 85, 0, 173, 66, 190, 174, 83, 137, 23, 80, 16, 228, 85, 90, 94, 248, 32, 221, 100, 38, 236, 41, 26, 166, 112, 86, 253, 251, 32, 0, 128, 196, 215, 121, 7, 17, 164, 223, 123, 20, 14, 184, 250, 81, 211, 226, 100, 40, 112, 69, 3, 185, 201, 32, 253, 187, 137, 173, 185, 209, 173, 182, 166, 128, 138, 7, 241, 20, 113, 203, 221, 148, 172, 13, 142, 118, 133, 87, 4, 34, 9, 1, 26, 224, 55, 163, 209, 4, 153, 73, 48, 73, 242, 253, 176, 232, 128, 91, 104, 33, 50, 197, 41, 8, 112, 85, 38, 5, 127, 115, 171, 127, 204, 171, 74, 246, 215, 42, 152, 5, 99, 77, 216, 211, 204, 83, 241, 48, 209, 128, 194, 212, 77, 55, 30, 95, 193, 245, 2, 39, 215, 73, 26, 214, 90, 208, 73, 99, 3, 97, 206, 251, 74, 177, 132, 72, 49, 35, 118, 9, 240, 131, 128, 105, 115, 94, 183, 132, 195, 15, 22, 205, 95, 199, 177, 61, 111, 196, 97, 199, 178, 18, 81, 201, 142, 21, 245, 71, 8, 117, 92, 114, 243, 167, 208, 128, 15, 55, 104, 161, 88, 195, 96, 67, 2, 226, 149, 33, 72, 136, 202, 35, 154, 26, 21, 176, 84, 136, 102, 163, 167, 3, 9, 137, 129, 141, 223, 55, 128, 141, 105, 25, 58, 70, 190, 193, 167, 206, 2, 101, 233, 128, 220, 208, 21, 206, 107, 78, 208, 112, 21, 17, 212, 119, 75, 174, 167, 33, 73, 240, 13, 128, 177, 206, 239, 41, 134, 239, 34, 224, 200, 204, 8, 103, 177, 214, 10, 224, 225, 185, 37, 72, 93, 76, 76, 115, 107, 203, 221, 202, 53, 118, 52, 116, 128, 157, 72, 36, 214, 255, 213, 59, 81, 59, 16, 26, 24, 150, 199, 157, 7, 32, 128, 109, 74, 226, 223, 183, 35, 31, 140, 249, 42, 183, 109, 50, 10, 128, 107, 253, 187, 240, 224, 190, 220, 185, 147, 182, 92, 156, 234, 30, 146, 154, 86, 215, 138, 59, 123, 197, 61, 27, 124, 166, 252, 72, 142, 34, 149, 238, 128, 189, 80, 185, 210, 193, 165, 136, 246, 11, 68, 58, 136, 194, 121, 177, 199, 6, 39, 140, 90, 231, 194, 99, 164, 182, 40, 86, 178, 151, 11, 234, 77], 
        vec![158, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 253, 166, 104, 95, 10, 188, 245, 27, 222, 65, 138, 14, 86, 107, 122, 75, 66, 31, 59, 242, 32, 1, 0, 0, 0, 0, 0, 0, 0, 128, 139, 146, 138, 165, 173, 89, 71, 236, 122, 160, 59, 225, 183, 30, 51, 12, 75, 152, 131, 237, 215, 218, 66, 141, 176, 146, 30, 58, 115, 235, 130, 234, 128, 14, 128, 168, 84, 245, 128, 38, 223, 221, 84, 86, 86, 191, 162, 183, 87, 162, 229, 129, 208, 87, 76, 202, 94, 151, 88, 139, 37, 83, 183, 240, 49, 80, 95, 14, 123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41, 8, 0, 0, 128, 162, 138, 27, 179, 178, 173, 136, 43, 131, 100, 29, 52, 248, 4, 9, 58, 75, 176, 85, 34, 255, 188, 76, 141, 175, 213, 66, 110, 112, 210, 232, 234, 104, 95, 8, 242, 131, 232, 130, 12, 246, 179, 105, 215, 10, 187, 160, 190, 136, 229, 32, 242, 0, 0, 0, 0, 0, 0, 0, 104, 95, 13, 175, 218, 65, 33, 225, 150, 51, 237, 160, 123, 37, 248, 10, 100, 93, 32, 1, 0, 0, 0, 0, 0, 0, 0, 128, 138, 173, 10, 164, 38, 250, 26, 70, 46, 177, 228, 224, 58, 62, 93, 214, 41, 83, 25, 11, 37, 216, 0, 164, 16, 49, 251, 118, 142, 96, 251, 47, 128, 197, 67, 136, 106, 81, 230, 216, 248, 107, 230, 33, 245, 79, 54, 124, 87, 196, 212, 43, 160, 49, 199, 73, 100, 164, 132, 210, 39, 13, 191, 217, 81, 128, 9, 68, 187, 63, 91, 170, 177, 195, 177, 72, 162, 250, 200, 19, 118, 145, 219, 189, 237, 215, 65, 17, 228, 107, 29, 93, 217, 77, 102, 93, 114, 126, 128, 175, 233, 199, 106, 161, 18, 153, 183, 250, 223, 172, 51, 90, 50, 39, 127, 8, 30, 250, 132, 11, 199, 143, 142, 91, 159, 171, 90, 84, 146, 68, 118],   
    ];
    let db = StorageProof::new(proofs.clone()).into_memory_db::<sp_runtime::traits::BlakeTwo256>();
    // type LayoutV0 = LayoutV0<Blake2Hasher>;
    let trie =
        TrieDBBuilder::<LayoutV1<sp_runtime::traits::BlakeTwo256>>::new(&db, &state_root).build();

    let scale_encoded_value = trie.get_with(&encoded_storage_key, |v: &[u8]| v.to_vec()).unwrap().unwrap(); // actually gets the value from the trie proof
    println!("get encoded Value from trie:\n{:?}", scale_encoded_value);
    
    // let scale_decode_value :Vec<u8>= codec::Decode::decode(&mut &scale_encoded_value[..]).unwrap();

    println!("get decoded value from trie:\n0x{}", hex::encode(scale_encoded_value.clone()));
    println!("expected_value:\n0x{}", hex::encode(expected_scale_encoded_value.clone()));
    assert_eq!(scale_encoded_value,expected_scale_encoded_value);

    // encode pb vec
    // let expected_sclae_encoded_value = codec::Encode::encode(&expected_pbencoded_value);
    // println!("encoded_expected_value:\n{:?}", expected_sclae_encoded_value);
    let result = sp_trie::verify_trie_proof::<LayoutV1<sp_runtime::traits::BlakeTwo256>, _, _, _>(
        &state_root,
        &proofs,
        &[(encoded_storage_key, Some(expected_scale_encoded_value))]
    );
    println!("sp_trie::verify_trie_proof result:\n{:?}", result);
    // assert!(result.is_ok());

    Ok(())
}

#[tokio::test]
pub async fn test_channel_state_proof() -> Result<(), Box<dyn std::error::Error>> {
   
	// pub type Channels<T: Config> = StorageMap<_, Blake2_128Concat, ChannelEndsPath, ChannelEnd>;
    // key: CHannelEndsPath
    // #[display(fmt = "channelEnds/ports/{_0}/channels/{_1}")]
    // pub struct ChannelEndsPath(pub PortId, pub ChannelId);
    // eg, ChannelEndsPath(PortId("transfer"), ChannelId("channel-0"))
    // value: ChannelEnd 
    // pub struct ChannelEnd {
    //     pub state: State,
    //     pub ordering: Order,
    //     pub remote: Counterparty,
    //     pub connection_hops: Vec<ConnectionId>,
    //     pub version: Version,
    // }
    // eg:
    // ChannelEnd { 
    //     state: Init, 
    //     ordering: Unordered, 
    //     remote: Counterparty { port_id: PortId("transfer"), channel_id: None }, 
    //     connection_hops: [ConnectionId("connection-0")], 
    //     version: Version("ics20-1") 
    // }


    // let state_root_bytes:[u8;32] = [
    //     10, 35, 47, 105, 98, 99, 46, 99, 111, 114, 101, 46, 99, 108, 105, 101, 110, 116, 46, 118,
    //     49, 46, 77,10, 35, 47, 105, 98, 99, 46, 99, 111,  
    // ];
    // let state_root = H256::from(state_root_bytes);
    let state_root = H256::from(hex!(
        "348feb6ec594b68f1f2c985a470da20cb8e07d8fb8ff3972c75f6fc0a5e7dcda"
    ));
    
    // key: CHannelEndsPath
    let encoded_storage_key:Vec<u8>= vec![101, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 119, 89, 204, 193, 141, 225, 114, 7, 131, 6, 202, 89, 115, 37, 26, 123, 125, 221, 66, 42, 79, 29, 220, 2, 212, 179, 202, 21, 234, 197, 132, 210, 32, 116, 114, 97, 110, 115, 102, 101, 114, 36, 99, 104, 97, 110, 110, 101, 108, 45, 48];
    // value: scale encode(ChannelEnd)
    let expected_scale_encoded_value:Vec<u8> = vec![1, 1, 32, 116, 114, 97, 110, 115, 102, 101, 114, 0, 4, 48, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 45, 48, 28, 105, 99, 115, 50, 48, 45, 49];
    let proofs: Vec<Vec<u8>>= vec![
        vec![1, 1, 32, 116, 114, 97, 110, 115, 102, 101, 114, 0, 4, 48, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 45, 48, 28, 105, 99, 115, 50, 48, 45, 49], 
        vec![63, 69, 89, 204, 193, 141, 225, 114, 7, 131, 6, 202, 89, 115, 37, 26, 123, 125, 221, 66, 42, 79, 29, 220, 2, 212, 179, 202, 21, 234, 197, 132, 210, 32, 116, 114, 97, 110, 115, 102, 101, 114, 36, 99, 104, 97, 110, 110, 101, 108, 45, 48, 187, 161, 124, 143, 68, 22, 130, 74, 148, 2, 218, 89, 66, 250, 162, 162, 96, 63, 4, 21, 54, 171, 142, 235, 144, 61, 101, 193, 102, 33, 44, 102], 
        vec![128, 128, 32, 128, 232, 77, 108, 100, 100, 62, 41, 168, 207, 255, 99, 40, 231, 58, 30, 249, 164, 64, 68, 104, 189, 207, 248, 99, 191, 23, 127, 42, 34, 9, 73, 206, 100, 94, 175, 218, 65, 33, 225, 150, 51, 237, 160, 123, 37, 248, 10, 100, 93, 32, 1, 0, 0, 0, 0, 0, 0, 0], 
        vec![128, 168, 21, 128, 55, 92, 36, 190, 155, 31, 216, 140, 77, 72, 159, 87, 116, 23, 200, 119, 47, 164, 112, 211, 69, 65, 75, 124, 130, 170, 193, 146, 97, 120, 235, 199, 128, 4, 185, 10, 84, 178, 150, 82, 26, 225, 237, 133, 3, 50, 58, 75, 236, 35, 84, 39, 236, 122, 88, 89, 82, 201, 118, 246, 175, 14, 131, 69, 87, 128, 167, 80, 60, 9, 242, 55, 155, 253, 158, 34, 247, 241, 17, 176, 253, 1, 101, 249, 172, 79, 37, 152, 61, 114, 185, 90, 140, 224, 83, 75, 128, 220, 128, 123, 54, 37, 121, 53, 201, 167, 241, 147, 32, 255, 154, 250, 154, 27, 132, 37, 247, 11, 98, 51, 104, 96, 97, 47, 82, 157, 162, 173, 16, 177, 143, 128, 7, 252, 233, 77, 152, 160, 180, 150, 177, 174, 169, 91, 252, 121, 210, 32, 38, 62, 58, 92, 30, 176, 163, 221, 178, 228, 89, 55, 7, 229, 18, 206, 128, 81, 119, 54, 240, 89, 55, 154, 228, 116, 2, 207, 155, 93, 147, 6, 215, 50, 179, 165, 115, 98, 242, 54, 144, 218, 23, 76, 154, 206, 45, 22, 132], 
        vec![128, 255, 255, 128, 240, 144, 108, 95, 207, 175, 188, 12, 89, 83, 113, 120, 54, 233, 182, 153, 16, 8, 190, 41, 190, 20, 154, 65, 80, 179, 27, 239, 36, 125, 164, 143, 128, 185, 52, 69, 36, 134, 66, 234, 235, 221, 56, 170, 2, 90, 18, 13, 183, 210, 255, 132, 4, 73, 0, 85, 10, 114, 111, 46, 5, 45, 130, 213, 9, 128, 24, 67, 129, 145, 104, 204, 181, 36, 80, 60, 108, 226, 164, 130, 89, 248, 246, 110, 170, 65, 61, 226, 188, 36, 229, 201, 216, 142, 41, 121, 150, 197, 128, 120, 181, 186, 67, 243, 204, 211, 64, 41, 134, 225, 145, 131, 151, 195, 98, 97, 126, 138, 63, 89, 32, 254, 247, 37, 113, 117, 34, 168, 120, 20, 131, 128, 174, 192, 179, 186, 206, 58, 152, 164, 131, 54, 3, 106, 65, 201, 46, 117, 38, 79, 14, 249, 27, 34, 128, 199, 230, 9, 202, 64, 19, 89, 151, 190, 128, 216, 252, 92, 65, 137, 83, 125, 4, 143, 162, 224, 232, 251, 98, 166, 52, 137, 191, 31, 240, 34, 171, 203, 70, 55, 109, 109, 104, 79, 67, 162, 110, 128, 100, 226, 207, 21, 107, 114, 229, 217, 60, 179, 102, 76, 15, 50, 127, 60, 113, 206, 43, 3, 212, 75, 203, 113, 241, 106, 193, 110, 208, 90, 206, 179, 128, 91, 104, 33, 50, 197, 41, 8, 112, 85, 38, 5, 127, 115, 171, 127, 204, 171, 74, 246, 215, 42, 152, 5, 99, 77, 216, 211, 204, 83, 241, 48, 209, 128, 194, 212, 77, 55, 30, 95, 193, 245, 2, 39, 215, 73, 26, 214, 90, 208, 73, 99, 3, 97, 206, 251, 74, 177, 132, 72, 49, 35, 118, 9, 240, 131, 128, 194, 233, 134, 207, 223, 134, 81, 201, 236, 48, 40, 241, 111, 137, 242, 235, 14, 188, 74, 65, 118, 112, 19, 158, 26, 143, 96, 116, 39, 116, 245, 23, 128, 255, 103, 244, 142, 150, 14, 228, 21, 21, 104, 5, 44, 234, 24, 184, 147, 240, 165, 107, 100, 244, 47, 204, 68, 70, 32, 66, 140, 126, 195, 248, 189, 128, 98, 124, 197, 18, 222, 132, 133, 170, 85, 254, 9, 160, 203, 27, 204, 216, 213, 6, 235, 115, 11, 90, 60, 31, 153, 177, 229, 11, 56, 164, 2, 246, 128, 248, 8, 57, 125, 161, 253, 57, 246, 197, 28, 221, 225, 106, 7, 54, 14, 69, 26, 239, 42, 104, 200, 126, 170, 124, 234, 76, 198, 177, 238, 101, 225, 128, 232, 54, 81, 112, 181, 43, 69, 138, 197, 105, 118, 97, 53, 253, 114, 192, 78, 205, 125, 10, 133, 161, 141, 40, 192, 43, 14, 171, 225, 8, 150, 78, 128, 107, 253, 187, 240, 224, 190, 220, 185, 147, 182, 92, 156, 234, 30, 146, 154, 86, 215, 138, 59, 123, 197, 61, 27, 124, 166, 252, 72, 142, 34, 149, 238, 128, 149, 216, 137, 19, 134, 131, 238, 228, 159, 150, 229, 219, 194, 171, 8, 74, 70, 177, 65, 15, 15, 226, 46, 60, 100, 61, 90, 190, 70, 73, 169, 254], 
        vec![158, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 253, 182, 128, 251, 95, 83, 184, 35, 9, 44, 102, 139, 162, 10, 61, 145, 133, 80, 72, 64, 142, 244, 72, 158, 114, 229, 251, 155, 207, 151, 86, 249, 95, 90, 218, 128, 212, 194, 220, 133, 47, 174, 193, 192, 27, 188, 162, 103, 171, 67, 32, 86, 228, 177, 248, 164, 190, 90, 242, 194, 132, 65, 168, 139, 151, 223, 104, 141, 128, 56, 75, 24, 31, 95, 213, 107, 63, 172, 71, 200, 150, 220, 170, 71, 120, 118, 254, 154, 119, 205, 167, 152, 136, 133, 2, 90, 95, 255, 132, 120, 108, 80, 95, 14, 123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41, 8, 0, 0, 128, 82, 229, 137, 145, 30, 223, 155, 164, 87, 145, 187, 15, 193, 69, 106, 158, 134, 51, 136, 92, 8, 24, 228, 7, 96, 21, 59, 240, 121, 21, 64, 60, 104, 95, 8, 242, 131, 232, 130, 12, 246, 179, 105, 215, 10, 187, 160, 190, 136, 229, 32, 242, 0, 0, 0, 0, 0, 0, 0, 128, 105, 35, 176, 169, 50, 130, 100, 52, 160, 221, 178, 36, 86, 149, 67, 22, 195, 178, 22, 147, 126, 206, 71, 30, 252, 253, 54, 194, 0, 12, 202, 114, 128, 130, 141, 219, 199, 219, 31, 216, 123, 40, 58, 124, 195, 219, 128, 59, 204, 35, 234, 54, 131, 190, 234, 246, 250, 105, 27, 68, 175, 13, 50, 85, 221, 128, 98, 154, 78, 127, 31, 177, 28, 5, 107, 172, 190, 160, 220, 174, 206, 254, 130, 222, 211, 174, 18, 20, 49, 207, 73, 42, 57, 96, 7, 58, 79, 198, 128, 125, 47, 133, 225, 2, 241, 165, 90, 99, 146, 62, 11, 139, 6, 98, 43, 182, 10, 243, 232, 190, 48, 156, 182, 137, 220, 206, 211, 64, 44, 188, 31, 128, 9, 68, 187, 63, 91, 170, 177, 195, 177, 72, 162, 250, 200, 19, 118, 145, 219, 189, 237, 215, 65, 17, 228, 107, 29, 93, 217, 77, 102, 93, 114, 126, 128, 177, 6, 166, 206, 60, 169, 29, 160, 247, 220, 243, 235, 226, 78, 71, 102, 246, 140, 5, 65, 24, 24, 3, 54, 27, 33, 12, 234, 27, 135, 129, 119]
    ];
    let db = StorageProof::new(proofs.clone()).into_memory_db::<sp_runtime::traits::BlakeTwo256>();
    // type LayoutV0 = LayoutV0<Blake2Hasher>;
    let trie =
        TrieDBBuilder::<LayoutV1<sp_runtime::traits::BlakeTwo256>>::new(&db, &state_root).build();

    let scale_encoded_value = trie.get_with(&encoded_storage_key, |v: &[u8]| v.to_vec()).unwrap().unwrap(); // actually gets the value from the trie proof
    println!("get encoded Value from trie:\n{:?}", scale_encoded_value);
    
    // let scale_decode_value :Vec<u8>= codec::Decode::decode(&mut &scale_encoded_value[..]).unwrap();

    println!("get decoded value from trie:\n0x{}", hex::encode(scale_encoded_value.clone()));
    println!("expected_value:\n0x{}", hex::encode(expected_scale_encoded_value.clone()));
    assert_eq!(scale_encoded_value,expected_scale_encoded_value);

    // encode pb vec
    // let expected_sclae_encoded_value = codec::Encode::encode(&expected_pbencoded_value);
    // println!("encoded_expected_value:\n{:?}", expected_sclae_encoded_value);
    let result = sp_trie::verify_trie_proof::<LayoutV1<sp_runtime::traits::BlakeTwo256>, _, _, _>(
        &state_root,
        &proofs,
        &[(encoded_storage_key, Some(expected_scale_encoded_value))]
    );
    println!("sp_trie::verify_trie_proof result:\n{:?}", result);
    // assert!(result.is_ok());

    Ok(())
}


#[tokio::test]
pub async fn test_channel_state_proof1() -> Result<(), Box<dyn std::error::Error>> {
   
	// pub type Channels<T: Config> = StorageMap<_, Blake2_128Concat, ChannelEndsPath, ChannelEnd>;
    // key: CHannelEndsPath
    // #[display(fmt = "channelEnds/ports/{_0}/channels/{_1}")]
    // pub struct ChannelEndsPath(pub PortId, pub ChannelId);
    // eg, ChannelEndsPath(PortId("transfer"), ChannelId("channel-0"))
    // value: ChannelEnd 
    // pub struct ChannelEnd {
    //     pub state: State,
    //     pub ordering: Order,
    //     pub remote: Counterparty,
    //     pub connection_hops: Vec<ConnectionId>,
    //     pub version: Version,
    // }
    // eg:
    // ChannelEnd { 
    //     state: Open, 
    //     ordering: Unordered, 
    //     remote: Counterparty { port_id: PortId("transfer"), channel_id: Some(ChannelId("channel-0")) }, 
    //     connection_hops: [ConnectionId("connection-0")], 
    //     version: Version("ics20-1") 
    // }

    // let state_root_bytes:[u8;32] = [
    //     10, 35, 47, 105, 98, 99, 46, 99, 111, 114, 101, 46, 99, 108, 105, 101, 110, 116, 46, 118,
    //     49, 46, 77,10, 35, 47, 105, 98, 99, 46, 99, 111,  
    // ];
    // let state_root = H256::from(state_root_bytes);
    let state_root = H256::from(hex!(
        "649830ab68730ceeac65aa11e6cf235bc3d36869a4e8b9a72df18b19e0c0f857"
    ));
    
    // key: CHannelEndsPath
    let encoded_storage_key:Vec<u8>= vec![101, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 119, 89, 204, 193, 141, 225, 114, 7, 131, 6, 202, 89, 115, 37, 26, 123, 125, 221, 66, 42, 79, 29, 220, 2, 212, 179, 202, 21, 234, 197, 132, 210, 32, 116, 114, 97, 110, 115, 102, 101, 114, 36, 99, 104, 97, 110, 110, 101, 108, 45, 48];
    // value: scale encode(ChannelEnd)
    let expected_scale_encoded_value:Vec<u8> = vec![3, 1, 32, 116, 114, 97, 110, 115, 102, 101, 114, 1, 36, 99, 104, 97, 110, 110, 101, 108, 45, 48, 4, 48, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 45, 48, 28, 105, 99, 115, 50, 48, 45, 49];
    let proofs: Vec<Vec<u8>>= vec![
        vec![3, 1, 32, 116, 114, 97, 110, 115, 102, 101, 114, 1, 36, 99, 104, 97, 110, 110, 101, 108, 45, 48, 4, 48, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 45, 48, 28, 105, 99, 115, 50, 48, 45, 49], 
        vec![63, 69, 89, 204, 193, 141, 225, 114, 7, 131, 6, 202, 89, 115, 37, 26, 123, 125, 221, 66, 42, 79, 29, 220, 2, 212, 179, 202, 21, 234, 197, 132, 210, 32, 116, 114, 97, 110, 115, 102, 101, 114, 36, 99, 104, 97, 110, 110, 101, 108, 45, 48, 26, 197, 113, 245, 149, 132, 54, 224, 213, 141, 56, 63, 19, 45, 21, 250, 85, 141, 43, 110, 6, 242, 242, 11, 241, 155, 70, 235, 97, 15, 24, 80], 
        vec![128, 128, 32, 128, 58, 225, 86, 97, 10, 58, 172, 85, 33, 225, 202, 13, 129, 16, 25, 181, 85, 115, 37, 142, 140, 34, 59, 32, 198, 141, 101, 92, 45, 166, 131, 31, 100, 94, 175, 218, 65, 33, 225, 150, 51, 237, 160, 123, 37, 248, 10, 100, 93, 32, 1, 0, 0, 0, 0, 0, 0, 0], 
        vec![128, 168, 21, 128, 55, 92, 36, 190, 155, 31, 216, 140, 77, 72, 159, 87, 116, 23, 200, 119, 47, 164, 112, 211, 69, 65, 75, 124, 130, 170, 193, 146, 97, 120, 235, 199, 128, 197, 198, 54, 159, 32, 113, 60, 68, 29, 254, 175, 232, 95, 101, 177, 124, 236, 165, 17, 80, 90, 107, 187, 203, 162, 147, 110, 46, 19, 82, 48, 211, 128, 167, 80, 60, 9, 242, 55, 155, 253, 158, 34, 247, 241, 17, 176, 253, 1, 101, 249, 172, 79, 37, 152, 61, 114, 185, 90, 140, 224, 83, 75, 128, 220, 128, 123, 54, 37, 121, 53, 201, 167, 241, 147, 32, 255, 154, 250, 154, 27, 132, 37, 247, 11, 98, 51, 104, 96, 97, 47, 82, 157, 162, 173, 16, 177, 143, 128, 7, 252, 233, 77, 152, 160, 180, 150, 177, 174, 169, 91, 252, 121, 210, 32, 38, 62, 58, 92, 30, 176, 163, 221, 178, 228, 89, 55, 7, 229, 18, 206, 128, 81, 119, 54, 240, 89, 55, 154, 228, 116, 2, 207, 155, 93, 147, 6, 215, 50, 179, 165, 115, 98, 242, 54, 144, 218, 23, 76, 154, 206, 45, 22, 132], 
        vec![128, 255, 255, 128, 110, 115, 223, 130, 149, 237, 240, 34, 14, 203, 153, 5, 219, 218, 14, 73, 139, 120, 87, 155, 182, 111, 132, 116, 19, 6, 77, 112, 139, 17, 138, 212, 128, 226, 196, 169, 115, 135, 66, 44, 244, 127, 34, 45, 168, 79, 26, 45, 186, 182, 138, 231, 47, 90, 193, 207, 145, 105, 144, 136, 0, 119, 41, 223, 168, 128, 48, 68, 101, 111, 115, 55, 226, 113, 49, 155, 185, 154, 139, 199, 159, 51, 96, 184, 214, 105, 12, 110, 83, 189, 109, 136, 153, 172, 119, 95, 99, 27, 128, 124, 249, 24, 51, 15, 229, 70, 125, 181, 155, 184, 96, 238, 254, 94, 230, 169, 231, 219, 19, 246, 12, 147, 47, 0, 226, 224, 154, 68, 98, 238, 204, 128, 170, 229, 228, 112, 127, 188, 173, 214, 8, 197, 235, 249, 117, 17, 232, 66, 124, 151, 134, 69, 181, 174, 252, 35, 224, 81, 72, 66, 168, 177, 244, 233, 128, 19, 208, 29, 50, 230, 87, 224, 154, 31, 129, 109, 240, 35, 243, 254, 249, 40, 104, 0, 84, 251, 185, 222, 3, 200, 224, 34, 95, 238, 52, 247, 97, 128, 148, 198, 204, 71, 131, 29, 18, 29, 125, 74, 36, 176, 40, 251, 193, 77, 172, 1, 90, 71, 156, 31, 45, 93, 156, 1, 96, 98, 213, 176, 188, 77, 128, 91, 104, 33, 50, 197, 41, 8, 112, 85, 38, 5, 127, 115, 171, 127, 204, 171, 74, 246, 215, 42, 152, 5, 99, 77, 216, 211, 204, 83, 241, 48, 209, 128, 194, 212, 77, 55, 30, 95, 193, 245, 2, 39, 215, 73, 26, 214, 90, 208, 73, 99, 3, 97, 206, 251, 74, 177, 132, 72, 49, 35, 118, 9, 240, 131, 128, 242, 70, 152, 253, 148, 27, 93, 148, 107, 141, 36, 22, 255, 0, 245, 10, 18, 190, 69, 98, 47, 254, 245, 122, 138, 26, 201, 24, 83, 70, 47, 222, 128, 212, 134, 14, 143, 157, 248, 129, 213, 211, 250, 134, 173, 128, 56, 245, 28, 17, 215, 21, 168, 25, 89, 47, 50, 133, 99, 203, 114, 180, 163, 224, 132, 128, 6, 79, 139, 72, 229, 109, 121, 22, 179, 13, 68, 13, 29, 84, 162, 53, 95, 97, 45, 18, 123, 67, 87, 185, 106, 12, 179, 115, 211, 106, 201, 63, 128, 252, 245, 1, 219, 68, 24, 76, 194, 208, 144, 253, 241, 103, 213, 5, 216, 52, 22, 190, 3, 68, 91, 74, 95, 161, 1, 98, 8, 0, 29, 175, 241, 128, 84, 57, 10, 43, 165, 71, 251, 206, 148, 131, 39, 164, 19, 87, 235, 54, 174, 134, 251, 140, 7, 218, 87, 181, 45, 70, 3, 194, 130, 203, 208, 41, 128, 107, 253, 187, 240, 224, 190, 220, 185, 147, 182, 92, 156, 234, 30, 146, 154, 86, 215, 138, 59, 123, 197, 61, 27, 124, 166, 252, 72, 142, 34, 149, 238, 128, 21, 143, 201, 147, 132, 172, 8, 96, 196, 33, 159, 101, 170, 106, 62, 71, 123, 32, 142, 219, 226, 54, 153, 124, 141, 124, 98, 72, 36, 245, 193, 106], 
        vec![158, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 253, 182, 128, 251, 95, 83, 184, 35, 9, 44, 102, 139, 162, 10, 61, 145, 133, 80, 72, 64, 142, 244, 72, 158, 114, 229, 251, 155, 207, 151, 86, 249, 95, 90, 218, 128, 212, 194, 220, 133, 47, 174, 193, 192, 27, 188, 162, 103, 171, 67, 32, 86, 228, 177, 248, 164, 190, 90, 242, 194, 132, 65, 168, 139, 151, 223, 104, 141, 128, 5, 22, 213, 157, 3, 170, 154, 49, 14, 108, 246, 233, 16, 45, 232, 71, 17, 221, 200, 57, 139, 200, 97, 93, 91, 35, 157, 221, 157, 137, 217, 21, 80, 95, 14, 123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41, 8, 0, 0, 128, 246, 95, 99, 216, 4, 0, 123, 51, 167, 118, 39, 209, 15, 248, 240, 142, 161, 200, 45, 240, 52, 0, 96, 135, 33, 20, 96, 39, 241, 93, 10, 238, 104, 95, 8, 242, 131, 232, 130, 12, 246, 179, 105, 215, 10, 187, 160, 190, 136, 229, 32, 242, 0, 0, 0, 0, 0, 0, 0, 128, 224, 143, 169, 158, 149, 64, 192, 223, 0, 62, 116, 83, 236, 245, 229, 134, 201, 143, 95, 101, 228, 127, 148, 46, 12, 246, 98, 198, 194, 240, 223, 189, 128, 161, 134, 8, 202, 50, 241, 81, 24, 144, 217, 166, 226, 181, 54, 129, 56, 76, 93, 77, 109, 79, 198, 135, 72, 18, 92, 29, 245, 21, 175, 34, 81, 128, 38, 252, 74, 183, 30, 157, 112, 56, 175, 144, 191, 82, 218, 141, 251, 227, 100, 197, 70, 71, 14, 22, 196, 204, 173, 209, 77, 28, 9, 13, 243, 241, 128, 125, 47, 133, 225, 2, 241, 165, 90, 99, 146, 62, 11, 139, 6, 98, 43, 182, 10, 243, 232, 190, 48, 156, 182, 137, 220, 206, 211, 64, 44, 188, 31, 128, 9, 68, 187, 63, 91, 170, 177, 195, 177, 72, 162, 250, 200, 19, 118, 145, 219, 189, 237, 215, 65, 17, 228, 107, 29, 93, 217, 77, 102, 93, 114, 126, 128, 238, 117, 244, 178, 239, 185, 160, 2, 181, 88, 43, 182, 134, 206, 70, 235, 204, 189, 204, 164, 225, 149, 186, 147, 167, 117, 127, 42, 78, 79, 229, 75]    
    ];
    let db = StorageProof::new(proofs.clone()).into_memory_db::<sp_runtime::traits::BlakeTwo256>();
    // type LayoutV0 = LayoutV0<Blake2Hasher>;
    let trie =
        TrieDBBuilder::<LayoutV1<sp_runtime::traits::BlakeTwo256>>::new(&db, &state_root).build();

    let scale_encoded_value = trie.get_with(&encoded_storage_key, |v: &[u8]| v.to_vec()).unwrap().unwrap(); // actually gets the value from the trie proof
    println!("get encoded Value from trie:\n{:?}", scale_encoded_value);
    
    // let scale_decode_value :Vec<u8>= codec::Decode::decode(&mut &scale_encoded_value[..]).unwrap();

    println!("get decoded value from trie:\n0x{}", hex::encode(scale_encoded_value.clone()));
    println!("expected_value:\n0x{}", hex::encode(expected_scale_encoded_value.clone()));
    assert_eq!(scale_encoded_value,expected_scale_encoded_value);

    // encode pb vec
    // let expected_sclae_encoded_value = codec::Encode::encode(&expected_pbencoded_value);
    // println!("encoded_expected_value:\n{:?}", expected_sclae_encoded_value);
    let result = sp_trie::verify_trie_proof::<LayoutV1<sp_runtime::traits::BlakeTwo256>, _, _, _>(
        &state_root,
        &proofs,
        &[(encoded_storage_key, Some(expected_scale_encoded_value))]
    );
    println!("sp_trie::verify_trie_proof result:\n{:?}", result);
    // assert!(result.is_ok());

    Ok(())
}

#[tokio::test]
pub async fn test_ack_state_proof() -> Result<(), Box<dyn std::error::Error>> {
   
  
	// pub type Acknowledgements<T: Config> =
    // StorageMap<_, Blake2_128Concat, AcksPath, IbcAcknowledgementCommitment>;
    // key: AcksPath
    // #[display(fmt = "acks/ports/{port_id}/channels/{channel_id}/sequences/{sequence}")]
    // pub struct AcksPath {
    //     pub port_id: PortId,
    //     pub channel_id: ChannelId,
    //     pub sequence: Sequence,
    // }

    // eg:
    // AcksPath { 
    //     port_id: PortId("transfer"), 
    //     channel_id: ChannelId("channel-0"), 
    //     sequence: Sequence(1) 
    // } 

    // value: hash of acknowledgement 
    // pub struct AcknowledgementCommitment(Vec<u8>);
    // eg:
    // AcknowledgementCommitment([8, 247, 85, 126, 213, 24, 38, 254, 24, 216, 69, 18, 191, 36, 236, 117, 0, 30, 219, 175, 33, 35, 164, 119, 223, 114, 160, 169, 243, 100, 10, 124])

    // let state_root_bytes:[u8;32] = [
    //     10, 35, 47, 105, 98, 99, 46, 99, 111, 114, 101, 46, 99, 108, 105, 101, 110, 116, 46, 118,
    //     49, 46, 77,10, 35, 47, 105, 98, 99, 46, 99, 111,  
    // ];
    // let state_root = H256::from(state_root_bytes);
    let state_root = H256::from(hex!(
        "3dffb59376a01f4ec5b1c97953114c1966b3845753923d2fb91935ee1362537a"
    ));
    
    // key: AcksPath
    let encoded_storage_key:Vec<u8>= vec![101, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 208, 197, 116, 78, 15, 149, 146, 226, 3, 61, 201, 201, 238, 150, 179, 10, 192, 0, 91, 214, 0, 87, 88, 239, 116, 33, 116, 87, 113, 55, 152, 74, 32, 116, 114, 97, 110, 115, 102, 101, 114, 36, 99, 104, 97, 110, 110, 101, 108, 45, 48, 1, 0, 0, 0, 0, 0, 0, 0];
    // value:scale encode(AcknowledgementCommitment) 
    let expected_scale_encoded_value:Vec<u8> = vec![128, 8, 247, 85, 126, 213, 24, 38, 254, 24, 216, 69, 18, 191, 36, 236, 117, 0, 30, 219, 175, 33, 35, 164, 119, 223, 114, 160, 169, 243, 100, 10, 124];
    let proofs: Vec<Vec<u8>>= vec![
        vec![63, 85, 197, 116, 78, 15, 149, 146, 226, 3, 61, 201, 201, 238, 150, 179, 10, 192, 0, 91, 214, 0, 87, 88, 239, 116, 33, 116, 87, 113, 55, 152, 74, 32, 116, 114, 97, 110, 115, 102, 101, 114, 36, 99, 104, 97, 110, 110, 101, 108, 45, 48, 1, 0, 0, 0, 0, 0, 0, 0, 185, 72, 113, 185, 163, 1, 47, 136, 120, 124, 209, 119, 33, 197, 18, 159, 186, 4, 210, 89, 225, 95, 11, 163, 186, 194, 32, 146, 100, 189, 236, 214], 
        vec![128, 1, 8, 128, 160, 19, 228, 154, 145, 25, 133, 128, 190, 63, 204, 140, 107, 5, 161, 56, 113, 81, 222, 93, 123, 148, 228, 253, 200, 192, 153, 247, 26, 176, 220, 207, 128, 132, 9, 81, 85, 23, 140, 195, 176, 28, 193, 68, 204, 48, 170, 220, 126, 31, 87, 112, 232, 199, 180, 75, 112, 116, 124, 219, 247, 67, 144, 247, 171],
        vec![128, 8, 247, 85, 126, 213, 24, 38, 254, 24, 216, 69, 18, 191, 36, 236, 117, 0, 30, 219, 175, 33, 35, 164, 119, 223, 114, 160, 169, 243, 100, 10, 124], 
        vec![128, 168, 21, 128, 55, 92, 36, 190, 155, 31, 216, 140, 77, 72, 159, 87, 116, 23, 200, 119, 47, 164, 112, 211, 69, 65, 75, 124, 130, 170, 193, 146, 97, 120, 235, 199, 128, 19, 187, 252, 196, 29, 36, 174, 218, 135, 201, 218, 52, 32, 38, 144, 156, 26, 93, 58, 178, 210, 106, 200, 77, 119, 228, 126, 170, 194, 174, 58, 153, 128, 167, 80, 60, 9, 242, 55, 155, 253, 158, 34, 247, 241, 17, 176, 253, 1, 101, 249, 172, 79, 37, 152, 61, 114, 185, 90, 140, 224, 83, 75, 128, 220, 128, 135, 183, 155, 184, 102, 164, 73, 131, 176, 234, 95, 136, 97, 135, 129, 217, 55, 163, 249, 198, 99, 251, 233, 227, 112, 222, 190, 14, 222, 105, 159, 85, 128, 7, 252, 233, 77, 152, 160, 180, 150, 177, 174, 169, 91, 252, 121, 210, 32, 38, 62, 58, 92, 30, 176, 163, 221, 178, 228, 89, 55, 7, 229, 18, 206, 128, 81, 119, 54, 240, 89, 55, 154, 228, 116, 2, 207, 155, 93, 147, 6, 215, 50, 179, 165, 115, 98, 242, 54, 144, 218, 23, 76, 154, 206, 45, 22, 132], 
        vec![128, 255, 255, 128, 170, 137, 197, 148, 196, 88, 116, 45, 156, 43, 212, 187, 137, 173, 81, 238, 176, 92, 36, 10, 80, 13, 242, 191, 231, 84, 0, 160, 180, 100, 218, 224, 128, 188, 152, 193, 138, 11, 188, 155, 73, 73, 241, 37, 158, 204, 234, 77, 7, 134, 15, 154, 202, 221, 99, 153, 14, 203, 232, 24, 180, 116, 107, 3, 119, 128, 129, 30, 177, 68, 129, 98, 143, 45, 207, 148, 206, 202, 206, 216, 38, 214, 123, 74, 123, 121, 51, 82, 173, 1, 74, 88, 231, 193, 237, 184, 230, 249, 128, 34, 213, 237, 91, 75, 128, 16, 247, 167, 242, 137, 13, 181, 151, 126, 73, 231, 205, 26, 65, 39, 139, 234, 160, 82, 234, 26, 75, 71, 222, 4, 1, 128, 251, 161, 209, 220, 157, 143, 30, 59, 135, 81, 67, 11, 48, 159, 70, 180, 98, 48, 56, 188, 150, 252, 227, 142, 10, 194, 250, 158, 27, 146, 24, 35, 128, 68, 61, 221, 101, 252, 164, 129, 55, 233, 189, 37, 119, 9, 116, 202, 148, 44, 109, 169, 234, 107, 215, 230, 218, 110, 60, 71, 63, 27, 132, 159, 15, 128, 25, 173, 56, 225, 138, 57, 94, 94, 254, 163, 128, 17, 56, 32, 163, 139, 241, 247, 25, 131, 231, 236, 99, 225, 219, 235, 233, 177, 71, 199, 2, 111, 128, 91, 104, 33, 50, 197, 41, 8, 112, 85, 38, 5, 127, 115, 171, 127, 204, 171, 74, 246, 215, 42, 152, 5, 99, 77, 216, 211, 204, 83, 241, 48, 209, 128, 194, 212, 77, 55, 30, 95, 193, 245, 2, 39, 215, 73, 26, 214, 90, 208, 73, 99, 3, 97, 206, 251, 74, 177, 132, 72, 49, 35, 118, 9, 240, 131, 128, 113, 132, 80, 125, 31, 113, 174, 195, 163, 96, 208, 126, 147, 221, 224, 75, 43, 173, 135, 46, 28, 149, 176, 217, 168, 51, 235, 96, 243, 117, 249, 252, 128, 127, 240, 3, 161, 47, 55, 19, 198, 167, 86, 100, 41, 83, 174, 95, 49, 102, 84, 35, 140, 116, 151, 177, 249, 88, 242, 67, 246, 14, 159, 80, 110, 128, 39, 27, 207, 229, 221, 25, 137, 152, 77, 15, 46, 16, 86, 67, 124, 167, 74, 124, 135, 195, 32, 211, 182, 130, 51, 104, 169, 237, 244, 166, 254, 76, 128, 109, 98, 240, 20, 206, 29, 202, 149, 61, 244, 69, 122, 214, 23, 245, 234, 5, 54, 183, 32, 9, 34, 30, 173, 230, 218, 244, 129, 148, 7, 208, 113, 128, 101, 195, 199, 158, 201, 111, 47, 175, 36, 210, 91, 106, 44, 188, 79, 234, 30, 32, 253, 0, 115, 127, 233, 155, 26, 85, 238, 47, 10, 232, 36, 131, 128, 107, 253, 187, 240, 224, 190, 220, 185, 147, 182, 92, 156, 234, 30, 146, 154, 86, 215, 138, 59, 123, 197, 61, 27, 124, 166, 252, 72, 142, 34, 149, 238, 128, 60, 37, 161, 13, 220, 253, 121, 230, 240, 237, 77, 115, 58, 104, 105, 191, 180, 93, 151, 66, 101, 51, 116, 230, 207, 74, 191, 218, 216, 55, 135, 81], 
        vec![158, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 253, 182, 128, 251, 95, 83, 184, 35, 9, 44, 102, 139, 162, 10, 61, 145, 133, 80, 72, 64, 142, 244, 72, 158, 114, 229, 251, 155, 207, 151, 86, 249, 95, 90, 218, 128, 212, 194, 220, 133, 47, 174, 193, 192, 27, 188, 162, 103, 171, 67, 32, 86, 228, 177, 248, 164, 190, 90, 242, 194, 132, 65, 168, 139, 151, 223, 104, 141, 128, 44, 204, 55, 232, 182, 53, 168, 120, 102, 171, 96, 200, 204, 193, 212, 130, 161, 250, 46, 234, 123, 39, 213, 49, 66, 32, 195, 223, 120, 97, 28, 29, 80, 95, 14, 123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41, 8, 0, 0, 128, 195, 215, 179, 47, 45, 131, 215, 202, 12, 128, 13, 151, 38, 189, 24, 215, 5, 59, 36, 40, 4, 231, 58, 91, 63, 109, 242, 205, 74, 1, 79, 194, 104, 95, 8, 242, 131, 232, 130, 12, 246, 179, 105, 215, 10, 187, 160, 190, 136, 229, 32, 12, 0, 0, 0, 0, 0, 0, 0, 128, 224, 143, 169, 158, 149, 64, 192, 223, 0, 62, 116, 83, 236, 245, 229, 134, 201, 143, 95, 101, 228, 127, 148, 46, 12, 246, 98, 198, 194, 240, 223, 189, 128, 156, 143, 206, 41, 62, 57, 42, 61, 211, 169, 70, 38, 242, 213, 93, 255, 151, 159, 109, 200, 240, 170, 87, 23, 41, 254, 61, 195, 23, 85, 218, 33, 128, 172, 121, 82, 235, 235, 195, 30, 21, 206, 29, 182, 181, 132, 72, 166, 141, 95, 202, 122, 146, 224, 178, 99, 13, 191, 148, 236, 127, 9, 4, 189, 131, 128, 125, 47, 133, 225, 2, 241, 165, 90, 99, 146, 62, 11, 139, 6, 98, 43, 182, 10, 243, 232, 190, 48, 156, 182, 137, 220, 206, 211, 64, 44, 188, 31, 128, 75, 185, 133, 2, 77, 67, 19, 190, 188, 230, 239, 218, 105, 159, 162, 164, 118, 227, 221, 206, 254, 163, 84, 252, 221, 45, 12, 196, 96, 253, 94, 154, 128, 126, 98, 144, 235, 110, 141, 186, 52, 5, 67, 188, 146, 247, 252, 15, 124, 8, 165, 74, 53, 60, 158, 209, 224, 57, 250, 161, 100, 152, 175, 9, 41]
            
    ];
    let db = StorageProof::new(proofs.clone()).into_memory_db::<sp_runtime::traits::BlakeTwo256>();
    // type LayoutV0 = LayoutV0<Blake2Hasher>;
    let trie =
        TrieDBBuilder::<LayoutV1<sp_runtime::traits::BlakeTwo256>>::new(&db, &state_root).build();

    let scale_encoded_value = trie.get_with(&encoded_storage_key, |v: &[u8]| v.to_vec()).unwrap().unwrap(); // actually gets the value from the trie proof
    println!("get encoded Value from trie:\n{:?}", scale_encoded_value);
    
    // let scale_decode_value :Vec<u8>= codec::Decode::decode(&mut &scale_encoded_value[..]).unwrap();

    println!("get decoded value from trie:\n0x{}", hex::encode(scale_encoded_value.clone()));
    println!("expected_scale_encoded_value:\n0x{}", hex::encode(expected_scale_encoded_value.clone()));
    assert_eq!(scale_encoded_value,expected_scale_encoded_value);

    // encode pb vec
    // let expected_sclae_encoded_value = codec::Encode::encode(&expected_pbencoded_value);
    // println!("encoded_expected_value:\n{:?}", expected_sclae_encoded_value);
    let result = sp_trie::verify_trie_proof::<LayoutV1<sp_runtime::traits::BlakeTwo256>, _, _, _>(
        &state_root,
        &proofs,
        &[(encoded_storage_key, Some(expected_scale_encoded_value))]
    );
    println!("sp_trie::verify_trie_proof result:\n{:?}", result);
    // assert!(result.is_ok());

    Ok(())
}

#[tokio::test]
pub async fn test_packet_commitment_state_proof() -> Result<(), Box<dyn std::error::Error>> {
   
	// pub type PacketCommitment<T: Config> =
	// 	StorageMap<_, Blake2_128Concat, CommitmentsPath, IbcPacketCommitment>;
    // key: CommitmentsPath
    // #[display(fmt = "commitments/ports/{port_id}/channels/{channel_id}/sequences/{sequence}")]
    // pub struct CommitmentsPath {
    //     pub port_id: PortId,
    //     pub channel_id: ChannelId,
    //     pub sequence: Sequence,
    // }

    // eg:
    // CommitmentsPath { 
    //     port_id: PortId("transfer"), 
    //     channel_id: ChannelId("channel-0"), 
    //     sequence: Sequence(1) 
    // }

    // value: hash of (timestamp, height, packet)
    // pub struct PacketCommitment(Vec<u8>);
    // eg:
    // PacketCommitment([235, 4, 6, 196, 75, 64, 84, 128, 236, 253, 168, 46, 222, 28, 78, 166, 201, 140, 230, 155, 146, 193, 77, 25, 215, 111, 9, 183, 125, 230, 39, 212])

    // let state_root_bytes:[u8;32] = [
    //     10, 35, 47, 105, 98, 99, 46, 99, 111, 114, 101, 46, 99, 108, 105, 101, 110, 116, 46, 118,
    //     49, 46, 77,10, 35, 47, 105, 98, 99, 46, 99, 111,  
    // ];
    // let state_root = H256::from(state_root_bytes);
    let state_root = H256::from(hex!(
        "eb7a8b9846960ecbf64d01c952c452b8ac58189a1891f15fab0edc832f670e36"
    ));
    
    // key: CommitmentsPath
    let encoded_storage_key:Vec<u8>= vec![101, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 7, 67, 100, 221, 193, 141, 254, 20, 47, 67, 140, 26, 178, 89, 186, 129, 192, 0, 91, 214, 0, 87, 88, 239, 116, 33, 116, 87, 113, 55, 152, 74, 32, 116, 114, 97, 110, 115, 102, 101, 114, 36, 99, 104, 97, 110, 110, 101, 108, 45, 48, 1, 0, 0, 0, 0, 0, 0, 0];
    // value:scale encode(PacketCommitment) 
    let expected_scale_encoded_value:Vec<u8> = vec![128, 235, 4, 6, 196, 75, 64, 84, 128, 236, 253, 168, 46, 222, 28, 78, 166, 201, 140, 230, 155, 146, 193, 77, 25, 215, 111, 9, 183, 125, 230, 39, 212];
    let proofs: Vec<Vec<u8>>= vec![
        vec![63, 85, 67, 100, 221, 193, 141, 254, 20, 47, 67, 140, 26, 178, 89, 186, 129, 192, 0, 91, 214, 0, 87, 88, 239, 116, 33, 116, 87, 113, 55, 152, 74, 32, 116, 114, 97, 110, 115, 102, 101, 114, 36, 99, 104, 97, 110, 110, 101, 108, 45, 48, 1, 0, 0, 0, 0, 0, 0, 0, 66, 161, 221, 118, 89, 214, 169, 254, 175, 96, 71, 79, 69, 206, 117, 36, 11, 180, 148, 174, 119, 172, 78, 98, 143, 11, 85, 95, 138, 234, 75, 150], 
        vec![128, 160, 132, 100, 94, 209, 30, 38, 53, 8, 217, 206, 214, 116, 96, 173, 68, 230, 25, 64, 32, 1, 0, 0, 0, 0, 0, 0, 0, 128, 108, 143, 36, 71, 122, 121, 188, 68, 28, 197, 196, 196, 93, 99, 179, 229, 253, 245, 13, 155, 110, 20, 81, 26, 250, 4, 150, 208, 234, 155, 225, 21, 100, 94, 188, 245, 27, 222, 65, 138, 14, 86, 107, 122, 75, 66, 31, 59, 242, 32, 1, 0, 0, 0, 0, 0, 0, 0, 128, 148, 241, 130, 88, 174, 222, 126, 84, 215, 123, 235, 246, 93, 186, 113, 171, 195, 18, 138, 250, 25, 55, 223, 186, 176, 229, 45, 177, 73, 152, 171, 254], 
        vec![128, 168, 21, 128, 55, 92, 36, 190, 155, 31, 216, 140, 77, 72, 159, 87, 116, 23, 200, 119, 47, 164, 112, 211, 69, 65, 75, 124, 130, 170, 193, 146, 97, 120, 235, 199, 128, 255, 34, 92, 218, 53, 190, 31, 6, 206, 241, 56, 83, 180, 176, 38, 250, 85, 245, 241, 58, 7, 75, 81, 170, 71, 227, 165, 16, 216, 83, 231, 43, 128, 167, 80, 60, 9, 242, 55, 155, 253, 158, 34, 247, 241, 17, 176, 253, 1, 101, 249, 172, 79, 37, 152, 61, 114, 185, 90, 140, 224, 83, 75, 128, 220, 128, 14, 196, 193, 144, 32, 139, 165, 100, 64, 235, 92, 238, 237, 123, 184, 198, 117, 125, 40, 60, 120, 193, 126, 66, 36, 174, 13, 250, 12, 218, 220, 74, 128, 7, 252, 233, 77, 152, 160, 180, 150, 177, 174, 169, 91, 252, 121, 210, 32, 38, 62, 58, 92, 30, 176, 163, 221, 178, 228, 89, 55, 7, 229, 18, 206, 128, 81, 119, 54, 240, 89, 55, 154, 228, 116, 2, 207, 155, 93, 147, 6, 215, 50, 179, 165, 115, 98, 242, 54, 144, 218, 23, 76, 154, 206, 45, 22, 132], 
        vec![128, 235, 4, 6, 196, 75, 64, 84, 128, 236, 253, 168, 46, 222, 28, 78, 166, 201, 140, 230, 155, 146, 193, 77, 25, 215, 111, 9, 183, 125, 230, 39, 212], 
        vec![128, 255, 255, 128, 30, 227, 64, 56, 206, 165, 43, 62, 107, 152, 143, 136, 143, 88, 113, 213, 251, 43, 62, 166, 124, 85, 101, 199, 229, 209, 134, 20, 206, 58, 209, 39, 128, 111, 126, 143, 209, 88, 58, 155, 120, 117, 40, 247, 91, 12, 146, 109, 29, 108, 199, 88, 162, 48, 40, 48, 25, 102, 164, 133, 31, 66, 100, 252, 23, 128, 196, 148, 229, 134, 191, 145, 249, 50, 172, 245, 239, 28, 188, 166, 132, 155, 100, 71, 4, 147, 99, 123, 168, 87, 59, 98, 123, 52, 102, 67, 7, 74, 128, 142, 125, 63, 71, 37, 248, 151, 208, 188, 157, 90, 115, 192, 141, 120, 115, 194, 29, 237, 178, 155, 255, 173, 38, 159, 87, 138, 11, 124, 230, 225, 70, 128, 51, 106, 83, 192, 217, 4, 201, 171, 18, 137, 143, 93, 86, 240, 151, 112, 221, 183, 114, 64, 73, 239, 246, 163, 242, 122, 244, 182, 125, 55, 31, 37, 128, 170, 36, 147, 205, 11, 35, 50, 146, 12, 105, 105, 253, 80, 2, 157, 5, 146, 77, 195, 69, 146, 236, 26, 135, 133, 131, 36, 137, 147, 84, 231, 47, 128, 150, 55, 74, 40, 194, 183, 37, 8, 18, 169, 73, 33, 107, 67, 149, 93, 194, 82, 59, 89, 62, 131, 195, 115, 81, 112, 99, 2, 119, 26, 15, 183, 128, 91, 104, 33, 50, 197, 41, 8, 112, 85, 38, 5, 127, 115, 171, 127, 204, 171, 74, 246, 215, 42, 152, 5, 99, 77, 216, 211, 204, 83, 241, 48, 209, 128, 194, 212, 77, 55, 30, 95, 193, 245, 2, 39, 215, 73, 26, 214, 90, 208, 73, 99, 3, 97, 206, 251, 74, 177, 132, 72, 49, 35, 118, 9, 240, 131, 128, 72, 213, 184, 69, 97, 24, 153, 109, 34, 184, 61, 110, 245, 207, 173, 246, 132, 214, 212, 189, 156, 111, 164, 2, 73, 138, 23, 178, 70, 2, 168, 227, 128, 155, 168, 247, 51, 49, 162, 91, 133, 8, 11, 242, 254, 82, 96, 39, 39, 90, 17, 97, 28, 161, 242, 115, 224, 115, 215, 229, 71, 4, 204, 225, 51, 128, 187, 32, 110, 71, 252, 229, 143, 56, 24, 109, 147, 112, 154, 70, 107, 104, 70, 98, 71, 128, 192, 103, 0, 21, 98, 170, 116, 45, 150, 8, 45, 233, 128, 181, 164, 201, 225, 60, 32, 91, 9, 98, 159, 58, 59, 177, 217, 92, 169, 98, 190, 178, 254, 151, 171, 63, 41, 145, 181, 166, 92, 86, 6, 187, 56, 128, 10, 156, 21, 195, 188, 169, 225, 13, 44, 233, 94, 46, 73, 50, 217, 214, 152, 138, 154, 79, 116, 148, 196, 184, 191, 74, 169, 30, 116, 189, 184, 107, 128, 107, 253, 187, 240, 224, 190, 220, 185, 147, 182, 92, 156, 234, 30, 146, 154, 86, 215, 138, 59, 123, 197, 61, 27, 124, 166, 252, 72, 142, 34, 149, 238, 128, 139, 55, 52, 48, 125, 237, 240, 147, 174, 155, 224, 104, 220, 28, 117, 254, 155, 145, 165, 248, 200, 80, 155, 190, 237, 184, 49, 62, 55, 107, 188, 81], vec![158, 204, 242, 3, 105, 192, 221, 218, 216, 45, 16, 3, 82, 58, 196, 142, 253, 182, 128, 182, 245, 82, 165, 101, 37, 149, 168, 219, 104, 43, 15, 232, 124, 140, 115, 7, 194, 97, 21, 218, 72, 64, 102, 207, 212, 115, 227, 218, 128, 7, 9, 128, 212, 194, 220, 133, 47, 174, 193, 192, 27, 188, 162, 103, 171, 67, 32, 86, 228, 177, 248, 164, 190, 90, 242, 194, 132, 65, 168, 139, 151, 223, 104, 141, 128, 44, 204, 55, 232, 182, 53, 168, 120, 102, 171, 96, 200, 204, 193, 212, 130, 161, 250, 46, 234, 123, 39, 213, 49, 66, 32, 195, 223, 120, 97, 28, 29, 80, 95, 14, 123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41, 8, 0, 0, 128, 23, 59, 158, 189, 64, 231, 17, 206, 105, 54, 58, 247, 140, 170, 249, 19, 167, 49, 241, 91, 145, 39, 75, 122, 127, 207, 72, 226, 28, 164, 184, 223, 104, 95, 8, 242, 131, 232, 130, 12, 246, 179, 105, 215, 10, 187, 160, 190, 136, 229, 32, 12, 0, 0, 0, 0, 0, 0, 0, 128, 224, 143, 169, 158, 149, 64, 192, 223, 0, 62, 116, 83, 236, 245, 229, 134, 201, 143, 95, 101, 228, 127, 148, 46, 12, 246, 98, 198, 194, 240, 223, 189, 128, 156, 143, 206, 41, 62, 57, 42, 61, 211, 169, 70, 38, 242, 213, 93, 255, 151, 159, 109, 200, 240, 170, 87, 23, 41, 254, 61, 195, 23, 85, 218, 33, 128, 172, 121, 82, 235, 235, 195, 30, 21, 206, 29, 182, 181, 132, 72, 166, 141, 95, 202, 122, 146, 224, 178, 99, 13, 191, 148, 236, 127, 9, 4, 189, 131, 128, 125, 47, 133, 225, 2, 241, 165, 90, 99, 146, 62, 11, 139, 6, 98, 43, 182, 10, 243, 232, 190, 48, 156, 182, 137, 220, 206, 211, 64, 44, 188, 31, 128, 75, 185, 133, 2, 77, 67, 19, 190, 188, 230, 239, 218, 105, 159, 162, 164, 118, 227, 221, 206, 254, 163, 84, 252, 221, 45, 12, 196, 96, 253, 94, 154, 128, 126, 98, 144, 235, 110, 141, 186, 52, 5, 67, 188, 146, 247, 252, 15, 124, 8, 165, 74, 53, 60, 158, 209, 224, 57, 250, 161, 100, 152, 175, 9, 41]        
    ];
    let db = StorageProof::new(proofs.clone()).into_memory_db::<sp_runtime::traits::BlakeTwo256>();
    // type LayoutV0 = LayoutV0<Blake2Hasher>;
    let trie =
        TrieDBBuilder::<LayoutV1<sp_runtime::traits::BlakeTwo256>>::new(&db, &state_root).build();

    let scale_encoded_value = trie.get_with(&encoded_storage_key, |v: &[u8]| v.to_vec()).unwrap().unwrap(); // actually gets the value from the trie proof
    println!("get encoded Value from trie:\n{:?}", scale_encoded_value);
    
    // let scale_decode_value :Vec<u8>= codec::Decode::decode(&mut &scale_encoded_value[..]).unwrap();

    println!("get decoded value from trie:\n0x{}", hex::encode(scale_encoded_value.clone()));
    println!("expected_scale_encoded_value:\n0x{}", hex::encode(expected_scale_encoded_value.clone()));
    assert_eq!(scale_encoded_value,expected_scale_encoded_value);

    // encode pb vec
    // let expected_sclae_encoded_value = codec::Encode::encode(&expected_pbencoded_value);
    // println!("encoded_expected_value:\n{:?}", expected_sclae_encoded_value);
    let result = sp_trie::verify_trie_proof::<LayoutV1<sp_runtime::traits::BlakeTwo256>, _, _, _>(
        &state_root,
        &proofs,
        &[(encoded_storage_key, Some(expected_scale_encoded_value))]
    );
    println!("sp_trie::verify_trie_proof result:\n{:?}", result);
    // assert!(result.is_ok());

    Ok(())
}