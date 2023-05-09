use codec::Decode;
use sp_core::H256;



use hex_literal::hex;

use sp_core::sp_std;

use sp_trie::{LayoutV0, StorageProof, Trie, TrieDBBuilder};
use tendermint::Time;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // let root = CommitmentRoot::from(finalized_head.state_root.as_bytes().to_vec());
    // let consensus_state = GpConsensusState::new(root, timestamp);

    let key = hex!("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb").to_vec();
    let state_root = H256::from(hex!(
        "dc4887669c2a6b3462e9557aa3105a66a02b6ec3b21784613de78c95dc3cbbe0"
    ));

    let proof = vec![
        hex!("80fffd8028b54b9a0a90d41b7941c43e6a0597d5914e3b62bdcb244851b9fc806c28ea2480d5ba6d50586692888b0c2f5b3c3fc345eb3a2405996f025ed37982ca396f5ed580bd281c12f20f06077bffd56b2f8b6431ee6c9fd11fed9c22db86cea849aeff2280afa1e1b5ce72ea1675e5e69be85e98fbfb660691a76fee9229f758a75315f2bc80aafc60caa3519d4b861e6b8da226266a15060e2071bba4184e194da61dfb208e809d3f6ae8f655009551de95ae1ef863f6771522fd5c0475a50ff53c5c8169b5888024a760a8f6c27928ae9e2fed9968bc5f6e17c3ae647398d8a615e5b2bb4b425f8085a0da830399f25fca4b653de654ffd3c92be39f3ae4f54e7c504961b5bd00cf80c2d44d371e5fc1f50227d7491ad65ad049630361cefb4ab1844831237609f08380c644938921d14ae611f3a90991af8b7f5bdb8fa361ee2c646c849bca90f491e6806e729ad43a591cd1321762582782bbe4ed193c6f583ec76013126f7f786e376280509bb016f2887d12137e73d26d7ddcd7f9c8ff458147cb9d309494655fe68de180009f8697d760fbe020564b07f407e6aad58ba9451b3d2d88b3ee03e12db7c47480952dcc0804e1120508a1753f1de4aa5b7481026a3320df8b48e918f0cecbaed3803360bf948fddc403d345064082e8393d7a1aad7a19081f6d02d94358f242b86c").to_vec(),
        hex!("9ec365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb20865c4a2b7f010000").to_vec(),
        hex!("8005088076c66e2871b4fe037d112ebffb3bfc8bd83a4ec26047f58ee2df7be4e9ebe3d680c1638f702aaa71e4b78cc8538ecae03e827bb494cc54279606b201ec071a5e24806d2a1e6d5236e1e13c5a5c84831f5f5383f97eba32df6f9faf80e32cf2f129bc").to_vec(),
    ];
    let db = StorageProof::new(proof).into_memory_db::<sp_runtime::traits::BlakeTwo256>();
    // type LayoutV0 = LayoutV0<Blake2Hasher>;
    let trie =
        TrieDBBuilder::<LayoutV0<sp_runtime::traits::BlakeTwo256>>::new(&db, &state_root).build();

    // let trie = sp_trie::TrieDB::<sp_trie::LayoutV0<Blake2Hasher>>::new(&db, &state_root)
    //     .unwrap();

    let value = trie.get_with(&key, |v: &[u8]| v.to_vec()).unwrap().unwrap(); // actually gets the value from the trie proof
    println!("the key value: {:?}", value);

    let timestamp: u64 = codec::Decode::decode(&mut &value[..]).unwrap();
    println!("timestamp from proof: {}", timestamp);

    use sp_std::time::Duration;
    let duration = Duration::from_millis(timestamp);
    println!(" duration = {:?}", duration);

    let tm_timestamp =
        Time::from_unix_timestamp(duration.as_secs() as i64, duration.subsec_nanos());
    println!("tm_timestamp = {:?}", tm_timestamp);

    let timestamp_str = tm_timestamp.unwrap().to_rfc3339();
    println!("timestamp_str = {:?}", timestamp_str);
    //0x470a069fc4eec01e7a8aa0e55a5c75db2c495efebcf684fdada8f1c6c63290c0
    //0x470a069fc4eec01e7a8aa0e55a5c75db2c495efebcf684fdada8f1c6c63290c0
    let state_root = H256::from(hex!(
        "470a069fc4eec01e7a8aa0e55a5c75db2c495efebcf684fdada8f1c6c63290c0"
    ));
    // 0xcd710b30bd2eab0352ddcc26417aa1941b3c252fcb29d88eff4f3de5de4476c363f5a4efb16ffa83d0070000
    // 0xcd710b30bd2eab0352ddcc26417aa1941b3c252fcb29d88eff4f3de5de4476c363f5a4efb16ffa83d0070000
    let key = hex!("cd710b30bd2eab0352ddcc26417aa1941b3c252fcb29d88eff4f3de5de4476c363f5a4efb16ffa83d0070000").to_vec();

    let proof = vec![
        hex!("3f180b3c252fcb29d88eff4f3de5de4476c363f5a4efb16ffa83d00700008cb5961e430e84c78fd485ddc5f48734525bdb26d814b7f4953ff10f4974b174").to_vec(),
        hex!("8004648031b60c9237ed343094831987f2bec10b211621255ad0b440cf161fa820d30db480f6f6801e4b41e2e6d8ec194dba122bfb9eb33feb2545ef5144cea79551f7cc528012cb74d5658cc044408815a1ce1104b4c5ca791dc0135e9074ad130d40fdf79d80eb2131e1e8e24de6f91fd32addc2c0b4db59dddda6bd17c69bfe57d3d87745ca").to_vec(),
        hex!("80ffff806219f485445da4884feea1f09b933bc77eb34e96aa059fa4c9fc096aa7a113cb80e59d7b787f421c048a6324f9c62135f42ffd466345883a95aab01d63a7dd26ee80d9981a224a7cd55255464744e0938e1cf600a2825d0d119ce1e6ed36ab15050f805b0999d27a38ad533fe643d6756b71fa7e684599d748f7de04a14d848d1ebde1800c4a0d3ce7d2560fdeeb704e62ec81d7aea9d269d050c13a2871d3800b0c121c80f82b4e4186441431b121df8d97e51b0d1390a1018753801992aa23b78309e54280a8946a28c482ead765fc8319e70464359d263fcc70cf52acfc44a54765653a39805b682132c52908705526057f73ab7fccab4af6d72a9805634dd8d3cc53f130d180c2d44d371e5fc1f50227d7491ad65ad049630361cefb4ab1844831237609f083804f6fb4ba043bc584d1c8b1ae82fb9a103e9d2e8b3c3ec726302f36a058d6c3c6809c33081b8ee4a18031c53cbaa4719556a593d650d4f75a34084df024d74a963b8030f8ff439d3a5ecdbd2a6ce3b1577c59a737a91550024c6fed952ef2ccb3fb8980587e95370248f105507977d5adbaadcfc2f49bd26daaa477756d71cac6de9b52806635c9ab61ee8dcd74e50d485cb4ab08d0b7c3a7f383d09a92fd6f58795ed4de806bfdbbf0e0bedcb993b65c9cea1e929a56d78a3b7bc53d1b7ca6fc488e2295ee80e78a212a664df92a357f3820e250342cb40fbf60aaa71751a85941466790ee5a").to_vec(),
        hex!("9e710b30bd2eab0352ddcc26417aa1945f4380699a53b51a9709a3a86039c49b5ef278e9fc244dae27e1a0380c91bff5b04885803284444dab27d8408f88b637143dcdde93648410c975c9dcf8ec580d7e8f3ec77c77081e0bfde17b36573208a06cb5cfba6b63f5a4efb16ffa83d0070000040280050fb9422cfb4cf5fa865879260a44dc24d432de97da9a960f34db22d74f70dd505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f03c716fb8fff3de61a883bb76adb34a20400805e290f2677915a695fb33533682c80c169044705b243c2e80e00f71aadf604b54c5f0f4993f016e2d2f8e5f43be7bb25948604008054c03fbb201074f300a4e963ab0db0fd10a34afe0b3b22db3ab063d724d2a23c").to_vec(),
        hex!("e102d90f400ff2253268a3025685f884dcc804d40871929998b083a9bf2cbee3c6cfed017f4d9b48dfc57905fae71b366a2078b6de4a580d1c9c7df8a7fed9bf7ac5e295ceed0096eaaae75144c0048093c959274f1ccd753d3db34d18138cec907cccfe080661757261207aa05c080000000005617572610101e6d19993d90d1646568c5089ed21d8265886fdeb2261d3169e7551b08eb74a7772983dbd6b0ebcf1287011500f1acf70522baf08623758820181dfc70c6a3589").to_vec(),
        
    ];
    let db = StorageProof::new(proof).into_memory_db::<sp_runtime::traits::BlakeTwo256>();
    // type LayoutV0 = LayoutV0<Blake2Hasher>;
    let trie =
        TrieDBBuilder::<LayoutV0<sp_runtime::traits::BlakeTwo256>>::new(&db, &state_root).build();

    // let trie = sp_trie::TrieDB::<sp_trie::LayoutV0<Blake2Hasher>>::new(&db, &state_root)
    //     .unwrap();

    let value = trie.get_with(&key, |v: &[u8]| v.to_vec()).unwrap().unwrap(); // actually gets the value from the trie proof
    println!("encode header: 0x{}", hex::encode(value.clone()));

    // let para_header = polkadot::runtime_types::sp_runtime::generic::header::Header::<core::primitive::u32,
    // sp_runtime::traits::BlakeTwo256>::decode(&mut value);
    let para_header = beefy_light_client::header::Header::decode(&mut &value[..]);
    println!("decode header: {:?}", para_header);

    Ok(())

}