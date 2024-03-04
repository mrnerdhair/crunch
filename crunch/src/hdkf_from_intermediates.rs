const HMAC_OUTER_BLOCK_PADDING: [u8; 32] = [0x80, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x03, 0x00];

fn bytes32_to_long8(x: [u8; 32]) -> [u32; 8] {
    [
        u32::from_be_bytes(x[0..4].try_into().unwrap()),
        u32::from_be_bytes(x[4..8].try_into().unwrap()),
        u32::from_be_bytes(x[8..12].try_into().unwrap()),
        u32::from_be_bytes(x[12..16].try_into().unwrap()),
        u32::from_be_bytes(x[16..20].try_into().unwrap()),
        u32::from_be_bytes(x[20..24].try_into().unwrap()),
        u32::from_be_bytes(x[24..28].try_into().unwrap()),
        u32::from_be_bytes(x[28..32].try_into().unwrap()),
    ]
}

fn long8_to_bytes32(x: [u32; 8]) -> [u8; 32] {
    [
        u32::to_be_bytes(x[0]),
        u32::to_be_bytes(x[1]),
        u32::to_be_bytes(x[2]),
        u32::to_be_bytes(x[3]),
        u32::to_be_bytes(x[4]),
        u32::to_be_bytes(x[5]),
        u32::to_be_bytes(x[6]),
        u32::to_be_bytes(x[7]),
    ].concat().try_into().unwrap()
}

pub fn hkdf_from_intermediates(outer_intermediate: [u8; 32], inner: [u8; 32]) -> [u8; 32] {
    let block: [u8; 64] = [inner, HMAC_OUTER_BLOCK_PADDING].concat().try_into().unwrap();
    let mut key = bytes32_to_long8(outer_intermediate);

    sha2::compress256(&mut key, &[block.into()]);

    long8_to_bytes32(key)
}

#[test]
fn test_hkdf_from_intermediates() {
    assert_eq!(
        hex::decode("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21").unwrap(),
        hkdf_from_intermediates(
            hex::decode("2dde0fbb235022bd7d4af6a25f93247c046021696a6f5005bbd4bc40de2dd147").unwrap().try_into().unwrap(),
            hex::decode("6faab530a4b8341ee76913cd3b134619ce21dc59760b71b307bba9e606ba6256").unwrap().try_into().unwrap(),
        ),
    );
}
