//! WebAuthn Level 3 §16 test vectors (RP ID `example.org`, origin
//! `https://example.org`) and a malformed-input sweep over them. The
//! vectors' authenticators mostly skip user verification, which our policy
//! requires, so those cases assert the rejection and verify the signature
//! directly.

use aws_lc_rs::digest::{SHA256, digest};

use super::{
    Rp, WebauthnError, assert, authdata, b64_encode, client_data, cose::CoseKey, register,
};

pub struct Vector {
    reg_challenge: &'static str,
    reg_credential_id: &'static str,
    reg_aaguid: &'static str,
    reg_client_data_json: &'static str,
    reg_attestation_object: &'static str,
    auth_challenge: &'static str,
    auth_authenticator_data: &'static str,
    auth_client_data_json: &'static str,
    auth_signature: &'static str,
}

pub const NONE_ES256: Vector = Vector {
    reg_challenge: "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130",
    reg_credential_id: "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4",
    reg_aaguid: "8446ccb9ab1db374750b2367ff6f3a1f",
    reg_client_data_json: "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d",
    reg_attestation_object: "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220",
    auth_challenge: "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408",
    auth_authenticator_data: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000",
    auth_client_data_json: "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d",
    auth_signature: "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87",
};
pub const PACKED_SELF_ES256: Vector = Vector {
    reg_challenge: "7869c2b772d4b58eba9378cf8f29e26cf935aa77df0da89fa99c0bdc0a76f7e5",
    reg_credential_id: "455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c",
    reg_aaguid: "df850e09db6afbdfab51697791506cfc",
    reg_client_data_json: "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2265476e4374334c55745936366b336a506a796e6962506b31716e666644616966715a774c33417032392d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205539685458764b453255526b4d6e625f307859485667227d",
    reg_attestation_object: "a363666d74667061636b65646761747453746d74a263616c672663736967584630440220067a20754ab925005dbf378097c92120031581c73228d1fb4f5b881bcd7da98302207fc7b147558c7c0eba3af18bd9d121fa3d3a26d17fe3f220272178f473b6006d68617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000df850e09db6afbdfab51697791506cfc0020455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58ca5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2",
    auth_challenge: "4478a10b1352348dd160c1353b0d469b5db19eb91c27f7dfa6fed39fe26af20b",
    auth_authenticator_data: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50900000000",
    auth_client_data_json: "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a225248696843784e534e493352594d45314f7731476d3132786e726b634a5f6666707637546e2d4a71386773222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a206754623533727a36456853576f6d58477a696d433151227d",
    auth_signature: "304402203310b9431903c401f1be2bdc8d23a4007682dbbddcf846994947b7f465daf84002204e94dd00047b316061b3b99772b7efd95994a83ef584b3b6b825ea3550251b66",
};
pub const CROSS_ORIGIN: Vector = Vector {
    reg_challenge: "3be5aacd03537142472340ab5969f240f1d87716e20b6807ac230655fa4b3b49",
    reg_credential_id: "6e1050c0d2ca2f07c755cb2c66a74c64fa43065c18f938354d9915db2bd5ce57",
    reg_aaguid: "883f4f6014f19c09d87aa38123be48d0",
    reg_client_data_json: "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a224f2d57717a514e5463554a484930437257576e7951504859647862694332674872434d475666704c4f306b222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a207a5a7175457444523944577170573574425754467567227d",
    reg_attestation_object: "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54500000000883f4f6014f19c09d87aa38123be48d000206e1050c0d2ca2f07c755cb2c66a74c64fa43065c18f938354d9915db2bd5ce57a501020326200121582022200a473f90b11078851550d03b4e44a2279f8c4eca27b3153dedfe03e4e97d225820cbd0be95e746ad6f5a8191be11756e4c0420e72f65b466d39bc56b8b123a9c6e",
    auth_challenge: "876aa517ba83fdee65fcffdbca4c84eeae5d54f8041a1fc85c991e5bbb273137",
    auth_authenticator_data: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50500000000",
    auth_client_data_json: "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a226832716c463771445f65356c5f505f62796b7945377135645650674547685f49584a6b655737736e4d5463222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a2039327063545644304162792d713464746d6a36656667227d",
    auth_signature: "3046022100eb12fcf23b12764c0f122e22371fab92e283879fd798f38ee1841c951b6e40e7022100c76237ff9db77b3c56f30837cda6a09acfa2e915544e609c0733b1184036d1cf",
};
pub const PACKED_RS256: Vector = Vector {
    reg_challenge: "bea8f0770009bd57f2c0df6fea9f743a27e4b61bbe923c862c7aad7a9fc8e4a6",
    reg_credential_id: "992a18acc83f67533600c1138a4b4c4bd236de13629cf025ed17cb00b00b74df",
    reg_aaguid: "428f8878298b9862a36ad8c7527bfef2",
    reg_client_data_json: "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2276716a776477414a76566679774e3976367039304f69666b7468752d6b6a79474c48717465705f49354b59222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d",
    reg_attestation_object: "a363666d74667061636b65646761747453746d74a363616c672663736967584730450221008b8c5c6ea8c142c032e0be69e1353d44461c5c9109941cdda951b976eb95b6b302204d52f406c19e254b3ff9589bd18070fb055ac8db12fdd0a6734bea9d7168e900637835638159022630820222308201c7a00302010202101f6fb7a5ece81b45896b983a995da5f3300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d03010703420004b7b36b7542a11120b443c794d0c99fdc25a06b76586413d81e086163ef6fe147a557afc34e2861d9057d6d465d4705a0310550bdeeb5f35ee35b9425ab859981a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e04160414fb37b647bccfb9e54d989eaaacc1633868703fb3301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d0403020349003046022100b86bc129d92afca7d9869a39f70f139a305b4073a39eb654d81424bed5757d91022100cf9f7c60cab7c4a7d3e7f0020f281a93d4fd0a9f95121b989f56932a68885fba68617574684461746159021bbfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000428f8878298b9862a36ad8c7527bfef20020992a18acc83f67533600c1138a4b4c4bd236de13629cf025ed17cb00b00b74dfa4010303390100205901b403fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012143010001",
    auth_challenge: "295f59f5fa8fe62c5aca9e27626c78c8da376ae6d8cd2dd29aebad601e1bc4c5",
    auth_authenticator_data: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000",
    auth_client_data_json: "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224b56395a39667150356978617970346e596d7834794e6f33617562597a5333536d75757459423462784d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d",
    auth_signature: "01063d52d7c39b4d432fc7063c5d93e582bdcb16889cd71f888d67d880ea730a428498d3bc8e1ee11f2b1ecbe6c292b118c55ffaaddefa8cad0a54dd137c51f1eec673f1bb6c4d1789d6826a222b22d0f585fc901fdc933212e579d199b89d672aa44891333e6a1355536025e82b25590256c3538229b55737083b2f6b9377e49e2472f11952f79fdd0da180b5ffd901b4049a8f081bb40711bef76c62aed943571f2d0575304cb549d68d8892f95086a30f93716aee818f8dc06e96c0d5e0ed4cfa9fd8773d90464b68cf140f7986666ff9c9e3302acd0535d60d769f465e2ab57ef8aabc89fccfef7ba32a64154a8b3d26be2298f470b8cc5377dbe3dfd4b0b45f8f01e63bde6cfc76b62771f9b70aa27cf40152cad93aa5acd784fd4b90f676e2ea828d0bf2400aebbaae4153e5838f537f88b6228346782a93a899be66ec77de45b3efcf311da6321c92e6b0cd11bfe653bf3e98cee8e341f02d67dbb6f9c98d9e8178090cfb5b70fbc6d541599ac794ae2f1d4de1286ec8de8c2daf7b1d15c8438e90d924df5c19045220a4c8438c1b979bbe016cf3d0eeec23c3999d4882cc645b776de930756612cdc6dd398160ff02a6",
};
pub const PACKED_EDDSA: Vector = Vector {
    reg_challenge: "a8abf9dabdc6b0df63466b39bda9e8a34a34e185337a59f1c579990676d3b3bd",
    reg_credential_id: "ce9f840ed96599580cd140fbc7bb3230633f50f61041aff73308ae71caa8a2bd",
    reg_aaguid: "d5aa33581e8ca478e20fe713f5d32ff2",
    reg_client_data_json: "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22714b763532723347734e396a526d733576616e6f6f306f303459557a656c6e7878586d5a426e6254733730222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20425f44543567375a445f2d394f544c59583549764551227d",
    reg_attestation_object: "a363666d74667061636b65646761747453746d74a363616c67266373696758483046022100d83f60bd80269537583218858aefb03ac57d45fa06e42feaae332d187f62da9f022100a02bd3cb6f7e1d283c93bad1f3f4b5a4c0494463da7fdbf256949116754d1f17637835638159022730820223308201c8a003020102021100b2cfc9ea33c8643b0e1a760463eaf164300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d03010703420004dd2b7a564b73b8c0b81c4c62e521925c4d1198ec9f583dbf1eebe364b65cd9c29a9bdf346aaa81fb6b9507e5249a52fdaf8e39e26b0b7dc45992a7e233b70f70a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e041604140ae27546bc7eccb1b4b597bd354f0c0b1f1f8f8e301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d0403020349003046022100a0d434ecb5fc3bfd7da5f41904517ad2836249f561bd834ba7a438a8ab7a4ce8022100fac845bb7a02513b58e9f319654dbe49b0f02b95835bac568c71f8a18cdde9ab6861757468446174615881bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54100000000d5aa33581e8ca478e20fe713f5d32ff20020ce9f840ed96599580cd140fbc7bb3230633f50f61041aff73308ae71caa8a2bda401010327200621582044e06ddd331c36a8dc667bab52bcae63486c916aa5e339e6acebaa84934bf832",
    auth_challenge: "895957e01c633a698348a2d8a31a54b7db27e8c1c43b2080d79ae2190267bfd2",
    auth_authenticator_data: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50100000000",
    auth_client_data_json: "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2269566c583442786a4f6d6d44534b4c596f7870557439736e364d48454f7943413135726947514a6e763949222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d",
    auth_signature: "f5c59c7e46c34f6f8cc197101ddf9934fa2595f68eb1913a637e8419eb9ba4cfdfc48f85393bc0d40b011f0d6fecb097d6607525713223a0dc0d453993dae00b",
};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn rp() -> Rp {
    Rp {
        id: "example.org".into(),
        origin: "https://example.org".into(),
    }
}

fn registration(v: &Vector) -> Result<register::Registered, WebauthnError> {
    let cd = client_data::parse(&hex(v.reg_client_data_json)).unwrap();
    assert_eq!(cd.challenge, b64_encode(&hex(v.reg_challenge)));
    register::verify(&rp(), &cd, &hex(v.reg_attestation_object))
}

/// The credential key, parsed straight out of the attestation object.
fn credential_key(v: &Vector) -> (authdata::AuthData, CoseKey) {
    let object = super::cbor::decode_exact(&hex(v.reg_attestation_object), "x").unwrap();
    let entries = super::cbor::map(&object, "x").unwrap();
    let raw = super::cbor::bytes(super::cbor::text_key(entries, "authData"), "x").unwrap();
    let data = authdata::parse(raw).unwrap();
    let cred = data.attested.clone().unwrap();
    assert_eq!(cred.credential_id, hex(v.reg_credential_id));
    assert_eq!(cred.aaguid.to_vec(), hex(v.reg_aaguid));
    let key = CoseKey::parse(&cred.public_key).unwrap();
    (data, key)
}

/// Verifies the vector's assertion signature with the registered key.
fn assertion_signature_ok(v: &Vector) -> Result<(), WebauthnError> {
    let (_, key) = credential_key(v);
    let mut signed = hex(v.auth_authenticator_data);
    signed.extend_from_slice(digest(&SHA256, &hex(v.auth_client_data_json)).as_ref());
    key.verify(&signed, &hex(v.auth_signature))
}

fn assertion(v: &Vector) -> Result<assert::Asserted, WebauthnError> {
    let (data, key) = credential_key(v);
    let cdj = hex(v.auth_client_data_json);
    let cd = client_data::parse(&cdj).unwrap();
    assert_eq!(cd.challenge, b64_encode(&hex(v.auth_challenge)));
    let stored = assert::Stored {
        key: &key,
        sign_count: 0,
        backup_eligible: data.flags.backup_eligible(),
    };
    let sig = hex(v.auth_signature);
    assert::verify(
        &rp(),
        &cd,
        &cdj,
        &hex(v.auth_authenticator_data),
        &sig,
        &stored,
    )
}

#[test]
fn packed_self_es256_registers_ignoring_the_attestation_statement() {
    let reg = registration(&PACKED_SELF_ES256).unwrap();
    assert_eq!(reg.credential_id, hex(PACKED_SELF_ES256.reg_credential_id));
    assert_eq!(reg.alg, super::ALG_ES256);
    assert_eq!((reg.backup_eligible, reg.backup_state), (true, true));
    assert_eq!(reg.sign_count, 0);
    assert!(assertion_signature_ok(&PACKED_SELF_ES256).is_ok());
    // Its assertion was made without user verification.
    assert_eq!(
        assertion(&PACKED_SELF_ES256),
        Err(WebauthnError::UserNotVerified)
    );
}

#[test]
fn packed_rs256_registers_and_its_signature_verifies() {
    let reg = registration(&PACKED_RS256).unwrap();
    assert_eq!(reg.alg, super::ALG_RS256);
    assert!(assertion_signature_ok(&PACKED_RS256).is_ok());
    assert_eq!(
        assertion(&PACKED_RS256),
        Err(WebauthnError::UserNotVerified)
    );
}

#[test]
fn vectors_without_user_verification_are_refused() {
    for v in [&NONE_ES256, &PACKED_EDDSA] {
        assert_eq!(registration(v), Err(WebauthnError::UserNotVerified));
        assert!(assertion_signature_ok(v).is_ok());
        assert_eq!(assertion(v), Err(WebauthnError::UserNotVerified));
    }
    assert_eq!(credential_key(&PACKED_EDDSA).1.alg(), super::ALG_EDDSA);
}

#[test]
fn cross_origin_vector_is_refused() {
    assert_eq!(registration(&CROSS_ORIGIN), Err(WebauthnError::CrossOrigin));
    assert_eq!(assertion(&CROSS_ORIGIN), Err(WebauthnError::CrossOrigin));
}

#[test]
fn tampering_is_detected() {
    let v = &PACKED_SELF_ES256;
    let cd = client_data::parse(&hex(v.reg_client_data_json)).unwrap();
    let other_rp = Rp {
        id: "example.com".into(),
        origin: "https://example.org".into(),
    };
    let object = hex(v.reg_attestation_object);
    assert_eq!(
        register::verify(&other_rp, &cd, &object),
        Err(WebauthnError::WrongRpId)
    );
    let other_origin = Rp {
        id: "example.org".into(),
        origin: "https://example.com".into(),
    };
    assert_eq!(
        register::verify(&other_origin, &cd, &object),
        Err(WebauthnError::WrongOrigin)
    );
    let (_, key) = credential_key(v);
    let mut signed = hex(v.auth_authenticator_data);
    signed.extend_from_slice(digest(&SHA256, &hex(v.auth_client_data_json)).as_ref());
    let mut sig = hex(v.auth_signature);
    let last = sig.len() - 1;
    sig[last] ^= 1;
    assert_eq!(key.verify(&signed, &sig), Err(WebauthnError::BadSignature));
}

/// Deterministic xorshift, so a failure reproduces.
fn mutations(seed: u64, input: &[u8], rounds: usize) -> impl Iterator<Item = Vec<u8>> + '_ {
    let mut state = seed;
    (0..rounds).map(move |_| {
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut out = input.to_vec();
        for _ in 0..1 + next() % 4 {
            let at = (next() as usize) % out.len().max(1);
            match next() % 3 {
                0 => {
                    if let Some(b) = out.get_mut(at) {
                        *b = next() as u8;
                    }
                }
                1 => out.truncate(at),
                _ => out.insert(at.min(out.len()), next() as u8),
            }
        }
        out
    })
}

#[test]
fn malformed_inputs_never_panic() {
    let rp = rp();
    for v in [
        &NONE_ES256,
        &PACKED_SELF_ES256,
        &CROSS_ORIGIN,
        &PACKED_RS256,
        &PACKED_EDDSA,
    ] {
        let object = hex(v.reg_attestation_object);
        let cd = client_data::parse(&hex(v.reg_client_data_json)).unwrap();
        for len in 0..object.len() {
            assert!(
                register::verify(&rp, &cd, &object[..len]).is_err(),
                "prefix {len}"
            );
        }
        for (i, input) in mutations(0x9e37_79b9_7f4a_7c15, &object, 3000).enumerate() {
            let _ = register::verify(&rp, &cd, &input);
            let _ = authdata::parse(&input);
            let _ = CoseKey::parse(&input);
            let _ = client_data::parse(&input);
            assert!(i < 3000);
        }
        let data = hex(v.auth_authenticator_data);
        for input in mutations(42, &data, 1000) {
            let _ = authdata::parse(&input);
        }
    }
    let mut state = 7u64;
    for len in [0, 1, 2, 37, 64, 300] {
        for _ in 0..200 {
            let garbage: Vec<u8> = (0..len)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1);
                    (state >> 33) as u8
                })
                .collect();
            let _ = super::cbor::decode_prefix(&garbage, "x");
            let _ = authdata::parse(&garbage);
            let _ = CoseKey::parse(&garbage);
        }
    }
}
