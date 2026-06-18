// crypto/encode — PKCS#8 private-key parse/encode codec migration
// (Phase 3b, final crypto/encode slice).
//
// Source: openHiTLS C SDV crypto/encode/test_suite_sdv_asn1_certkey.{c,data}
//   - SDV_BSL_ASN1_ENCODE_PRIKEY_BUFF_TC001: decode a key file, re-encode, and
//     compare to the inline `asn1` DER (PKCS#8 PrivateKeyInfo).
//
// Migrated file-free against the inline DER, via the existing public
// hitls_pki::pkcs8 parse/encode APIs:
//   - private PKCS#8 (Ed25519 / X25519): parse_pkcs8_der -> re-encode via the
//     type's single-value encoder -> byte-exact == asn1. **This round-trip also
//     drove a real encoder bug fix** (see I-phase): `encode_pkcs8_der_raw`
//     emitted a spurious NULL `parameters` for these algorithms, which RFC 8410
//     §3 forbids — the parameters field must be absent.
//   - private PKCS#8 (EC / RSA / SM2): parse-only (decode KAT). Documented
//     encoder gaps: EC `encode_ec_pkcs8_der` omits the SEC1 OPTIONAL
//     `[1] publicKey` the C key carries; RSA/SM2 re-encode needs per-type
//     plumbing.
//
// Out of scope: the raw SEC1 / PKCS#1 private-key formats (CRYPT_PRIKEY_ECC /
// CRYPT_PRIKEY_RSA, not PKCS#8) and the non-standard SDV "subKeyInfo" SPKI
// fragments (AlgorithmIdentifier + BIT STRING without the outer SEQUENCE, which
// `parse_spki_der` correctly rejects).

#![cfg(all(feature = "x509", feature = "pkcs8"))]

use hitls_pki::pkcs8::{
    encode_ed25519_pkcs8_der, encode_x25519_pkcs8_der, parse_pkcs8_der, Pkcs8PrivateKey,
};
use hitls_utils::hex::hex;

const PRIV_PKCS8: &[&str] = &[
    "302e020100300506032b656e0422042058b8657e15813b36ee81da2ca184f07d8c6ae71df5e8126998644a339083b37d",
    "302e020100300506032b657004220420cbc4e3b0b901b75865a96c42f1c979c3065bd23aeb4c4b1a74c06bc85fafc4cf",
    "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420c5983f142e49d2e2f2c55e216ac7a32803df0a0c5eb5134238e16204579cbea0a14403420004a6a52df225c7064b5daf8defb3902e24e80a090abd1f74d60556f924bef62cd8083d73107eae27bed467ed642c2781643ad0f557d089930503cbd1ab36584371",
    "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b020101043011f1ad7fd68d2bdc0fe972b521d6416b1c2d0d6ea82875b1ae97b05be297d9e7990db33f08882fdee4a285c1d87472c8a16403620004aebf47bd84a597cb41f09e1f28e13813993476c2840084dab242737516d1231b5db3cd30df7159e04abe5a6bed2f36016c2fdabb9a6f28ea558ccdd4b8e8aaca9e8aca0f55c04dad4f0f1028e4d4b0185e55c37cb25fcdfada182f0355b4aaad",
    "308206fe020100300d06092a864886f70d0101010500048206e8308206e40201000282018100aada19940c11e9e4195b10f3810333fb9dfbda704dc4296aa52991588de6ac1c80d743ade09a8fdac9998ca5d4f827ed441ce94aaa76a63170cf68517ebac1965e8368ffd07d763500faf3e112ec7f449e2f3e1ea3adcad16cddcf7503c13e14d878ae37e49a4442532a1a2dcd68a87dff94cf3c4ea535244902c0cfe4058c87748f0257d8ec9961145b4384c1edd7060121afe5ea9918f82e781d43175a736022418392ac1a6e3bd9acc689bb4190400dc3f815ca63c1413b33b913a16b14f4c1ff4a6ca8e64c1b8ce97561c2516eb09d6ffceb8816257108bbc3a780443ef699a78339abaedad58fe67f6893b578cba14ba588e23ace22f27e5620b89ca3516354a64c20510cda6db3dbb6449c05d889a83bd1d69be95b99fb464a397120224ac8120216e95b8e99f744cf8d810e1d818f2c149ecde87b20842ad696c2c15e4a75f99c478f91ffcdb84c16ac329922231357aef95dd5c50b32cd4e2e043cc691d612911d8a67c2014c89b892ea2ec6b53c819dd712d87786b0b6cbcb2ffaf3020301000102820180117d025c96cbb29ef2ead1166120a723dcad03540c31c5c7867675cbe9b7db4038fea537d978c366dd77468aa6fd1676814ab04feb43a534045c714cd390619bcc65892193ac1ea5c2f442731f266ec9e2f894fee5398c9183f799c7b185b34970f5bc12393d2d3ad8c66e283d66b6c5dc4680315274de0c03c930b156f6d671506b5f0db245030233e78f9c0ee468912871294f25da06a5f37914b861b33ed76ff4e2cc92ff4aef52130f13841916f4923425631d9f63bb13489d1636fca8b2a6061a92b6db0b3be9812ea2f1c74b3ed0f2f9e7d6bb47aa853c740c311282b83f41234b839edff15ed821fcb3e55a4ea95953013bad3634b8cac4bd799c5b01129645dd3e035409f01a2264cc86bbf47e6e7ce527f90117e0a2382096fc455bcc6b7918ad74006ed1e0b7654c8a1ebacf64b5192e8383160bb22eb371d79d03142ae9f5353c908d578dfea1188910a5b1efada3c33d5c704a29500100d452dc568f73bc5ad3afe7287787407c40c85969400b8727cf4eb4a86ba745d15524010281c100e66dfa686b07257c667e18c302cad6ad2049f75ed72527c0ffe52649de938e5c4978221b3520f475ea28d3230aad8e7e6ba81f386aaada56614eccbd67874015d8b1f5f0ed2b121d368541281b5a2c65b37351043785e3b3fa1795c2782563f14784645ad0b81afad04a5eba1df42d4a22bb935c1a8a4c4d06c11c826955a777e130caf69744e47033da46ad9279d0b9d634e9ae25db896421295a7fc3e650379a2009d7e3b9e51602ff8a20292b8d03a953c09148174c8696b4e9a4ab0680f30281c100bdcfa549fc0a248985c183288bd210481f0998cf21a735aa5a295686b054832964f4a73f6652215623ff82087b3a20c52d4b6f37d3ae0db357ab9ad4c86bc645505304135bef16a9c5f442e6a2a0eab059dd52f8e38de90684658fef58b35497d40917ed6b62fb249608ff5896f7c560a3b9f8b03cd9a6a0b539200ccb7360c092d752be4b9e1ea995bee657f8ef58c810374c6e02c60c1a3dde10b4dd8afd1ba72900db5f22845e9cf9ba61f337b1ffa306259c122d46dec48b3fd929ff1e010281c032755cc326c4aed9b9dbdcf23f1749c12973e8fe54a0673f2509f9c36d40e488a2f1f28e00a951becc62da312f32682498d07cddaec5f0ffbf59310e3cb06a411e6d81cc9b32b649bd599ab5fc9f575f81d73ba36fc11ae69b5a34ca1be31c2a869da0181ee261ce1074689fdad550618e8f82aa45898941c8bbdad157dd90c9787f65c26fc77f3a6eb05a8fc1a679256899b79e11de2c0cc81235260b30d0da0c1efde8cf8e32730a7f08b11832d833380e05fa0a4e47cca50dc2a7f3677e2f0281c100b2ffdb3486475a65868a13926d2950c972dbae0bc804d40b2eb3c53187a06b80e20006a93769449ee39bd59901fcb362bf70601619be0e958e9bfa8ba7e65b388aa37f38727e6ab4f8457dc1daa43e2ec8d07baad38dc4afacb3caa540d4fd75a1346228381944162097a3967be8756ec9785c1a77881a277c3fbf05d1e7a0da7aa02d1be05be136b44d2f14cf61882c437ea2c92c3c70b55e9ac8ce880ec6db092d15edcb2dd5ff13b23e1e992b70e54f6c40938a60c070dc9125493adda8010281c1008b44f1d6efa2fccc2aa5a51cd1d44928784325799e4408dceafa09e0d7742fb9d8c1ce94209808deb1739cde3ac0be17e979c65c1a1eb1fb7f8b572ebc5c749fcfc05d6d6d3f05e4d33822ae9aa027848b5f5626b649461e042ebfaea2359aef063939a83e8c099b4ed93d50c2685cc2686d48bc5fe8891ee8fabbbeec0a75e1d3843aef3067205b0cdd90241f3ca25c38a0ec51e9eb7dd1cdc1ae61f6f69067da91769db3b15e8bad3ee33cb63c974acde255bd75cd23163c57650046207536",
];
#[test]
fn tc_pkcs8_private_key_parse_and_reencode() {
    let mut roundtripped = 0usize;
    let mut parse_only = 0usize;
    for v in PRIV_PKCS8 {
        let der = hex(v);
        let key =
            parse_pkcs8_der(&der).unwrap_or_else(|e| panic!("parse_pkcs8_der failed ({e:?}): {v}"));
        match &key {
            // Single-value encoders -> byte-exact round-trip.
            Pkcs8PrivateKey::Ed25519(kp) => {
                assert_eq!(
                    encode_ed25519_pkcs8_der(kp.seed()),
                    der,
                    "Ed25519 re-encode: {v}"
                );
                roundtripped += 1;
            }
            Pkcs8PrivateKey::X25519(sk) => {
                assert_eq!(
                    encode_x25519_pkcs8_der(&sk.to_bytes()),
                    der,
                    "X25519 re-encode: {v}"
                );
                roundtripped += 1;
            }
            // Decode KAT only:
            //  - EC: the C SEC1 ECPrivateKey carries the OPTIONAL `[1] publicKey`
            //    field, which `encode_ec_pkcs8_der` omits (a documented encoder
            //    gap — re-encode would need the public point);
            //  - RSA / SM2: re-encode needs per-type plumbing.
            Pkcs8PrivateKey::Ec { .. } | Pkcs8PrivateKey::Rsa(_) | Pkcs8PrivateKey::Sm2(_) => {
                parse_only += 1
            }
            _ => panic!("unexpected key variant for {v}"),
        }
    }
    assert!(roundtripped >= 2, "expected Ed25519 + X25519 round-trips");
    assert!(
        parse_only >= 1,
        "expected at least one EC/RSA/SM2 decode KAT"
    );
}
