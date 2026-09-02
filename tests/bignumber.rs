/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
#[cfg(all(not(feature = "openssl"), feature = "crypto"))]
use unknown_order::crypto::BigNumber;
#[cfg(all(not(any(feature = "openssl", feature = "crypto")), feature = "gmp"))]
use unknown_order::gmp::BigNumber;
#[cfg(feature = "openssl")]
use unknown_order::openssl::BigNumber;
#[cfg(all(
    not(any(feature = "openssl", feature = "crypto", feature = "gmp")),
    feature = "rust"
))]
use unknown_order::rust::BigNumber;

use unknown_order::{Group, GroupElement};

fn check_reduced_group<T>()
where
    T: GroupElement + From<u8> + PartialEq + core::fmt::Debug,
{
    assert!(matches!(
        Group::new(T::zero()),
        Err(unknown_order::Error::InvalidModulus)
    ));
    assert!(matches!(
        Group::new(T::one()),
        Err(unknown_order::Error::InvalidModulus)
    ));
    assert!(matches!(
        Group::prime_field(T::from(8)),
        Err(unknown_order::Error::ModulusNotPrime)
    ));

    let group = Group::new(T::from(7)).unwrap();
    assert_eq!(group.modulus(), &T::from(7));
    assert!(!group.is_prime_field());
    assert_eq!(group.zero().into_value(), T::zero());
    assert_eq!(group.one().into_value(), T::one());
    assert_eq!(group.neg(&T::from(3)), T::from(4));
    assert_eq!(group.sum([T::from(6), T::from(6)]), T::from(5));
    assert_eq!(group.product([T::from(3), T::from(5)]), T::one());

    let three = group.element(T::from(10));
    let five = group.element(T::from(12));
    assert_eq!(three.group().modulus(), &T::from(7));
    assert_eq!(three.value(), &T::from(3));
    assert_eq!(three.checked_add(&five).unwrap().into_value(), T::one());
    assert_eq!(three.checked_sub(&five).unwrap().into_value(), T::from(5));
    assert_eq!(three.checked_mul(&five).unwrap().into_value(), T::one());
    assert_eq!(three.checked_div(&five).unwrap().into_value(), T::from(2));
    assert_eq!(three.negated().into_value(), T::from(4));
    assert_eq!(three.pow(&T::from(3)).into_value(), T::from(6));

    assert_eq!((&three + &five).unwrap().into_value(), T::one());
    assert_eq!((&three - &five).unwrap().into_value(), T::from(5));
    assert_eq!((&three * &five).unwrap().into_value(), T::one());
    assert_eq!((&three / &five).unwrap().into_value(), T::from(2));
    assert_eq!((-&three).into_value(), T::from(4));

    let mut assigned = group.element(T::from(3));
    assigned.checked_add_assign(&five).unwrap();
    assert_eq!(assigned.value(), &T::one());
    assigned.checked_sub_assign(&five).unwrap();
    assert_eq!(assigned.value(), &T::from(3));
    assigned.checked_mul_assign(&five).unwrap();
    assert_eq!(assigned.value(), &T::one());
    assigned.checked_div_assign(&five).unwrap();
    assert_eq!(assigned.value(), &T::from(3));
    assigned.negate();
    assert_eq!(assigned.value(), &T::from(4));
    assigned.pow_assign(&T::from(2));
    assert_eq!(assigned.value(), &T::from(2));

    let other_group = Group::new(T::from(11)).unwrap();
    let other_value = other_group.element(T::from(3));
    assert!(matches!(
        three.checked_add(&other_value),
        Err(unknown_order::Error::MismatchedGroups)
    ));

    let composite_group = Group::new(T::from(8)).unwrap();
    let numerator = composite_group.element(T::from(3));
    let noninvertible = composite_group.element(T::from(2));
    assert!(matches!(
        numerator.checked_div(&noninvertible),
        Err(unknown_order::Error::NonInvertible)
    ));

    let field = Group::prime_field(T::from(7)).unwrap();
    assert!(field.is_prime_field());
}

#[cfg(all(
    feature = "crypto",
    feature = "gmp",
    feature = "openssl",
    feature = "rust"
))]
#[test]
fn all_backends_can_be_used_together() {
    check_reduced_group::<unknown_order::crypto::BigNumber>();
    check_reduced_group::<unknown_order::gmp::BigNumber>();
    check_reduced_group::<unknown_order::openssl::BigNumber>();
    check_reduced_group::<unknown_order::rust::BigNumber>();
}

#[test]
fn group_values_auto_reduce() {
    check_reduced_group::<BigNumber>();
}

/// Taken from https://github.com/mikelodder7/cunningham_chain/blob/master/findings.md
/// Each decimal value is prefixed with the multibase base-10 marker `9`.
const TEST_PRIMES: [&str; 4] = [
    "9153739637779647327330155094463476939112913405723627932550795546376536722298275674187199768137486929460478138431076223176750734095693166283451594721829574797878338183845296809008576378039501400850628591798770214582527154641716248943964626446190042367043984306973709604255015629102866732543697075866901827761489",
    "966295144163396665403376179086308918015255210762161712943347745256800426733181435998953954369657699924569095498869393378860769817738689910466139513014839505675023358799693196331874626976637176000078613744447569887988972970496824235261568439949705345174465781244618912962800788579976795988724553365066910412859",
    "937313426856874901938110133384605074194791927500210707276948918975046371522830901596065044944558427864187196889881993164303255749681644627614963632713725183364319410825898054225147061624559894980555489070322738683900143562848200257354774040241218537613789091499134051387344396560066242901217378861764936185029",
    "989884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203768010560056939935696678829394884407208311246423715319737062188883946712432742638151109800623047059726541476042502884419075341171231440736956555270413618581675255342293149119973622969239858152417678164815053566739",
];

fn get_modulus() -> BigNumber {
    b10(TEST_PRIMES[0]) * b10(TEST_PRIMES[1])
}

fn b10(s: &str) -> BigNumber {
    let mut bytes = vec![0u8];
    for digit in s.strip_prefix('9').expect("missing base-10 marker").bytes() {
        assert!(digit.is_ascii_digit(), "invalid base-10 digit");
        let mut carry = u16::from(digit - b'0');
        for byte in bytes.iter_mut().rev() {
            let value = u16::from(*byte) * 10 + carry;
            *byte = value as u8;
            carry = value >> 8;
        }
        if carry != 0 {
            bytes.insert(0, carry as u8);
        }
    }
    BigNumber::from_slice(bytes)
}

#[test]
fn random() {
    let n = get_modulus();
    for _ in 0..100 {
        let s = BigNumber::random(&n).unwrap();
        assert!(s < n);
    }
}

#[test]
fn random_bits_has_requested_size() {
    assert!(BigNumber::random_bits(0).unwrap().is_zero());
    for bits in [1, 7, 8, 9, 63, 64, 65, 256] {
        assert_eq!(
            BigNumber::random_bits(bits).unwrap().bit_length(),
            bits as usize
        );
    }
}

#[test]
fn signed_equality_and_conversion() {
    use subtle::ConstantTimeEq;

    let positive = BigNumber::from(17);
    let negative = BigNumber::from(-17);
    assert_eq!(positive.ct_eq(&positive).unwrap_u8(), 1);
    assert_eq!(positive.ct_eq(&negative).unwrap_u8(), 0);
    assert!(!positive.is_negative());
    assert!(negative.is_negative());
    assert!(!BigNumber::zero().is_negative());

    #[cfg(target_pointer_width = "64")]
    assert_eq!(BigNumber::from(i128::MIN), -BigNumber::from(1u128 << 127));
}

#[test]
fn formatting_uses_the_requested_radix() {
    for raw in [0, 1, 7, 8, 15, 16, 255, 256, 511, 0x102, u64::MAX] {
        let value = BigNumber::from(raw);
        assert_eq!(format!("{value:b}"), format!("{raw:b}"));
        assert_eq!(format!("{value:o}"), format!("{raw:o}"));
        assert_eq!(format!("{value:x}"), format!("{raw:x}"));
        assert_eq!(format!("{value:X}"), format!("{raw:X}"));
    }
    assert_eq!(format!("{:x}", -BigNumber::from(0x102)), "-102");
}

#[test]
fn group_reductions_update_accumulators() {
    let modulus = BigNumber::from(5);
    let mut value = BigNumber::from(-3);

    GroupElement::modadd_assign(&mut value, &BigNumber::from(-4), &modulus);
    assert_eq!(value, BigNumber::from(3));
    GroupElement::modsub_assign(&mut value, &BigNumber::from(4), &modulus);
    assert_eq!(value, BigNumber::from(4));
    GroupElement::modmul_assign(&mut value, &BigNumber::from(3), &modulus);
    assert_eq!(value, BigNumber::from(2));
    GroupElement::moddiv_assign(&mut value, &BigNumber::from(2), &modulus);
    assert_eq!(value, BigNumber::one());

    let group = Group::new(modulus).unwrap();
    assert_eq!(
        group.sum([BigNumber::from(-3), BigNumber::from(-4)]),
        BigNumber::from(3)
    );
    assert_eq!(
        group.product([BigNumber::from(-3), BigNumber::from(4)]),
        BigNumber::from(3)
    );
}

#[test]
fn noninvertible_value_returns_none() {
    assert!(BigNumber::from(2).invert(&BigNumber::from(4)).is_none());
}

#[test]
fn invert() {
    let n = get_modulus();
    let seven = BigNumber::from(7);
    let res = seven.invert(&n);
    assert!(res.is_some());
    let inv_sev = res.unwrap();
    let e = b10(
        "98736164100197231989787188588600960668069231385527654883722188521294636032401969483008945072483969138624775854861975726576062103939220928630158097991729478054488847175819214957276712990801597205987508160592161411562878226113426472758518077060830360520857340372917204559754499877424661206747919186595155095664390759910479790933107207818246310062809031809548440757639655172156206658836643666598028545699906946474098999286204150351756528088230861166258151032711654628115284610488946624661733330727293087598638805428569835503052197782968695111929188140960550805397118405320674665165150825485362977018330562195374374788901",
    );
    assert_eq!(e, inv_sev);

    let a = BigNumber::random(&n).unwrap();
    let res = a.invert(&n);
    assert!(res.is_some());
}

#[test]
fn zero_modulus_returns_zero() {
    let base = BigNumber::from(7);
    let exp = BigNumber::from(3);
    let modulus = BigNumber::from(0);
    assert_eq!(base.modpow(&exp, &modulus), BigNumber::zero());
}

#[test]
fn exp() {
    // known bad inputs
    let base = b10(
        "912714671911903680502393098440562958150461307840092575886187217264492970515611166458444182780904860535776274190597528985988632488194981204988199325501696648896748368401254829974173258613724800116424602180755019588176641580062215499750550535543002990347313784260314641340394494547935943176226649412526659864646068220114536172189443925908781755710141006387091748541976715633668919725277837668568166444731358541327097786024076841158424402136565558677098853060675674958695935207345864359540948421232816012865873346545455513695413921957708811080877422273777355768568166638843699798663264533662595755767287970642902713301649",
    );
    let exp = b10(
        "913991423645225256679625502829143442357836305738777175327623021076136862973228390317258480888217725740262243618881809894688804251512223982403225288178492105393953431042196371492402144120299046493467608097411259757604892535967240041988260332063962457178993277482991886508015739613530825229685281072180891075265116698114782553748364913010741387964956740720544998915158970813171997488129859542399633104746793770216517872705889857552727967921847493285577238",
    );
    let modulus = b10(
        "9991272771610724400277702356109350334773782112020672787325464582894874455338156617087078683660308327009158085342465983713825070967004447592080649030930737560915527173820649490032274245863850782844569456999473516497618489127293328524608584652323593452247534656999363158875176879817952982494174728640545484193154314433925648566686738628413929222467005197087738850212963801663981588243042912430590088435419451359859770426041670326127890520192033283832465411962274045956439947646966560440910244870464709982605844468449227905039953511431640780483761563845223213570597106855699997837768334871601402132694515676785338799407204529154456178837013845488372635042715003769626150545960460800980936426723680755798495767188398126674428244764038147226578038085253616108968402209263400729503458144370189359160926796812468410806201905992347006546335038212090539118675048292666041345556742530041533878341459110515497642054583635133581316796089099043782055893003258788369004899742992039315008110063759802733045648131896557338576682560236591353394201381103042167106112201578883917022695113857967398885475101031596068885337186646296664517159150904935112836318654117577507707562065113238913343761942585545093919444150946120523831367132144754209388110483749",
    );
    let n = base.modpow(&exp, &modulus);
    assert_eq!(
        n,
        b10(
            "9156669382818249607878298589043381544147555658222157929549484054385620519150887267126359684884641035264854247223281407349108771361611707714806192334779156374961296686821846487267487447347213829476609283133961216115764596907219173912888367998704856300105745961091899745329082513615681466199188236178266479183520370119131067362815102553237342546358580424556049196548520326206809677290296313839918774603549816182657993044271509706055893922152644469350618465711055733369291523796837304622919600074130968607301641438272377350795631212741686475924538423333008944556761300787668873766797549942827958501053262330421256183088509761636226277739400954175538503984519144969688787730088704522060486181427528150632576628856946041322195818246199503927686629821338146828603690778689292695518745939007886131151503766930229761608131819298276772877945842806872426029069949874062579870088710097070526608376602732627661781899595747063793310401032556802468649888104062151213860356554306295111191704764944574687548637446778783560586599000631975868701382113259027374431129732911012887214749014288413818636520182416636289308770657630129067046301651835893708731812616847614495049523221056260334965662875649480493232265453415256612460815802528012166114764216881"
        )
    );

    let base = BigNumber::from(6);
    let exp = BigNumber::from(-5);
    let modulus = BigNumber::from(13);
    assert_eq!(BigNumber::from(7), base.modpow(&exp, &modulus));

    let modulus = BigNumber::from(1);
    assert_eq!(BigNumber::zero(), base.modpow(&exp, &modulus));

    let modulus = BigNumber::from(-1);
    assert_eq!(BigNumber::default(), base.modpow(&exp, &modulus));

    let modulus = BigNumber::from(-5);
    assert_eq!(BigNumber::from(1), base.modpow(&exp, &modulus));
}

#[test]
fn modulus() {
    let base = BigNumber::from(6);

    for (modulus, expected) in [
        (BigNumber::from(1), BigNumber::zero()),
        (BigNumber::from(-1), BigNumber::zero()),
        (BigNumber::from(2), BigNumber::zero()),
        (BigNumber::from(-2), BigNumber::zero()),
        (BigNumber::from(5), BigNumber::from(1)),
        (BigNumber::from(-5), BigNumber::from(1)),
    ]
    .iter()
    {
        assert_eq!(*expected, &base % modulus);
    }
}

#[test]
fn is_prime() {
    // taken from https://github.com/mikelodder7/cunningham_chain/blob/master/findings.md
    let tests = [
        ("918088387217903330459", 6),
        ("933376463607021642560387296949", 6),
        ("9170141183460469231731687303717167733089", 6),
        (
            "9113910913923300788319699387848674650656041243163866388656000063249848353322899",
            5,
        ),
        (
            "91675975991242824637446753124775730765934920727574049172215445180465220503759193372100234287270862928461253982273310756356719235351493321243304213304923049",
            5,
        ),
        (
            "9153739637779647327330155094463476939112913405723627932550795546376536722298275674187199768137486929460478138431076223176750734095693166283451594721829574797878338183845296809008576378039501400850628591798770214582527154641716248943964626446190042367043984306973709604255015629102866732543697075866901827761489",
            4,
        ),
        (
            "966295144163396665403376179086308918015255210762161712943347745256800426733181435998953954369657699924569095498869393378860769817738689910466139513014839505675023358799693196331874626976637176000078613744447569887988972970496824235261568439949705345174465781244618912962800788579976795988724553365066910412859",
            4,
        ),
    ];

    let one = BigNumber::from(1);
    for (p, chain) in tests.iter() {
        let mut prime = b10(p);
        for _ in 1..*chain {
            prime = (prime << 1usize) + &one;
            assert!(prime.is_prime().unwrap());
        }
    }
}

#[test]
fn clone_negative() {
    let n = BigNumber::from(-1);
    assert_eq!(n, n.clone());
}

#[test]
fn copies_magnitude_into_existing_buffer() {
    for value in [
        BigNumber::zero(),
        BigNumber::one(),
        BigNumber::from(0x0102_0304_0506_0708u64),
        BigNumber::from(-0x0102_0304_0506_0708i64),
    ] {
        let expected = value.to_bytes();
        let mut buffer = vec![0; expected.len()];
        value.copy_bytes_into_buffer(&mut buffer).unwrap();
        assert_eq!(buffer, expected);
    }
}

#[test]
fn fallible_inputs_return_errors() {
    let value = BigNumber::from(257);
    let mut short_buffer = [0u8; 1];
    assert!(matches!(
        value.copy_bytes_into_buffer(&mut short_buffer),
        Err(unknown_order::Error::BufferLength {
            expected: 2,
            actual: 1
        })
    ));

    assert!(matches!(
        BigNumber::random_range(&value, &value),
        Err(unknown_order::Error::InvalidRange)
    ));
    assert!(matches!(
        BigNumber::prime(1),
        Err(unknown_order::Error::BitLengthTooSmall { actual: 1, .. })
    ));
    assert!(matches!(
        BigNumber::safe_prime(2),
        Err(unknown_order::Error::BitLengthTooSmall { actual: 2, .. })
    ));
}

#[test]
fn owned_arithmetic_preserves_signs() {
    for (lhs, rhs, sum, difference) in [
        (8, 3, 11, 5),
        (3, 8, 11, -5),
        (-8, 3, -5, -11),
        (8, -3, 5, 11),
        (-8, -3, -11, -5),
    ] {
        let lhs = BigNumber::from(lhs);
        let rhs = BigNumber::from(rhs);

        assert_eq!(lhs.clone() + rhs.clone(), BigNumber::from(sum));
        assert_eq!(lhs.clone() - rhs.clone(), BigNumber::from(difference));

        let mut assigned = lhs.clone();
        assigned += rhs.clone();
        assert_eq!(assigned, BigNumber::from(sum));

        assigned = lhs;
        assigned -= rhs;
        assert_eq!(assigned, BigNumber::from(difference));
    }
}

#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
struct SerializableNumber {
    value: BigNumber,
}

#[test]
fn serialization_formats_round_trip() {
    let value = SerializableNumber {
        value: -BigNumber::from(257),
    };

    let json = serde_json::to_string(&value).unwrap();
    assert_eq!(
        serde_json::from_str::<SerializableNumber>(&json).unwrap(),
        value
    );

    let toml = toml::to_string(&value).unwrap();
    assert_eq!(toml::from_str::<SerializableNumber>(&toml).unwrap(), value);

    let yaml = serde_yaml_ng::to_string(&value).unwrap();
    assert_eq!(
        serde_yaml_ng::from_str::<SerializableNumber>(&yaml).unwrap(),
        value
    );

    let postcard = postcard::to_allocvec(&value).unwrap();
    assert_eq!(
        postcard::from_bytes::<SerializableNumber>(&postcard).unwrap(),
        value
    );

    let mut cbor = Vec::new();
    ciborium::into_writer(&value, &mut cbor).unwrap();
    assert_eq!(
        ciborium::from_reader::<SerializableNumber, _>(cbor.as_slice()).unwrap(),
        value
    );
}

#[test]
fn serialize_str() {
    use serde_test::{Configure, Token, assert_de_tokens, assert_tokens};

    assert_tokens(&BigNumber::from(257).readable(), &[Token::Str("0101")]);
    assert_tokens(&(-BigNumber::from(1)).readable(), &[Token::Str("-01")]);
    assert_de_tokens(&(-BigNumber::from(1)).readable(), &[Token::Str("-1")]);
}

#[test]
fn serialize_bytes() {
    use serde_test::{Configure, Token, assert_tokens};

    assert_tokens(&BigNumber::from(257).compact(), &[Token::Bytes(&[0, 1, 1])]);
    assert_tokens(
        &(-BigNumber::from(257)).compact(),
        &[Token::Bytes(&[1, 1, 1])],
    );
}

#[test]
fn prime() {
    let p = BigNumber::prime(1024).unwrap();
    assert!(p.is_prime().unwrap());
    let s = p.to_string().len();
    // Assumes base 10 length
    assert!((308..=309).contains(&s));
}

#[test]
fn safe_prime() {
    // any larger and it will take a long time
    let p = BigNumber::safe_prime(256).unwrap();
    assert!(p.is_prime().unwrap());
    let ptick: BigNumber = p >> 1;
    assert!(ptick.is_prime().unwrap());
}

#[test]
fn gcd_ext() {
    let a = BigNumber::from(13);
    let b = BigNumber::from(17);
    let res = a.extended_gcd(&b);
    assert_eq!(res.gcd, BigNumber::one());
}

#[test]
fn bytes() {
    let m = BigNumber::from(7);
    let s = m.to_bytes();
    assert_eq!(m, BigNumber::from_slice(&s));
}

#[test]
fn rsa_round_trip() {
    rsa_round_trip_with_prime_bits(256);
}

#[test]
#[ignore = "slow 3072-bit RSA stress test"]
fn rsa_round_trip_3072() {
    rsa_round_trip_with_prime_bits(1536);
}

fn rsa_round_trip_with_prime_bits(bit_length: usize) {
    let p = BigNumber::prime(bit_length).unwrap();
    let mut q = BigNumber::prime(bit_length).unwrap();
    while p == q {
        q = BigNumber::prime(bit_length).unwrap();
    }

    let n = &p * &q;
    let pm1 = &p - BigNumber::one();
    let qm1 = &q - BigNumber::one();
    let lambda = pm1.lcm(&qm1);

    let e = BigNumber::from(65537);
    let d = e.invert(&lambda).unwrap();
    let m = BigNumber::random(&n).unwrap();
    let c = m.modpow(&e, &n);
    let mm = c.modpow(&d, &n);

    assert_eq!(m, mm);
}
