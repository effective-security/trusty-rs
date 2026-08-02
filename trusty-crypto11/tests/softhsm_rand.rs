//! SoftHSM GenRandom tests (ignored without config).

#[path = "common/mod.rs"]
mod common;

#[test]
#[ignore = "requires SoftHSM config at TRUSTY_SOFTHSM_CONFIG or /tmp/trusty11/softhsm_unittest.json"]
fn gen_random_sizes() {
    let Some(lib) = common::open_lib() else {
        return;
    };

    for size in [1usize, 16, 32, 1024, 32 * 1024] {
        let mut buf = vec![0u8; size];
        let n = lib.gen_random(&mut buf).expect("gen_random");
        assert_eq!(n, size);
    }
}
