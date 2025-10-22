use yara_on_map::pager::PageCache;

#[test]
fn cache_ttl_and_crc() {
    let c = PageCache::new(10_000);
    let pid = 1234u32;
    let base = 0x1000u64;
    assert_eq!(c.check(pid, base, b"abc"), false);
    assert_eq!(c.check(pid, base, b"abc"), true);
    assert_eq!(c.check(pid, base, b"abd"), false);
}
