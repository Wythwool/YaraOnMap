use yara_on_map::pager::PageCache;

#[test]
fn cache_tracks_page_digest_until_ttl() {
    let cache = PageCache::new(10_000);
    let pid = 1234;
    let base = 0x1000;

    assert!(!cache.check(pid, base, b"abc"));
    assert!(cache.check(pid, base, b"abc"));
    assert!(!cache.check(pid, base, b"abd"));
}
