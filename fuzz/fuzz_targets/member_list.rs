//! A conversation's member list, as every welcome and commit carries it in the group's context:
//! what reads writes back to the same list.
#![no_main]

use duvet_e2e_rules::MemberList;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(list) = MemberList::read(data) {
        let mut again = Vec::new();
        ciborium::into_writer(&list, &mut again).expect("a list read writes");
        assert_eq!(MemberList::read(&again).expect("and reads back"), list);
    }
});
