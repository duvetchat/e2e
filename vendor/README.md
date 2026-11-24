# Vendored crates

## `openmls/`: OpenMLS 0.9.2 with one change

The crate as crates.io publishes it (checksum `ce4173f914cbc2dd28d9499f19e92f3e1bfebd9eea1607889924a77ca63d3ffc`,
upstream commit `8a8f83b4b61fc45f28facec25e914992b3465de6`, as its `.cargo_vcs_info.json` says), plus
`openmls-received-commit-lifetimes.patch` and a `LICENSE` file (the published crate ships none; OpenMLS is
MIT, © 2020 OpenMLS Authors). `Cargo.toml` and `fuzz/Cargo.toml` put it in place of the registry's with
`[patch.crates-io]`, and the workspace excludes it, so its own tests and lints aren't the workspace's. CI's
`deny` job holds it to that: it fetches the crate from crates.io by that checksum, applies the patch, and
fails on any other difference but `LICENSE`.

### What changed

A member processing a commit it received no longer checks the lifetimes of the key packages the commit
adds. Everything else that checked them still does:

- `PublicGroup::validate_commit` and `validate_add_proposals` take a `LeafNodeLifetimePolicy`.
  `MlsGroup::stage_commit`, which every received commit goes through, passes `Skip`;
  `PublicGroup::stage_commit`, which the API's validator goes through, and the commit builder, which every
  commit a member makes goes through, pass `Verify`.
- `AddProposalIn::validate`, which reads each key package a received message adds, reads it with
  `KeyPackageIn::validate_with_lifetime(.., Skip)`. That check repeated the one staging makes, which decides
  per path as above. A key package without a lifetime is still refused. The public `KeyPackageIn::validate`
  (the core's `choose`, the API's checks) still checks the lifetime.

### Why

The API's validator checks an added key package's lifetime as it takes the commit. OpenMLS 0.9.2 then checked
it again, by the system's clock, on every member that processed the commit, and a failure there is a refused
commit, which blocks the group. So a member that applied the commit after the key package expired blocked:
decision 53 adds inactive devices on purpose, whose key packages are the nearest their end, and a member away
two weeks meets them (issue #24). So did a member whose clock was more than an hour behind (`NotValidYet`).
OpenMLS has no switch for it on `process_message`: its welcomes and external commits have
`skip_lifetime_validation`, and its global `skip_validation` flag is private and test-only.

### Carrying it to a new OpenMLS

1. Put the new release in `openmls/` (the crate as published, without `.cargo-ok`), keep `LICENSE`, and
   apply the patch: `patch -p1 -d vendor/openmls < vendor/openmls-received-commit-lifetimes.patch`.
2. Check that a received commit's added key packages are still read and staged only where the patch
   touches (`grep -rn 'life_time()' src`), and that nothing new checks them on `process_message`.
3. Run `a_commit_applied_after_its_key_package_expired_applies` (`crates/duvet-e2e/tests/groups.rs`) and
   `an_added_key_package_expires_for_the_validator_not_for_a_member_applying_late`
   (`crates/duvet-e2e-validator/tests/validator.rs`): the first fails without the change, the second if the
   validator or the commit builder lose the check.
4. Refresh the patch (`diff -ruN` of the published crate against this copy), both lock files, and the
   version and checksum in CI's step (`vendor/openmls is the published crate plus its patch`).

Drop the copy once OpenMLS offers the switch on processing a message.
