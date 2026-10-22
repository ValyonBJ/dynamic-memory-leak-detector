# Contributing to dmld

Everyone taking part in the project is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before opening a pull request

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
sudo -E cargo test --test integration   # needs eBPF privileges
```

Please include the kernel version and distribution you tested on.

## License of contributions

dmld uses two sets of license terms:

| Part of the project | License |
|---|---|
| User space (`dmld`, `dmld-common`, everything outside `dmld-ebpf`) | MIT OR Apache-2.0 |
| eBPF programs (`dmld-ebpf`) | MIT OR GPL-2.0 |

Unless you explicitly state otherwise, any contribution you submit for inclusion in dmld is licensed under the same terms as the part of the project it modifies (MIT OR Apache-2.0 for user space, MIT OR GPL-2.0 for `dmld-ebpf`), without additional terms or conditions.

You keep the copyright on your contributions.

## Developer Certificate of Origin (DCO)

Every commit must be signed off. The sign-off certifies that you wrote the change, or otherwise have the right to submit it under the project's licenses, as described in the [Developer Certificate of Origin 1.1](https://developercertificate.org/):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

To sign off, commit with `-s`:

```bash
git commit -s -m "Add calloc probe"
```

Git adds a line with the name and email from your Git configuration:

```
Signed-off-by: Jane Doe <jane@example.com>
```

Use your real name. Pull requests with unsigned commits can't be merged.

If you forgot to sign off, fix the last commit with `git commit --amend -s --no-edit`, or every commit on your branch with `git rebase --signoff main`, then force-push.
