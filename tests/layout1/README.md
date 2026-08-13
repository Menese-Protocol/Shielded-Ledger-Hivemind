# Frozen layout-1 `StableBlobSet`

`StableBlobSet.mo` in this directory is the module as it stood **before** the layout-2 bump, taken
verbatim from `3a5f4c1^:src/StableBlobSet.mo`. It is byte-identical to that blob — no header was
added, precisely so the identity can be asserted:

    sha256(tests/layout1/StableBlobSet.mo) == c9195aaeb0e3970a4e530dc5f04837ff4767531256f07c10eb2af9a740038657

`scripts/set-migration-battery.sh` checks that hash before it builds anything, and aborts if it
does not match. A drifted copy would silently turn a cross-version upgrade test into a
same-version one, which is the failure mode this whole directory exists to prevent.

## Why a frozen copy at all

Layout 2 is only correct if a set **written by the previous module** keeps answering the same
membership questions after the module is replaced. That property cannot be tested by any amount of
layout-2 code: producing genuine layout-1 bytes requires the layout-1 compiler output. The battery
therefore builds two wasms from the *same* `tests/ScaleFixture.mo`, differing in exactly one
import, installs the first, seeds it, and upgrades to the second.

`ScaleFixture.mo` reads the stride out of the region header rather than calling a module function,
so it compiles unchanged against both modules. That is what keeps the two builds differing in
`StableBlobSet.mo` alone.
