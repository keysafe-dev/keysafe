# Changelog

## [0.3.1](https://github.com/keysafe-dev/keysafe/compare/v0.3.0...v0.3.1) (2026-10-06)


### Bug Fixes

* release binaries that run without Nix ([#26](https://github.com/keysafe-dev/keysafe/issues/26)) ([01c2819](https://github.com/keysafe-dev/keysafe/commit/01c2819af03536a59179fc887b03e2954332301c))

## [0.3.0](https://github.com/keysafe-dev/keysafe/compare/v0.2.0...v0.3.0) (2026-10-06)


### Features

* add `config init`, `config edit` and `config path` ([#23](https://github.com/keysafe-dev/keysafe/issues/23)) ([0e33d58](https://github.com/keysafe-dev/keysafe/commit/0e33d5833cb8148e0d9dbfc63038bd4e78c50c8d)), closes [#14](https://github.com/keysafe-dev/keysafe/issues/14)
* add `doctor` ([#24](https://github.com/keysafe-dev/keysafe/issues/24)) ([11e736f](https://github.com/keysafe-dev/keysafe/commit/11e736ff5c947bbf993ef10933533e2d304e77dc)), closes [#15](https://github.com/keysafe-dev/keysafe/issues/15)
* add `status`, use the config's default profile, clarify `profile show` ([#19](https://github.com/keysafe-dev/keysafe/issues/19)) ([935be0a](https://github.com/keysafe-dev/keysafe/commit/935be0aaa6703e2af946c54e48f091eacd5529ec)), closes [#11](https://github.com/keysafe-dev/keysafe/issues/11) [#13](https://github.com/keysafe-dev/keysafe/issues/13) [#16](https://github.com/keysafe-dev/keysafe/issues/16)
* add `unload`, the counterpart of `load` ([#21](https://github.com/keysafe-dev/keysafe/issues/21)) ([7daf634](https://github.com/keysafe-dev/keysafe/commit/7daf6342d65176a2a784e89768e8c6e77f09294f)), closes [#12](https://github.com/keysafe-dev/keysafe/issues/12)
* add examples to every command's help, and `-q`/`-v` ([#25](https://github.com/keysafe-dev/keysafe/issues/25)) ([bb0a2e6](https://github.com/keysafe-dev/keysafe/commit/bb0a2e60ac9b6333107a3bfb111ab6d6913a127c)), closes [#17](https://github.com/keysafe-dev/keysafe/issues/17) [#18](https://github.com/keysafe-dev/keysafe/issues/18)

## [0.2.0](https://github.com/keysafe-dev/keysafe/compare/v0.1.0...v0.2.0) (2026-10-06)


### ⚠ BREAKING CHANGES

* move each profile's `account: <account>` into a `provider` section: `provider: { type: 1password, account: <account> }`.
* rename `accounts` to `profiles` in the config file.

### Features

* rename `accounts` to `profiles` in the config ([75810aa](https://github.com/keysafe-dev/keysafe/commit/75810aa024bbf5442e9a72354365ebcbff9bab7d))
* select the password manager with a `provider` section per profile ([db436cd](https://github.com/keysafe-dev/keysafe/commit/db436cdc3c0388bbc4021764c08ace12e51b9285))

## 0.1.0 (2026-10-06)


### Features

* add init for zsh and bash shell integration ([#4](https://github.com/keysafe-dev/keysafe/issues/4)) ([f1739bb](https://github.com/keysafe-dev/keysafe/commit/f1739bb0904336810124b83c60993768fb949693))
* initial release ([38783df](https://github.com/keysafe-dev/keysafe/commit/38783df2ffe99d39c9a4487008352a239d4c8f7c))
* rename commands to load, read and profile; use XDG locations ([#6](https://github.com/keysafe-dev/keysafe/issues/6)) ([0f90c75](https://github.com/keysafe-dev/keysafe/commit/0f90c75fa1935bfe00c58d6cb8d93a2045261aec)), closes [#1](https://github.com/keysafe-dev/keysafe/issues/1)
