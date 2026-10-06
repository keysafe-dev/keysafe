# Changelog

## [0.2.0](https://github.com/keysafe-dev/keysafe/compare/v0.1.0...v0.2.0) (2026-10-06)


### ⚠ BREAKING CHANGES

* replace each profile's `account: <account>` with
* rename `accounts` to `profiles` in the config file.

### Features

* rename `accounts` to `profiles` in the config ([75810aa](https://github.com/keysafe-dev/keysafe/commit/75810aa024bbf5442e9a72354365ebcbff9bab7d))
* select the password manager with a `provider` section per profile ([db436cd](https://github.com/keysafe-dev/keysafe/commit/db436cdc3c0388bbc4021764c08ace12e51b9285))

## 0.1.0 (2026-10-06)


### Features

* add init for zsh and bash shell integration ([#4](https://github.com/keysafe-dev/keysafe/issues/4)) ([f1739bb](https://github.com/keysafe-dev/keysafe/commit/f1739bb0904336810124b83c60993768fb949693))
* initial release ([38783df](https://github.com/keysafe-dev/keysafe/commit/38783df2ffe99d39c9a4487008352a239d4c8f7c))
* rename commands to load, read and profile; use XDG locations ([#6](https://github.com/keysafe-dev/keysafe/issues/6)) ([0f90c75](https://github.com/keysafe-dev/keysafe/commit/0f90c75fa1935bfe00c58d6cb8d93a2045261aec)), closes [#1](https://github.com/keysafe-dev/keysafe/issues/1)
