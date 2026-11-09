# blvm-miniscript

This module overrides `getdescriptorinfo` and `analyzepsbt`. It parses a descriptor or a PSBT and returns the analysis JSON. It does not hold keys, and it does not change Bitcoin consensus. The `bitcoin` and `miniscript` crates stay inside this binary.

See the [BLVM documentation](https://docs.btcdecoded.org/blvm) for architecture and usage.

## Development

```bash
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```
