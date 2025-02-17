dev:
  cargo build
  cargo test
  cargo fmt
  cargo doc --no-deps
  cargo doc
  git cliff -o CHANGELOG.md e6705a5..HEAD
