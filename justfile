verify:
  cargo run -p clash-rs -- -t

run:
  cargo run -p clash-rs -- -c config.yaml

fmt:
  cargo +nightly fmt

docs:
  rm -rf ./docs
  cargo doc -p clash-doc --no-deps
  echo '<meta http-equiv="refresh" content="0; url=clash_doc">' > target/doc/index.html
  cp -r target/doc ./docs

test-no-docker:
  CLASH_RS_CI=true cargo test --all --all-features

verge-win verge_path='C:\Apps\Clash Verge\verge-mihomo-alpha.exe':
  cargo build -p clash-rs --profile detailed-release --features=standard
  rm -f "{{verge_path}}"
  cp target/release/clash-rs.exe "{{verge_path}}"

test-api token='test_token' url='http://127.0.0.1:9090/group':
  curl -H "Authorization: Bearer {{token}}" {{url}}
