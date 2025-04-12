dir='circom-wasm'
if [ -d "$dir" ]; then exit 0; fi
git clone https://github.com/iden3/circom $dir
cd $dir
git checkout v2.2.2
cargo build --release
