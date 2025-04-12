dir='wasmsnark'
if [ -d "$dir" ]; then exit 0; fi
git clone https://github.com/iden3/wasmsnark.git $dir
cd $dir
git checkout v0.0.12
