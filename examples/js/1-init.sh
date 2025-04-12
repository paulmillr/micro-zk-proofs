dir='circom-js'
if [ -d "$dir" ]; then exit 0; fi
git clone https://github.com/iden3/circom_old $dir
cd $dir
git checkout v0.0.35
npm install
