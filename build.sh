scriptFolder=$(dirname $(realpath $0))
pushd . >/dev/null 2>&1
trap 'popd >/dev/null 2>&1' EXIT SIGINT SIGHUP
cd $scriptFolder
mkdir -p $scriptFolder/build
rm -rf $scriptFolder/build/*
cd src
if [ "$(uname -m)" = "x86_64" ]; then
    export CGO_CXXFLAGS="-std=c++17 -mcx16"
else
    export CGO_CXXFLAGS="-std=c++17"
fi
go build -o $scriptFolder/build/tmasque
if [[ $? -ne 0 ]]; then
    echo "Build failed. Aborting."
    exit 1
fi
echo "Masque binary is available at $scriptFolder/build/tmasque"
mkdir -p /etc/tmasque/certs
if [ ! -f /etc/tmasque/tmasque.conf ]; then
    cp $scriptFolder/tmasque.conf.template /etc/tmasque/
    echo "Cannot find /etc/tmasque/tmasque.conf. Please create one from tmasque.conf.template."
fi
popd

