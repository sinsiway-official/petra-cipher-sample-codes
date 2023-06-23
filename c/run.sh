export LD_LIBRARY_PATH=.

check_header(){
    header_file_name=PcAPIL.h
    if [ ! -f "$header_file_name" ]; then
        echo "File [$header_file_name] not found."
        echo "Generate the header to use. ln -sf /path/to/$header_file_name"
        exit 1
    fi
}

check_library(){
    library_file_name=libpcapi.so
    if [ ! -f "$library_file_name" ]; then
        echo "File [$library_file_name] not found."
        echo "Generate the header to use. ln -sf /path/to/$library_file_name"
        exit 1
    fi
}

check_configure(){
    config_file_name=petra_cipher_api.conf
    if [ ! -f "$config_file_name" ]; then
        echo "File [$config_file_name] not found."
        echo "Generate the header to use. ln -sf /path/to/$config_file_name"
        exit 1
    fi
}

build(){
    check_header
    check_library
    check_configure

    [[ -f dummy ]] && rm -rf dummy
    
    gcc -o dummy program.cpp -lpcapi -I. -L.
    [[ ! -f "dummy" ]] && echo "[Fail] build failed." && exit 1
    
    echo "[OK] build complete"
    echo
    
    ./dummy
    [[ -f "dummy" ]] && rm -rf dummy
    
}

build