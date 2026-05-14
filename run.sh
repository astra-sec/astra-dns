RUSTFLAGS=-Awarnings cargo build
./target/debug/astra-dns -c named.yaml

# dig @127.0.0.1 -p 8053 baidu.com
