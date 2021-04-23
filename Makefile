all:
	cargo test

debug:
	cargo test -- --nocapture

clean:
	cargo clean
	rm -fv tests/data/ca_*.der
