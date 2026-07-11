all:

clean:
	cargo cache --remove-dir all
	rm -rf target

