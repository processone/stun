all: deps/% src

deps/%:
	rebar get-deps

src:
	rebar compile

clean:
	rebar clean

.PHONY: clean src all
