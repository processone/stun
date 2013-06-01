all: deps/% src

deps/%:
	rebar get-deps

src:
	rebar compile

clean:
	rebar clean

doc:
	rebar skip_deps=true doc

.PHONY: clean src all doc
