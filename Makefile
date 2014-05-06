all: deps/% src

deps/%:
	rebar get-deps

src:
	rebar compile

clean:
	rebar clean

doc:
	rebar skip_deps=true doc

test: all
	rebar -v skip_deps=true eunit

.PHONY: clean src all doc rebar
