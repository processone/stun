REBAR ?= rebar3

all: deps/% src

deps/%:
	$(REBAR) get-deps

src:
	$(REBAR) compile

clean:
	$(REBAR) clean

doc:
	$(REBAR) skip_deps=true doc

test: all
	$(REBAR) -v skip_deps=true eunit

.PHONY: clean src all doc rebar
