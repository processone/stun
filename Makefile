all: src

src:
	rebar compile

clean:
	rebar clean

.PHONY: clean src
