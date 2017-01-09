%%%-------------------------------------------------------------------
%%% File    : stun.hrl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Description : STUN values
%%% Created :  8 Aug 2009 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%%
%%%
%%% Copyright (C) 2002-2017 ProcessOne, SARL. All Rights Reserved.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%%-------------------------------------------------------------------
-define(STUN_MAGIC, 16#2112a442).

%% I know, this is terrible. Refer to 'STUN Message Structure' of
%% RFC5389 to understand this.
-define(STUN_METHOD(Type),
	((Type band 16#3e00) bsr 2) bor
	((Type band 16#e0) bsr 1) bor (Type band 16#f)).
-define(STUN_CLASS(Type),
	((Type band 16#100) bsr 7) bor
	((Type band 16#10) bsr 4)).
-define(STUN_TYPE(C, M),
	(((M band 16#f80) bsl 2)
	 bor ((M band 16#70) bsl 1)
	 bor (M band 16#f) )
	bor (((C band 16#2) bsl 7) bor ((C band 16#1) bsl 4))).

-define(is_required(A), (A =< 16#7fff)).

-define(STUN_METHOD_BINDING, 16#001).
-define(STUN_METHOD_ALLOCATE, 16#003).
-define(STUN_METHOD_REFRESH, 16#004).
-define(STUN_METHOD_SEND, 16#006).
-define(STUN_METHOD_DATA, 16#007).
-define(STUN_METHOD_CREATE_PERMISSION, 16#008).
-define(STUN_METHOD_CHANNEL_BIND, 16#009).

%% Comprehension-required range (0x0000-0x7FFF)
-define(STUN_ATTR_MAPPED_ADDRESS, 16#0001).
-define(STUN_ATTR_USERNAME, 16#0006).
-define(STUN_ATTR_MESSAGE_INTEGRITY, 16#0008).
-define(STUN_ATTR_ERROR_CODE, 16#0009).
-define(STUN_ATTR_UNKNOWN_ATTRIBUTES, 16#000a).
-define(STUN_ATTR_REALM, 16#0014).
-define(STUN_ATTR_NONCE, 16#0015).
-define(STUN_ATTR_XOR_MAPPED_ADDRESS, 16#0020).
-define(STUN_ATTR_CHANNEL_NUMBER, 16#000c).
-define(STUN_ATTR_LIFETIME, 16#000d).
-define(STUN_ATTR_XOR_PEER_ADDRESS, 16#0012).
-define(STUN_ATTR_DATA, 16#0013).
-define(STUN_ATTR_XOR_RELAYED_ADDRESS, 16#0016).
-define(STUN_ATTR_EVEN_PORT, 16#0018).
-define(STUN_ATTR_REQUESTED_TRANSPORT, 16#0019).
-define(STUN_ATTR_DONT_FRAGMENT, 16#001a).
-define(STUN_ATTR_RESERVATION_TOKEN, 16#0022).

%% Comprehension-optional range (0x8000-0xFFFF)
-define(STUN_ATTR_SOFTWARE, 16#8022).
-define(STUN_ATTR_ALTERNATE_SERVER, 16#8023).
-define(STUN_ATTR_FINGERPRINT, 16#8028).

-record(stun, {class = request :: request | response | error | indication,
	       method = ?STUN_METHOD_BINDING :: non_neg_integer(),
	       magic = ?STUN_MAGIC :: non_neg_integer(),
	       trid = 0 :: non_neg_integer(),
	       raw = <<>> :: binary(),
	       unsupported = [],
	       'ALTERNATE-SERVER',
	       'CHANNEL-NUMBER',
	       'DATA',
	       'DONT-FRAGMENT' = false,
	       'ERROR-CODE',
	       'LIFETIME',
	       'MAPPED-ADDRESS',
	       'MESSAGE-INTEGRITY',
	       'NONCE',
	       'REALM',
	       'REQUESTED-TRANSPORT',
	       'SOFTWARE',
	       'UNKNOWN-ATTRIBUTES' = [],
	       'USERNAME',
	       'XOR-MAPPED-ADDRESS',
	       'XOR-PEER-ADDRESS' = [],
	       'XOR-RELAYED-ADDRESS'}).

-record(turn, {channel = 0 :: non_neg_integer(),
	       data = <<>> :: binary()}).

%% Workarounds.
%%-define(NO_PADDING, true).
