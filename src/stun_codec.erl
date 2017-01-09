%%%-------------------------------------------------------------------
%%% File    : stun_codec.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Description : STUN codec
%%% Created :  7 Aug 2009 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
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

-module(stun_codec).

%% API
-export([decode/2,
	 encode/1,
	 encode/2,
	 version/1,
	 error/1,
	 check_integrity/2,
	 add_fingerprint/1,
	 pp/1]).

-include("stun.hrl").

%%====================================================================
%% API
%%====================================================================
decode(<<0:2, Type:14, Len:16, Magic:32, TrID:96,
	Body:Len/binary, Tail/binary>> = Data, Transport) ->
    case catch decode(Type, Magic, TrID, Body) of
	{'EXIT', _} ->
	    {error, unparsed};
	{Res, RawSize} when Transport == datagram ->
	    {ok, add_raw(Res, Data, RawSize)};
	{Res, RawSize} ->
	    {ok, add_raw(Res, Data, RawSize), Tail}
    end;
decode(<<1:2, _:6, _/binary>> = Pkt, datagram) ->
    case Pkt of
	<<Channel:16, Len:16, Data:Len/binary, _/binary>> ->
	    {ok, #turn{channel = Channel, data = Data}};
	_ ->
	    {error, unparsed}
    end;
decode(<<1:2, _:6, _/binary>> = Pkt, stream) ->
    case Pkt of
	<<Channel:16, Len:16, Rest/binary>> ->
	    PaddLen = padd_len(Len),
	    case Rest of
		<<Data:Len/binary, _:PaddLen, Tail/binary>> ->
		    {ok, #turn{channel = Channel, data = Data}, Tail};
		_ ->
		    more
	    end;
	_ ->
	    more
    end;
decode(<<0:2, _:6, _/binary>>, stream) ->
    more;
decode(<<>>, stream) ->
    empty;
decode(_, _Transport) ->
    {error, unparsed}.

encode(Msg) ->
    encode(Msg, undefined).

encode(#turn{channel = Channel, data = Data}, _Password) ->
    Len = size(Data),
    PaddLen = padd_len(Len),
    <<Channel:16, Len:16, Data/binary, 0:PaddLen>>;
encode(#stun{class = Class,
	     method = Method,
	     magic = Magic,
	     trid = TrID} = Msg, Key) ->
    ClassCode = case Class of
		    request -> 0;
		    indication -> 1;
		    response -> 2;
		    error -> 3
		end,
    Type = ?STUN_TYPE(ClassCode, Method),
    Attrs = enc_attrs(Msg),
    Len = size(Attrs),
    if Key /= undefined ->
	    NewKey = case Key of
			 {User, Realm, Password} ->
			     crypto:hash(md5, [User, $:, Realm, $:, Password]);
			 _ ->
			     Key
		     end,
	    Data = <<0:2, Type:14, (Len+24):16, Magic:32,
		    TrID:96, Attrs/binary>>,
	    MessageIntegrity = crypto:hmac(sha, NewKey, Data),
	    <<Data/binary, ?STUN_ATTR_MESSAGE_INTEGRITY:16,
	     20:16, MessageIntegrity/binary>>;
       true ->
	    <<0:2, Type:14, Len:16, Magic:32,
	     TrID:96, Attrs/binary>>
    end.

add_fingerprint(<<T:16, L:16, Tail/binary>>) ->
    Data = <<T:16, (L+8):16, Tail/binary>>,
    CRC32 = erlang:crc32(Data),
    <<Data/binary, ?STUN_ATTR_FINGERPRINT:16, 4:16, CRC32:32>>.

check_integrity(#stun{raw = Raw, 'MESSAGE-INTEGRITY' = MI}, Key)
  when is_binary(Raw), is_binary(MI), Key /= undefined ->
    NewKey = case Key of
		 {User, Realm, Password} ->
		     crypto:hash(md5, [User, $:, Realm, $:, Password]);
		 _ ->
		     Key
	     end,
    crypto:hmac(sha, NewKey, Raw) == MI;
check_integrity(_Msg, _Key) ->
    false.

pp(Term) ->
    io_lib_pretty:print(Term, fun pp/2).

version(#stun{magic = ?STUN_MAGIC}) ->
    new;
version(#stun{}) ->
    old.

error(300) -> {300, <<"Try Alternate">>};
error(400) -> {400, <<"Bad Request">>};
error(401) -> {401, <<"Unauthorized">>};
error(403) -> {403, <<"Forbidden">>};
error(405) -> {405, <<"Method Not Allowed">>};
error(420) -> {420, <<"Unknown Attribute">>};
error(437) -> {437, <<"Allocation Mismatch">>};
error(438) -> {438, <<"Stale Nonce">>};
error(441) -> {441, <<"Wrong Credentials">>};
error(442) -> {442, <<"Unsupported Transport Protocol">>};
error(486) -> {486, <<"Allocation Quota Reached">>};
error(500) -> {500, <<"Server Error">>};
error(508) -> {508, <<"Insufficient Capacity">>};
error(Int) -> {Int, <<"Undefined Error">>}.

%%====================================================================
%% Internal functions
%%====================================================================
decode(Type, Magic, TrID, Body) ->
    Method = ?STUN_METHOD(Type),
    Class = case ?STUN_CLASS(Type) of
		0 -> request;
		1 -> indication;
		2 -> response;
		3 -> error
	    end,
    dec_attrs(Body, 20, #stun{class = Class,
			      method = Method,
			      magic = Magic,
			      trid = TrID}).

dec_attrs(<<Type:16, Len:16, Rest/binary>>, Bytes, Msg) ->
    PaddLen = padd_len(Len),
    <<Val:Len/binary, _:PaddLen, Tail/binary>> = Rest,
    NewMsg = dec_attr(Type, Val, Msg),
    if Type == ?STUN_ATTR_MESSAGE_INTEGRITY ->
	    {NewMsg, Bytes};
       true ->
	    NewBytes = Bytes + 4 + Len + (PaddLen div 8),
	    dec_attrs(Tail, NewBytes, NewMsg)
    end;
dec_attrs(<<>>, _Bytes, Msg) ->
    {Msg, 0}.

enc_attrs(Msg) ->
    iolist_to_binary(
      [enc_attr(?STUN_ATTR_SOFTWARE, Msg#stun.'SOFTWARE'),
       enc_addr(?STUN_ATTR_MAPPED_ADDRESS, Msg#stun.'MAPPED-ADDRESS'),
       enc_xor_addr(?STUN_ATTR_XOR_MAPPED_ADDRESS,
		    Msg#stun.magic, Msg#stun.trid,
		    Msg#stun.'XOR-MAPPED-ADDRESS'),
       enc_xor_addr(?STUN_ATTR_XOR_RELAYED_ADDRESS,
		    Msg#stun.magic, Msg#stun.trid,
		    Msg#stun.'XOR-RELAYED-ADDRESS'),
       enc_xor_peer_addr(Msg#stun.magic, Msg#stun.trid,
			 Msg#stun.'XOR-PEER-ADDRESS'),
       enc_req_trans(Msg#stun.'REQUESTED-TRANSPORT'),
       enc_attr(?STUN_ATTR_DATA, Msg#stun.'DATA'),
       enc_df(Msg#stun.'DONT-FRAGMENT'),
       enc_addr(?STUN_ATTR_ALTERNATE_SERVER, Msg#stun.'ALTERNATE-SERVER'),
       enc_attr(?STUN_ATTR_USERNAME, Msg#stun.'USERNAME'),
       enc_attr(?STUN_ATTR_REALM, Msg#stun.'REALM'),
       enc_attr(?STUN_ATTR_NONCE, Msg#stun.'NONCE'),
       enc_error_code(Msg#stun.'ERROR-CODE'),
       enc_uint32(?STUN_ATTR_LIFETIME, Msg#stun.'LIFETIME'),
       enc_chan(Msg#stun.'CHANNEL-NUMBER'),
       enc_unknown_attrs(Msg#stun.'UNKNOWN-ATTRIBUTES')]).

dec_attr(?STUN_ATTR_MAPPED_ADDRESS, Val, Msg) ->
    <<_, Family, Port:16, AddrBin/binary>> = Val,
    Addr = dec_addr(Family, AddrBin),
    Msg#stun{'MAPPED-ADDRESS' = {Addr, Port}};
dec_attr(?STUN_ATTR_XOR_MAPPED_ADDRESS, Val, Msg) ->
    AddrPort = dec_xor_addr(Val, Msg),
    Msg#stun{'XOR-MAPPED-ADDRESS' = AddrPort};
dec_attr(?STUN_ATTR_SOFTWARE, Val, Msg) ->
    Msg#stun{'SOFTWARE' = Val};
dec_attr(?STUN_ATTR_USERNAME, Val, Msg) ->
    Msg#stun{'USERNAME' = Val};
dec_attr(?STUN_ATTR_REALM, Val, Msg) ->
    Msg#stun{'REALM' = Val};
dec_attr(?STUN_ATTR_NONCE, Val, Msg) ->
    Msg#stun{'NONCE' = Val};
dec_attr(?STUN_ATTR_MESSAGE_INTEGRITY, Val, Msg) ->
    Msg#stun{'MESSAGE-INTEGRITY' = Val};
dec_attr(?STUN_ATTR_ALTERNATE_SERVER, Val, Msg) ->
    <<_, Family, Port:16, Address/binary>> = Val,
    IP = dec_addr(Family, Address),
    Msg#stun{'ALTERNATE-SERVER' = {IP, Port}};
dec_attr(?STUN_ATTR_ERROR_CODE, Val, Msg) ->
    <<_:21, Class:3, Number:8, Reason/binary>> = Val,
    if Class >=3, Class =< 6, Number >=0, Number =< 99 ->
	    Code = Class * 100 + Number,
	    Msg#stun{'ERROR-CODE' = {Code, Reason}}
    end;
dec_attr(?STUN_ATTR_UNKNOWN_ATTRIBUTES, Val, Msg) ->
    Attrs = dec_unknown_attrs(Val, []),
    Msg#stun{'UNKNOWN-ATTRIBUTES' = Attrs};
dec_attr(?STUN_ATTR_XOR_RELAYED_ADDRESS, Val, Msg) ->
    AddrPort = dec_xor_addr(Val, Msg),
    Msg#stun{'XOR-RELAYED-ADDRESS' = AddrPort};
dec_attr(?STUN_ATTR_XOR_PEER_ADDRESS, Val, Msg) ->
    AddrPort = dec_xor_addr(Val, Msg),
    Tail = Msg#stun.'XOR-PEER-ADDRESS',
    Msg#stun{'XOR-PEER-ADDRESS' = [AddrPort|Tail]};
dec_attr(?STUN_ATTR_REQUESTED_TRANSPORT, Val, Msg) ->
    <<ProtoInt, _:3/binary>> = Val,
    Proto = case ProtoInt of
		17 -> udp;
		_ -> unknown
	    end,
    Msg#stun{'REQUESTED-TRANSPORT' = Proto};
dec_attr(?STUN_ATTR_DATA, Val, Msg) ->
    Msg#stun{'DATA' = Val};
dec_attr(?STUN_ATTR_LIFETIME, Val, Msg) ->
    <<Seconds:32>> = Val,
    Msg#stun{'LIFETIME' = Seconds};
dec_attr(?STUN_ATTR_DONT_FRAGMENT, _Val, Msg) ->
    Msg#stun{'DONT-FRAGMENT' = true};
dec_attr(?STUN_ATTR_CHANNEL_NUMBER, Val, Msg) ->
    <<Channel:16, _:16>> = Val,
    Msg#stun{'CHANNEL-NUMBER' = Channel};
dec_attr(Attr, _Val, #stun{unsupported = Attrs} = Msg)
  when Attr < 16#8000 ->
    Msg#stun{unsupported = [Attr|Attrs]};
dec_attr(_Attr, _Val, Msg) ->
    Msg.

dec_addr(1, <<A1, A2, A3, A4>>) ->
    {A1, A2, A3, A4};
dec_addr(2, <<A1:16, A2:16, A3:16, A4:16,
	     A5:16, A6:16, A7:16, A8:16>>) ->
    {A1, A2, A3, A4, A5, A6, A7, A8}.

dec_xor_addr(<<_, Family, XPort:16, XAddr/binary>>, Msg) ->
    Magic = Msg#stun.magic,
    Port = XPort bxor (Magic bsr 16),
    Addr = dec_xor_addr(Family, Magic, Msg#stun.trid, XAddr),
    {Addr, Port}.

dec_xor_addr(1, Magic, _TrID, <<XAddr:32>>) ->
    Addr = XAddr bxor Magic,
    dec_addr(1, <<Addr:32>>);
dec_xor_addr(2, Magic, TrID, <<XAddr:128>>) ->
    Addr = XAddr bxor ((Magic bsl 96) bor TrID),
    dec_addr(2, <<Addr:128>>).

dec_unknown_attrs(<<Attr:16, Tail/binary>>, Acc) ->
    dec_unknown_attrs(Tail, [Attr|Acc]);
dec_unknown_attrs(<<>>, Acc) ->
    lists:reverse(Acc).

enc_attr(_Attr, undefined) ->
    <<>>;
enc_attr(Attr, Val) ->
    Len = size(Val),
    PaddLen = padd_len(Len),
    <<Attr:16, Len:16, Val/binary, 0:PaddLen>>.

enc_addr(_Type, undefined) ->
    <<>>;
enc_addr(Type, {{A1, A2, A3, A4}, Port}) ->
    enc_attr(Type, <<0, 1, Port:16, A1, A2, A3, A4>>);
enc_addr(Type, {{A1, A2, A3, A4, A5, A6, A7, A8}, Port}) ->
    enc_attr(Type, <<0, 2, Port:16, A1:16, A2:16, A3:16,
		    A4:16, A5:16, A6:16, A7:16, A8:16>>).

enc_xor_addr(_Type, _Magic, _TrID, undefined) ->
    <<>>;
enc_xor_addr(Type, Magic, _TrID, {{A1, A2, A3, A4}, Port}) ->
    XPort = Port bxor (Magic bsr 16),
    <<Addr:32>> = <<A1, A2, A3, A4>>,
    XAddr = Addr bxor Magic,
    enc_attr(Type, <<0, 1, XPort:16, XAddr:32>>);
enc_xor_addr(Type, Magic, TrID,
	     {{A1, A2, A3, A4, A5, A6, A7, A8}, Port}) ->
    XPort = Port bxor (Magic bsr 16),
    <<Addr:128>> = <<A1:16, A2:16, A3:16, A4:16,
		    A5:16, A6:16, A7:16, A8:16>>,
    XAddr = Addr bxor ((Magic bsl 96) bor TrID),
    enc_attr(Type, <<0, 2, XPort:16, XAddr:128>>).

enc_xor_peer_addr(Magic, TrID, AddrPortList) ->
    [enc_xor_addr(?STUN_ATTR_XOR_PEER_ADDRESS,
		  Magic, TrID, AddrPort) ||
	AddrPort <- AddrPortList].

enc_error_code(undefined) ->
    <<>>;
enc_error_code({Code, Reason}) ->
    Class = Code div 100,
    Number = Code rem 100,
    enc_attr(?STUN_ATTR_ERROR_CODE,
	     <<0:21, Class:3, Number:8, Reason/binary>>).

enc_unknown_attrs([]) ->
    <<>>;
enc_unknown_attrs(Attrs) ->
    enc_attr(?STUN_ATTR_UNKNOWN_ATTRIBUTES,
	     iolist_to_binary([<<Attr:16>> || Attr <- Attrs])).

enc_uint32(_Type, undefined) ->
    <<>>;
enc_uint32(Type, Seconds) ->
    enc_attr(Type, <<Seconds:32>>).

enc_req_trans(undefined) ->
    <<>>;
enc_req_trans(udp) ->
    enc_attr(?STUN_ATTR_REQUESTED_TRANSPORT, <<17, 0:24>>).

enc_df(false) ->
    <<>>;
enc_df(true) ->
    enc_attr(?STUN_ATTR_DONT_FRAGMENT, <<>>).

enc_chan(undefined) ->
    <<>>;
enc_chan(Channel) ->
    enc_attr(?STUN_ATTR_CHANNEL_NUMBER, <<Channel:16, 0:16>>).

%%====================================================================
%% Auxiliary functions
%%====================================================================
pp(Tag, N) ->
    try
	pp1(Tag, N)
    catch _:_ ->
	    no
    end.

pp1(stun, N) ->
    N = record_info(size, stun) - 1,
    record_info(fields, stun);
pp1(turn, N) ->
    N = record_info(size, turn) - 1,
    record_info(fields, turn);
pp1(_, _) ->
    no.

add_raw(Msg, _Data, 0) ->
    Msg;
add_raw(Msg, Data, Size) ->
    <<Head:Size/binary, _/binary>> = Data,
    <<Type:16, _:16, Tail/binary>> = Head,
    Raw = <<Type:16, (Size+4):16, Tail/binary>>,
    Msg#stun{raw = Raw}.

%% Workaround for stupid clients.
-ifdef(NO_PADDING).
padd_len(_Len) ->
    0.
-else.
padd_len(Len) ->
    case Len rem 4 of
	0 -> 0;
	N -> 8*(4-N)
    end.
-endif.
