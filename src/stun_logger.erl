%%%----------------------------------------------------------------------
%%% File    : stun_logger.erl
%%% Author  : Holger Weiss <holger@zedat.fu-berlin.de>
%%% Purpose : Wrap OTP Logger for STUN/TURN logging
%%% Created : 19 Jul 2020 by Holger Weiss <holger@zedat.fu-berlin.de>
%%%
%%%
%%% Copyright (C) 2020-2021 ProcessOne, SARL. All Rights Reserved.
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
%%%----------------------------------------------------------------------

-module(stun_logger).

-author('holger@zedat.fu-berlin.de').

-export([start/0, stop/0, set_metadata/2, set_metadata/3, set_metadata/4, set_metadata/5,
         add_metadata/1, make_id/0, encode_addr/1, encode_transport/1]).

-type sub_domain() :: listener | stun | turn.
-type transport() :: udp | tcp | tls.
-type sock_mod() :: gen_udp | gen_tcp | fast_tls.

%% API.

-ifdef(USE_OLD_LOGGER).

-export([log/2, log/3]).

-spec start() -> ok.
start() ->
    ok.

-spec stop() -> ok.
stop() ->
    ok.

-spec set_metadata(sub_domain(), transport()) -> ok.
set_metadata(SubDomain, Transport) ->
    put(?MODULE,
        #{domain => [stun, SubDomain], stun_transport => encode_transport(Transport)}),
    ok.

-spec set_metadata(sub_domain(), transport(), binary()) -> ok.
set_metadata(SubDomain, Transport, ID) ->
    put(?MODULE,
        #{domain => [stun, SubDomain],
          stun_transport => encode_transport(Transport),
          stun_session_id => ID}),
    ok.

-spec set_metadata(sub_domain(),
                   sock_mod(),
                   binary(),
                   {inet:ip_address(), inet:port_number()},
                   binary() | anonymous) ->
                      ok.
set_metadata(SubDomain, SockMod, ID, Addr, User) ->
    put(?MODULE,
        #{domain => [stun, SubDomain],
          stun_transport => encode_transport(SockMod),
          stun_session_id => ID,
          stun_client => encode_addr(Addr),
          stun_user => User}),
    ok.

-spec add_metadata(logger:metadata()) -> ok.
add_metadata(Meta) ->
    put(?MODULE, maps:merge(get(?MODULE), Meta)),
    ok.

-spec log(info | warning | error, iodata() | atom() | map()) -> ok.
log(Level, #{verbatim := {Format, Args}}) ->
    log(Level, Format, Args);
log(Level, Text) ->
    {Format, Args} = format_msg(Text, get(?MODULE)),
    case Level of
        info ->
            error_logger:info_msg(Format, Args);
        warning ->
            error_logger:warning_msg(Format, Args);
        error ->
            error_logger:error_msg(Format, Args)
    end.

-spec log(info | warning | error, io:format(), [term()]) -> ok.
log(Level, Format, Args) ->
    Text = io_lib:format(Format, Args),
    log(Level, Text).

-else.

-export([filter/2]).

-spec start() -> ok.
start() ->
    case logger:add_primary_filter(stun, {fun ?MODULE:filter/2, none}) of
        ok ->
            ok;
        {error, {already_exist, _}} ->
            ok
    end.

-spec stop() -> ok.
stop() ->
    case logger:remove_primary_filter(stun) of
        ok ->
            ok;
        {error, {not_found, _}} ->
            ok
    end.

-spec set_metadata(sub_domain(), transport()) -> ok.
set_metadata(SubDomain, Transport) ->
    logger:set_process_metadata(#{domain => [stun, SubDomain],
                                  stun_transport => encode_transport(Transport)}).

-spec set_metadata(sub_domain(), transport(), binary()) -> ok.
set_metadata(SubDomain, Transport, ID) ->
    logger:set_process_metadata(#{domain => [stun, SubDomain],
                                  stun_transport => encode_transport(Transport),
                                  stun_session_id => ID}).

-spec set_metadata(sub_domain(),
                   sock_mod(),
                   binary(),
                   {inet:ip_address(), inet:port_number()},
                   binary() | anonymous) ->
                      ok.
set_metadata(SubDomain, SockMod, ID, Addr, User) ->
    logger:set_process_metadata(#{domain => [stun, SubDomain],
                                  stun_transport => encode_transport(SockMod),
                                  stun_session_id => ID,
                                  stun_client => encode_addr(Addr),
                                  stun_user => User}).

-spec add_metadata(logger:metadata()) -> ok.
add_metadata(Meta) ->
    logger:update_process_metadata(Meta).

-spec filter(logger:log_event(), logger:filter_arg()) -> logger:filter_return().
filter(#{meta := #{domain := [stun | _]}, msg := {report, #{verbatim := Msg}}} = Event,
       _Extra) ->
    Event#{msg => Msg};
filter(#{meta := #{domain := [stun | _], stun_transport := _Transport} = Meta,
         msg := {Format, Args}} =
           Event,
       _Extra)
    when Format =/= report ->
    Text =
        case Format of
            string ->
                Args;
            _ ->
                io_lib:format(Format, Args)
        end,
    Event#{msg => format_msg(Text, Meta)};
filter(_Event, _Extra) ->
    ignore.

-endif.

-spec set_metadata(sub_domain(),
                   sock_mod(),
                   binary(),
                   {inet:ip_address(), inet:port_number()}) ->
                      ok.
set_metadata(SubDomain, SockMod, ID, Addr) ->
    set_metadata(SubDomain, SockMod, ID, Addr, anonymous).

-spec make_id() -> binary().
make_id() ->
    iolist_to_binary(io_lib:format("~.36b", [erlang:unique_integer([positive])])).

-spec encode_addr({inet:ip_address(), inet:port_number()} | inet:ip_address()) ->
                     iolist().
encode_addr({Addr, Port}) when is_tuple(Addr) ->
    [encode_addr(Addr), [$: | integer_to_list(Port)]];
encode_addr({0, 0, 0, 0, 0, 16#FFFF, D7, D8}) ->
    encode_addr({D7 bsr 8, D7 band 255, D8 bsr 8, D8 band 255});
encode_addr({_, _, _, _, _, _, _, _} = Addr) ->
    [$[, inet:ntoa(Addr), $]];
encode_addr(Addr) ->
    inet:ntoa(Addr).

-spec encode_transport(atom()) -> binary().
encode_transport(udp) ->
    <<"UDP">>;
encode_transport(tcp) ->
    <<"TCP">>;
encode_transport(tls) ->
    <<"TLS">>;
encode_transport(gen_udp) ->
    <<"UDP">>;
encode_transport(gen_tcp) ->
    <<"TCP">>;
encode_transport(fast_tls) ->
    <<"TLS">>.

%% Internal functions.

-spec format_msg(iodata() | atom(), map()) -> {io:format(), [term()]}.
format_msg(Text,
           #{stun_transport := Transport,
             stun_session_id := ID,
             stun_user := User,
             stun_client := Client,
             stun_relay := Relay}) ->
    {"~s [~s, session ~s, ~s, client ~s, relay ~s]",
     [Text, Transport, ID, format_user(User), Client, Relay]};
format_msg(Text,
           #{stun_transport := Transport,
             stun_session_id := ID,
             stun_user := User,
             stun_client := Client}) ->
    {"~s [~s, session ~s, ~s, client ~s]", [Text, Transport, ID, format_user(User), Client]};
format_msg(Text, #{stun_transport := Transport, stun_session_id := ID}) ->
    {"~s [~s, session ~s]", [Text, Transport, ID]};
format_msg(Text, #{stun_transport := Transport}) ->
    {"~s [~s]", [Text, Transport]}.

-spec format_user(anonymous | iodata()) -> iodata().
format_user(anonymous) ->
    <<"anonymous">>;
format_user(User) ->
    [<<"user ">>, User].
