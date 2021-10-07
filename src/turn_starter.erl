%%%----------------------------------------------------------------------
%%% File    : stun_listener.erl
%%% Author  : Feliks Pobiedzinski <feliks.pobiedzinski@gmail.com>
%%% Purpose :
%%% Created : 15 Aug 2021 by Feliks Pobiedzinski <feliks.pobiedzinski@gmail.com>
%%%
%%%
%%% Copyright (C) 2002-2021 ProcessOne, SARL. All Rights Reserved.
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

-module(turn_starter).

-export([start/2]).

-include("stun.hrl").

start(Secret, Opts) ->
    IP = proplists:get_value(ip, Opts, {127, 0, 0, 1}),
    Port = proplists:get_value(port, Opts, 0),
    Transport = proplists:get_value(transport, Opts, udp),
    Auth_fun =
        fun(User, _Realm) ->
           Hash = crypto:mac(hmac, sha, Secret, User),
           base64:encode(Hash)
        end,

    TurnOpts = [{use_turn, true}, {auth_fun, Auth_fun}, {auth_realm, "turn.stun.localhost"}],
    stun_listener:add_listener(IP, Port, Transport, TurnOpts).
