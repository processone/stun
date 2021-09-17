%% Copyright 2021 feliks
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(turn_starter).

-export([start/1, start/2]).

-include("stun.hrl").

start(Secret) ->
    start(Secret, 0).

start(Secret, Port) ->
    Auth_fun =
        fun(User, _Realm) ->
           Hash = crypto:mac(hmac, sha, Secret, User),
           base64:encode(Hash)
        end,

    Opts = [{use_turn, true}, {auth_fun, Auth_fun}, {auth_realm, "turn.stun.localhost"}],
    stun_listener:add_listener({127, 0, 0, 1}, Port, udp, Opts).
