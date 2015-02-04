%%%----------------------------------------------------------------------
%%% File    : stun_sup.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Purpose : stun supervisor
%%% Created : 2 May 2013 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%%
%%%
%%% stun, Copyright (C) 2002-2015   ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this program; if not, write to the Free Software
%%% Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
%%% 02111-1307 USA
%%%
%%%----------------------------------------------------------------------

-module(stun_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================
init([]) ->
    StunTmpSup = {stun_tmp_sup, {stun_tmp_sup, start_link, []},
		  permanent, infinity, supervisor, [stun_tmp_sup]},
    TurnTmpSup = {turn_tmp_sup, {turn_tmp_sup, start_link, []},
		  permanent, infinity, supervisor, [turn_tmp_sup]},
    TurnSM = {turn_sm, {turn_sm, start_link, []},
	      permanent, 2000, worker, [turn_sm]},
    StunListen = {stun_listener, {stun_listener, start_link, []},
		  permanent, 2000, worker, [stun_listener]},
    {ok, {{one_for_one, 10, 1}, [TurnSM, StunTmpSup, TurnTmpSup, StunListen]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
