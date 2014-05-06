%%%-------------------------------------------------------------------
%%% @author Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% @copyright (C) 2013, Evgeniy Khramtsov
%%% @doc
%%%
%%% @end
%%% Created :  2 May 2013 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%%-------------------------------------------------------------------
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
