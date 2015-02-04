%%%-------------------------------------------------------------------
%%% File    : turn_sm.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Description : Registers TURN sessions and credentials
%%% Created : 23 Aug 2009 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
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
%%%-------------------------------------------------------------------

-module(turn_sm).

-behaviour(gen_server).

%% API
-export([start_link/0,
	 start/0,
	 find_allocation/1,
	 add_allocation/5,
	 del_allocation/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include("stun.hrl").

-record(state, {}).

%%====================================================================
%% API
%%====================================================================
start() ->
    gen_server:start({local, ?MODULE}, ?MODULE, [], []).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

find_allocation(AddrPort) ->
    case ets:lookup(turn_allocs, AddrPort) of
	[{_, Pid}] ->
	    {ok, Pid};
	_ ->
	    {error, notfound}
    end.

add_allocation(AddrPort, _User, _Realm, _MaxAllocs, Pid) ->
    ets:insert(turn_allocs, {AddrPort, Pid}),
    ok.

del_allocation(AddrPort, _User, _Realm) ->
    ets:delete(turn_allocs, AddrPort),
    ok.

%%====================================================================
%% gen_server callbacks
%%====================================================================
init([]) ->
    ets:new(turn_allocs, [named_table, public]),
    {ok, #state{}}.

handle_call(_Request, _From, State) ->
    {reply, {error, badarg}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------
