%%%----------------------------------------------------------------------
%%% File    : stun_listener.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Purpose : 
%%% Created : 9 Jan 2011 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%%
%%%
%%% Copyright (C) 2002-2022 ProcessOne, SARL. All Rights Reserved.
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

-module(stun_listener).

-behaviour(gen_server).

%% API
-export([start_link/0, add_listener/4, del_listener/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include("stun_logger.hrl").

-record(state, {listeners = #{}}).

%%%===================================================================
%%% API
%%%===================================================================
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

add_listener(IP, Port, Transport, Opts) ->
    gen_server:call(?MODULE, {add_listener, IP, Port, Transport, Opts}).

del_listener(IP, Port, Transport) ->
    gen_server:call(?MODULE, {del_listener, IP, Port, Transport}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init([]) ->
    {ok, #state{}}.

handle_call({add_listener, IP, Port, Transport, Opts}, _From,
	    #state{listeners = Listeners} = State) ->
    Key = {IP, Port, Transport},
    case maps:find(Key, Listeners) of
	{ok, _PID} ->
	    {reply, {error, already_started}, State};
	error ->
	    Args = [IP, Port, Transport, Opts],
	    case supervisor:start_child(stun_acceptor_sup, Args) of
		{ok, PID} ->
		    NewListeners = maps:put(Key, PID, Listeners),
		    {reply, ok, State#state{listeners = NewListeners}};
		{error, _Reason} = Err ->
		    {reply, Err, State}
	    end
    end;
handle_call({del_listener, IP, Port, Transport}, _From,
	    #state{listeners = Listeners} = State) ->
    Key = {IP, Port, Transport},
    case maps:find(Key, Listeners) of
	{ok, PID} ->
	    case supervisor:terminate_child(stun_acceptor_sup, PID) of
		ok ->
		    NewListeners = maps:remove(Key, Listeners),
		    {reply, ok, State#state{listeners = NewListeners}};
		{error, _Reason} = Err ->
		    {reply, Err, State}
	    end;
	error ->
	    {reply, {error, not_found}, State}
    end;
handle_call(Request, From, State) ->
    ?LOG_ERROR("Got unexpected request from ~p: ~p", [From, Request]),
    {reply, {error, badarg}, State}.

handle_cast(Msg, State) ->
    ?LOG_ERROR("Got unexpected message: ~p", [Msg]),
    {noreply, State}.

handle_info(Info, State) ->
    ?LOG_ERROR("Got unexpected info: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, #state{listeners = Listeners}) ->
    lists:foreach(fun(PID) ->
			  _ = supervisor:terminate_child(stun_acceptor_sup, PID)
		  end, maps:values(Listeners)).

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
