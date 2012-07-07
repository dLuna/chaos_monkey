%% @author Daniel Luna <daniel@lunas.se>
%% @copyright 2012 Daniel Luna
%% @doc 
-module(chaos_monkey_app).
-author('Daniel Luna <daniel@lunas.se>').
-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    chaos_monkey_sup:start_link().

stop(_State) ->
    ok.

