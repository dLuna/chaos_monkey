%% @author Daniel Luna <daniel@lunas.se>
%% @copyright 2012 Daniel Luna
%% @doc 
-module(chaos_monkey_sup).
-author('Daniel Luna <daniel@lunas.se>').
-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

mk_spec(Type, Module, Args) ->
    Timeout = case Type of
                  worker -> 5000;
                  supervisor -> infinity
              end,
    {Module,
     {Module, start_link, Args},
     permanent,
     Timeout,
     Type,
     [Module]}.

init([]) ->
    Children = [mk_spec(worker, chaos_monkey, [])],
    {ok, {{one_for_one, 5, 10}, Children}}.
