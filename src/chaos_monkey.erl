%% @author Daniel Luna <daniel@lunas.se>
%% @copyright 2012 Daniel Luna
%% @doc 
-module(chaos_monkey).
-author('Daniel Luna <daniel@lunas.se>').
-behaviour(gen_server).

%% API
-export([start/0]).
-export([start_link/0]).

-export([find_orphans/0,
         almost_kill/0,
         almost_kill/1,
         kill/0,
         off/0,
         on/0,
         on/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-define(TIMER, 5000).
-define(DEFAULT_OPTS,
        [{ms, ?TIMER},
         {apps, all_but_otp}]).

-record(state, {
          is_active = false,
          avg_wait,
          timer_ref,
          apps,
          intervals = []}).

start() ->
    application:start(?MODULE).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% START OF EXTERNAL API

almost_kill() ->
    do_almost_kill(all_but_otp).

almost_kill(Apps) ->
    do_almost_kill(Apps).

find_orphans() ->
    do_find_orphans().

kill() ->
    do_kill(all_but_otp).

on() ->
    gen_server:call(?SERVER, {on, ?DEFAULT_OPTS}, infinity).

on(Opts) ->
    gen_server:call(?SERVER, {on, Opts ++ ?DEFAULT_OPTS}, infinity).

off() ->
    gen_server:call(?SERVER, off, infinity).

%% END OF EXTERNAL API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% START OF GEN_SERVER CALLBACKS

init([]) ->
    case application:get_env(auto_start) of
        undefined ->
            ok;
        {ok, false} ->
            ok;
        {ok, true} ->
            Opts = case application:get_env(ms) of
                       undefined -> [];
                       {ok, Ms} -> [{ms, Ms}]
                   end ++
                case application:get_env(apps) of
                    undefined -> [];
                    {ok, Apps} -> [{apps, Apps}]
                end ++
                ?DEFAULT_OPTS,
            case verify_opts(Opts) of
                {ok, _, _} ->
                    spawn_link(fun() -> {ok, started} = on(Opts) end);
                {error, Error} ->
                    exit(Error)
            end
    end,
    random:seed(now()),
    {ok, #state{}}.

handle_call({on, Opts}, _From, State = #state{is_active = false}) ->
    case verify_opts(Opts) of
        {ok, Ms, Apps} ->
            NewState = State#state{avg_wait = Ms,
                                   apps = Apps,
                                   is_active = true},
            self() ! kill_something,
            {reply, {ok, started}, NewState};
        {error, Error} ->
            {reply, {error, Error}, State}
    end;
handle_call(off, _From, State = #state{is_active = true, timer_ref = Ref}) ->
    timer:cancel(Ref),
    receive kill_something -> ok
    after 0 -> ok
    end,
    NewState = State#state{is_active = false},
    {reply, {ok, stopped}, NewState};
handle_call({on, _}, _From, State = #state{is_active = true}) ->
    {reply, {error, already_running}, State};
handle_call(off, _From, State = #state{is_active = false}) ->
    {reply, {error, not_running}, State};

handle_call(_Msg, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(kill_something, State = #state{avg_wait = AvgWait, apps = Apps}) ->
    case do_kill(Apps) of
        {ok, KilledInfo} ->
            p("Killed ~p", [KilledInfo]);
        {error, no_killable_processes} ->
            p("Warning: no killable processes.", [])
    end,
    Var = 0.3, %% I.e. 70% to 130% of Waittime
    WaitTime = round(AvgWait * ((1 - Var) + (Var * 2 * random:uniform()))),
    {ok, Ref} = timer:send_after(WaitTime, kill_something),
    {noreply, State#state{timer_ref = Ref}};
handle_info(Info, State) ->
    p("Unknown info ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% END OF GEN_SERVER CALLBACKS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% START OF DO_ FUNCTIONS

do_almost_kill(AppFilter) ->
    All = [{case application:get_application(P) of
                {ok, App} -> App; %% No apps named undefined, please!
                undefined -> undefined
            end, P} || P <- erlang:processes()],
    TaggedProcesses =
        lists:filter(fun({App, Pid}) ->
                             is_killable(Pid, App, AppFilter, false)
                     end, randomize(All)),
    ByApp = lists:foldl(fun({App, P}, [{App, Ps} | Acc]) ->
                                [{App, [P | Ps]} | Acc];
                           ({App, P}, Acc) ->
                                [{App, [P]} | Acc]
                        end, [], lists:sort(TaggedProcesses)),
    %% Start off by killing everything which doesn't belong to an app
    {KilledNoApp, Ps1} =
        case lists:keytake(undefined, 1, ByApp) of
            {value, {undefined, Undefined}, PsNoUndefined} ->
                {lists:foldl(
                  fun(Pid, N) ->
                          case is_supervisor(Pid) of
                              true ->
                                  p("Why is there a supervisor which "
                                    "doesn't belong to an application.  "
                                    "Take a closer look at ~p", [Pid]),
                                  %% Should I handle this better?
                                  %% Probably.  Because this will
                                  %% happen whenever somebody out
                                  %% there can't be bothered making
                                  %% proper app files. Which happens a
                                  %% lot.
                                  N;
                              false ->
                                  kill(Pid),
                                  N + 1
                          end
                  end, 0, Undefined), PsNoUndefined};
            false ->
                {0, ByApp}
        end,
    KilledApp =
        lists:sum(
          [begin
               p("About to kill things in ~p", [App]),
               app_killer(App, Pids)
           end || {App, Pids} <- randomize(Ps1)]),
    {ok, KilledNoApp + KilledApp}.

do_find_orphans() ->
    Ps = [{P,
           application:get_application(P),
           pman_process:is_system_process(P)}
          || P <- erlang:processes()],
    lists:zf(fun({P, undefined, false}) ->
                     case is_shell(P) of
                         true -> false;
                         false -> {true, P}
                     end;
                (_) -> false end, Ps).

do_kill(AppFilter) ->
    kill_one(randomize(erlang:processes()), AppFilter).

%% END OF DO_ FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% START OF AUXILIARY FUNCTIONS

verify_opts(Opts) ->
    try case lists:keyfind(ms, 1, Opts) of
            {ms, Ms} when is_integer(Ms), Ms >= 0 ->
                case lists:keyfind(apps, 1, Opts) of
                    {apps, Apps} ->
                        case Apps =:= all
                            orelse Apps =:= all_but_otp
                            orelse lists:all(fun(X) -> is_atom(X) end, Apps) of
                            true ->
                                AllApps = application:loaded_applications(),
                                case lists:all(
                                       fun(X) ->
                                               lists:keymember(X, 1, AllApps)
                                       end, Apps) of
                                    true ->
                                        {ok, Ms, Apps};
                                    false ->
                                        {error, unknown_application}
                                end;
                            false ->
                                {error, badly_formed_apps}
                        end;
                    _ ->
                        {error, bad_apps}
                end;
            _ ->
                {error, bad_ms}
        end
    catch
        _:_ ->
            {error, badarg}
    end.

randomize(Xs) ->
    [V || {_, V} <- lists:sort([{random:uniform(), X} || X <- Xs])].

%% random(L) ->
%%     lists:nth(random:uniform(length(L)), L).

 -record(node,
        {pid,
         type,
         will_die_at = 1,
         intensity,
         period,
         child_data = []}).

app_killer(App, Pids) ->
    {Sups, Other} = lists:partition(fun(Pid) -> is_supervisor(Pid) end, Pids),
    SupStates = [supervision_state(Pid) || Pid <- Sups],
    {Orphans, Tree} = make_tree(SupStates, Other),
    KilledOrphans =
        case Orphans =:= [] of
            true -> 0;
            false ->
                p("There are processes in ~s which don't belong to a "
                  "supervision tree.  The Chaos Monkey stomps on them.",
                  [App]),
                [kill(Pid) || Pid <- Orphans],
                length(Orphans)
        end,
    {RealTree, KilledTrees} =
        case Tree of
            [Single] ->
                {Single, 0};
            [Single | _] ->
                p("There are multiple top level supervision trees for ~p.  "
                  "The Chaos Money picks one randomly to harass.  At some"
                  "point in the future it will pick the right one and kill"
                  "the others.  Hand in a feature request.", [App]),
                %% Look at '$ancestors' to find the *real* supervision
                %% tree.  Easy to do but we are under a deadline
                %% here...
                {Single, 0}
        end,
    p("Supervision tree for ~p will go down at ~p kills if The Chaos "
      "Monkey kills it in the right order.",
      [App, RealTree#node.will_die_at]),
    TreeKilling = almost_kill_tree(RealTree),
    KilledOrphans + KilledTrees + TreeKilling.

almost_kill_tree(#node{type = child}) -> 0;
almost_kill_tree(#node{type = supervisor,
                       child_data = Children,
                       intensity = Intensity}) ->
    KillAllButOne = lists:sublist(Children, Intensity),
    case randomize(KillAllButOne) of
        [] -> 0; %% nothing to kill, we are done here
        L when length(L) < Intensity ->
            lists:sum([kill_tree(Child) || Child <- Children]);
        [DontKill | KillList] ->
            almost_kill_tree(DontKill) +
                lists:sum([kill_tree(Kill) || Kill <- KillList])
    end.

kill_tree(#node{pid = Pid, type = child}) ->
    kill(Pid),
    %% p("killed", []),
    1;
kill_tree(#node{type = supervisor,
                child_data = Children,
                intensity = Intensity}) ->
    KillAll = lists:sublist(Children, Intensity),
    lists:sum([kill_tree(Child) || Child <- KillAll]).

%% Copied from supervisor.erl
-record(child, {% pid is undefined when child is not running
	        pid = undefined,
		name,
		mfargs,
		restart_type,
		shutdown,
		child_type,
		modules = []}).

supervision_state(Pid) ->
    try sys:get_status(Pid) of
        %% from sys.erl
        {status, Pid, {module, _Mod},
         [_PDict, _SysState, _Parent, _Debug, FmtMisc]} ->
            [_, _, {data, [{"State", State}]}] = FmtMisc,
            %% From supervisor.erl but I already have a #state{} in
            %% this module so cannot copy the one from there
            {state, _Name, _Strategy, Children, _Dynamics, Intensity,
             Period, _Restarts, _Module, _Args} = State,
            ChildPids = [CPid || #child{pid = CPid} <- Children],
            {#node{pid = Pid,
                   type = supervisor,
                   intensity = Intensity,
                   period = Period}, ChildPids}
    catch
        exit:timeout ->
            throw({supervisor_died_before_we_could_query_it,
                   report_this_as_a_bug_or_just_rerun_the_command})
    end.

make_tree(SupStates, OtherPids) ->
    make_tree(SupStates, OtherPids, []).

make_tree([], Orphans, Tree) ->
    {Orphans, Tree};
make_tree([{Node, Children} | SupStates], OtherPids, Completed) ->
    {NewSupStates, NewOtherPids, NewCompleted, NewNode} =
        make_tree(Children, SupStates, OtherPids, Completed, Node),
    make_tree(NewSupStates, NewOtherPids, [NewNode | NewCompleted]).

make_tree([], SupStates, OtherPids, Completed, Node) ->
    Sorted = lists:sort(fun(#node{will_die_at = D1},
                            %% TODO: check that this comparison is in
                            %% the right direction.  I don't have a
                            %% good test case and am too tired to do
                            %% it by thinking.  Deadline moving
                            %% closer...
                            #node{will_die_at = D2}) -> D1 > D2
                        end, Node#node.child_data),
    WillDieAt =
        lists:sum(lists:sublist([N#node.will_die_at || N <- Sorted],
                                Node#node.intensity)),
    {SupStates, OtherPids, Completed, Node#node{will_die_at = WillDieAt,
                                                child_data = Sorted}};
make_tree([ChildPid | ChildPids],
          SupStates,
          OtherPids,
          Completed,
          Node) ->
    case lists:keytake(ChildPid, 1, SupStates) of
        {value, {ChildPid, {Node, ChildChildren}}, NewSupStates} ->
            {NewNewSupStates, NewOtherPids, NewCompleted, Child} =
                make_tree(ChildChildren,
                          NewSupStates,
                          OtherPids,
                          Completed,
                          Node),
            make_tree(ChildPids,
                      NewNewSupStates,
                      NewOtherPids,
                      NewCompleted,
                      Node#node{child_data = [Child | Node#node.child_data]});
        false ->
            case lists:splitwith(fun(X) -> X =/= ChildPid end, OtherPids) of
                {Pre, [ChildPid | Post]} ->
                    make_tree(ChildPids,
                              SupStates,
                              Pre ++ Post,
                              Completed,
                              Node#node{
                                child_data = [#node{pid = ChildPid,
                                                    type = child} |
                                              Node#node.child_data]});
                {_, []} ->
                    case lists:keytake(ChildPid, #node.pid, Completed) of
                        {value, CompletedChild, NewCompleted} ->
                            make_tree(ChildPids,
                                      SupStates,
                                      OtherPids,
                                      NewCompleted,
                                      Node#node{
                                        child_data = [CompletedChild |
                                                      Node#node.child_data]});
                        false ->
                            case ChildPid =:= undefined of
                                true ->
                                    ok;
                                false ->
                                    p("Missing child ~p, ignoring", [ChildPid])
                            end,
                            make_tree(ChildPids,
                                      SupStates,
                                      OtherPids,
                                      Completed,
                                      Node)
                    end
            end
    end.

kill_one([], _AppFilter) -> {error, no_killable_processes};
kill_one([Pid | Pids], AppFilter) ->
    App = case application:get_application(Pid) of
              {ok, A} -> A; %% No apps named undefined, please!
              undefined -> undefined
          end,
    case is_killable(Pid, App, AppFilter) of
        true -> {ok, {Pid, App, kill(Pid)}};
        false -> kill_one(Pids, AppFilter)
    end.

kill(Pid) ->
    erlang:monitor(process, Pid),
    exit(Pid, im_killing_you),
    receive
        {'DOWN', _, process, Pid, Reason} ->
            Reason
    after 500 ->
            exit(Pid, kill),
            receive
                {'DOWN', _, process, Pid, Reason} ->
                    Reason
            end
    end.

%% END OF AUXILIARY FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% START OF FORMATTING FUNCTIONS

p(Format, Data) ->
    catch throw(get_stacktrace), Stacktrace = erlang:get_stacktrace(),
    MFAInfo = hd(tl(Stacktrace)),
    String =
        case MFAInfo of
            {M, F, A} ->
                format_single_line("~p ~p:~p/~p " ++ Format,
                                   [self(), M, F, A | Data]);
            {M, F, A, Info} ->
                case lists:keysearch(line, 1, Info) of
                    {value, {line, Line}} ->
                        format_single_line("~p ~p:~p/~p #~p " ++ Format,
                                           [self(), M, F, A, Line | Data]);
                    false ->
                        format_single_line("~p ~p:~p/~p " ++ Format,
                                           [self(), M, F, A | Data])
                end
        end,
    io:format("~s~n", [String]).

format_single_line(Format, Data) ->
    oneline(lists:flatten(io_lib:format(Format, Data))).

oneline([$\n | Rest]) -> [$\s | newline(Rest)];
oneline([C | Rest]) -> [C | oneline(Rest)];
oneline([]) -> [].

newline([$\s | Rest]) -> newline(Rest);
newline(Rest) -> oneline(Rest).

%% END OF FORMATTING FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% START OF BOOLEAN FUNCTONS

is_supervisor(Pid) ->
    %% inspired by pman_process:is_system_process2/1 which seems
    %% cleaner somehow to just grabbing the info from the process_info
    %% dictionary (this is what happens in the background anyway).
    {initial_call, Init} = erlang:process_info(Pid, initial_call),
    SortofActualInit =
        case Init of
            {proc_lib, init_p, 5} -> proc_lib:translate_initial_call(Pid);
            Init -> Init
        end,
    case SortofActualInit of
        {supervisor, _, _} -> true;
        _ -> false
    end.

-define(OTP_APPS,
        [appmon, asn1, common_test, compiler, cosEvent,
         cosEventDomain, cosFileTransfer, cosNotification,
         cosProperty, cosTime, cosTransactions, crypto, debugger,
         dialyzer, diameter, edoc, eldap, erl_docgen, erl_interface,
         erts, et, eunit, gs, hipe, ic, inets, inviso, jinterface,
         kernel, megaco, mnesia, observer, odbc, orber, os_mon,
         otp_mibs, parsetools, percept, pman, public_key, reltool,
         runtime_tools, sasl, snmp, ssh, ssl, stdlib, syntax_tools,
         test_server, toolbar, tools, tv, typer, webtool, wx, xmerl]).

%% is_killable(Pid, App) ->
%%     is_killable(Pid, App, all_but_otp, true).

is_killable(Pid, App, AppFilter) ->
    is_killable(Pid, App, AppFilter, true).

is_killable(Pid, App, AppFilter, IsSupervisorKillable)
  when is_pid(Pid), is_atom(App), is_boolean(IsSupervisorKillable) ->
    (App =:= undefined
     orelse
     case AppFilter of
         all -> true;
         all_but_otp -> not(lists:member(App, ?OTP_APPS));
         Apps when is_list(Apps) -> lists:member(App, Apps)
     end) 
        andalso
        not(lists:member(App, [kernel, chaos_monkey]))
        andalso
        not(pman_process:is_system_process(Pid))
        andalso
        not(is_shell(Pid))
        andalso
        not(Pid =:= self())
        andalso
        (not(IsSupervisorKillable)
         orelse
         not(is_supervisor(Pid))).

%% Theoretically pman_process:is_system_process/1 should say true for
%% the shell.  Well, it doesn't, so this is a workaround until it
%% does.
is_shell(Pid) ->
    %% The shell never belongs to any applicition.  To optimize, check
    %% that application:get_application(Pid) yields undefined before
    %% calling this function.
    {group_leader, Leader} = erlang:process_info(Pid, group_leader),
    case lists:keyfind(shell, 1, group:interfaces(Leader)) of
        {shell, Pid} -> true;
        {shell, Shell} ->
            case erlang:process_info(Shell, dictionary) of
                {dictionary, Dict} ->
                    proplists:get_value(evaluator, Dict) =:= Pid
            end;
        false -> false
    end.
