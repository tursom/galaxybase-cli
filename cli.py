import argparse
import functools
import json
import re
import sys
from typing import Iterable

import graphdbapi
import yaml
from graphdbapi.v1.graph.GsGraph import GsGraph
from prompt_toolkit import prompt
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter, FuzzyCompleter, merge_completers, PathCompleter, Completer
from tabulate import tabulate

from graphdbapi.db import GraphDb
from bolt.exceptions import DatabaseException
from bolt.message.exceptions import ClientException, GraphDbException

procedure_args_re = re.compile("([a-zA-Z]+) :: ")
space_re = re.compile("\\s+")

cypher_words = [
    "all", "and", "as", "asc", "ascending", "assert", "by", "call", "case", "commit", "constraint", "contains",
    "count", "create", "csv", "delete", "desc", "descending", "detach", "distinct", "drop", "else", "end", "ends",
    "exists", "explain", "false", "foreach", "from", "in", "index", "insert", "is", "join", "key", "limit", "load",
    "match", "merge", "node", "not", "null", "on", "optional", "or", "periodic", "profile", "remove", "return",
    "scan", "set", "skip", "start", "starts", "then", "true", "union", "unique", "unwind", "update", "using",
    "when", "where", "with", "xor", "yield",
]
cypher_functions = [
    # 断言函数
    "all", "any", "exists", "none", "single",
    # 标量函数
    "coalesce", "endNode", "head", "id", "last", "length", "properties", "randomUUID", "size", "startNode",
    "timestamp", "toBoolean", "toFloat", "toBigDecimal", "toInteger", "type",
    # 聚合函数
    "avg", "collect", "count", "max", "min", "percentileCont", "percentileDisc", "stDev", "stDevP", "sum",
    # 列表函数
    "keys", "labels", "nodes", "range", "reduce", "relationships", "reverse", "tail",
    # 数学函数
    "abs", "ceil", "follr", "rand", "round", "sign",
    # 数学函数-对数和幂
    "e", "exp", "log", "log10", "sqrt",
    # 数学函数-三角函数
    "acos", "asin", "atan", "atan2", "cos", "cot", "degrees", "haversin", "pi", "radians", "sin", "tan",
    # 字符串函数
    "left", "ltrim", "replace", "right", "rtrim", "split", "substring", "toLower", "toUpper", "trim",
    # 时间函数 - 时刻类型
    "date", "time", "datetime", "timezone", "localdatetime", "localtime",
    "statement", "transaction", "statement", "realtime",
    "millennium", "century", "decade", "year", "weekYear", "quarter", "month", "week", "day", "hour", "minute",
    "second", "millisecond", "microsecond",
    "truncate", "realtime",
    # 时间函数 - 时段类型
    "duration", "period",
    "between", "inMonths", "inDays", "inSeconds",
    # 空间函数
    "distance", "point",
]


class Env:
    def __init__(self):
        self.other_hint = set()

        args = parse_args()
        self.args = args
        self.driver: graphdbapi.Driver | None = None
        self.graph: GsGraph | None = None

        self.functions = []
        self.aggregation_functions = []
        self.procedures = []
        self.procedure_args = []
        self.completer: Completer | None = None

        self.cmd_cnt = 0
        self.cypher = ""

        self.sys_cmd = {}
        self._define_sys_cmd_handlers()

    def load_completer(self):
        if self.driver is not None and self.args.load_functions:
            self.functions = [f["name"] for f in self.driver.execute_cypher("call dbms.functions()")]
        else:
            self.functions = []

        if self.driver is not None and self.args.load_aggregation:
            self.aggregation_functions = [f["name"] for f in
                                          self.driver.execute_cypher("call dbms.aggregationFunctions()")]
        else:
            self.aggregation_functions = []

        if self.driver is not None and self.args.load_procedures:
            self.procedures = [f["name"] for f in self.driver.execute_cypher("call dbms.procedures()")]
            self.procedure_args = [
                arg
                for args in (procedure_args_re.findall(f["signature"])
                             for f in self.driver.execute_cypher("call dbms.procedures()"))
                for arg in args
            ]
        else:
            self.procedures = []
            self.procedure_args = []

        self.completer = FuzzyCompleter(
            merge_completers([
                WordCompleter(
                    list(set(
                        [w.lower() for w in cypher_words] +
                        [w.upper() for w in cypher_words] +
                        cypher_functions +
                        self.functions +
                        self.aggregation_functions +
                        self.procedures +
                        ["call " + p for p in self.procedures] +
                        ["CALL " + p for p in self.procedures] +
                        self.procedure_args +
                        [f":{k}" for k in self.sys_cmd.keys()] +
                        list(self.other_hint)
                    )),
                    ignore_case=True,
                    WORD=True,
                ),
                PathCompleter(),
            ])
        )

    def message(self):
        if self.cypher == "":
            return self._message()
        else:
            return ("." * (len(self._message()) - 2)) + "> "

    def _message(self):
        if self.graph is None:
            return f"[{self.cmd_cnt}] cypher> "
        else:
            return f"[{self.cmd_cnt}] {self.graph.name}> "

    def get_sys_cmd_handler(self, cmd):
        return self.sys_cmd.get(
            space_re.split(cmd)[0],
            lambda: print("Unknown command.")
        )

    def _sys_cmd_handler(self, cmd):
        def decorator(func):
            self.sys_cmd[cmd] = func
            return func

        return decorator

    def _define_sys_cmd_handlers(self):
        @self._sys_cmd_handler("exit")
        def exit_handler():
            sys.exit(0)

        @self._sys_cmd_handler("graph")
        def graph_handler():
            graph_name = self.cypher[7:].strip()
            if len(graph_name) == 0:
                print("graph name can not be empty.")
            else:
                self.graph = GraphDb.driver_by_name(self.driver, graph_name)

        self.other_hint.add(":show graphs")
        self.other_hint.add(":show edges")
        self.other_hint.add(":show vertexes")

        @self._sys_cmd_handler("show")
        def show_handler():
            if self.cypher.startswith(":show graphs"):
                print(tabulate([[g] for g in GraphDb.graphs(self.driver)], headers=["graph"], tablefmt="outline"))
            elif self.cypher.startswith(":show edges"):
                edges = self.graph.schema().get_edge_types()
                print(tabulate([[e] for e in edges], headers=["edge"], tablefmt="outline"))
            elif self.cypher.startswith(":show vertexes"):
                vertexes = self.graph.schema().get_vertex_types()
                print(tabulate([[v] for v in vertexes], headers=["vertex"], tablefmt="outline"))
            else:
                print("Unknown command.")

        @self._sys_cmd_handler("graphs")
        def graphs():
            print(tabulate([[g] for g in GraphDb.graphs(self.driver)], headers=["graph"], tablefmt="outline"))

        @self._sys_cmd_handler("graph_index")
        def graph_index():
            indexes = GraphDb.graphx_indexs(self.driver)
            print(indexes)

        @self._sys_cmd_handler("new_graph")
        def new_graph():
            graph_name = self.cypher[10:].strip()
            GraphDb.new_graph(self.driver, graph_name)
            self.graph = GraphDb.driver_by_name(self.driver, graph_name)

        @self._sys_cmd_handler("delete_graph")
        def delete_graph():
            graph_name = self.cypher[13:].strip()
            graph = GraphDb.driver_by_name(self.driver, graph_name)
            graph.delete_graph()
            if graph.name == self.graph.name:
                self.graph = None

        @self._sys_cmd_handler("metrics")
        def metrics():
            for m in GraphDb.metrics(self.driver):
                print(tabulate([
                    ["id", m.get_id()],
                    ["node_start_time", m.get_node_start_time()],
                    ["addresses", list(m.get_addresses())],
                    ["host_name", list(m.get_host_name())],
                    ["heap_init", m.get_heap_init()],
                    ["heap_used", m.get_heap_used()],
                    ["heap_committed", m.get_heap_committed()],
                    ["heap_max", m.get_heap_max()],
                    ["heap_total", m.get_heap_total()],
                    ["last_update_time", m.get_last_update_time()],
                    ["thread_cnt", m.get_thread_cnt()],
                    ["daemon_thread_cnt", m.get_daemon_thread_cnt()],
                    ["peak_thread_cnt", m.get_peak_thread_cnt()],
                    ["started_thread_cnt", m.get_started_thread_cnt()],
                    ["graph_metrics", m.get_graph_metrics()],
                ], tablefmt="outline"))

        @self._sys_cmd_handler("history")
        def history():
            fh = FileHistory(".history.txt")

            cnt = self.cypher[8:].strip()
            if len(cnt) == 0:
                cnt = 1000
            else:
                cnt = int(cnt)

            histories = []
            for h in fh.load_history_strings():
                if cnt <= 0:
                    break

                histories.append([h])

                cnt = cnt - 1

            histories.reverse()
            print(tabulate(histories, headers=["id", "history"], tablefmt="outline"))

        self.load_completer()


def map_results(max_value_length: int | None, results: Iterable[graphdbapi.Record]) -> tuple[list[str], list[any]]:
    keys = []
    values = []
    for r in results:
        if len(keys) == 0:
            keys = r.keys()

        if len(values) >= 20:
            yield keys, values
            values = []

        if max_value_length is not None and max_value_length <= 0:
            values.append(r.values())
        else:
            values.append([str(v)[:max_value_length] for v in r.values()])

    yield keys, values


def parse_args():
    parser = argparse.ArgumentParser(
        prog="galaxybase cli",
        description="galaxybase graph database cli client.",  # 描述
        epilog="Copyright(r), 2024"  # 说明信息
    )

    parser.add_argument(
        "-H", "--host", "--url",
        default=None,
        help="The url of the graph database.",
    )
    parser.add_argument(
        "-u", "--user",
        default=None,
        help="The user of the graph database.",
    )
    parser.add_argument(
        "-p", "--password",
        default=None,
        help="The password of the graph database.",
    )
    parser.add_argument(
        "-g", "--graph",
        default=None,
        help="The name of the graph.",
    )
    parser.add_argument(
        "-c", "--config",
        default=None,
        help="The config file.",
    )

    parser.add_argument(
        "--load_functions",
        default=True,
        help="Load graph functions for auto complete.",
    )
    parser.add_argument(
        "--load_aggregation",
        default=True,
        help="Load graph aggregation functions for auto complete.",
    )
    parser.add_argument(
        "--load_procedures",
        default=True,
        help="Load graph procedures for auto complete.",
    )

    parser.add_argument(
        "--mvl", "--max_value_length",
        default=None,
        help="Load graph procedures for auto complete.",
        type=int,
    )

    return parser.parse_args()


def connect(args):
    config_file = args.config
    if config_file is not None:
        with open(config_file, "r", encoding="UTF-8") as f:
            cfg = yaml.safe_load(f)
    else:
        cfg = None

    url = args.host
    if url is None and cfg is not None and "bolt" in cfg:
        url = cfg["bolt"].get("url", None)
    if url is None:
        url = prompt("url: ")

    user = args.user
    if user is None and cfg is not None and "bolt" in cfg:
        user = cfg["bolt"].get("user", None)
    if user is None:
        user = prompt("user: ")

    password = args.password
    if password is None and cfg is not None and "bolt" in cfg:
        password = cfg["bolt"].get("password", None)
    if password is None:
        password = prompt("password: ", is_password=True)

    graph_name = args.graph
    if graph_name is None and cfg is not None and "bolt" in cfg:
        graph_name = cfg["bolt"].get("graph", None)
    # if graph_name is None:
    #     graph_name = prompt("graph: ")

    driver = GraphDb.connect(url, user, password)
    if graph_name is not None:
        graph = GraphDb.driver_by_name(driver, graph_name)
    else:
        graph = None

    return driver, graph


def main():
    env = Env()
    env.driver, env.graph = connect(env.args)
    env.load_completer()

    while True:
        message = env.message()

        try:
            line = prompt(
                message,
                history=FileHistory(".history.txt"),
                auto_suggest=AutoSuggestFromHistory(),
                completer=env.completer,
                reserve_space_for_menu=6,
            )
        except KeyboardInterrupt:
            env.cypher = ""
            continue
        except (KeyboardInterrupt, EOFError):
            break

        if line.endswith("\\"):
            env.cypher = env.cypher + line[:-1] + "\n"
        else:
            env.cypher = env.cypher + line
            if len(env.cypher) == 0:
                continue
            try:
                if env.cypher.startswith(":"):
                    env.get_sys_cmd_handler(env.cypher[1:])()
                    continue

                if env.graph is None:
                    results = env.driver.execute_cypher(env.cypher, None)
                else:
                    results = env.graph.execute_cypher(env.cypher, None)
                for (keys, values) in map_results(
                        env.args.mvl,
                        results,
                ):
                    print(tabulate(values, headers=keys, tablefmt="outline"))

                env.cmd_cnt = env.cmd_cnt + 1
            except (DatabaseException, ClientException, GraphDbException) as e:
                print(e)
                continue
            finally:
                env.cypher = ""


if __name__ == "__main__":
    main()
