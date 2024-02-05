import argparse
import sys
from typing import Iterable

import graphdbapi
import yaml
from prompt_toolkit import prompt
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter, FuzzyCompleter, merge_completers, PathCompleter
from tabulate import tabulate

from graphdbapi.db import GraphDb
from bolt.exceptions import DatabaseException
from bolt.message.exceptions import ClientException, GraphDbException


def map_results(results: Iterable[graphdbapi.Record]) -> tuple[list[str], list[any]]:
    keys = []
    values = []
    for r in results:
        if len(keys) == 0:
            keys = r.keys()
        values.append(r.values())

    return keys, values


def connect():
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

    args = parser.parse_args()

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
    if graph_name is None:
        graph_name = prompt("graph: ")

    driver = GraphDb.connect(url, user, password)
    graph = GraphDb.driver_by_name(driver, graph_name)

    return driver, graph


def main():
    driver, graph = connect()

    cypher_words = [
        "all", "and", "as", "asc", "ascending", "assert", "by", "call", "case", "commit", "constraint", "contains",
        "count", "create", "csv", "delete", "desc", "descending", "detach", "distinct", "drop", "else", "end", "ends",
        "exists", "explain", "false", "foreach", "from", "in", "index", "insert", "is", "join", "key", "limit", "load",
        "match", "merge", "node", "not", "null", "on", "optional", "or", "periodic", "profile", "remove", "return",
        "scan", "set", "skip", "start", "starts", "then", "true", "union", "unique", "unwind", "update", "using",
        "when", "where", "with", "xor", "yield",
    ]
    functions = [
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
    apoc_functions = [
        # 数学函数
        "apoc.math.round", "apoc.math.maxLong", "apoc.math.minLong", "apoc.math.maxDouble", "apoc.math.minDouble",
        "apoc.math.maxInt", "apoc.math.minInt", "apoc.math.maxByte", "apoc.math.minByte", "apoc.math.random",
        "apoc.math.sqrt", "apoc.math.acos", "apoc.math.asin", "apoc.math.atan", "apoc.math.atan2", "apoc.math.cbrt",
        "apoc.math.ceil", "apoc.math.cos", "apoc.math.copySign", "apoc.math.cosh", "apoc.math.exp", "apoc.math.expm1",
        "apoc.math.floor", "apoc.math.hypot", "apoc.math.IEEEremainder", "apoc.math.log", "apoc.math.log1p",
        "apoc.math.addExact", "apoc.math.decrementExact", "apoc.math.floorDiv", "apoc.math.floorMod",
        "apoc.math.getExponent", "apoc.math.incrementExact", "apoc.math.max", "apoc.math.min", "apoc.math.log10",
        "apoc.math.nextAfter", "apoc.math.nextDown", "apoc.math.nextUp", "apoc.math.pow", "apoc.math.rint",
        "apoc.math.scalb", "apoc.math.signum", "apoc.math.sin", "apoc.math.sinh", "apoc.math.tan",
        "apoc.math.multiplyExact", "apoc.math.negateExact", "apoc.math.subtractExact", "apoc.math.toIntExact",
        "apoc.math.tanh", "apoc.math.toDegrees", "apoc.math.toRadians", "apoc.math.ulp",

        # 位操作
        "apoc.bitwise.op",

        # 地址解析
        "apoc.data.email", "apoc.data.url",

        # 集合操作
        "apoc.coll.zip", "apoc.coll.pairs", "apoc.coll.pairsMin", "apoc.coll.sum", "apoc.coll.avg", "apoc.coll.min",
        "apoc.coll.max", "apoc.coll.contains", "apoc.coll.set", "apoc.coll.insert", "apoc.coll.insertAll",
        "apoc.coll.remove", "apoc.coll.indexOf", "apoc.coll.containsAll", "apoc.coll.containsSorted",
        "apoc.coll.containsAllSorted", "apoc.coll.isEqualCollection", "apoc.coll.toSet", "apoc.coll.sumLongs",
        "apoc.coll.sort", "apoc.coll.sortNodes", "apoc.coll.sortMaps", "apoc.coll.union", "apoc.coll.subtract",
        "apoc.coll.removeAll", "apoc.coll.intersection", "apoc.coll.disjunction", "apoc.coll.unionAll",
        "apoc.coll.shuffle", "apoc.coll.randomItem", "apoc.coll.randomItems", "apoc.coll.containsDuplicates",
        "apoc.coll.duplicates", "apoc.coll.duplicatesWithCount", "apoc.coll.frequencies", "apoc.coll.frequenciesAsMap",
        "apoc.coll.occurrences", "apoc.coll.flatten", "apoc.coll.reverse", "apoc.coll.different",
        "apoc.coll.dropDuplicateNeighbors", "apoc.coll.fill",

        # 类型转换
        "apoc.convert.toMap", "apoc.convert.toString", "apoc.convert.toList", "apoc.convert.toBoolean",
        "apoc.convert.toNode", "apoc.convert.toRelationship", "apoc.convert.toInteger", "apoc.convert.toSet",
        "apoc.convert.toIntList", "apoc.convert.toStringList", "apoc.convert.toBooleanList", "apoc.convert.toNodeList",
        "apoc.convert.toRelationshipList",

        # JSON转换
        "apoc.json.path", "apoc.convert.toJson", "apoc.convert.fromJsonMap", "apoc.convert.fromJsonList",
        "apoc.convert.toSortedJsonMap",

        # 时间转换
        "apoc.date.toYears", "apoc.date.fields", "apoc.date.field", "apoc.date.currentTimestamp", "apoc.date.format",
        "apoc.date.toISO8601", "apoc.date.fromISO8601", "apoc.date.parse", "apoc.date.parseAsZonedDateTime",
        "apoc.date.systemTimezone", "apoc.date.convert", "apoc.date.convertFormat", "apoc.date.add",

        # Map操作
        "apoc.map.groupBy", "apoc.map.groupByMulti", "apoc.map.fromPairs", "apoc.map.fromLists", "apoc.map.values",
        "apoc.map.fromValues", "apoc.map.merge", "apoc.map.mergeList", "apoc.map.get", "apoc.map.mget",
        "apoc.map.submap", "apoc.map.setKey", "apoc.map.setEntry", "apoc.map.setPairs", "apoc.map.setLists",
        "apoc.map.setValues", "apoc.map.removeKey", "apoc.map.removeKeys", "apoc.map.clean", "apoc.map.updateTree",
        "apoc.map.flatten", "apoc.map.sortedProperties",

        # 获取类型
        "apoc.meta.type", "apoc.meta.typeName", "apoc.meta.types", "apoc.meta.isType", "apoc.meta.cypher.type",
        "apoc.meta.cypher.types",

        # 数字转换
        "apoc.number.format", "apoc.number.parseInt", "apoc.number.parseFloat", "apoc.number.romanToArabic",
        "apoc.number.arabicToRoman",

        # 大数操作
        "apoc.number.exact.add", "apoc.number.exact.sub", "apoc.number.exact.mul", "apoc.number.exact.div",
        "apoc.number.exact.toInteger", "apoc.number.exact.toFloat", "apoc.number.exact.toExact",

        # 分数计算
        "apoc.scoring.existence", "apoc.scoring.pareto",

        # 临时转换
        "apoc.temporal.format", "apoc.temporal.formatDuration",

        # 语音匹配算法
        "apoc.text.phonetic", "apoc.text.doubleMetaphone",

        # 字符串操作
        "apoc.text.indexOf", "apoc.text.indexesOf", "apoc.text.replace", "apoc.text.byteCount", "apoc.text.bytes",
        "apoc.text.regreplace", "apoc.text.split", "apoc.text.regexGroups", "apoc.text.join", "apoc.text.clean",
        "apoc.text.compareCleaned", "apoc.text.distance", "apoc.text.levenshteinSimilarity",
        "apoc.text.hammingDistance", "apoc.text.jaroWinklerDistance", "apoc.text.sorensenDiceSimilarity",
        "apoc.text.fuzzyMatch", "apoc.text.urlencode", "apoc.text.urldecode", "apoc.text.lpad", "apoc.text.rpad",
        "apoc.text.format", "apoc.text.slug", "apoc.text.random", "apoc.text.capitalize", "apoc.text.capitalizeAll",
        "apoc.text.decapitalize", "apoc.text.decapitalizeAll", "apoc.text.swapCase", "apoc.text.camelCase",
        "apoc.text.upperCamelCase", "apoc.text.snakeCase", "apoc.text.toUpperCase", "apoc.text.base64Encode",
        "apoc.text.base64Decode", "apoc.text.base64UrlEncode", "apoc.text.base64UrlDecode", "apoc.text.charAt",
        "apoc.text.code", "apoc.text.hexValue", "apoc.text.hexCharAt", "apoc.text.toCypher", "apoc.text.repeat",

        # 加密
        "apoc.hashing.fingerprint",

        # 创建
        "apoc.create.uuid", "apoc.create.vNode", "apoc.create.virtual.fromNode",

        # 比较
        "apoc.diff.nodes",

        # 路径
        "apoc.path.slice", "apoc.path.elements",

        # 点操作
        "apoc.node.relationship", "apoc.nodes.connected", "apoc.node.labels", "apoc.node.id", "apoc.rel.id",
        "apoc.rel.type", "apoc.any.properties", "apoc.any.property", "apoc.node.degree", "apoc.node.degree.in",
        "apoc.node.degree.out",

        # 聚合数列
        "apoc.agg.nth", "apoc.agg.first", "apoc.agg.last", "apoc.agg.slice",

        # 中位数
        "apoc.agg.median",

        # 百分数
        "apoc.agg.percentiles",

        # 乘积
        "apoc.agg.product",

        # 统计数据
        "apoc.agg.statistics",
    ]

    open_cypher_completer = FuzzyCompleter(
        merge_completers([
            WordCompleter(
                list(set([w.lower() for w in cypher_words] + [w.upper() for w in
                                                              cypher_words] + functions + apoc_functions)),
                ignore_case=True,
                WORD=True,
            ),
            PathCompleter(),
        ])
    )

    cmd_cnt = 0

    cypher = ""
    while True:
        if cypher == "":
            message = f"[{cmd_cnt}] cypher> "
        else:

            message = ("." * (len(str(cmd_cnt)) + 9)) + "> "

        try:
            line = prompt(
                message,
                history=FileHistory(".history.txt"),
                auto_suggest=AutoSuggestFromHistory(),
                completer=open_cypher_completer,
                reserve_space_for_menu=4,
            )
        except KeyboardInterrupt:
            cypher = ""
            continue
        except (KeyboardInterrupt, EOFError):
            break

        if line.endswith("\\"):
            cypher = cypher + line[:-1] + "\n"
        else:
            cypher = cypher + line
            if len(cypher) == 0:
                continue
            try:
                (keys, values) = map_results(graph.execute_cypher(cypher, None))
                print(tabulate(values, headers=keys, tablefmt="grid"))

                cmd_cnt = cmd_cnt + 1
            except (DatabaseException, ClientException, GraphDbException) as e:
                print(e)
                continue
            finally:
                cypher = ""


if __name__ == "__main__":
    main()
