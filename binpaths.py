#!/usr/bin/python3
import argparse
import bisect
import enum
import glob
import os
import re
import sys

from dataclasses import dataclass
from typing import Union, List

import angr
import networkx as nx
import cxxfilt

class NodeNameMatcher:
    def __init__(self, r):
        self.regex = re.compile(r)

    def is_match(self, node):
        return (node.name is not None) and (self.regex.fullmatch(node.name) is not None)

    def __str__(self):
        return self.regex.pattern


class NodeAddrMatcher:
    def __init__(self, addr):
        self.addr = addr

    def is_match(self, node):
        return self.addr == node.addr

    def __str__(self):
        return hex(self.addr)


def get_matcher(node_desc: str):
    if node_desc.startswith('0x'):
        return NodeAddrMatcher(int(node_desc, 16))
    else:
        return NodeNameMatcher(node_desc)


class DfsTraverseNode:
    def __init__(self, graph, start_node):
        self._graph = graph
        self._stack_path = [start_node]
        self._stack_inds = [0]
        self._visited = set([start_node])
        self.branch_done = False

    def _pop(self):
        if len(self._stack_path) > 1:
            top = self._stack_path.pop()
            self._visited.remove(top)
            self._stack_inds.pop()
            self._stack_inds[-1] += 1
            return True
        else:
            return False

    def _push(self, node):
        self._stack_path.append(node)
        self._stack_inds.append(0)
        self._visited.add(node)

    def _succesors(self, node):
        return node.successors

    def _next(self):
        top = self._stack_path[-1]
        ind = self._stack_inds[-1]
        if self.branch_done or self._is_end_of_branch():
            self.branch_done = False
            return self._pop()
        else:
            self.branch_done = False
            self._push(self._succesors(top)[ind])
            return True

    def _is_end_of_branch(self):
        top = self._stack_path[-1]
        ind = self._stack_inds[-1]
        succ = self._succesors(top)
        return len(succ) <= ind or succ[ind] in self._visited

    def is_dead_end(self):
        return len(self._succesors(self._stack_path[-1])) == 0

    def items(self):
        has_work = self._next()
        while has_work:
            yield self._stack_path
            has_work = self._next()

    def __str__(self):
        return '\n'.join(f'{a.name or str(a.addr)}, {b} / {len(self._succesors(a))}'
                         for a, b in zip(self._stack_path, self._stack_inds))


class DfsTraverseNodeRev(DfsTraverseNode):
    def _succesors(self, node):
        return node.predecessors

class DfsTraverseGraph(DfsTraverseNode):
    def _succesors(self, node):
        return list(self._graph.successors(node))

class DfsTraverseGraphRev(DfsTraverseNode):
    def _succesors(self, node):
        return list(self._graph.predecessors(node))

def get_traverse(graph, start_node, reverse, edited):
    if reverse:
        if edited:
            return DfsTraverseGraphRev(graph, start_node)
        else:
            return DfsTraverseNodeRev(graph, start_node)
    else:
        if edited:
            return DfsTraverseGraph(graph, start_node)
        else:
            return DfsTraverseNode(graph, start_node)


class AddrToLine:
    def __init__(self, loader) -> None:
        self.objs = [(list(o.addr_to_line.keys()), o) for o in loader.all_elf_objects]

    def addr_to_line(self, addr):
        for keys, o in self.objs:
            ind = bisect.bisect(keys, addr)
            if 0 <= ind < len(keys):
                return o.addr_to_line.get(keys[ind]) or (None, None)
        return (None, None)


class SrcFinder:
    def __init__(self, binfile, src_dirs, src_glob):
        self.bindir = os.path.dirname(binfile)
        self.src_dirs = src_dirs
        self.src_files = { src_dir: glob.glob('**/' + src_glob, root_dir=src_dir, recursive=True)
                           for src_dir in src_dirs }

    def simplify(self, fname):
        if fname.startswith('/usr'):
            return fname
        else:
            return os.path.basename(fname)

    def find(self, fname):
        if os.path.isfile(fname):
            return fname

        rel_fname = os.path.relpath(fname, self.bindir)
        for src_dir, src_files in self.src_files.items():
            r = os.path.join(src_dir, rel_fname)
            if r in src_files and os.path.isfile(r):
                return r
            r = os.path.basename(r)
            for i in src_files:
                src = os.path.join(src_dir, i)
                if r == os.path.basename(i) and os.path.isfile(src):
                    return src

        return None


class FileLinesCache:
    def __init__(self):
        self.fname = None
        self.lines = None

    def get(self, fname, start_line, end_line):
        if fname != self.fname:
            with open(fname) as f:
                self.lines = tuple(f.readlines())
                self.fname = fname
        return self.lines[start_line:end_line]


def get_node_name(node, strip_addr, demangle, cut_args):
    if node.name:
        name = node.name
        addr = None
        try:
            ind = node.name.index('+')
            name = node.name[:ind]
            addr = node.name[ind:]
        except ValueError:
            pass

        if demangle:
            try:
                name = cxxfilt.demangle(name, external_only = False)
            except cxxfilt.InvalidName:
                pass

            if cut_args:
                try:
                    angle_brk_open = name.index('<')
                    angle_brk_close = name.rindex('>')
                    if angle_brk_open < angle_brk_close:
                        name = name[:angle_brk_open] + name[angle_brk_close + 1:]
                except ValueError:
                    pass

                try:
                    name = name[:name.index('(')]
                except ValueError:
                    pass

        if addr and not strip_addr:
            name += addr
        return name.strip()
    else:
        return hex(node.addr)


def write_graph(graph, fname, strip_addr, demangle, cut_args):
    stgraph = nx.classes.digraph.DiGraph()
    for a,b in graph.edges():
        an = get_node_name(a, strip_addr, demangle, cut_args)
        bn = get_node_name(b, strip_addr, demangle, cut_args)
        if an != bn:
            stgraph.add_edge(an, bn)

    nx.write_graphml(stgraph, fname)


@dataclass
class PathDesc:
    src_file: Union[int, None]
    src_start_line: Union[str, None]
    src_end_line: Union[str, None]
    ctx_start_line: Union[str, None]
    ctx_end_line: Union[str, None]
    src_context: Union[str, None]
    name: str
    addr: int


def path_to_desc(
    dbg_info:AddrToLine,
    sources:SrcFinder,
    fcache: FileLinesCache,
    ctx_lines:int,
    demangle: bool,
    cut_args: bool,
    path:List[angr.knowledge_plugins.cfg.cfg_node.CFGENode]
):
    res = []
    for step in path:
        # try to map to source
        fname, start_line = dbg_info.addr_to_line(step.addr)
        _, end_line = dbg_info.addr_to_line(step.addr + (step.size or 1))
        if end_line is None:
            end_line = start_line

        name = get_node_name(step, False, demangle, cut_args)

        if (fname is None) or (sources is None):
            res.append(PathDesc(fname, start_line, end_line, None, None, None, name, step.addr))
        else:
            src_fname = sources.find(fname)
            if src_fname is None:
                src_fname = sources.simplify(fname)
                ctx_start_line, ctx_end_line, ctx = None, None, None
            else:
                # try to merge with previous source sample
                if len(res) > 0:
                    last = res[-1]
                    if last.src_file == src_fname:
                        if last.src_start_line <= start_line <= last.src_end_line and \
                           last.src_start_line <= end_line <= last.src_end_line:
                            continue
                        should_pop = False
                        if start_line <= last.src_end_line <= end_line:
                            start_line = last.src_start_line
                            should_pop = True
                        if start_line <= last.src_start_line <= end_line:
                            end_line = last.src_end_line
                            should_pop = True
                        if should_pop:
                            res.pop()

                # get source context
                ctx_start_line = max(0, start_line - ctx_lines - 1)
                ctx_end_line = end_line + ctx_lines
                rawctx = fcache.get(src_fname, ctx_start_line, ctx_end_line)
                ctx = ''.join(
                            f'{src_fname}:{i} ' + ('> ' if start_line <= i <= end_line else '  ') + v
                            for i, v in
                                zip(range(ctx_start_line + 1, ctx_end_line + 1), rawctx))
            res.append(PathDesc(src_fname, start_line, end_line, ctx_start_line, ctx_end_line, ctx, name, step.addr))
    return res


class PathMatch(enum.Enum):
    NONE = 0
    PARTIAL = 1
    FULL = 2


def path_matches(matchers, path, allow_partial):
    if matchers and path:
        if not matchers[0].is_match(path[0]):
            return PathMatch.NONE

        if matchers[-1].is_match(path[-1]):
            r = PathMatch.FULL
        elif allow_partial:
            r = PathMatch.PARTIAL
        else:
            return PathMatch.NONE

        m_ind = 1
        m_max = len(matchers) - 1
        if m_max - m_ind > 0:
            for p in path[1:-1]:
                if matchers[m_ind].is_match(p):
                    m_ind += 1
                    if m_ind >= m_max:
                        return r
            r = PathMatch.NONE

        return r
    else:
        return PathMatch.FULL


def location_arg_to_addr(loader, arg):
    if arg.startswith('0x'):
        addr = int(args.entry, 16)
        return next(o.offset_to_addr(addr) for o in loader.all_objects if o.contains_addr(addr))
    else:
        return loader.find_symbol(arg).rebased_addr


def get_paths_graph(paths, strip_addr, demangle, cut_args):
    g = nx.classes.digraph.DiGraph()
    for path_id, path in enumerate(paths):
        start = get_node_name(path[0], strip_addr, demangle, cut_args)
        end = get_node_name(path[-1], strip_addr, demangle, cut_args)
        if len(path) == 2:
            if start != end:
                g.add_edge(start, end)
        else:
            suffix = f'-{path_id}'
            mid = [get_node_name(i, strip_addr, demangle, cut_args) + suffix for i in path[1:-1]]
            g.add_edge(start, mid[0])
            g.add_edge(mid[-1], end)
            for a, b in nx.utils.pairwise(mid):
                if a != b:
                    g.add_edge(a, b)
    return g


def write_paths_graph(paths, fname, strip_addr, demangle, cut_args):
    g = get_paths_graph(paths, strip_addr, demangle, cut_args)
    nx.write_graphml(g, fname)


def parse_args():
    ap = argparse.ArgumentParser(
        'binpaths.py', description='find execution paths leading to a certain point and print or export them to GraphML'
    )

    ap.add_argument('--entry',
                    required=True,
                    help='name of entry point symbol or entry point address in hex, not neccessarily real entry point')
    ap.add_argument('--step',
                    action='append',
                    required=True,
                    help='regex for node name that expresses a mandatory step in execution path.'
                         'Must pass at least two --step args to describe source and destination of the path. '
                         'Steps in the middle (if any) will be required to be somewhere in the path in the same order')
    ap.add_argument('--avoid',
                    action='append',
                    help='symbol or address in hex to avoid in execution. Use several --avoid args if needed')
    ap.add_argument('--avoid-re',
                    action='append',
                    help='regex for node name to avoid in results. Use several --avoid-re args if needed')
    ap.add_argument('--src-dir',
                    action='append',
                    help='sources directory, can be specified more than once. Use several --src-dir args if needed')
    ap.add_argument('--src-glob',
                    default='*.c*',
                    help='glob to limit source files from src-dir e.g. *.c, *.cpp')
    ap.add_argument('--ctx-lines',
                    type=int,
                    default=0,
                    help='how many lines of surrounding context to show with sources')
    ap.add_argument('--demangle',
                    action='store_true',
                    help='try to revert C++ name mangling for symbols')
    ap.add_argument('--demangle-cut-args',
                    action='store_true',
                    help='cut arguments from demangled C++ symbols, implies --demangle')
    ap.add_argument('--cfg-out-full',
                    help='file to store full control flow graph')
    ap.add_argument('--cfg-out-full-fun-only',
                    action='store_true',
                    help='when saving control flow graph, treat all offsets in a function as the same node')

    ap.add_argument('--cfg-out',
                    help='file to store control flow graph part that passes through --step args')
    ap.add_argument('--cfg-out-fun-only',
                    action='store_true',
                    help='when saving filtered control flow graph, treat all offsets in a function as the same node')

    ap.add_argument('--reverse-search',
                    action='store_true',
                    help='walk CFG from last step to first step. Depending on graph shape can save a lot of time')
    ap.add_argument('--keep-dead-ends',
                    action='store_true',
                    help='keep dead end paths in CFG. Useful to see sources or destinations (with --reverse-search) you didn\'t think of')
    ap.add_argument('--paths-out',
                    help='file to store paths graph where same nodes in different paths are treated as different nodes')
    ap.add_argument('--paths-out-fun-only',
                    action='store_true',
                    help='when saving paths graph, treat all offsets in a function as the same node')
    ap.add_argument('--connect-same-addr',
                    action='store_true',
                    help='connect same address nodes in CFG even if they represent different call contexts. '
                         'Mostly to work around angr not seeing a path that is definitely there')
    ap.add_argument('--no-src',
                    action='store_true',
                    help='Do not try to match with sources or show debug info')

    ap.add_argument('binfile', help='binary file to analyze')

    args = ap.parse_args()

    if len(args.step) < 2:
        print('Less than 2 steps given')
        exit(1)

    if args.demangle_cut_args:
        args.demangle = True

    return args


args = parse_args()
proj = angr.Project(args.binfile, load_options={'auto_load_libs': False, 'load_debug_info': True})

proj.entry = location_arg_to_addr(proj.loader, args.entry)

if proj.loader.main_object.image_base_delta:
    print('Binary relocated to:', hex(proj.loader.main_object.image_base_delta))

cfg = proj.analyses.CFGEmulated(
    resolve_indirect_jumps = True,
    normalize=True,
    avoid_runs=[location_arg_to_addr(proj.loader, i) for i in args.avoid] if args.avoid else None
)

print(f'Control flow graph has {len(cfg.graph.nodes())} nodes, {len(cfg.graph.edges())} edges')

if args.connect_same_addr:
    print('Connecting nodes for the same addresses')
    for n in cfg.nodes():
        for i in cfg.get_all_nodes(n):
            if i != n:
                cfg.add_edge(n, i)

    print(f'Control flow graph now has {len(cfg.graph.nodes())} nodes, {len(cfg.graph.edges())} edges')


if args.cfg_out_full:
    write_graph(cfg.graph, args.cfg_out_full, args.cfg_out_full_fun_only, args.demangle, args.demangle_cut_args)

avoiders = [get_matcher(i) for i in args.avoid_re] if args.avoid_re else []
matchers = [get_matcher(i) for i in args.step]
dst = [i for i in cfg.nodes() if matchers[-1].is_match(i)]
src = [i for i in cfg.nodes() if matchers[0].is_match(i)]

if args.reverse_search:
    matchers.reverse()
    src, dst = dst, src

bad_matchers = [m for m in matchers if (not any(filter(m.is_match, cfg.nodes())))]
if bad_matchers:
    for m in bad_matchers:
        print(f'ERROR: step "{m}" doesn\'t match any node in control flow graph', file=sys.stderr)
    exit(1)


dbg_info = AddrToLine(proj.loader)
sources = SrcFinder(args.binfile, args.src_dir, args.src_glob) if args.src_dir else None
file_cache = FileLinesCache()

if args.cfg_out:
    cfg_filtered = nx.classes.digraph.DiGraph()

if args.paths_out:
    paths = []

for src_node in src:
    t = get_traverse(cfg.graph, src_node, args.reverse_search, args.connect_same_addr)
    for path in t.items():
        if any(i.is_match(path[-1]) for i in avoiders):
            t.branch_done = True
        else:
            match = path_matches(matchers, path, args.keep_dead_ends and t.is_dead_end())
            if match == PathMatch.FULL or (args.keep_dead_ends and match == PathMatch.PARTIAL):
                t.branch_done = True

                if args.reverse_search:
                    path = list(reversed(path))

                if args.cfg_out:
                    for a, b in nx.utils.pairwise(path):
                        cfg_filtered.add_edge(a, b)

                if args.paths_out:
                    paths.append(path)

                desc = path_to_desc(dbg_info, sources, file_cache, args.ctx_lines, args.demangle, args.demangle_cut_args, path)

                print('-----------------------------------------------------------------------')
                for step in desc:
                    if args.no_src:
                        print(f'-> {step.name}')
                    else:
                        if step.src_file is None:
                            print(f'-> {step.name}')
                        else:
                            print(f'-> {step.src_file}:{step.src_start_line}-{step.src_end_line} {step.name}')
                        if step.src_context:
                            print(step.src_context)

if args.paths_out:
    write_paths_graph(paths, args.paths_out, args.paths_out_fun_only, args.demangle, args.demangle_cut_args)

if args.cfg_out:
    write_graph(cfg_filtered, args.cfg_out, args.cfg_out_fun_only, args.demangle, args.demangle_cut_args)
