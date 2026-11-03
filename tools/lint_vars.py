#!/usr/bin/env python3
"""Find Tcl procs that use a namespace-level variable without `variable` / `upvar` / `global`.

Heuristic lint: for each namespace, collect names declared by `variable` at
namespace scope, then check every `proc ::ns::name` body that references
`name(` or `$name` without declaring it. Catches the classic "can't read X: no
such variable" bug at review time instead of at 3am.
"""
import re, sys, glob

def procs(text):
    # yield (fullname, body) using brace matching
    for m in re.finditer(r'^proc\s+(\S+)\s+\{([^{}]*)\}\s*\{', text, re.M):
        start = m.end(); depth = 1; i = start
        while i < len(text) and depth:
            c = text[i]
            if c == '\\': i += 2; continue
            if c == '{': depth += 1
            elif c == '}': depth -= 1
            i += 1
        yield m.group(1), m.group(2), text[start:i-1]

bad = 0
for f in sorted(glob.glob(sys.argv[1] if len(sys.argv) > 1 else 'tclguard.vfs/lib/tclguard/*.tcl')):
    text = open(f).read()
    nsvars = {}
    for m in re.finditer(r'namespace eval (\S+) \{(.*?)^\}', text, re.M | re.S):
        ns, body = m.group(1), m.group(2)
        names = set()
        for vm in re.finditer(r'^\s*variable\s+(.+)$', body, re.M):
            for tok in re.split(r'[\s;]+', vm.group(1)):
                if re.fullmatch(r'[A-Za-z_]\w*', tok): names.add(tok)
        for vm in re.finditer(r'foreach v \{([^}]*)\}\s*\{\s*array set', body):
            names |= set(vm.group(1).split())
        nsvars[ns] = names
    for full, args, body in procs(text):
        ns = full.rsplit('::', 1)[0]
        names = nsvars.get(ns, set())
        argnames = set(re.findall(r'[A-Za-z_]\w*', args))
        declared = set()
        for dm in re.finditer(r'\b(?:variable|global)\s+([^\n;]+)', body):
            declared |= set(re.findall(r'[A-Za-z_]\w*', dm.group(1)))
        for dm in re.finditer(r'upvar[^\n;]*\s(\w+)\s*(?:;|\n|$)', body):
            declared.add(dm.group(1))
        # locals assigned via set/foreach/lassign are fine even if same as a ns var
        assigned = set(re.findall(r'\b(?:set|lassign|foreach|incr|append|lappend|dict set|array set)\s+\{?([A-Za-z_]\w*)\b(?!\()', body))
        for v in names - declared - argnames:
            if re.search(r'(?<![\w:$])\$%s\(|(?<![\w:])%s\(\$|\$%s\b(?!\()|(?<![\w:])(?:set|incr|lappend|append|unset)\s+(?:-nocomplain\s+)?%s\b' % ((v,) * 4), body):
                # allow plain local scalars that merely share a name
                arr_use = re.search(r'\$%s\(|(?<![\w:])%s\(' % (v, v), body)
                if arr_use:
                    print(f'{f}: {full}: uses namespace var "{v}" without declaring it'); bad += 1
sys.exit(1 if bad else 0)
