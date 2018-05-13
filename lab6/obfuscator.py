#!/usr/bin/python2

import ast
import astor
import copy
from pretty import dump


class ConstantPropagator(ast.NodeTransformer):
    def __init__(self):
        self.constants = {}

    def visit_Module(self, node):
        # Get all assignments on module level
        assignments = [x for x in node.body if isinstance(x, ast.Assign)]

        for _a in assignments:
            # Check that a number or string is assigned
            if isinstance(_a.value, (ast.Num, ast.Str)):
                for _t in _a.targets:
                    # Leave only variables in the upper register by filtering
                    # and add themm in constnts dictionary
                    if isinstance(_t, ast.Name) and _t.id.isupper():
                        self.constants[_t.id] = _a.value

        self.generic_visit(node)

    def visit_Name(self, node):
        # Replace constants only in load case
        if isinstance(node.ctx, ast.Load):
            return self.constants.get(node.id, node)

        return node


class FunctionInliner(ast.NodeTransformer):
    class ArgSubstitutor(ast.NodeTransformer):
        def __init__(self):
            self._sub = {}

        def substitute(self, sub):
            self._sub = sub

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load):
                return self._sub.get(node.id, node)
            return node

    def __init__(self):
        self.substitutor = FunctionInliner.ArgSubstitutor()
        self.func = {}

    def generate_inline_func(self, name, args):   # Add keywords stargs kwargs
        _args = {}
        for pos_arg, val in zip(self.func[name].args.args, args):
            _args[pos_arg.id] = val

        self.substitutor.substitute(_args)
        body = copy.deepcopy(self.func[name].body)
        for node in body:
            if isinstance(node, ast.Return):
                body[-1] = ast.Assign(targets=[ast.Name(id='result',
                                               ctx=ast.Store)],
                                      value=node.value)
            else:
                self.substitutor.visit(node)

        return body

    def visit_Module(self, node):
        for _node in node.body:
            if isinstance(_node, ast.FunctionDef):
                self.func[_node.name] = _node

        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if node.name in self.func and node == self.func[node.name]:
            return node         # None

        return node

    def visit_Expr(self, node):
        if not isinstance(node.value, ast.Call):
            return node
        func = node.value.func
        if isinstance(func, ast.Name) and func.id in self.func:
            return self.generate_inline_func(func.id, node.value.args)

        return node

    def visit_Assign(self, node):
        targets = node.targets
        if (isinstance(node.value, ast.Call) and
           isinstance(node.value.func, ast.Name) and
           node.value.func.id in self.func):
                inline_func = self.generate_inline_func(
                                node.value.func.id, node.value.args)
                inline_func.append(
                    ast.Assign(targets=targets, value=ast.Name(
                                                    id='result',
                                                    ctx=ast.Load)))
                print(inline_func)
                return inline_func
        else:
            return node


class ForMultiplier(ast.NodeTransformer):
    def visit_For(self, node):
        self.generic_visit(node)
        return [ast.For(node.target, node.iter, [_node], node.orelse)
                for _node in node.body]


class Obfuscator:
    def __init__(self, file, obfusctors=None):
        if obfusctors is None:
            self.obfusctors = [ConstantPropagator]
        else:
            self.obfusctors = obfusctors

        with open(file) as fp:
            self.content = fp.read()

        self.tree = ast.parse(self.content)

    def obfusacte(self):
        for obf in self.obfusctors:
            obf().visit(self.tree)
            ast.fix_missing_locations(self.tree)

    def to_code(self):
        return astor.to_source(self.tree)


def main():
    obf = Obfuscator(
        "/home/katya/bsuir/security/lab1/cezar.py",
        obfusctors=[ConstantPropagator, FunctionInliner, ForMultiplier])
    obf.obfusacte()
    with open('obf.py', 'w') as fp:
        fp.write(obf.to_code())


if __name__ == '__main__':
    main()
