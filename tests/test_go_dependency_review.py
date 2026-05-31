import tempfile
import unittest
from pathlib import Path

from app.dependency_review import build_dependency_context, dependency_type
from app.sbom import read_go_mod, read_go_sum


class GoDependencyReviewTests(unittest.TestCase):
    def test_go_mod_go_sum_inventory_and_reachability(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / 'go.mod').write_text(
                'module example.com/app\n\n'
                'go 1.26\n\n'
                'require (\n'
                '\tgithub.com/example/direct v1.2.3\n'
                '\tgithub.com/example/indirect v0.4.0 // indirect\n'
                ')\n',
                encoding='utf-8',
            )
            (target / 'go.sum').write_text(
                'github.com/example/direct v1.2.3 h1:abc\n'
                'github.com/example/direct v1.2.3/go.mod h1:def\n'
                'github.com/example/transitive v0.9.0 h1:ghi\n',
                encoding='utf-8',
            )
            source = target / 'main.go'
            source.write_text(
                'package main\n\nimport "github.com/example/direct/subpkg"\n\nfunc main() {}\n',
                encoding='utf-8',
            )

            go_mod_components = read_go_mod(target)
            go_sum_components = read_go_sum(target)
            context = build_dependency_context(target, [])

        self.assertEqual(len(go_mod_components), 2)
        self.assertEqual(len(go_sum_components), 2)
        by_name = {component.name: component for component in context['components']}
        self.assertIn('github.com/example/direct', by_name)
        self.assertIn('github.com/example/transitive', by_name)
        self.assertEqual(by_name['github.com/example/direct'].manifest_path, 'go.mod')
        self.assertEqual(dependency_type(by_name['github.com/example/direct']), 'direct')
        direct_key = by_name['github.com/example/direct'].key
        self.assertEqual(context['usage'][direct_key][0].kind, 'go-import')


if __name__ == '__main__':
    unittest.main()
