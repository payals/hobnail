"""Contract-side refusal cases for the implemented protected adapter surfaces."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hobnail.client import canonical_json
from hobnail.contracts import ContractError, coverage_report, validate_contract
from hobnail.git_effects import validate_action
from test_contracts import contract


def git_document():
    document = contract()
    document["actions"][0].update(plugin="git.commit", target="approved-repository", arguments={
        "branch": "main", "base_commit": "a" * 40, "paths": ["src/example.py"], "message": "Apply exact repair"})
    return document


def research_document():
    document = contract()
    document["actions"][0].update(plugin="research.promote", target="registry/" + "a" * 64 + ".json", arguments={})
    return document


class AdapterContractTests(unittest.TestCase):
    def test_git_contract_and_consumer_agree_on_valid_exact_arguments(self):
        for branch, oid in (("main", "a" * 40), ("repairs/issue-12", "b" * 64)):
            document = git_document()
            arguments = document["actions"][0]["arguments"]
            arguments.update(branch=branch, base_commit=oid, paths=["src/example.py", "docs/note.md"],
                             message="Apply exact repair\n\nPreserve independent checks")
            self.assertEqual(validate_contract(document), document)
            content = canonical_json({path: b"exact bytes".hex() for path in arguments["paths"]}).encode()
            self.assertEqual(validate_action(arguments, content), {path: b"exact bytes" for path in arguments["paths"]})

    def test_git_argument_shape_and_types_are_closed(self):
        for field in ("branch", "base_commit", "paths", "message"):
            document = git_document()
            del document["actions"][0]["arguments"][field]
            with self.subTest(missing=field), self.assertRaises(ContractError):
                validate_contract(document)
        for field, value in (("force", True), ("hooks", False), ("remote", "external"), ("shell", "unused")):
            document = git_document()
            document["actions"][0]["arguments"][field] = value
            with self.subTest(extra=field), self.assertRaises(ContractError):
                validate_contract(document)
        for field in ("branch", "base_commit", "paths", "message"):
            document = git_document()
            document["actions"][0]["arguments"][field] = True
            with self.subTest(invalid_type=field), self.assertRaises(ContractError):
                validate_contract(document)

    def test_git_ref_syntax_and_exact_object_ids_refuse_aliases(self):
        branches = ("-main", "refs/../main", "main//repair", "main/", "main.", "main/.hidden",
                    "main.lock", "main.lock/child", "a..b", "@{HEAD}", "a\\b", "x" * 129)
        for branch in branches:
            document = git_document()
            document["actions"][0]["arguments"]["branch"] = branch
            with self.subTest(branch=branch), self.assertRaises(ContractError):
                validate_contract(document)
        for oid in ("HEAD", "main", "a" * 39, "A" * 40, "a" * 41, "a" * 65):
            document = git_document()
            document["actions"][0]["arguments"]["base_commit"] = oid
            with self.subTest(oid=oid), self.assertRaises(ContractError):
                validate_contract(document)

    def test_git_protected_paths_and_path_sets_refuse(self):
        reserved = (".git", ".gitignore", ".gitattributes", ".gitmodules", ".gitconfig", ".githooks", ".husky", ".pre-commit-config.yaml")
        invalid_paths = [["nested/" + name.upper() + "/payload"] for name in reserved]
        invalid_paths += [[value] for value in ("../file", "/absolute", "a//b", "a/./b", "a/../b", "a/", "é", "file\nname", "x" * 1025)]
        invalid_paths += [[], ["x", "x"], ["directory", "directory/file"], ["directory/file", "directory"], ["new.py", "NEW.py"], ["Dir/a", "dir/b"],
                          ["Dir/sub/a", "Dir/SUB/b"], [True], [f"file-{i}" for i in range(65)]]
        for paths in invalid_paths:
            document = git_document()
            document["actions"][0]["arguments"]["paths"] = paths
            with self.subTest(paths=paths), self.assertRaises(ContractError):
                validate_contract(document)

    def test_git_messages_are_exact_and_byte_bounded(self):
        for message in ("", " \t\n ", "message\n", "message\rbody", "message\x00body", "é" * 1025):
            document = git_document()
            document["actions"][0]["arguments"]["message"] = message
            with self.subTest(message=repr(message[:30])), self.assertRaises(ContractError):
                validate_contract(document)
        document = git_document()
        document["actions"][0]["arguments"]["message"] = "é" * 1024
        validate_contract(document)

    def test_git_target_is_an_alias_and_total_metadata_is_bounded(self):
        for alias in ("/absolute/repo", "repo//other", "repo/", "../repo", "repo name", "x" * 129):
            document = git_document()
            document["actions"][0]["target"] = alias
            with self.subTest(alias=alias), self.assertRaises(ContractError):
                validate_contract(document)
        document = git_document()
        document["actions"][0]["arguments"]["paths"] = [f"{index}-" + "x" * 1000 for index in range(17)]
        with self.assertRaises(ContractError):
            validate_contract(document)

    def test_research_target_names_exact_identity_without_replacing_existing_record(self):
        document = research_document()
        validate_contract(document)
        for target in ("registry/current.json", "a" * 63 + ".json", "A" * 64 + ".json", "a" * 64 + ".JSON",
                       "../" + "a" * 64 + ".json", "registry//" + "a" * 64 + ".json",
                       "registry/./" + "a" * 64 + ".json", "registry\\" + "a" * 64 + ".json"):
            candidate = copy.deepcopy(document)
            candidate["actions"][0]["target"] = target
            with self.subTest(target=target), self.assertRaises(ContractError):
                validate_contract(candidate)
        document["actions"][0]["arguments"] = {"replace": True}
        with self.assertRaises(ContractError) as caught:
            validate_contract(document)
        self.assertEqual(caught.exception.code, "UNSUPPORTED_CAPABILITY")

    def test_known_adapter_coverage_names_real_backend_without_claiming_qualification(self):
        for document, backend in ((git_document(), "local-git"), (research_document(), "research-registry")):
            report = coverage_report(document)
            action = next(item for item in report["requirements"] if item["requirement"].startswith("action:"))
            self.assertEqual(action["status"], "implemented")
            self.assertEqual(action["execution_backend"], backend)
            self.assertFalse(report["qualified"])
        document = research_document()
        document["actions"][0]["plugin"] = "research.activate_champion"
        with self.assertRaises(ContractError) as caught:
            validate_contract(document)
        self.assertEqual(caught.exception.code, "UNSUPPORTED_CAPABILITY")
        self.assertFalse(coverage_report(document)["supported"])

    def test_custom_validator_requirement_remains_external_after_adapter_validation(self):
        document = research_document()
        document["checks"][0].update(plugin="custom:research-check", parameters={"window": "approved"})
        report = coverage_report(document)
        check = next(item for item in report["requirements"] if item["requirement"].startswith("check:"))
        self.assertEqual(check["status"], "external")
        self.assertFalse(report["qualified"])


if __name__ == "__main__":
    unittest.main()
