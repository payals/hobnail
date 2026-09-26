"""Reviewed role controller. Configuration comes only from its allowed file."""

import importlib.util
import json
import os
from pathlib import Path
import sys

# Load only this explicitly granted package. Scanning its parent directory
# would require widening the profile over unrelated packages or source trees.
package = Path(__file__).resolve().parent
specification = importlib.util.spec_from_file_location("hobnail", package / "__init__.py",
                                                     submodule_search_locations=[str(package)])
module = importlib.util.module_from_spec(specification)
sys.modules["hobnail"] = module
specification.loader.exec_module(module)
from hobnail.client import Client, Connection, PsqlTransport, TransportError, canonical_json, parse_json
from hobnail.effects import FileObserver, FilePublisher, dispatch_file, observe_file
from hobnail.deployment import NativeConsumer
from hobnail.git_effects import GitCommitter, GitObserver, dispatch_git, observe_git
from hobnail.integrations.research import ResearchRegistry, dispatch_promotion, observe_promotion



def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError("one configuration path required")
        path = Path(sys.argv[1])
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "r") as stream:
            config = parse_json(stream.read(16385))
        request = parse_json(sys.stdin.read(36_000_001))
        transport = PsqlTransport(Connection(**config["connection"]), psql=config["psql"])
        client = Client(transport)
        command = request["command"]
        if command == "api":
            response = client.call(request["operation"], request["payload"])
        elif command in {"file.dispatch", "file.observe", "git.dispatch", "git.observe", "research.dispatch", "research.observe"}:
            if set(request) != {"command", "effect_id"} or type(request["effect_id"]) is not int or request["effect_id"] < 1:
                raise ValueError("an exact positive effect ID is required")
            prefix, action = command.split(".")
            if config["role"] != ("adapter" if action == "dispatch" else "observer"):
                raise ValueError("consumer command does not match role")
            consumer = NativeConsumer.from_document(config["consumer"]) if "consumer" in config else NativeConsumer.file(config["destination"])
            if consumer.plugin != {"file": "file.publish", "git": "git.commit", "research": "research.promote"}[prefix]:
                raise ValueError("consumer command does not match protected configuration")
            effect_id = request["effect_id"]
            if prefix == "file":
                response = dispatch_file(client, effect_id, FilePublisher(consumer.root)) if action == "dispatch" else observe_file(client, effect_id, FileObserver(consumer.root))
            elif prefix == "research":
                response = dispatch_promotion(client, effect_id, ResearchRegistry(consumer.root)) if action == "dispatch" else observe_promotion(client, effect_id, FileObserver(consumer.root))
            else:
                repositories = dict(consumer.repositories)
                response = dispatch_git(client, effect_id, GitCommitter(repositories, executable=consumer.executable)) if action == "dispatch" else observe_git(client, effect_id, GitObserver(repositories, executable=consumer.executable))
        else:
            raise ValueError("unsupported service command")
        print(canonical_json(response))
    except Exception as error:
        # Exception bodies can contain runtime connection data. Retain type only.
        print(json.dumps({"service_error": type(error).__name__}))


if __name__ == "__main__":
    main()
