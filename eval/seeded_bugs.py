from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SeededCase:
	filename: str
	code: str
	has_issue: bool
	description: str


SEEDED_CASES = [
	SeededCase(
		"hardcoded_password.py",
		'password = "demo-password-123"\nprint(password)\n',
		True,
		"Hardcoded credential",
	),
	SeededCase(
		"dynamic_eval.py",
		"def calculate(user_input):\n    return eval(user_input)\n",
		True,
		"Untrusted input passed to eval",
	),
	SeededCase(
		"shell_injection.py",
		"import subprocess\n\ndef run(command):\n    return subprocess.call(command, shell=True)\n",
		True,
		"Shell command built from caller input",
	),
	SeededCase(
		"unsafe_pickle.py",
		"import pickle\n\ndef load(payload):\n    return pickle.loads(payload)\n",
		True,
		"Unsafe pickle deserialization",
	),
	SeededCase(
		"unsafe_yaml.py",
		"import yaml\n\ndef load(stream):\n    return yaml.load(stream)\n",
		True,
		"Unsafe YAML deserialization",
	),
	SeededCase(
		"mutable_default.py",
		"def add_item(item, items=[]):\n    items.append(item)\n    return items\n",
		True,
		"Mutable function default",
	),
	SeededCase(
		"undefined_name.py",
		"def total(values):\n    return sum(value for value in values) + tax_rate\n",
		True,
		"Undefined variable reference",
	),
	SeededCase(
		"bare_except.py",
		"def parse(value):\n    try:\n        return int(value)\n    except:\n        return 0\n",
		True,
		"Bare exception handler",
	),
	SeededCase(
		"safe_subprocess.py",
		"import subprocess\n\ndef run(arguments):\n    return subprocess.run(arguments, check=True, capture_output=True)\n",
		False,
		"Argument-list subprocess invocation",
	),
	SeededCase(
		"environment_secret.py",
		"import os\n\npassword = os.environ.get(\"APP_PASSWORD\")\n",
		False,
		"Credential loaded from environment",
	),
]
