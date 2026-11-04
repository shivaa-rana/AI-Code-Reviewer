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

	# --- added cases: more vulnerability classes and many more safe controls -------------------
	SeededCase(
		"aws_key.py",
		'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\nprint(len(AWS_KEY))\n',
		True,
		"Committed AWS access key",
	),
	SeededCase(
		"weak_hash.py",
		"import hashlib\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n",
		True,
		"MD5 used for hashing",
	),
	SeededCase(
		"tls_off.py",
		"import requests\n\ndef fetch(url):\n    return requests.get(url, verify=False, timeout=5)\n",
		True,
		"TLS verification disabled",
	),
	SeededCase(
		"sql_injection.py",
		'def find(cursor, name):\n    cursor.execute("SELECT * FROM users WHERE name = \'%s\'" % name)\n',
		True,
		"SQL built with string formatting",
	),
	SeededCase(
		"flask_debug.py",
		"from flask import Flask\n\napp = Flask(__name__)\n\nif __name__ == \"__main__\":\n    app.run(debug=True)\n",
		True,
		"Flask debug mode enabled",
	),
	SeededCase(
		"os_system.py",
		"import os\n\ndef ping(host):\n    os.system(\"ping -c 1 \" + host)\n",
		True,
		"Shell command from caller input",
	),
	SeededCase(
		"return_in_finally.py",
		"def run(job):\n    try:\n        return job()\n    finally:\n        return None\n",
		True,
		"return in finally swallows exceptions",
	),
	SeededCase(
		"late_binding.py",
		"def make():\n    return [lambda: i for i in range(3)]\n",
		True,
		"Closure captures loop variable",
	),
	SeededCase(
		"insecure_tempfile.py",
		"import tempfile\n\ndef scratch():\n    return tempfile.mktemp()\n",
		True,
		"Race-prone mktemp",
	),
	SeededCase(
		"safe_yaml.py",
		"import yaml\n\ndef load(stream):\n    return yaml.safe_load(stream)\n",
		False,
		"safe_load",
	),
	SeededCase(
		"safe_hash.py",
		"import hashlib\n\ndef digest(data):\n    return hashlib.sha256(data).hexdigest()\n",
		False,
		"SHA-256",
	),
	SeededCase(
		"safe_sql.py",
		'def find(cursor, name):\n    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n',
		False,
		"Parameterized query",
	),
	SeededCase(
		"safe_request.py",
		"import requests\n\ndef fetch(url):\n    return requests.get(url, timeout=5)\n",
		False,
		"Default TLS verification",
	),
	SeededCase(
		"safe_json.py",
		"import json\n\ndef parse(text):\n    return json.loads(text)\n",
		False,
		"json.loads",
	),
	SeededCase(
		"safe_except.py",
		"def parse(value):\n    try:\n        return int(value)\n    except ValueError:\n        return 0\n",
		False,
		"Specific exception",
	),
	SeededCase(
		"safe_default.py",
		"def add_item(item, items=None):\n    items = [] if items is None else items\n    items.append(item)\n    return items\n",
		False,
		"None default",
	),
	SeededCase(
		"safe_paths.py",
		"from pathlib import Path\n\ndef read(name):\n    return (Path(\"data\") / name).read_text()\n",
		False,
		"pathlib read",
	),
	SeededCase(
		"safe_tempfile.py",
		"import tempfile\n\ndef scratch():\n    return tempfile.NamedTemporaryFile()\n",
		False,
		"NamedTemporaryFile",
	),
]
