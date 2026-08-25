#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 record --repo PATH --output PATH | guard --for wave|build|install --repo PATH --record PATH [--target TARGET] [--allow PATH ...] | self-test" >&2
  exit 2
}

mode=${1:-}
[[ -n "$mode" ]] || usage
shift

repo=""
record=""
output=""
consumer=""
target=""
declare -a allowed=()
while (($#)); do
  case "$1" in
    --repo) repo=${2:?}; shift 2 ;;
    --record) record=${2:?}; shift 2 ;;
    --output) output=${2:?}; shift 2 ;;
    --for) consumer=${2:?}; shift 2 ;;
    --target) target=${2:?}; shift 2 ;;
    --allow) allowed+=("${2:?}"); shift 2 ;;
    *) usage ;;
  esac
done

record_or_guard() {
  local operation=$1
  [[ -d "$repo/.git" ]] || { echo "preflight: invalid repository" >&2; return 2; }
  if [[ "$operation" == record ]]; then
    [[ -n "$output" && "$output" != "$repo"/* ]] || {
      echo "preflight: record must be outside repository" >&2
      return 2
    }
    record=$output
  else
    [[ -f "$record" ]] || { echo "preflight: missing record" >&2; return 2; }
    [[ "$consumer" == wave || "$consumer" == build || "$consumer" == install ]] || {
      echo "preflight: guard consumer must be wave, build, or install" >&2
      return 2
    }
    if [[ "$consumer" == build || "$consumer" == install ]]; then
      [[ -n "$target" ]] || { echo "preflight: target is required" >&2; return 2; }
    fi
  fi

  local allowed_json
  if ((${#allowed[@]})); then
    allowed_json=$(printf '%s\0' "${allowed[@]}" | python3 -c 'import json,sys; print(json.dumps([p.decode() for p in sys.stdin.buffer.read().split(b"\0") if p]))')
  else
    allowed_json='[]'
  fi
  PAYGATE_PREFLIGHT_OPERATION=$operation \
  PAYGATE_PREFLIGHT_REPO=$repo \
  PAYGATE_PREFLIGHT_RECORD=$record \
  PAYGATE_PREFLIGHT_ALLOWED=$allowed_json \
  PAYGATE_PREFLIGHT_CONSUMER=$consumer \
  PAYGATE_PREFLIGHT_TARGET=$target \
  python3 - <<'PY'
import hashlib, json, os, pathlib, platform, pwd, shlex, stat, subprocess, sys, tempfile

operation = os.environ["PAYGATE_PREFLIGHT_OPERATION"]
repo = pathlib.Path(os.environ["PAYGATE_PREFLIGHT_REPO"]).resolve()
record = pathlib.Path(os.environ["PAYGATE_PREFLIGHT_RECORD"]).resolve()
allowed = set(json.loads(os.environ["PAYGATE_PREFLIGHT_ALLOWED"]))
consumer = os.environ["PAYGATE_PREFLIGHT_CONSUMER"]
requested_target = os.environ["PAYGATE_PREFLIGHT_TARGET"]

def command(*args):
    return subprocess.run(args, cwd=repo, check=True, stdout=subprocess.PIPE).stdout

def dirty_state():
    raw = command("git", "status", "--porcelain=v1", "-z", "--untracked-files=all")
    fields = raw.split(b"\0")
    entries, index = [], 0
    while index < len(fields) and fields[index]:
        item = fields[index]
        status_code = item[:2].decode("ascii")
        path = os.fsdecode(item[3:])
        entries.append((path, status_code, "destination" if "R" in status_code or "C" in status_code else "path"))
        index += 1
        if "R" in status_code or "C" in status_code:
            if index < len(fields) and fields[index]:
                entries.append((os.fsdecode(fields[index]), status_code, "source"))
                index += 1
    return raw, sorted(entries)

def identity(relative, status_code=None, role=None):
    path = repo / relative
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        result = {"path": relative, "type": "missing", "sha256": None}
        if status_code is not None:
            result.update({"index": status_code[0], "worktree": status_code[1], "role": role})
        return result
    mode = metadata.st_mode
    if stat.S_ISREG(mode):
        kind, payload = "file", path.read_bytes()
    elif stat.S_ISLNK(mode):
        kind, payload = "symlink", os.fsencode(os.readlink(path))
    elif stat.S_ISDIR(mode):
        kind = "directory"
        payload = b"\0".join(
            os.fsencode(str(item.relative_to(path))) for item in sorted(path.rglob("*"))
        )
    else:
        kind, payload = "other", str(stat.S_IFMT(mode)).encode()
    result = {"path": relative, "type": kind, "sha256": hashlib.sha256(payload).hexdigest()}
    if status_code is not None:
        result.update({"index": status_code[0], "worktree": status_code[1], "role": role})
    return result

ABSENT_SENTINEL = "none-detected-launchctl-or-active-process"
ACTIVE_WITHOUT_SUPERVISOR = "no-launchctl-service-active-process"

def owner(metadata):
    uid = metadata.st_uid
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        name = str(uid)
    return {"name": name, "uid": uid}

def path_kind(metadata):
    if stat.S_ISLNK(metadata.st_mode): return "symlink"
    if stat.S_ISREG(metadata.st_mode): return "regular"
    if stat.S_ISDIR(metadata.st_mode): return "directory"
    return "other"

def observation():
    if os.environ.get("PAYGATE_PREFLIGHT_SELF_TEST") == "1" and os.environ.get("PAYGATE_PREFLIGHT_TEST_IDENTITY"):
        return json.loads(os.environ["PAYGATE_PREFLIGHT_TEST_IDENTITY"])
    rust = subprocess.run(["rustc", "-vV"], text=True, stdout=subprocess.PIPE, check=True).stdout
    rust_host = next(line.split(": ", 1)[1] for line in rust.splitlines() if line.startswith("host: "))
    launcher = subprocess.run(
        ["sh", "-c", "command -v paygate || true"], text=True, stdout=subprocess.PIPE, check=True
    ).stdout.strip() or None
    launcher_observation = None
    if launcher:
        launcher_path = pathlib.Path(launcher)
        launcher_metadata = launcher_path.lstat()
        resolved_path = launcher_path.resolve(strict=True)
        resolved_metadata = resolved_path.stat()
        interpreter = None
        if stat.S_ISREG(resolved_metadata.st_mode):
            first_line = resolved_path.read_bytes().splitlines()[0] if resolved_path.stat().st_size else b""
            if first_line.startswith(b"#!"):
                interpreter_text = os.fsdecode(first_line[2:].strip().split(None, 1)[0])
                interpreter = str(pathlib.Path(interpreter_text).resolve(strict=True))
        launcher_observation = {
            "path": launcher,
            "kind": path_kind(launcher_metadata),
            "symlink_target": os.readlink(launcher_path) if stat.S_ISLNK(launcher_metadata.st_mode) else None,
            "owner": owner(launcher_metadata),
            "resolved_path": str(resolved_path),
            "resolved_kind": path_kind(resolved_metadata),
            "resolved_executable": os.access(resolved_path, os.X_OK),
            "resolved_owner": owner(resolved_metadata),
            "resolved_interpreter": interpreter,
            "resolved_sha256": hashlib.sha256(resolved_path.read_bytes()).hexdigest()
            if stat.S_ISREG(resolved_metadata.st_mode) else None,
        }
    supervisor_identifier = None
    if platform.system() == "Darwin":
        listed = subprocess.run(
            ["launchctl", "list"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        ).stdout.splitlines()
        labels = sorted(line.split()[-1] for line in listed if "paygate" in line.lower())
        supervisor_identifier = labels[0] if labels else None
    # One process-table snapshot prevents PID-set races between discovery and
    # ownership inspection. Python console scripts normally appear under the
    # interpreter name, so match exact executable identity rather than comm.
    process_rows = subprocess.run(
        ["ps", "-axo", "pid=,uid=,user=,command="],
        text=True, stdout=subprocess.PIPE, check=True,
    ).stdout.splitlines()
    process_pids, process_owners = [], []
    if launcher_observation is not None:
        launcher_paths = {
            launcher_observation["path"], launcher_observation["resolved_path"]
        }
        resolved_interpreter = launcher_observation["resolved_interpreter"]
        for row in process_rows:
            parts = row.strip().split(None, 3)
            if len(parts) != 4:
                continue
            pid_text, uid_text, user, command_text = parts
            pid = int(pid_text)
            if pid == os.getpid():
                continue
            try:
                argv = shlex.split(command_text)
            except ValueError:
                continue
            if not argv:
                continue
            executable = argv[0]
            try:
                executable_resolved = str(pathlib.Path(executable).resolve(strict=True))
            except (FileNotFoundError, OSError):
                executable_resolved = executable
            direct = executable in launcher_paths or executable_resolved in launcher_paths
            interpreter_script = (
                resolved_interpreter is not None
                and executable_resolved == resolved_interpreter
                and len(argv) > 1
                and argv[1] in launcher_paths
            )
            if direct or interpreter_script:
                process_pids.append(str(pid))
                process_owners.append({"uid": int(uid_text), "name": user})
        process_owners.sort(key=lambda value: (value["uid"], value["name"]))
    return {
        "os": platform.system(),
        "architecture": platform.machine(),
        "rust_target": rust_host,
        "launcher": launcher_observation,
        "supervisor": {
            "mechanism": "launchctl",
            "present": supervisor_identifier is not None,
            "identifier": supervisor_identifier,
        },
        "process": {
            "present": bool(process_pids),
            "owners": process_owners,
            "observed_count": len(process_pids),
        },
        "python_command": subprocess.run(
            ["sh", "-c", "command -v python3 || true"], text=True, stdout=subprocess.PIPE, check=True
        ).stdout.strip() or None,
        "python_version": platform.python_version(),
    }

def record_deployment(current):
    launcher = current["launcher"]
    if launcher is None:
        raise ValueError("deployment launcher is required")
    if launcher["kind"] != "symlink":
        raise ValueError("deployment launcher is not a symlink")
    if launcher["resolved_kind"] != "regular" or not launcher["resolved_executable"]:
        raise ValueError("deployment launcher target is not executable")
    if launcher["resolved_interpreter"] is None:
        raise ValueError("deployment launcher interpreter is missing")
    principal = launcher["resolved_owner"]
    if launcher["owner"] != principal:
        raise ValueError("launcher ownership is inconsistent")
    supervisor = current["supervisor"]
    process = current["process"]
    if process["present"] and (
        process.get("observed_count", len(process.get("owners", []))) != len(process.get("owners", []))
        or any(value != principal for value in process.get("owners", []))
    ):
        raise ValueError("active process ownership is inconsistent")
    if not supervisor["present"] and not process["present"]:
        supervisor_value = ABSENT_SENTINEL
    elif supervisor["present"]:
        supervisor_value = f"launchctl:{supervisor['identifier']}"
    else:
        supervisor_value = ACTIVE_WITHOUT_SUPERVISOR
    return {
        "os": current["os"],
        "architecture": current["architecture"],
        "rust_target": current["rust_target"],
        "launcher": launcher["path"],
        "launcher_kind": "symlink-to-python-console-script",
        "resolved_launcher": launcher["resolved_path"],
        "launcher_symlink_target": launcher["symlink_target"],
        "resolved_launcher_sha256": launcher["resolved_sha256"],
        "resolved_interpreter": launcher["resolved_interpreter"],
        "installed_python": launcher["resolved_interpreter"],
        "supervisor": supervisor_value,
        "process_present": process["present"],
        "process_owner": principal["name"],
        "process_uid": principal["uid"],
        "python_command": current["python_command"],
        "python_version": current["python_version"],
    }

def expected_install_identity(deployment):
    launcher = deployment.get("launcher")
    principal = {"name": deployment.get("process_owner"), "uid": deployment.get("process_uid")}
    if not launcher or principal["name"] is None or principal["uid"] is None:
        raise ValueError("launcher expected owner is missing")
    if deployment.get("launcher_kind") != "symlink-to-python-console-script":
        raise ValueError("launcher kind is contradictory")
    if not deployment.get("resolved_launcher"):
        raise ValueError("launcher resolution is missing")
    if not deployment.get("launcher_symlink_target") or not deployment.get("resolved_launcher_sha256"):
        raise ValueError("launcher content identity is missing from frozen record")
    interpreter = deployment.get("resolved_interpreter")
    installed = deployment.get("installed_python")
    if not interpreter or not installed or interpreter != installed:
        raise ValueError("launcher interpreter is contradictory")
    supervisor_value = deployment.get("supervisor")
    if supervisor_value == ABSENT_SENTINEL:
        supervisor = {"mechanism": "launchctl", "present": False, "identifier": None}
        process_present = False
        if deployment.get("process_present") not in (None, False):
            raise ValueError("process presence is contradictory")
    elif isinstance(supervisor_value, str) and supervisor_value.startswith("launchctl:") and len(supervisor_value) > len("launchctl:"):
        supervisor = {"mechanism": "launchctl", "present": True, "identifier": supervisor_value.split(":", 1)[1]}
        process_present = deployment.get("process_present")
        if not isinstance(process_present, bool):
            raise ValueError("process presence is missing")
    elif supervisor_value == ACTIVE_WITHOUT_SUPERVISOR:
        supervisor = {"mechanism": "launchctl", "present": False, "identifier": None}
        process_present = deployment.get("process_present")
        if process_present is not True:
            raise ValueError("process presence is contradictory")
    else:
        raise ValueError("supervisor identity is unknown")
    return {
        "launcher": {
            "path": launcher,
            "kind": "symlink",
            "resolved_path": deployment["resolved_launcher"],
            "symlink_target": deployment["launcher_symlink_target"],
            "resolved_sha256": deployment["resolved_launcher_sha256"],
            "resolved_kind": "regular",
            "resolved_executable": True,
            "resolved_interpreter": interpreter,
            "owner": principal,
            "resolved_owner": principal,
        },
        "supervisor": supervisor,
        "process": {"present": process_present, "expected_owner": principal},
    }

def fail_install(message):
    print(f"preflight guard: {message}", file=sys.stderr)
    sys.exit(1)

def compare_install_identity(deployment, current):
    try:
        expected = expected_install_identity(deployment)
    except KeyError:
        fail_install("install record identity is contradictory")
    except ValueError as error:
        fail_install(str(error))
    actual_launcher = current.get("launcher")
    wanted = expected["launcher"]
    if actual_launcher is None or actual_launcher.get("path") != wanted["path"]:
        fail_install("launcher path mismatch")
    if actual_launcher.get("kind") != wanted["kind"]:
        fail_install("launcher kind mismatch")
    if actual_launcher.get("resolved_path") != wanted["resolved_path"]:
        fail_install("launcher resolution mismatch")
    if actual_launcher.get("symlink_target") != wanted["symlink_target"]:
        fail_install("launcher symlink target mismatch")
    if actual_launcher.get("resolved_sha256") != wanted["resolved_sha256"]:
        fail_install("launcher resolved content mismatch")
    if actual_launcher.get("owner") != wanted["owner"]:
        fail_install("launcher ownership mismatch")
    if actual_launcher.get("resolved_owner") != wanted["resolved_owner"]:
        fail_install("launcher ownership mismatch")
    if actual_launcher.get("resolved_kind") != "regular" or not actual_launcher.get("resolved_executable"):
        fail_install("launcher resolved target type mismatch")
    if actual_launcher.get("resolved_interpreter") != wanted["resolved_interpreter"]:
        fail_install("launcher interpreter mismatch")
    actual_supervisor = current.get("supervisor")
    if not isinstance(actual_supervisor, dict) or actual_supervisor.get("mechanism") != "launchctl":
        fail_install("supervisor identity mismatch")
    if actual_supervisor.get("present") != expected["supervisor"]["present"]:
        fail_install("supervisor presence mismatch")
    if actual_supervisor.get("identifier") != expected["supervisor"]["identifier"]:
        fail_install("supervisor identity mismatch")
    actual_process = current.get("process")
    if not isinstance(actual_process, dict) or actual_process.get("present") != expected["process"]["present"]:
        fail_install("process presence mismatch")
    if actual_process.get("present"):
        owners = actual_process.get("owners", [])
        observed_count = actual_process.get("observed_count", len(owners))
        if observed_count != len(owners) or not owners or any(value != expected["process"]["expected_owner"] for value in owners):
            fail_install("process ownership mismatch")

raw, dirty = dirty_state()
def is_allowed(path):
    return any(path == item or path.startswith(item.rstrip("/") + "/") for item in allowed)

entries = [identity(path, status_code, role) for path, status_code, role in dirty if not is_allowed(path)]
if operation == "guard":
    if stat.S_IMODE(record.lstat().st_mode) != 0o600:
        print("preflight guard: record mode mismatch", file=sys.stderr)
        sys.exit(1)
    data = json.loads(record.read_text())
    if data.get("schema") != "paygate-minimal-rust-cutover-preflight-v1":
        print("preflight guard: record schema mismatch", file=sys.stderr)
        sys.exit(1)
    if pathlib.Path(data.get("repository", "")).resolve() != repo:
        print("preflight guard: repository identity mismatch", file=sys.stderr)
        sys.exit(1)
    baseline = data["dirty_baseline"]
    expected = baseline["entries"]
    if baseline.get("path_count") != len(expected):
        print("preflight guard: invalid dirty manifest", file=sys.stderr)
        sys.exit(1)
    if expected and any(not all(field in item for field in ("index", "worktree", "role")) for item in expected):
        print("preflight guard: dirty manifest lacks per-path status identity", file=sys.stderr)
        sys.exit(1)
    if not allowed and baseline.get("porcelain_v1_z_sha256") != hashlib.sha256(raw).hexdigest():
        print("preflight guard: dirty porcelain identity drift", file=sys.stderr)
        sys.exit(1)
    if entries != expected:
        print("preflight guard: dirty baseline drift", file=sys.stderr)
        sys.exit(1)
    if consumer in ("build", "install"):
        deployment = data["deployment"]
        if requested_target != deployment.get("rust_target"):
            print("preflight guard: target mismatch", file=sys.stderr)
            sys.exit(1)
        if consumer == "install":
            # Establish that the frozen record contains historical launcher
            # content evidence before observing current launcher bytes.
            try:
                expected_install_identity(deployment)
            except KeyError:
                fail_install("install record identity is contradictory")
            except ValueError as error:
                fail_install(str(error))
        current = observation()
        for field in ("os", "architecture", "rust_target"):
            if current.get(field) != deployment.get(field):
                print(f"preflight guard: deployment {field} mismatch", file=sys.stderr)
                sys.exit(1)
        if consumer == "install":
            compare_install_identity(deployment, current)
    print(f"preflight guard ({consumer}): PASS")
    sys.exit(0)

deployment = record_deployment(observation())
data = {
    "schema": "paygate-minimal-rust-cutover-preflight-v1",
    "repository": str(repo),
    "start_commit": command("git", "rev-parse", "HEAD").decode().strip(),
    "deployment": deployment,
    "state": {
        "config": str(pathlib.Path("~/.config/paygate-client/config.yaml").expanduser()),
        "wallet_storage": str(pathlib.Path("~/.local/share/paygate-client/breez").expanduser()),
        "credential_cache": str(pathlib.Path("~/.config/paygate-client/credentials.json").expanduser()),
        "keyring_service": "paygate-client.credentials",
        "ledger": str(pathlib.Path("~/.local/state/paygate-client/daily-spend-ledger.json").expanduser()),
    },
    "dirty_baseline": {
        "porcelain_v1_z_sha256": hashlib.sha256(raw).hexdigest(),
        "path_count": len(entries),
        "entries": entries,
    },
}
record.parent.mkdir(parents=True, exist_ok=True)
descriptor, temporary = tempfile.mkstemp(prefix=record.name + ".", dir=record.parent)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")
    os.replace(temporary, record)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
print(record)
PY
}

self_test() {
  local fixture record_path variants recorded_target launcher_root launcher_path target_path interpreter matching_identity
  fixture=$(mktemp -d /tmp/paygate-preflight-self-test.XXXXXX)
  record_path=$(mktemp /tmp/paygate-preflight-record.XXXXXX)
  variants=$(mktemp -d /tmp/paygate-preflight-variants.XXXXXX)
  trap '[[ "$fixture" == /tmp/paygate-preflight-self-test.* ]] && rm -rf -- "$fixture"; [[ "$variants" == /tmp/paygate-preflight-variants.* ]] && rm -rf -- "$variants"; [[ "$record_path" == /tmp/paygate-preflight-record.* ]] && rm -f -- "$record_path"' RETURN
  git -C "$fixture" init -q
  git -C "$fixture" config user.email preflight@example.invalid
  git -C "$fixture" config user.name preflight
  printf 'tracked\n' > "$fixture/tracked.txt"
  git -C "$fixture" add tracked.txt
  git -C "$fixture" commit -qm baseline
  printf 'dirty\n' >> "$fixture/tracked.txt"
  mkdir -p "$fixture/compat"
  printf 'keyring==25.7.0\n' > "$fixture/compat/native-keyring-requirements.txt"
  launcher_root="$variants/deployment"
  launcher_path="$launcher_root/bin/paygate"
  target_path="$launcher_root/venv/bin/paygate"
  interpreter=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.executable).resolve())')
  mkdir -p "$launcher_root/bin" "$launcher_root/venv/bin"
  printf '#!%s\nimport time\ntime.sleep(30)\n' "$interpreter" > "$target_path"
  chmod 755 "$target_path"
  ln -s "$target_path" "$launcher_path"
  PATH="$launcher_root/bin:$PATH" repo=$fixture output=$record_path record_or_guard record >/dev/null
  consumer=wave repo=$fixture record=$record_path record_or_guard guard >/dev/null

  recorded_target=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["deployment"]["rust_target"])' "$record_path")
  consumer=build target=$recorded_target repo=$fixture record=$record_path record_or_guard guard >/dev/null
  ! consumer=build target=wrong-target repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  PATH="$launcher_root/bin:$PATH" consumer=install target=$recorded_target repo=$fixture record=$record_path record_or_guard guard >/dev/null

  for mutation in schema repository os architecture rust_target launcher resolved_launcher supervisor process_owner; do
    python3 - "$record_path" "$variants/$mutation.json" "$mutation" <<'PY'
import json, os, sys
source, destination, mutation = sys.argv[1:]
data = json.load(open(source))
if mutation == "schema":
    data["schema"] = "wrong-schema"
elif mutation == "repository":
    data["repository"] = "/definitely/not/the/repository"
else:
    data["deployment"][mutation] = "mismatch-value"
with open(destination, "w") as stream:
    json.dump(data, stream)
os.chmod(destination, 0o600)
PY
    if [[ "$mutation" == schema || "$mutation" == repository ]]; then
      ! consumer=wave repo=$fixture record="$variants/$mutation.json" record_or_guard guard >/dev/null 2>&1
    elif [[ "$mutation" == os || "$mutation" == architecture || "$mutation" == rust_target ]]; then
      ! consumer=build target=$recorded_target repo=$fixture record="$variants/$mutation.json" record_or_guard guard >/dev/null 2>&1
    else
      ! PATH="$launcher_root/bin:$PATH" consumer=install target=$recorded_target repo=$fixture record="$variants/$mutation.json" record_or_guard guard >/dev/null 2>&1
    fi
  done
  cp "$record_path" "$variants/mode.json"
  chmod 644 "$variants/mode.json"
  ! consumer=wave repo=$fixture record="$variants/mode.json" record_or_guard guard >/dev/null 2>&1

  python3 - "$record_path" "$launcher_path" "$target_path" "$interpreter" > "$variants/identity.json" <<'PY'
import json, os, pathlib, pwd, sys
record, launcher, target, interpreter = sys.argv[1:]
deployment = json.load(open(record))["deployment"]
def principal(path, follow):
    metadata = os.stat(path, follow_symlinks=follow)
    return {"name": pwd.getpwuid(metadata.st_uid).pw_name, "uid": metadata.st_uid}
identity = {
    "os": deployment["os"], "architecture": deployment["architecture"],
    "rust_target": deployment["rust_target"],
    "launcher": {
        "path": launcher, "kind": "symlink", "owner": principal(launcher, False),
        "symlink_target": os.readlink(launcher),
        "resolved_path": str(pathlib.Path(target).resolve()), "resolved_kind": "regular", "resolved_executable": True,
        "resolved_owner": principal(target, True), "resolved_interpreter": interpreter,
        "resolved_sha256": __import__("hashlib").sha256(pathlib.Path(target).read_bytes()).hexdigest(),
    },
    "supervisor": {"mechanism": "launchctl", "present": False, "identifier": None},
    "process": {"present": False, "owners": []},
    "python_command": deployment["python_command"], "python_version": deployment["python_version"],
}
print(json.dumps(identity))
PY
  matching_identity=$(<"$variants/identity.json")

  # A Python-backed console script must be found even though its process name
  # is the interpreter. An unrelated Python process with the launcher path in a
  # later argument must not be treated as the deployment.
  "$launcher_path" &
  active_pid=$!
  sleep 0.1
  ! PATH="$launcher_root/bin:$PATH" consumer=install target=$recorded_target repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  kill "$active_pid"
  wait "$active_pid" 2>/dev/null || true
  "$interpreter" -c 'import time; time.sleep(30)' "$target_path" &
  unrelated_pid=$!
  sleep 0.1
  PATH="$launcher_root/bin:$PATH" consumer=install target=$recorded_target repo=$fixture record=$record_path record_or_guard guard >/dev/null
  kill "$unrelated_pid"
  wait "$unrelated_pid" 2>/dev/null || true

  mv "$launcher_path" "$variants/launcher.saved"
  ! PATH="$launcher_root/bin:$PATH" consumer=install target=$recorded_target repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  mv "$variants/launcher.saved" "$launcher_path"
  mv "$launcher_path" "$variants/launcher.saved"
  printf '#!%s\nexit 0\n' "$interpreter" > "$launcher_path"
  chmod 755 "$launcher_path"
  ! PATH="$launcher_root/bin:$PATH" consumer=install target=$recorded_target repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  rm "$launcher_path"
  mv "$variants/launcher.saved" "$launcher_path"
  printf '#!%s\nexit 0\n' "$interpreter" > "$variants/alternate-paygate"
  chmod 755 "$variants/alternate-paygate"
  ln -snf "$variants/alternate-paygate" "$launcher_path"
  ! PATH="$launcher_root/bin:$PATH" consumer=install target=$recorded_target repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  ln -snf "$target_path" "$launcher_path"
  mkdir "$variants/not-a-file"
  ln -snf "$variants/not-a-file" "$launcher_path"
  ! PATH="$launcher_root/bin:$PATH" consumer=install target=$recorded_target repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  ln -snf "$target_path" "$launcher_path"
  cp "$target_path" "$variants/target.saved"
  printf '#!/bin/sh\nexit 0\n' > "$target_path"
  chmod 755 "$target_path"
  ! PATH="$launcher_root/bin:$PATH" consumer=install target=$recorded_target repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  mv "$variants/target.saved" "$target_path"

  for owner_field in owner resolved_owner; do
    python3 - "$variants/identity.json" "$variants/$owner_field.json" "$owner_field" <<'PY'
import json, sys
source, destination, field = sys.argv[1:]
data=json.load(open(source)); data["launcher"][field]={"name":"wrong-owner","uid":99999}
json.dump(data, open(destination,"w"))
PY
    ! PAYGATE_PREFLIGHT_SELF_TEST=1 PAYGATE_PREFLIGHT_TEST_IDENTITY=$(<"$variants/$owner_field.json") \
      consumer=install target=$recorded_target repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  done

  python3 - "$record_path" "$variants" "$variants/identity.json" <<'PY'
import json, os, pathlib, sys
record_path, variants, identity_path = sys.argv[1:]
base_record=json.load(open(record_path)); base_identity=json.load(open(identity_path))
def write(name, value, mode=False):
    path=pathlib.Path(variants)/name
    json.dump(value, open(path,"w"))
    if mode: os.chmod(path,0o600)
sup_identity=json.loads(json.dumps(base_identity)); sup_identity["supervisor"]={"mechanism":"launchctl","present":True,"identifier":"com.example.paygate"}
write("supervisor-present-identity.json",sup_identity)
wrong_label=json.loads(json.dumps(sup_identity)); wrong_label["supervisor"]["identifier"]="com.example.other"
write("supervisor-wrong-label.json",wrong_label)
sup_record=json.loads(json.dumps(base_record)); sup_record["deployment"]["supervisor"]="launchctl:com.example.paygate"; sup_record["deployment"]["process_present"]=False
write("supervisor-present-record.json",sup_record,True)
active_identity=json.loads(json.dumps(base_identity)); principal={"name":base_record["deployment"]["process_owner"],"uid":base_record["deployment"]["process_uid"]}; active_identity["process"]={"present":True,"owners":[principal]}
write("process-active-identity.json",active_identity)
wrong_owner=json.loads(json.dumps(active_identity)); wrong_owner["process"]["owners"]=[{"name":"wrong-owner","uid":99999}]
write("process-wrong-owner.json",wrong_owner)
mixed=json.loads(json.dumps(active_identity)); mixed["process"]["owners"].append({"name":"wrong-owner","uid":99999})
write("process-mixed-owner.json",mixed)
active_record=json.loads(json.dumps(base_record)); active_record["deployment"]["supervisor"]="no-launchctl-service-active-process"; active_record["deployment"]["process_present"]=True
write("process-active-record.json",active_record,True)
null_owner=json.loads(json.dumps(base_record)); null_owner["deployment"]["process_owner"]=None
write("null-owner-record.json",null_owner,True)
PY
  ! PAYGATE_PREFLIGHT_SELF_TEST=1 PAYGATE_PREFLIGHT_TEST_IDENTITY=$(<"$variants/supervisor-present-identity.json") consumer=install target=$recorded_target repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  ! PAYGATE_PREFLIGHT_SELF_TEST=1 PAYGATE_PREFLIGHT_TEST_IDENTITY=$matching_identity consumer=install target=$recorded_target repo=$fixture record="$variants/supervisor-present-record.json" record_or_guard guard >/dev/null 2>&1
  PAYGATE_PREFLIGHT_SELF_TEST=1 PAYGATE_PREFLIGHT_TEST_IDENTITY=$(<"$variants/supervisor-present-identity.json") consumer=install target=$recorded_target repo=$fixture record="$variants/supervisor-present-record.json" record_or_guard guard >/dev/null
  ! PAYGATE_PREFLIGHT_SELF_TEST=1 PAYGATE_PREFLIGHT_TEST_IDENTITY=$(<"$variants/supervisor-wrong-label.json") consumer=install target=$recorded_target repo=$fixture record="$variants/supervisor-present-record.json" record_or_guard guard >/dev/null 2>&1
  ! PAYGATE_PREFLIGHT_SELF_TEST=1 PAYGATE_PREFLIGHT_TEST_IDENTITY=$(<"$variants/process-active-identity.json") consumer=install target=$recorded_target repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  ! PAYGATE_PREFLIGHT_SELF_TEST=1 PAYGATE_PREFLIGHT_TEST_IDENTITY=$matching_identity consumer=install target=$recorded_target repo=$fixture record="$variants/process-active-record.json" record_or_guard guard >/dev/null 2>&1
  PAYGATE_PREFLIGHT_SELF_TEST=1 PAYGATE_PREFLIGHT_TEST_IDENTITY=$(<"$variants/process-active-identity.json") consumer=install target=$recorded_target repo=$fixture record="$variants/process-active-record.json" record_or_guard guard >/dev/null
  for identity_case in process-wrong-owner process-mixed-owner; do
    ! PAYGATE_PREFLIGHT_SELF_TEST=1 PAYGATE_PREFLIGHT_TEST_IDENTITY=$(<"$variants/$identity_case.json") consumer=install target=$recorded_target repo=$fixture record="$variants/process-active-record.json" record_or_guard guard >/dev/null 2>&1
  done
  ! PAYGATE_PREFLIGHT_SELF_TEST=1 PAYGATE_PREFLIGHT_TEST_IDENTITY=$matching_identity consumer=install target=$recorded_target repo=$fixture record="$variants/null-owner-record.json" record_or_guard guard >/dev/null 2>&1

  cp "$fixture/tracked.txt" "$fixture/tracked.saved"
  printf 'changed\n' >> "$fixture/tracked.txt"
  ! consumer=wave repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  mv "$fixture/tracked.saved" "$fixture/tracked.txt"
  git -C "$fixture" add tracked.txt
  ! consumer=wave repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  git -C "$fixture" reset -q HEAD -- tracked.txt
  git -C "$fixture" rm -q --cached tracked.txt
  ! consumer=wave repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  git -C "$fixture" add tracked.txt
  git -C "$fixture" reset -q HEAD -- tracked.txt
  git -C "$fixture" mv tracked.txt renamed.txt
  ! consumer=wave repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  git -C "$fixture" mv renamed.txt tracked.txt
  git -C "$fixture" reset -q HEAD -- tracked.txt
  printf 'allowed wave implementation\n' > "$fixture/wave.txt"
  allowed=(wave.txt)
  consumer=wave repo=$fixture record=$record_path record_or_guard guard >/dev/null
  allowed=()
  rm "$fixture/wave.txt"
  mv "$fixture/compat/native-keyring-requirements.txt" "$fixture/compat/requirements.saved"
  ! consumer=wave repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  mv "$fixture/compat/requirements.saved" "$fixture/compat/native-keyring-requirements.txt"
  rm "$fixture/compat/native-keyring-requirements.txt"
  ln -s tracked.txt "$fixture/compat/native-keyring-requirements.txt"
  ! consumer=wave repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  rm "$fixture/compat/native-keyring-requirements.txt"
  printf 'keyring==25.7.0\n' > "$fixture/compat/native-keyring-requirements.txt"
  printf 'new\n' > "$fixture/added.txt"
  ! consumer=wave repo=$fixture record=$record_path record_or_guard guard >/dev/null 2>&1
  echo "preflight self-test: PASS"
}

case "$mode" in
  record) record_or_guard record ;;
  guard) record_or_guard guard ;;
  self-test) self_test ;;
  *) usage ;;
esac
