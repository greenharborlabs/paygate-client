#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

usage() {
  echo "usage: $0 checkpoint --candidate DIR --acceptance FILE --gate GATE --operator ID [--record FILE --rollback-dir DIR] [--name NAME] [--result PASS] [--max-amount-sats N --max-fee-sats N --daily-cap-sats N] --confirm | install --repo PATH --record FILE --candidate DIR --rollback-dir DIR --acceptance FILE | rollback --record FILE --rollback-dir DIR | finalize --repo PATH --record FILE --candidate DIR --rollback-dir DIR --acceptance FILE --recovery-record FILE --confirm FINALIZE_RUST_AND_RETAIN_QUARANTINE" >&2
  exit 2
}

mode=${1:-}; [[ -n "$mode" ]] || usage; shift
repo="" record="" candidate="" rollback="" acceptance="" gate="" name="" result="" recovery="" confirm=""
operator=""
max_amount="" max_fee="" daily_cap=""
while (($#)); do
  case "$1" in
    --repo) repo=${2:?}; shift 2;; --record) record=${2:?}; shift 2;;
    --candidate) candidate=${2:?}; shift 2;; --rollback-dir) rollback=${2:?}; shift 2;;
    --acceptance) acceptance=${2:?}; shift 2;; --gate) gate=${2:?}; shift 2;;
    --operator) operator=${2:?}; shift 2;;
    --name) name=${2:?}; shift 2;; --result) result=${2:?}; shift 2;;
    --max-amount-sats) max_amount=${2:?}; shift 2;; --max-fee-sats) max_fee=${2:?}; shift 2;;
    --daily-cap-sats) daily_cap=${2:?}; shift 2;; --recovery-record) recovery=${2:?}; shift 2;;
    --confirm) confirm=${2:-yes}; if [[ $# -gt 1 && ${2:-} != --* ]]; then shift 2; else shift; fi;;
    *) usage;;
  esac
done

candidate_check() {
  [[ "$candidate" == /* && -f "$candidate/paygate" && -f "$candidate/manifest.json" ]] || { echo "cutover: invalid candidate" >&2; exit 2; }
  python3 - "$candidate" <<'PY'
import hashlib,json,pathlib,re,sys
p=pathlib.Path(sys.argv[1]); d=json.load(open(p/'manifest.json'))
if d.get('schema')!='paygate-rust-candidate-v1' or d.get('package')!='paygate-client' or d.get('binary')!='paygate': raise SystemExit('cutover: candidate manifest identity mismatch')
if not isinstance(d.get('runtime_lock_identity'),str) or re.fullmatch(r'(?:darwin-volume-object-v1:[0-9a-f]{32}:[0-9]+:[0-9]+|linux-device-inode-v1:[0-9]+:[0-9]+)',d['runtime_lock_identity']) is None: raise SystemExit('cutover: candidate runtime lock identity malformed')
if not isinstance(d.get('runtime_lock_binding'),str) or not pathlib.Path(d['runtime_lock_binding']).is_absolute() or not isinstance(d.get('runtime_lock_binding_sha256'),str) or re.fullmatch(r'[0-9a-f]{64}',d['runtime_lock_binding_sha256']) is None: raise SystemExit('cutover: candidate runtime lock binding malformed')
h=hashlib.sha256((p/'paygate').read_bytes()).hexdigest()
if h!=d.get('binary_sha256'): raise SystemExit('cutover: candidate binary hash mismatch')
PY
}

if [[ "$mode" == _witness-check || "$mode" == _witness-create ]]; then
  python3 - <<'PY'
import hashlib,json,os,pathlib,stat
document=pathlib.Path(os.environ['PAYGATE_WITNESS_DOCUMENT']); acceptance=pathlib.Path(os.environ['PAYGATE_WITNESS_ACCEPTANCE']); d=json.loads(document.read_bytes()); entries=d.get('checkpoints'); session=d.get('cutover_session_id'); identity=d.get('candidate_identity'); create=os.environ['PAYGATE_WITNESS_MODE']=='create'
if not isinstance(entries,list) or not isinstance(session,str): raise SystemExit('witness: malformed acceptance')
if not create and len(entries)!=int(os.environ['PAYGATE_WITNESS_EXPECTED']): raise SystemExit('witness: count mismatch')
prior=entries[:-1] if create else entries; root=acceptance.parent/(acceptance.name+'.witnesses'); session_dir=root/session; owner=acceptance.lstat().st_uid if acceptance.exists() else os.getuid(); previous=None
def canonical_entry(entry): return json.dumps(entry,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def expected(entry,ordinal):
 w={'schema':'paygate-cutover-witness-v1','candidate_identity':identity,'acceptance_record':str(acceptance.resolve(strict=False)),'cutover_session_id':session,'ordinal':ordinal,'gate':entry.get('gate'),'entry_sha256':hashlib.sha256(canonical_entry(entry)).hexdigest(),'previous_witness_sha256':previous}
 if ordinal>7:
  installation=d.get('installation')
  if not isinstance(installation,dict): raise SystemExit('witness: installed binding absent')
  for key in ('install_session_id','installed_at_epoch','rollback_manifest_sha256','transaction_receipt','transaction_receipt_sha256','installed_launcher'): w[key]=installation.get(key)
 return w
def directory(path):
 s=path.lstat()
 if path.is_symlink() or not stat.S_ISDIR(s.st_mode) or s.st_uid!=owner or stat.S_IMODE(s.st_mode)!=0o700: raise SystemExit('witness: unsafe directory')
if prior:
 directory(root); directory(session_dir)
 expected_names={f'{i:02d}-{entry.get("gate")}.json' for i,entry in enumerate(prior,1)}
 if {p.name for p in session_dir.iterdir()}!=expected_names: raise SystemExit('witness: omission or extra file')
for ordinal,entry in enumerate(prior,1):
 path=session_dir/f'{ordinal:02d}-{entry.get("gate")}.json'; ls=path.lstat(); fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)); fs=os.fstat(fd); raw=os.read(fd,16385); os.close(fd)
 if not stat.S_ISREG(fs.st_mode) or (ls.st_dev,ls.st_ino)!=(fs.st_dev,fs.st_ino) or fs.st_uid!=owner or fs.st_nlink!=1 or stat.S_IMODE(fs.st_mode)!=0o400 or fs.st_size!=len(raw) or not raw or len(raw)>16384: raise SystemExit('witness: unsafe file')
 try: actual=json.loads(raw)
 except (UnicodeError,json.JSONDecodeError): raise SystemExit('witness: malformed JSON')
 if set(actual)!=set(expected(entry,ordinal)) or actual!=expected(entry,ordinal): raise SystemExit('witness: binding mismatch')
 previous=hashlib.sha256(raw).hexdigest()
if create:
 if not entries: raise SystemExit('witness: no prospective entry')
 if not root.exists(): os.mkdir(root,0o700); os.chmod(root,0o700)
 directory(root)
 if not session_dir.exists(): os.mkdir(session_dir,0o700); os.chmod(session_dir,0o700)
 directory(session_dir)
 ordinal=len(entries); entry=entries[-1]; name=f'{ordinal:02d}-{entry.get("gate")}.json'
 if {p.name for p in session_dir.iterdir()}!={f'{i:02d}-{e.get("gate")}.json' for i,e in enumerate(prior,1)}: raise SystemExit('witness: abandoned or extra file')
 payload=(json.dumps(expected(entry,ordinal),sort_keys=True,indent=2)+'\n').encode()
 try: fd=os.open(session_dir/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o400)
 except FileExistsError: raise SystemExit('witness: session already consumed')
 os.fchmod(fd,0o400); os.write(fd,payload); os.fsync(fd); os.close(fd); directory_fd=os.open(session_dir,os.O_RDONLY); os.fsync(directory_fd); os.close(directory_fd)
PY
  exit 0
fi

if [[ "$mode" == _process-check ]]; then
  python3 - <<'PY'
import ast,ctypes,errno,os,re,resource,shlex,struct,subprocess,sys,tempfile
old_paths={os.environ[k] for k in ('PAYGATE_OLD_ENTRY','PAYGATE_QUARANTINE_ENTRY') if os.environ.get(k)}; wrapper=os.environ.get('PAYGATE_RECORDED_WRAPPER',''); rust_target=os.environ.get('PAYGATE_RUST_TARGET','')
ignored={int(x) for x in os.environ.get('PAYGATE_IGNORE_PIDS','').split(',') if x.isdigit()}|{os.getpid(),os.getppid()}
def limit(): resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576))
try:
 with tempfile.TemporaryFile() as output:
  subprocess.run(['ps','-axo','pid=,command='],stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.DEVNULL,check=True,timeout=3,preexec_fn=limit)
  if output.tell()>1048576: raise ValueError('process output exceeds bound')
  output.seek(0); rows=output.read().decode('utf-8').splitlines()
except (OSError,subprocess.SubprocessError,UnicodeError,ValueError) as e: raise SystemExit(f'process scan unverifiable: {e}')
if len(rows)>4096: raise SystemExit('process scan unverifiable: too many rows')
python_name=re.compile(r'python(?:[0-9]+(?:\.[0-9]+)?)?$',re.I); module_name=re.compile(r'paygate(?:\..+)?$',re.I)
def exact_argv(pid,approx):
 def bounded_row_relevant():
  command=' '.join(approx)
  return any(token in old_paths or (rust_target and token==rust_target) for token in approx) or bool(re.search(r'(?:^|\s)-m\s+paygate(?:\.[A-Za-z0-9_.-]+)?(?:\s|$)|\b(?:import|from)\s+paygate\b|__import__\s*\(\s*["\x27]paygate|import_module\s*\(\s*["\x27]paygate',command,re.I))
 try:
  if sys.platform=='darwin':
   libc=ctypes.CDLL(None,use_errno=True); mib=(ctypes.c_int*3)(1,49,pid); size=ctypes.c_size_t()
   if libc.sysctl(mib,3,None,ctypes.byref(size),None,0)!=0: raise OSError(ctypes.get_errno(),'KERN_PROCARGS2 size')
   if size.value<5 or size.value>1048576: raise ValueError('argv size bound')
   capacity=size.value; buf=ctypes.create_string_buffer(capacity)
   if libc.sysctl(mib,3,buf,ctypes.byref(size),None,0)!=0: raise OSError(ctypes.get_errno(),'KERN_PROCARGS2 data')
   raw=buf.raw[:capacity]; argc=struct.unpack_from('i',raw)[0]; pos=raw.find(b'\0',4)
   if argc<1 or argc>256 or pos<0: raise ValueError('argv header')
   while pos<len(raw) and raw[pos]==0: pos+=1
   result=[]
   for _ in range(argc):
    end=raw.find(b'\0',pos)
    if end<0: raise ValueError('argv terminator')
    result.append(raw[pos:end].decode('utf-8')); pos=end+1
   return result
  proc=f'/proc/{pid}/cmdline'
  if os.path.exists(proc):
   raw=open(proc,'rb').read(1048577)
   if len(raw)>1048576: raise ValueError('argv size bound')
   return [part.decode('utf-8') for part in raw.rstrip(b'\0').split(b'\0')]
  return approx
 except OSError as e:
  if e.errno in (errno.ESRCH,errno.ENOENT): return None
  if bounded_row_relevant(): raise SystemExit(f'process scan unverifiable: exact relevant argv: {e}')
  return approx
 except (UnicodeError,ValueError) as e:
  if bounded_row_relevant(): raise SystemExit(f'process scan unverifiable: exact relevant argv: {e}')
  return approx
def imports_paygate(code):
 if len(code)>65536: raise SystemExit('process scan unverifiable: python -c bound')
 try: tree=ast.parse(code)
 except SyntaxError:
  if 'paygate' in code.lower(): raise SystemExit('process scan unverifiable: python -c syntax')
  return False
 for n in ast.walk(tree):
  if (isinstance(n,ast.Import) and any(x.name.split('.')[0]=='paygate' for x in n.names)) or (isinstance(n,ast.ImportFrom) and (n.module or '').split('.')[0]=='paygate'): return True
  if isinstance(n,ast.Call) and n.args and isinstance(n.args[0],ast.Constant) and isinstance(n.args[0].value,str) and module_name.fullmatch(n.args[0].value):
   if isinstance(n.func,ast.Name) and n.func.id=='__import__': return True
   if isinstance(n.func,ast.Attribute) and n.func.attr=='import_module' and isinstance(n.func.value,ast.Name) and n.func.value.id=='importlib': return True
 return False
def relevant(command,argv=None):
 if argv and any(token in old_paths or (rust_target and token==rust_target) for token in argv): return True
 if re.search(r'(?:^|\s)-m\s+paygate(?:\.[A-Za-z0-9_.-]+)?(?:\s|$)',command): return True
 return False
for row in rows:
 if any(path in row for path in old_paths): raise SystemExit('process scan unverifiable: protected path in raw command')
 if len(row)>8192:
  if relevant(row): raise SystemExit('process scan unverifiable: oversized relevant row')
  continue
 parts=row.strip().split(None,1)
 if len(parts)!=2 or not parts[0].isdigit():
  if 'paygate' in row.lower(): raise SystemExit('process scan unverifiable: malformed paygate row')
  continue
 pid=int(parts[0]); command=parts[1]
 if pid in ignored: continue
 try: argv=shlex.split(command)
 except ValueError:
  if 'paygate' in command.lower(): raise SystemExit('process scan unverifiable: malformed paygate argv')
  continue
 if rust_target and argv and os.path.realpath(argv[0])==os.path.realpath(rust_target): raise SystemExit(f'Rust paygate executable active: {pid}')
 # Conservative evidence pass applies to every non-helper process, regardless
 # of interpreter basename or selector position. Exact protected paths are
 # intentionally rejected even when they appear only as argument data.
 protected=[path for path in old_paths if path]+([rust_target] if rust_target else [])
 if any(path in command or any(path in token for token in argv) for path in protected): raise SystemExit(f'protected paygate path active: {pid}')
 if re.search(r'(?:^|\s)-m\s+paygate(?:\.[A-Za-z0-9_.-]+)?(?:\s|$)|\b(?:import|from)\s+paygate(?:\b|\.)|__import__\s*\(\s*["\x27]paygate(?:\.|["\x27])|(?:importlib\s*\.\s*)?import_module\s*\(\s*["\x27]paygate(?:\.|["\x27])',command,re.I): raise SystemExit(f'paygate execution evidence active: {pid}')
 if any(re.search(r'\b(?:exec|open)\s*\(\s*["\x27]'+re.escape(path)+r'["\x27]',command) for path in protected): raise SystemExit(f'protected paygate path execution active: {pid}')
 if not argv or len(argv)>256:
  if relevant(command,argv): raise SystemExit('process scan unverifiable: relevant argv bound')
  continue
 if os.path.basename(argv[0])=='env' or python_name.fullmatch(os.path.basename(argv[0])):
  argv=exact_argv(pid,argv)
  if argv is None: continue
  if not argv or len(argv)>256:
   if relevant(command,argv): raise SystemExit('process scan unverifiable: exact relevant argv bound')
   continue
 if argv[0]==wrapper or argv[0] in old_paths: raise SystemExit(f'Python paygate direct launcher active: {pid}')
 index=0
 if os.path.basename(argv[0])=='env':
  index=1
  while index<len(argv):
   token=argv[index]
   if token in ('-S','--split-string'):
    index+=1
    if index>=len(argv): raise SystemExit('process scan unverifiable: env -S missing command')
    try: expanded=shlex.split(argv[index])
    except ValueError: raise SystemExit('process scan unverifiable: env -S command')
    if not expanded or len(expanded)>64: raise SystemExit('process scan unverifiable: env -S bound')
    argv=argv[:index]+expanded+argv[index+1:]; continue
   if token in ('-i','--ignore-environment','-0','--null','-v','--debug'): index+=1; continue
   if token in ('-u','--unset','-C','--chdir'):
    index+=2
    if index>len(argv): raise SystemExit('process scan unverifiable: env option missing value')
    continue
   if token.startswith('--unset=') or token.startswith('--chdir='): index+=1; continue
   if token=='--': index+=1; break
   if '=' in token and not token.startswith('='): index+=1; continue
   if token.startswith('-'):
    if relevant(command,argv): raise SystemExit('process scan unverifiable: unknown relevant env option')
    index=len(argv); break
   break
 if index>=len(argv) or not python_name.fullmatch(os.path.basename(argv[index])): continue
 index+=1
 while index<len(argv):
  token=argv[index]
  if token=='--':
   index+=1
   if index<len(argv) and (argv[index] in old_paths or argv[index]==wrapper): raise SystemExit(f'Python paygate script active: {pid}')
   break
  if token=='-m':
   if index+1>=len(argv): raise SystemExit('process scan unverifiable: python -m missing module')
   if module_name.fullmatch(argv[index+1]): raise SystemExit(f'Python paygate module active: {pid}')
   break
  if token=='-c':
   if index+1>=len(argv): raise SystemExit('process scan unverifiable: python -c missing code')
   if imports_paygate(argv[index+1]): raise SystemExit(f'Python paygate import active: {pid}')
   break
  if token in ('-W','-X','--check-hash-based-pycs'):
   if index+1>=len(argv): raise SystemExit('process scan unverifiable: python option missing value')
   index+=2; continue
  if token.startswith('-W') or token.startswith('-X') or token.startswith('--check-hash-based-pycs='): index+=1; continue
  if token in ('-B','-d','-E','-h','-i','-I','-O','-OO','-P','-q','-s','-S','-u','-v','-V','-x','--help','--version'): index+=1; continue
  if token.startswith('-'):
   if relevant(command,argv): raise SystemExit('process scan unverifiable: unknown relevant Python option')
   break
  if token=='-': break
  if token in old_paths or token==wrapper: raise SystemExit(f'Python paygate script active: {pid}')
  break
PY
  exit 0
fi

if [[ "$mode" == _supervisor-check ]]; then
  "$0" _process-check
  python3 - <<'PY'
import os,platform,subprocess,sys
recorded=os.environ.get('PAYGATE_RECORDED_SUPERVISOR',''); rust=os.environ.get('PAYGATE_RUST_TARGET',''); wrapper=os.environ.get('PAYGATE_RECORDED_WRAPPER',''); phase=os.environ.get('PAYGATE_RUNTIME_PHASE','installed'); old_paths={os.environ.get('PAYGATE_OLD_ENTRY',''),os.environ.get('PAYGATE_QUARANTINE_ENTRY','')}-{''}
if recorded=='none-detected-launchctl-or-active-process':
 if platform.system()!='Darwin': raise SystemExit(0)
 try: rows=subprocess.run(['launchctl','list'],text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True,timeout=3).stdout.splitlines()
 except (OSError,subprocess.SubprocessError): raise SystemExit('supervisor unverifiable')
 if len(rows)>4096 or any('paygate' in row.lower() for row in rows): raise SystemExit('supervisor/paygate label drift')
 raise SystemExit(0)
if not recorded.startswith('launchctl:') or platform.system()!='Darwin': raise SystemExit('supervisor identity unknown')
label=recorded.split(':',1)[1]
try:
 rows=subprocess.run(['launchctl','list'],text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True,timeout=3).stdout.splitlines(); matches=[row for row in rows if 'paygate' in row.lower()]
 detail=subprocess.run(['launchctl','print',f'gui/{os.getuid()}/{label}'],text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True,timeout=3).stdout if matches else ''
except (OSError,subprocess.SubprocessError): raise SystemExit('supervisor unverifiable')
if len(matches)>1 or (matches and matches[0].split()[-1]!=label): raise SystemExit('supervisor label drift')
if phase in ('preinstall','rollback'):
 if len(matches)!=1 or not matches[0].lstrip().startswith('-'): raise SystemExit('recorded supervisor must remain listed and stopped before mutation')
 if wrapper not in detail and rust not in detail: raise SystemExit('supervisor configuration is not reconcilable')
 raise SystemExit(0)
if len(matches)!=1 or (wrapper not in detail and rust not in detail) or any(path in detail for path in old_paths) or 'pid =' not in detail: raise SystemExit('supervisor is not exact Rust service')
PY
  exit 0
fi

if [[ "$mode" == _runtime-check ]]; then
  python3 - <<'PY'
import hashlib,json,os,pathlib,stat,subprocess,sys
manifest_path=pathlib.Path(os.environ['PAYGATE_RUNTIME_MANIFEST']); candidate=pathlib.Path(os.environ['PAYGATE_RUNTIME_CANDIDATE']); r=json.load(open(manifest_path)); m=json.load(open(candidate/'manifest.json')); receipt=pathlib.Path(r['transaction_receipt'])
sys.path.insert(0,str(pathlib.Path(os.environ['PAYGATE_RUNTIME_SCRIPT']).parent)); from runtime_lock_identity import path_identity
def full(s): return (s.st_dev,s.st_ino,s.st_uid,stat.S_IMODE(s.st_mode),s.st_size,s.st_nlink)
identity={k:m[k] for k in ('source_commit','cargo_lock_sha256','binary_sha256','rust_target')}; binary=candidate/'paygate'; bs=binary.stat(); launcher=pathlib.Path(r['launcher']); ls=launcher.lstat(); resolved=launcher.resolve(strict=True).stat(); original=pathlib.Path(r['python_environment_original']); quarantine=pathlib.Path(r['python_environment_quarantine']); qs=quarantine.stat(); old=quarantine/r['python_paygate_relative']; olds=old.stat(); qe=r['python_environment_identity']; oe=r['python_paygate_identity']
receipt_ls=receipt.lstat(); fd=os.open(receipt,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)); receipt_fs=os.fstat(fd); receipt_raw=os.read(fd,16385); os.close(fd); receipt_data=json.loads(receipt_raw); manifest_hash=hashlib.sha256(manifest_path.read_bytes()).hexdigest()
if r.get('schema')!='paygate-rust-rollback-v3' or r.get('candidate_identity')!=identity or not stat.S_ISLNK(ls.st_mode) or os.readlink(launcher)!=r['installed_rust_launcher_target'] or (resolved.st_dev,resolved.st_ino)!=(bs.st_dev,bs.st_ino) or hashlib.sha256(binary.read_bytes()).hexdigest()!=identity['binary_sha256']: raise SystemExit('runtime state: Rust launcher/candidate mismatch')
if original.exists() or original.is_symlink() or quarantine.is_symlink() or path_identity(quarantine)!=qe['stable'] or (qs.st_uid,stat.S_IMODE(qs.st_mode))!=(qe['uid'],qe['mode']) or old.is_symlink() or not stat.S_ISREG(olds.st_mode) or path_identity(old)!=oe['stable'] or (olds.st_uid,stat.S_IMODE(olds.st_mode),olds.st_size)!=(oe['uid'],oe['mode'],oe['size']) or hashlib.sha256(old.read_bytes()).hexdigest()!=oe['sha256']: raise SystemExit('runtime state: quarantine mismatch')
receipt_keys={'schema','candidate_identity','acceptance_record','cutover_session_id','install_session_id','installed_at_epoch','rollback_directory','rollback_manifest_sha256','python_launcher_target','installed_rust_launcher_target'}
if not stat.S_ISREG(receipt_fs.st_mode) or full(receipt_ls)!=full(receipt_fs) or receipt_fs.st_nlink!=1 or stat.S_IMODE(receipt_fs.st_mode)!=0o400 or set(receipt_data)!=receipt_keys or receipt_data.get('schema')!='paygate-rust-cutover-receipt-v1' or receipt_data.get('candidate_identity')!=identity or receipt_data.get('acceptance_record')!=str(pathlib.Path(r['acceptance_record']).resolve()) or receipt_data.get('rollback_directory')!=str(manifest_path.parent.resolve()) or receipt_data.get('rollback_manifest_sha256')!=manifest_hash or any(receipt_data.get(k)!=r.get(k) for k in ('cutover_session_id','install_session_id','installed_at_epoch','python_launcher_target','installed_rust_launcher_target')): raise SystemExit('runtime state: receipt/session mismatch')
env=os.environ.copy(); env.update(PAYGATE_OLD_ENTRY=str(original/r['python_paygate_relative']),PAYGATE_QUARANTINE_ENTRY=str(old),PAYGATE_RECORDED_WRAPPER=str(launcher),PAYGATE_RECORDED_SUPERVISOR=r['supervisor'],PAYGATE_RUST_TARGET=r['installed_rust_launcher_target'])
subprocess.run([os.environ['PAYGATE_RUNTIME_SCRIPT'],'_supervisor-check'],env=env,check=True,timeout=8,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
PY
  exit 0
fi

if [[ "$mode" == checkpoint ]]; then
  [[ -n "$acceptance" && -n "$gate" && -n "$operator" && "$confirm" == yes ]] || usage
  candidate_check
  if [[ "$gate" == installed-doctor-pass || "$gate" == restart-cache-pass || "$gate" == runtime-only-pass ]]; then
    [[ -n "$record" && -n "$rollback" && -f "$rollback/manifest.json" ]] || { echo "checkpoint: preflight record and rollback directory required for installed gates" >&2; exit 2; }
    python3 - "$record" "$candidate" "$rollback" "$acceptance" "$gate" "$operator" "$result" "$0" <<'PY'
import fcntl,hashlib,json,os,pathlib,re,shlex,stat,subprocess,sys,tempfile,time
pre=json.load(open(sys.argv[1])); candidate=pathlib.Path(sys.argv[2]); rollback=pathlib.Path(sys.argv[3]); acceptance=pathlib.Path(sys.argv[4]); gate,operator,result=sys.argv[5:8]; script=pathlib.Path(sys.argv[8]); manifest_path=rollback/'manifest.json'; candidate_manifest_path=candidate/'manifest.json'; candidate_binary=candidate/'paygate'; launcher=pathlib.Path(pre['deployment']['launcher'])
def meta(s): return (s.st_dev,s.st_ino,s.st_uid,stat.S_IMODE(s.st_mode),s.st_size,s.st_nlink)
def read_fd(fd,limit):
 data=bytearray(); os.lseek(fd,0,os.SEEK_SET)
 while True:
  chunk=os.read(fd,min(65536,limit+1-len(data)))
  if not chunk: return bytes(data)
  data.extend(chunk)
  if len(data)>limit: raise SystemExit('checkpoint: authoritative input exceeds bound')
def open_snapshot(path,limit):
 before=path.lstat(); fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)); current=os.fstat(fd)
 if not stat.S_ISREG(current.st_mode) or meta(before)!=meta(current): raise SystemExit('checkpoint: unstable/nonregular input')
 raw=read_fd(fd,limit); return fd,meta(current),raw,hashlib.sha256(raw).hexdigest()
acceptance_pre=meta(acceptance.lstat())
# This pre-lock read locates the receipt only; it grants no authority. The
# manifest is reopened and parsed from a held descriptor after the lock.
locator_fd,_,locator_raw,_=open_snapshot(manifest_path,131072); os.close(locator_fd); receipt=pathlib.Path(json.loads(locator_raw).get('transaction_receipt','/'))
lock_fd=os.open(acceptance.parent/(acceptance.name+'.lock'),os.O_CREAT|os.O_RDWR,0o600); fcntl.flock(lock_fd,fcntl.LOCK_EX)
replacement=os.environ.get('PAYGATE_CUTOVER_TEST_CHECKPOINT_REPLACEMENT')
if replacement: os.replace(replacement,acceptance)
if meta(acceptance.lstat())!=acceptance_pre: raise SystemExit('checkpoint: acceptance replaced while acquiring lock')
paths=(acceptance,manifest_path,receipt,candidate_manifest_path,candidate_binary); limits=(1048576,131072,16384,131072,134217728); held=[open_snapshot(p,n) for p,n in zip(paths,limits)]
acceptance_fd,acceptance_meta,acceptance_raw,_=held[0]; manifest_fd,manifest_meta,manifest_raw,manifest_hash=held[1]; receipt_fd,receipt_meta,receipt_raw,receipt_hash=held[2]; candidate_manifest_fd,candidate_manifest_meta,candidate_manifest_raw,_=held[3]; candidate_fd,candidate_meta,candidate_raw,candidate_hash=held[4]
m=json.loads(candidate_manifest_raw); r=json.loads(manifest_raw); a=json.loads(acceptance_raw); identity={k:m[k] for k in ('source_commit','cargo_lock_sha256','binary_sha256','rust_target')}
if receipt_meta[3]!=0o400 or receipt_meta[5]!=1 or receipt_meta[4]<=0 or receipt_meta[4]>16384 or receipt_meta[2] not in (0,pre['deployment']['process_uid']): raise SystemExit('checkpoint: untrusted transaction receipt object')
receipt_data=json.loads(receipt_raw)
installation=a.get('installation'); install_keys={'cutover_session_id','install_session_id','installed_at_epoch','rollback_manifest_sha256','transaction_receipt','transaction_receipt_sha256','installed_launcher'}
if r.get('schema')!='paygate-rust-rollback-v3' or r.get('candidate_identity')!=identity or r.get('acceptance_record')!=str(acceptance.resolve()) or r.get('rollback_directory')!=str(rollback.resolve()): raise SystemExit('checkpoint: rollback manifest identity mismatch')
receipt_keys={'schema','candidate_identity','acceptance_record','cutover_session_id','install_session_id','installed_at_epoch','rollback_directory','rollback_manifest_sha256','python_launcher_target','installed_rust_launcher_target'}
if set(receipt_data)!=receipt_keys or receipt_data.get('schema')!='paygate-rust-cutover-receipt-v1' or receipt_data.get('candidate_identity')!=identity or receipt_data.get('acceptance_record')!=str(acceptance.resolve()) or receipt_data.get('rollback_directory')!=str(rollback.resolve()) or receipt_data.get('rollback_manifest_sha256')!=manifest_hash or any(receipt_data.get(k)!=r.get(k) for k in ('cutover_session_id','install_session_id','installed_at_epoch','python_launcher_target','installed_rust_launcher_target')): raise SystemExit('checkpoint: transaction receipt identity mismatch')
if set(a)!= {'schema','candidate_identity','cutover_session_id','phase','checkpoints','installation'} or a.get('schema')!='paygate-cutover-acceptance-v2' or a.get('phase') not in ('installed','postinstall-accepted') or a.get('candidate_identity')!=identity or not isinstance(installation,dict) or set(installation)!=install_keys: raise SystemExit('checkpoint: malformed installed acceptance')
if any(installation.get(k)!=r.get(k) for k in ('cutover_session_id','install_session_id','installed_at_epoch')) or installation.get('rollback_manifest_sha256')!=manifest_hash or installation.get('transaction_receipt')!=str(receipt) or installation.get('transaction_receipt_sha256')!=hashlib.sha256(receipt_raw).hexdigest() or installation.get('installed_launcher')!=str(launcher): raise SystemExit('checkpoint: installed session binding mismatch')
launcher_lstat=launcher.lstat(); launcher_link=os.readlink(launcher); resolved_lstat=launcher.resolve(strict=True).stat()
if not stat.S_ISLNK(launcher_lstat.st_mode) or launcher_link!=r['installed_rust_launcher_target'] or (resolved_lstat.st_dev,resolved_lstat.st_ino)!=(candidate_meta[0],candidate_meta[1]) or candidate_hash!=m['binary_sha256']: raise SystemExit('checkpoint: installed launcher identity mismatch')
original_env=pathlib.Path(r['python_environment_original']); quarantine=pathlib.Path(r['python_environment_quarantine']); old=quarantine/r['python_paygate_relative']
def scan():
 env=os.environ.copy(); env.update(PAYGATE_RUNTIME_MANIFEST=str(manifest_path),PAYGATE_RUNTIME_CANDIDATE=str(candidate),PAYGATE_RUNTIME_WRAPPER=pre['deployment']['resolved_launcher'],PAYGATE_RUNTIME_SCRIPT=str(script),PAYGATE_RUNTIME_PHASE='installed',PAYGATE_IGNORE_PIDS=f'{os.getpid()},{os.getppid()}')
 subprocess.run([str(script),'_runtime-check'],env=env,check=True,timeout=10,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
scan()
allowed=['fixture-oracle-pass','rust-product-tests-pass','candidate-doctor-pass','invoice-approved','invoice-pass','request-approved','request-pass','installed-doctor-pass','restart-cache-pass','runtime-only-pass']; idx=allowed.index(gate); entries=a.get('checkpoints')
if not isinstance(entries,list) or [x.get('gate') if isinstance(x,dict) else None for x in entries]!=allowed[:idx]: raise SystemExit('checkpoint: installed gates must be appended exactly once and in order')
def ident(v): return isinstance(v,str) and 0<len(v)<=128 and re.fullmatch(r'[A-Za-z0-9._:-]+',v) is not None
previous=0
for entry in entries:
 g=entry['gate']; wanted={'gate','passed','recorded_at_epoch','operator','cutover_session_id'}|({'name','max_amount_sats','max_fee_sats','daily_cap_sats'} if g=='invoice-approved' else {'name'} if g=='request-approved' else {'result'})|(install_keys if g in allowed[7:] else set())
 if set(entry)!=wanted or entry.get('passed') is not True or entry.get('cutover_session_id')!=a.get('cutover_session_id') or not ident(entry.get('operator')): raise SystemExit('checkpoint: malformed prior checkpoint')
 ts=entry.get('recorded_at_epoch')
 if isinstance(ts,bool) or not isinstance(ts,int) or ts<=0 or ts<previous: raise SystemExit('checkpoint: malformed prior timestamp')
 previous=ts
 if g in allowed[7:] and any(entry.get(k)!=installation.get(k) for k in install_keys): raise SystemExit('checkpoint: stale prior installed checkpoint')
 if g=='invoice-approved' and (not ident(entry.get('name')) or any(isinstance(entry.get(k),bool) or not isinstance(entry.get(k),int) or entry[k]<=0 for k in ('max_amount_sats','max_fee_sats','daily_cap_sats'))): raise SystemExit('checkpoint: malformed invoice approval')
 if g=='request-approved' and not ident(entry.get('name')): raise SystemExit('checkpoint: malformed request approval')
 if g not in ('invoice-approved','request-approved') and entry.get('result')!='PASS': raise SystemExit('checkpoint: malformed PASS result')
if not ident(operator) or result!='PASS': raise SystemExit('checkpoint: operator and explicit PASS required')
entry={'gate':gate,'passed':True,'recorded_at_epoch':max(int(time.time()),installation['installed_at_epoch'],previous),'operator':operator,'result':'PASS'}; entry.update(installation); entries.append(entry); a['phase']='postinstall-accepted' if idx==9 else 'installed'
fd,tmp=tempfile.mkstemp(prefix=acceptance.name+'.',dir=acceptance.parent); os.fchmod(fd,0o600)
with os.fdopen(fd,'w') as f: json.dump(a,f,sort_keys=True,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
witness_env=os.environ.copy(); witness_env.update(PAYGATE_WITNESS_DOCUMENT=tmp,PAYGATE_WITNESS_ACCEPTANCE=str(acceptance),PAYGATE_WITNESS_MODE='create')
subprocess.run([str(script),'_witness-create'],env=witness_env,check=True,stdin=subprocess.DEVNULL,timeout=5)
hook=os.environ.get('PAYGATE_CUTOVER_TEST_PRECOMMIT_SWAP')
if hook: os.unlink(tmp); raise SystemExit('checkpoint: test-only precommit transient swap rejected')
for path,(held_fd,held_meta,held_raw,held_hash) in zip(paths,held):
 if meta(path.lstat())!=held_meta or meta(os.fstat(held_fd))!=held_meta or hashlib.sha256(read_fd(held_fd,len(held_raw))).hexdigest()!=held_hash: os.unlink(tmp); raise SystemExit('checkpoint: authoritative input changed before commit')
if meta(launcher.lstat())!=meta(launcher_lstat) or os.readlink(launcher)!=launcher_link or (launcher.resolve(strict=True).stat().st_dev,launcher.resolve(strict=True).stat().st_ino)!=(candidate_meta[0],candidate_meta[1]): os.unlink(tmp); raise SystemExit('checkpoint: launcher changed before commit')
scan()
os.replace(tmp,acceptance); directory_fd=os.open(acceptance.parent,os.O_RDONLY); os.fsync(directory_fd); os.close(directory_fd)
try: scan()
except BaseException:
 restore_fd,restore_tmp=tempfile.mkstemp(prefix=acceptance.name+'.restore.',dir=acceptance.parent); os.fchmod(restore_fd,0o600)
 with os.fdopen(restore_fd,'wb') as f: f.write(acceptance_raw); f.flush(); os.fsync(f.fileno())
 os.replace(restore_tmp,acceptance); directory_fd=os.open(acceptance.parent,os.O_RDONLY); os.fsync(directory_fd); os.close(directory_fd)
 raise SystemExit('checkpoint: post-commit process scan failed; checkpoint reverted')
PY
    echo "checkpoint: $gate recorded"; exit 0
  fi
  python3 - "$acceptance" "$candidate/manifest.json" "$gate" "$operator" "$name" "$result" "$max_amount" "$max_fee" "$daily_cap" "$0" <<'PY'
import fcntl,hashlib,json,os,pathlib,re,secrets,subprocess,sys,tempfile,time
path,manifest_path,gate,operator,name,result,amount,fee,daily=sys.argv[1:10]
script=pathlib.Path(sys.argv[10])
allowed=['fixture-oracle-pass','rust-product-tests-pass','candidate-doctor-pass','invoice-approved','invoice-pass','request-approved','request-pass','installed-doctor-pass','restart-cache-pass','runtime-only-pass']
if gate not in allowed: raise SystemExit('checkpoint: unknown gate')
m=json.load(open(manifest_path)); p=pathlib.Path(path); p.parent.mkdir(parents=True,exist_ok=True); lock_fd=os.open(p.parent/(p.name+'.lock'),os.O_CREAT|os.O_RDWR,0o600); fcntl.flock(lock_fd,fcntl.LOCK_EX)
identity={k:m[k] for k in ('source_commit','cargo_lock_sha256','binary_sha256','rust_target')}
d=json.load(open(p)) if p.exists() else {'schema':'paygate-cutover-acceptance-v2','candidate_identity':identity,'cutover_session_id':secrets.token_hex(16),'phase':'preinstall-recording','checkpoints':[]}
def identifier(value): return isinstance(value,str) and 0<len(value)<=128 and re.fullmatch(r'[A-Za-z0-9._:-]+',value) is not None
def valid(current, expected):
 has_installation='installation' in current
 expected_keys={'schema','candidate_identity','cutover_session_id','phase','checkpoints'}|({'installation'} if has_installation else set())
 if set(current)!=expected_keys or current.get('schema')!='paygate-cutover-acceptance-v2' or current.get('candidate_identity')!=identity or set(identity)!=set(('source_commit','cargo_lock_sha256','binary_sha256','rust_target')) or not re.fullmatch(r'[0-9a-f]{32}',current.get('cutover_session_id','')): return False
 expected_phase='postinstall-accepted' if len(expected)==10 else 'installed' if has_installation else 'preinstall-accepted' if len(expected)==7 else 'preinstall-recording'
 if current.get('phase')!=expected_phase: return False
 installation=current.get('installation')
 if has_installation:
  if not isinstance(installation,dict) or set(installation)!= {'cutover_session_id','install_session_id','installed_at_epoch','rollback_manifest_sha256','installed_launcher'} or installation.get('cutover_session_id')!=current.get('cutover_session_id') or not re.fullmatch(r'[0-9a-f]{32}',installation.get('install_session_id','')) or not re.fullmatch(r'[0-9a-f]{64}',installation.get('rollback_manifest_sha256','')) or not isinstance(installation.get('installed_at_epoch'),int) or not isinstance(installation.get('installed_launcher'),str): return False
 if not all(isinstance(identity[k],str) and identity[k] for k in identity) or not all(re.fullmatch(r'[0-9a-f]{64}',identity[k]) for k in ('cargo_lock_sha256','binary_sha256')): return False
 entries=current.get('checkpoints');
 if not isinstance(entries,list) or [x.get('gate') if isinstance(x,dict) else None for x in entries]!=expected: return False
 previous=0
 for entry in entries:
  g=entry['gate']; base={'gate','passed','recorded_at_epoch','operator','cutover_session_id'}; wanted=base|({'name','max_amount_sats','max_fee_sats','daily_cap_sats'} if g=='invoice-approved' else {'name'} if g=='request-approved' else {'result'})
  if g in allowed[7:]: wanted|={'cutover_session_id','install_session_id','installed_at_epoch','rollback_manifest_sha256','installed_launcher'}
  if set(entry)!=wanted or entry.get('passed') is not True or entry.get('cutover_session_id')!=current.get('cutover_session_id') or not identifier(entry.get('operator')): return False
  timestamp=entry.get('recorded_at_epoch')
  if isinstance(timestamp,bool) or not isinstance(timestamp,int) or timestamp<=0 or timestamp<previous: return False
  if len(expected)>7 and g.startswith(('installed-','restart-','runtime-')):
   for k in ('cutover_session_id','install_session_id','installed_at_epoch','rollback_manifest_sha256','installed_launcher'):
    if entry.get(k)!=installation.get(k): return False
   if timestamp<installation['installed_at_epoch']: return False
  previous=timestamp
  if g=='invoice-approved':
   if not identifier(entry.get('name')) or any(isinstance(entry.get(k),bool) or not isinstance(entry.get(k),int) or entry[k]<=0 for k in ('max_amount_sats','max_fee_sats','daily_cap_sats')): return False
  elif g=='request-approved':
   if not identifier(entry.get('name')): return False
  elif entry.get('result')!='PASS': return False
 return True
done=[x.get('gate') if isinstance(x,dict) else None for x in d.get('checkpoints',[])] if isinstance(d,dict) and isinstance(d.get('checkpoints'),list) else []
if not valid(d,allowed[:len(done)]): raise SystemExit('checkpoint: malformed or candidate-mismatched acceptance record')
if not identifier(operator): raise SystemExit('checkpoint: invalid operator identifier')
idx=allowed.index(gate)
if gate in done or done != allowed[:idx]: raise SystemExit('checkpoint: gates must be recorded exactly once and in order')
entry={'gate':gate,'passed':True,'recorded_at_epoch':int(time.time()),'operator':operator,'cutover_session_id':d['cutover_session_id']}
if idx>=7:
    installation=d['installation']; entry.update(installation)
if gate=='invoice-approved':
    if not name or not all(x.isdigit() and int(x)>0 for x in (amount,fee,daily)): raise SystemExit('checkpoint: named invoice and positive caps required')
    entry.update(name=name,max_amount_sats=int(amount),max_fee_sats=int(fee),daily_cap_sats=int(daily))
elif gate=='request-approved':
    if not name: raise SystemExit('checkpoint: named protected request required')
    entry['name']=name
elif gate.endswith('-pass'):
    if result!='PASS': raise SystemExit('checkpoint: explicit PASS result required')
    entry['result']='PASS'
d['checkpoints'].append(entry)
d['phase']='preinstall-accepted' if idx==6 else 'postinstall-accepted' if idx==9 else d['phase']
if not valid(d,allowed[:idx+1]): raise SystemExit('checkpoint: generated acceptance record failed schema validation')
fd,tmp=tempfile.mkstemp(prefix=p.name+'.',dir=p.parent); os.fchmod(fd,0o600)
with os.fdopen(fd,'w') as f: json.dump(d,f,sort_keys=True,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
env=os.environ.copy(); env.update(PAYGATE_WITNESS_DOCUMENT=tmp,PAYGATE_WITNESS_ACCEPTANCE=str(p),PAYGATE_WITNESS_MODE='create')
subprocess.run([str(script),'_witness-create'],env=env,check=True,stdin=subprocess.DEVNULL,timeout=5)
os.replace(tmp,p); parent_fd=os.open(p.parent,os.O_RDONLY); os.fsync(parent_fd); os.close(parent_fd)
PY
  echo "checkpoint: $gate recorded"; exit 0
fi

[[ -n "$record" && "$record" == /* ]] || usage

if [[ "$mode" == install ]]; then
  [[ -n "$repo" && -n "$candidate" && -n "$rollback" && -n "$acceptance" ]] || usage
  repo=$(cd "$repo" && pwd -P); candidate=$(cd "$candidate" && pwd -P)
  [[ "$rollback" == /* && ! -e "$rollback" && "$rollback" != / && "$rollback" != "$repo" && "$rollback" != "$repo"/* ]] || { echo "cutover: unsafe rollback path" >&2; exit 2; }
  candidate_check
  read -r target launcher process_present < <(python3 - "$record" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); x=d['deployment']; print(x['rust_target'],x['launcher'],str(x.get('process_present',False)).lower())
PY
)
  [[ "$process_present" == false ]] || { echo "cutover: preflight recorded an active product process" >&2; exit 1; }
  "$repo/scripts/preflight-minimal-rust-cutover.sh" guard --for install --repo "$repo" --record "$record" --target "$target" >/dev/null
  python3 - "$repo" "$record" "$candidate/manifest.json" <<'PY'
import hashlib,json,pathlib,subprocess,sys
repo=pathlib.Path(sys.argv[1]); pre=json.load(open(sys.argv[2])); m=json.load(open(sys.argv[3]))
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
lock=hashlib.sha256((repo/'Cargo.lock').read_bytes()).hexdigest()
if m['source_commit']!=commit or m['cargo_lock_sha256']!=lock or m['rust_target']!=pre['deployment']['rust_target']: raise SystemExit('cutover: candidate source, lock, or target mismatch')
PY
  acceptance_snapshot=$(python3 - "$acceptance" "$candidate/manifest.json" <<'PY'
import hashlib,json,os,pathlib,re,sys
a=json.load(open(sys.argv[1])); m=json.load(open(sys.argv[2])); required=['fixture-oracle-pass','rust-product-tests-pass','candidate-doctor-pass','invoice-approved','invoice-pass','request-approved','request-pass']; all_required=required+['installed-doctor-pass','restart-cache-pass','runtime-only-pass']; keys=('source_commit','cargo_lock_sha256','binary_sha256','rust_target'); identity={k:m[k] for k in keys}
def ident(v): return isinstance(v,str) and 0<len(v)<=128 and re.fullmatch(r'[A-Za-z0-9._:-]+',v) is not None
if set(a)!= {'schema','candidate_identity','cutover_session_id','phase','checkpoints'} or a.get('schema')!='paygate-cutover-acceptance-v2' or a.get('phase')!='preinstall-accepted' or not re.fullmatch(r'[0-9a-f]{32}',a.get('cutover_session_id','')) or a.get('candidate_identity')!=identity or set(a.get('candidate_identity',{}))!=set(keys): raise SystemExit('cutover: acceptance is not a fresh pre-install session')
if not all(isinstance(identity[k],str) and identity[k] for k in keys) or not all(re.fullmatch(r'[0-9a-f]{64}',identity[k]) for k in ('cargo_lock_sha256','binary_sha256')): raise SystemExit('cutover: acceptance candidate identity malformed')
entries=a.get('checkpoints')
gates=[x.get('gate') if isinstance(x,dict) else None for x in entries] if isinstance(entries,list) else None
if gates != required: raise SystemExit('cutover: product acceptance gates incomplete, stale, or reordered')
previous=0
for entry in entries:
 g=entry['gate']; wanted={'gate','passed','recorded_at_epoch','operator','cutover_session_id'}|({'name','max_amount_sats','max_fee_sats','daily_cap_sats'} if g=='invoice-approved' else {'name'} if g=='request-approved' else {'result'})
 if set(entry)!=wanted or entry.get('passed') is not True or entry.get('cutover_session_id')!=a.get('cutover_session_id') or not ident(entry.get('operator')): raise SystemExit('cutover: malformed acceptance checkpoint')
 timestamp=entry.get('recorded_at_epoch')
 if isinstance(timestamp,bool) or not isinstance(timestamp,int) or timestamp<=0 or timestamp<previous: raise SystemExit('cutover: malformed acceptance timestamp')
 previous=timestamp
 if g=='invoice-approved':
  if not ident(entry.get('name')) or any(isinstance(entry.get(k),bool) or not isinstance(entry.get(k),int) or entry[k]<=0 for k in ('max_amount_sats','max_fee_sats','daily_cap_sats')): raise SystemExit('cutover: malformed invoice approval')
 elif g=='request-approved':
  if not ident(entry.get('name')): raise SystemExit('cutover: malformed request approval')
 elif entry.get('result')!='PASS': raise SystemExit('cutover: malformed PASS result')
raw=pathlib.Path(sys.argv[1]).read_bytes(); st=os.stat(sys.argv[1])
print(a['cutover_session_id'],hashlib.sha256(raw).hexdigest(),st.st_dev,st.st_ino,sep='\t')
PY
)
  IFS=$'\t' read -r cutover_session acceptance_sha acceptance_dev acceptance_ino <<< "$acceptance_snapshot"
  PAYGATE_WITNESS_DOCUMENT="$acceptance" PAYGATE_WITNESS_ACCEPTANCE="$acceptance" PAYGATE_WITNESS_EXPECTED=7 PAYGATE_WITNESS_MODE=check "$0" _witness-check
  stage=$(mktemp -d "$(dirname "$rollback")/.paygate-rollback.XXXXXX")
  trap '[[ -n "${stage:-}" && -d "$stage" ]] && rm -rf -- "$stage" || true' EXIT
  python3 - "$record" "$stage" "$candidate/manifest.json" "$candidate/paygate" "$repo" "$acceptance" "$rollback" "$cutover_session" <<'PY'
import hashlib,json,os,pathlib,re,resource,secrets,selectors,shutil,signal,stat,subprocess,sys,tempfile,time
record,out,manifest_path,candidate_binary,repo,acceptance,rollback=map(pathlib.Path,sys.argv[1:8]); cutover_session=sys.argv[8]; d=json.load(open(record)); dep=d['deployment']; state=d['state']; candidate_manifest=json.load(open(manifest_path))
sys.path.insert(0,str(repo/'scripts')); from runtime_lock_identity import descriptor_identity,path_identity
launcher=pathlib.Path(dep['launcher']); resolved=pathlib.Path(dep['resolved_launcher'])
if not launcher.is_symlink() or launcher.resolve()!=resolved.resolve(): raise SystemExit('cutover: launcher changed before backup')
def overlaps(a,b):
 try: a.relative_to(b); return True
 except ValueError: pass
 try: b.relative_to(a); return True
 except ValueError: return False
dist=resolved.parent.parent; owner_uid=dep.get('process_uid')
if not isinstance(owner_uid,int) or isinstance(owner_uid,bool) or not resolved.is_absolute() or resolved.parent.name!='bin' or resolved.name!='paygate' or len(dist.parts)<4: raise SystemExit('cutover: old environment path is broad or malformed')
for p in (dist,resolved):
 if p.is_symlink() or p.resolve(strict=True)!=p or p.lstat().st_uid!=owner_uid: raise SystemExit('cutover: old environment identity mismatch')
if not dist.is_dir() or not resolved.is_file() or not stat.S_ISREG(resolved.stat().st_mode) or not os.access(resolved,os.X_OK) or hashlib.sha256(resolved.read_bytes()).hexdigest()!=dep.get('resolved_launcher_sha256'): raise SystemExit('cutover: old paygate launcher identity mismatch')
dist_stat=dist.stat(); launcher_stat=resolved.stat(); old_relative=str(resolved.relative_to(dist))
shared=[pathlib.Path('/usr'),pathlib.Path('/usr/local'),pathlib.Path('/opt'),pathlib.Path('/opt/homebrew'),pathlib.Path('/opt/local')]
if any(dist==p or overlaps(dist,p) for p in shared): raise SystemExit('cutover: system/shared Python prefix refused')
exclusions=[launcher.parent.resolve(strict=True),repo.resolve(strict=True),candidate_binary.parent.resolve(strict=True),acceptance.resolve(strict=True),rollback.parent.resolve(strict=True)/rollback.name]
exclusions += [pathlib.Path(state[k]).resolve(strict=True) for k in ('config','wallet_storage','credential_cache','ledger')]
if any(overlaps(dist,p) for p in exclusions): raise SystemExit('cutover: isolated venv overlaps protected deployment path')
items=[]
def digest(p):
 h=hashlib.sha256()
 if p.is_symlink(): h.update(os.readlink(p).encode())
 elif p.is_file(): h.update(p.read_bytes())
 elif p.is_dir():
  for q in sorted(p.rglob('*')):
   h.update(str(q.relative_to(p)).encode()+b'\0')
   if q.is_symlink(): h.update(os.readlink(q).encode())
   elif q.is_file(): h.update(q.read_bytes())
 return h.hexdigest()
for key in ('config','wallet_storage','credential_cache','ledger'):
 p=pathlib.Path(state[key])
 if not p.exists() and not p.is_symlink(): raise SystemExit(f'cutover: missing state backup source: {key}')
 if p.is_symlink(): raise SystemExit(f'cutover: state root symlinks are not safely restorable: {key}')
 if not p.is_file() and not p.is_dir(): raise SystemExit(f'cutover: unsupported state path type: {key}')
 dest=out/'state'/key; dest.parent.mkdir(parents=True,exist_ok=True)
 if p.is_dir(): shutil.copytree(p,dest,symlinks=True)
 else: shutil.copy2(p,dest,follow_symlinks=False)
 ps=p.parent.stat(); ds=dest.stat()
 items.append({'key':key,'path':str(p),'path_type':'directory' if p.is_dir() else 'file','parent_canonical':str(p.parent.resolve(strict=True)),'parent_dev':ps.st_dev,'parent_ino':ps.st_ino,'backup':str(pathlib.Path('state')/key),'backup_dev':ds.st_dev,'backup_ino':ds.st_ino,'sha256':digest(dest)})
identity={k:candidate_manifest[k] for k in ('source_commit','cargo_lock_sha256','binary_sha256','rust_target')}
receipt=acceptance.parent/(acceptance.name+'.cutover-'+cutover_session+'.receipt.json')
install_session=secrets.token_hex(16); quarantine=dist.parent/('.'+dist.name+'.paygate-disabled-'+install_session)
if quarantine.exists() or quarantine.is_symlink() or quarantine.parent.resolve()!=dist.parent.resolve(): raise SystemExit('cutover: unsafe quarantine path')
runtime_lock=str(launcher.parent/'.paygate-runtime.lock'); runtime_marker=str(launcher.parent/'.paygate-runtime.lock.transaction.json')
try: runtime_fd=os.open(runtime_lock,os.O_RDWR|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
except OSError: raise SystemExit('cutover: candidate deployment lock binding mismatch')
runtime_fs=os.fstat(runtime_fd); runtime_ls=pathlib.Path(runtime_lock).lstat(); runtime_identity=descriptor_identity(runtime_fd); os.close(runtime_fd)
binding=pathlib.Path(candidate_manifest.get('runtime_lock_binding',''))
try: binding_fd=os.open(binding,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)); binding_fs=os.fstat(binding_fd); binding_raw=os.read(binding_fd,16385); os.close(binding_fd)
except OSError: raise SystemExit('cutover: candidate deployment lock binding mismatch')
if binding.parent!=launcher.parent or binding.name not in ('.paygate-runtime.lock.binding.json','.paygate-runtime.lock.binding-v2.json') or not stat.S_ISREG(binding_fs.st_mode) or binding_fs.st_uid!=owner_uid or binding_fs.st_nlink!=1 or stat.S_IMODE(binding_fs.st_mode)!=0o400 or binding_fs.st_size!=len(binding_raw) or not binding_raw or len(binding_raw)>16384 or hashlib.sha256(binding_raw).hexdigest()!=candidate_manifest.get('runtime_lock_binding_sha256'): raise SystemExit('cutover: candidate deployment lock binding mismatch')
if candidate_manifest.get('runtime_lock')!=runtime_lock or candidate_manifest.get('runtime_transaction_marker')!=runtime_marker or candidate_manifest.get('runtime_lock_uid')!=owner_uid or candidate_manifest.get('runtime_lock_identity')!=runtime_identity or not stat.S_ISREG(runtime_fs.st_mode) or (runtime_ls.st_dev,runtime_ls.st_ino)!=(runtime_fs.st_dev,runtime_fs.st_ino) or runtime_fs.st_uid!=owner_uid or runtime_fs.st_nlink!=1 or stat.S_IMODE(runtime_fs.st_mode)!=0o600: raise SystemExit('cutover: candidate deployment lock binding mismatch')
manifest={'schema':'paygate-rust-rollback-v3','cutover_session_id':cutover_session,'install_session_id':install_session,'installed_at_epoch':int(time.time()),'candidate_identity':identity,'launcher':str(launcher),'launcher_symlink_target':dep.get('launcher_symlink_target'),'resolved_launcher':dep.get('resolved_launcher'),'resolved_launcher_sha256':dep.get('resolved_launcher_sha256'),'process_uid':owner_uid,'runtime_lock':runtime_lock,'runtime_lock_dev':runtime_fs.st_dev,'runtime_lock_ino':runtime_fs.st_ino,'runtime_lock_identity':runtime_identity,'runtime_lock_binding':str(binding),'runtime_lock_binding_sha256':hashlib.sha256(binding_raw).hexdigest(),'runtime_transaction_marker':runtime_marker,'supervisor':dep.get('supervisor'),'python_launcher_target':os.readlink(launcher),'installed_rust_launcher_target':str(candidate_binary.resolve()),'python_environment_original':str(dist),'python_environment_quarantine':str(quarantine),'python_environment_identity':{'stable':path_identity(dist),'dev':dist_stat.st_dev,'ino':dist_stat.st_ino,'uid':dist_stat.st_uid,'mode':stat.S_IMODE(dist_stat.st_mode)},'python_paygate_relative':old_relative,'python_paygate_identity':{'stable':path_identity(resolved),'dev':launcher_stat.st_dev,'ino':launcher_stat.st_ino,'uid':launcher_stat.st_uid,'mode':stat.S_IMODE(launcher_stat.st_mode),'size':launcher_stat.st_size,'sha256':hashlib.sha256(resolved.read_bytes()).hexdigest()},'repository':str(repo.resolve()),'acceptance_record':str(acceptance.resolve()),'rollback_directory':str(rollback.resolve(strict=False)),'transaction_receipt':str(receipt),'state':items}
(out/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n'); os.chmod(out/'manifest.json',0o400)
PY
  mv "$stage" "$rollback"; stage=""
  python3 - "$rollback" <<'PY'
import os,pathlib,sys
p=pathlib.Path(sys.argv[1]); fd=os.open(p.parent,os.O_RDONLY); os.fsync(fd); os.close(fd)
if os.environ.get('PAYGATE_CUTOVER_TEST_HOOK')=='after-rollback': raise SystemExit('cutover: test hook after rollback publication')
PY
  python3 - "$acceptance" "$rollback/manifest.json" "$launcher" "$acceptance_sha" "$acceptance_dev" "$acceptance_ino" "$0" <<'PY'
import fcntl,hashlib,json,os,pathlib,re,shlex,stat,subprocess,sys,tempfile,time
p=pathlib.Path(sys.argv[1]); manifest_path=pathlib.Path(sys.argv[2]); launcher=pathlib.Path(sys.argv[3]); expected_sha=sys.argv[4]; expected_dev=int(sys.argv[5]); expected_ino=int(sys.argv[6]); script=pathlib.Path(sys.argv[7]); r=json.load(open(manifest_path)); hook=os.environ.get('PAYGATE_CUTOVER_TEST_HOOK','')
sys.path.insert(0,str(script.parent)); from runtime_lock_identity import descriptor_identity,path_identity
lock_path=p.parent/(p.name+'.lock'); lock_fd=os.open(lock_path,os.O_CREAT|os.O_RDWR,0o600); fcntl.flock(lock_fd,fcntl.LOCK_EX)
runtime_path=pathlib.Path(r['runtime_lock'])
try: runtime_fd=os.open(runtime_path,os.O_RDWR|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
except OSError: raise SystemExit('cutover: deployment runtime lock is unavailable')
runtime_fs=os.fstat(runtime_fd); runtime_ls=runtime_path.lstat()
if not stat.S_ISREG(runtime_fs.st_mode) or (runtime_ls.st_dev,runtime_ls.st_ino)!=(runtime_fs.st_dev,runtime_fs.st_ino) or descriptor_identity(runtime_fd)!=r['runtime_lock_identity'] or runtime_fs.st_uid!=r['process_uid'] or runtime_fs.st_nlink!=1 or stat.S_IMODE(runtime_fs.st_mode)!=0o600: raise SystemExit('cutover: deployment runtime lock identity mismatch')
try: fcntl.flock(runtime_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError: raise SystemExit('cutover: Rust paygate is active')
runtime_ls=runtime_path.lstat()
if (runtime_ls.st_dev,runtime_ls.st_ino)!=(runtime_fs.st_dev,runtime_fs.st_ino): raise SystemExit('cutover: deployment runtime lock changed while installing')
runtime_marker=pathlib.Path(r['runtime_transaction_marker'])
if runtime_marker.exists() or runtime_marker.is_symlink(): raise SystemExit('cutover: deployment recovery is required')
def sync_dir(path): fd=os.open(path,os.O_RDONLY); os.fsync(fd); os.close(fd)
def ident(v): return isinstance(v,str) and 0<len(v)<=128 and re.fullmatch(r'[A-Za-z0-9._:-]+',v) is not None
if hook=='replace-acceptance':
 replacement=pathlib.Path(os.environ['PAYGATE_CUTOVER_TEST_ACCEPTANCE_REPLACEMENT']); os.replace(replacement,p); sync_dir(p.parent)
raw=p.read_bytes(); st=p.stat(); a=json.loads(raw)
required=['fixture-oracle-pass','rust-product-tests-pass','candidate-doctor-pass','invoice-approved','invoice-pass','request-approved','request-pass']; identity=r['candidate_identity']
if hashlib.sha256(raw).hexdigest()!=expected_sha or st.st_dev!=expected_dev or st.st_ino!=expected_ino: raise SystemExit('cutover: acceptance path or snapshot replaced before publication')
if set(a)!= {'schema','candidate_identity','cutover_session_id','phase','checkpoints'} or a.get('schema')!='paygate-cutover-acceptance-v2' or a.get('phase')!='preinstall-accepted' or a.get('candidate_identity')!=identity or a.get('cutover_session_id')!=r.get('cutover_session_id') or not re.fullmatch(r'[0-9a-f]{32}',a.get('cutover_session_id','')): raise SystemExit('cutover: acceptance session changed while installing')
entries=a.get('checkpoints'); gates=[x.get('gate') if isinstance(x,dict) else None for x in entries] if isinstance(entries,list) else None
if gates!=required: raise SystemExit('cutover: acceptance gates changed while installing')
witness_env=os.environ.copy(); witness_env.update(PAYGATE_WITNESS_DOCUMENT=str(p),PAYGATE_WITNESS_ACCEPTANCE=str(p),PAYGATE_WITNESS_EXPECTED='7',PAYGATE_WITNESS_MODE='check')
subprocess.run([str(script),'_witness-check'],env=witness_env,check=True,stdin=subprocess.DEVNULL,timeout=5)
previous=0
for entry in entries:
 g=entry['gate']; wanted={'gate','passed','recorded_at_epoch','operator','cutover_session_id'}|({'name','max_amount_sats','max_fee_sats','daily_cap_sats'} if g=='invoice-approved' else {'name'} if g=='request-approved' else {'result'})
 if set(entry)!=wanted or entry.get('passed') is not True or entry.get('cutover_session_id')!=a.get('cutover_session_id') or not ident(entry.get('operator')): raise SystemExit('cutover: malformed acceptance checkpoint at publication')
 ts=entry.get('recorded_at_epoch')
 if isinstance(ts,bool) or not isinstance(ts,int) or ts<=0 or ts<previous: raise SystemExit('cutover: malformed acceptance timestamp at publication')
 previous=ts
 if g=='invoice-approved':
  if not ident(entry.get('name')) or any(isinstance(entry.get(k),bool) or not isinstance(entry.get(k),int) or entry[k]<=0 for k in ('max_amount_sats','max_fee_sats','daily_cap_sats')): raise SystemExit('cutover: malformed invoice approval at publication')
 elif g=='request-approved':
  if not ident(entry.get('name')): raise SystemExit('cutover: malformed request approval at publication')
 elif entry.get('result')!='PASS': raise SystemExit('cutover: malformed PASS at publication')
scan_env=os.environ.copy(); original_env=pathlib.Path(r['python_environment_original']); quarantine=pathlib.Path(r['python_environment_quarantine']); scan_env.update(PAYGATE_OLD_ENTRY=str(original_env/r['python_paygate_relative']),PAYGATE_QUARANTINE_ENTRY=str(quarantine/r['python_paygate_relative']),PAYGATE_RECORDED_WRAPPER=str(launcher),PAYGATE_IGNORE_PIDS=f'{os.getpid()},{os.getppid()}',PAYGATE_RECORDED_SUPERVISOR=r['supervisor'],PAYGATE_RUST_TARGET=r['installed_rust_launcher_target'],PAYGATE_RUNTIME_PHASE='preinstall')
original=r['python_launcher_target']; rust=r['installed_rust_launcher_target']; manifest_hash=hashlib.sha256(manifest_path.read_bytes()).hexdigest()
receipt=pathlib.Path(r['transaction_receipt'])
receipt_data={'schema':'paygate-rust-cutover-receipt-v1','candidate_identity':identity,'acceptance_record':str(p.resolve()),'cutover_session_id':r['cutover_session_id'],'install_session_id':r['install_session_id'],'installed_at_epoch':r['installed_at_epoch'],'rollback_directory':str(manifest_path.parent.resolve()),'rollback_manifest_sha256':manifest_hash,'python_launcher_target':r['python_launcher_target'],'installed_rust_launcher_target':r['installed_rust_launcher_target']}
try: receipt_fd=os.open(receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400)
except FileExistsError: raise SystemExit('cutover: cutover session receipt already exists')
with os.fdopen(receipt_fd,'w') as f: json.dump(receipt_data,f,sort_keys=True,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
sync_dir(receipt.parent)
if hook=='after-receipt': raise SystemExit('cutover: test hook after receipt')
install_marker={'schema':'paygate-rust-install-recovery-v1','install_session_id':r['install_session_id'],'rollback_manifest_sha256':manifest_hash,'process_uid':r['process_uid'],'runtime_lock':str(runtime_path),'runtime_lock_dev':runtime_fs.st_dev,'runtime_lock_ino':runtime_fs.st_ino,'launcher':str(launcher),'python_launcher_target':original,'installed_rust_launcher_target':rust}
pending_install=runtime_marker.parent/(runtime_marker.name+'.pending-install-'+r['install_session_id'])
if pending_install.exists() or pending_install.is_symlink(): raise SystemExit('cutover: unsafe pending install marker')
marker_fd=os.open(pending_install,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
with os.fdopen(marker_fd,'w') as f: json.dump(install_marker,f,sort_keys=True,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(pending_install,runtime_marker); sync_dir(runtime_marker.parent)
tmp_link=launcher.parent/('.paygate-cutover-'+str(os.getpid()))
os.symlink(rust,tmp_link); os.replace(tmp_link,launcher); sync_dir(launcher.parent)
if not launcher.is_symlink() or os.readlink(launcher)!=rust or launcher.resolve()!=pathlib.Path(rust).resolve(): raise SystemExit('cutover: maintenance launcher switch failed; rollback is required')
subprocess.run([str(script),'_supervisor-check'],env=scan_env,check=True,timeout=8,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
if hook=='pause-after-final-scan':
 ready=pathlib.Path(os.environ['PAYGATE_CUTOVER_TEST_INSTALL_READY']); release=pathlib.Path(os.environ['PAYGATE_CUTOVER_TEST_INSTALL_RELEASE']); ready.write_text('ready\n'); sync_dir(ready.parent); deadline=time.monotonic()+8
 while not release.exists():
  if time.monotonic()>=deadline: raise SystemExit('cutover: timed out waiting for install race test release')
  time.sleep(0.01)
installation={'cutover_session_id':r['cutover_session_id'],'install_session_id':r['install_session_id'],'installed_at_epoch':r['installed_at_epoch'],'rollback_manifest_sha256':manifest_hash,'transaction_receipt':str(receipt),'transaction_receipt_sha256':hashlib.sha256(receipt.read_bytes()).hexdigest(),'installed_launcher':str(launcher)}
a['phase']='installed'; a['installation']=installation
fd,tmp=tempfile.mkstemp(prefix=p.name+'.',dir=p.parent); os.fchmod(fd,0o600)
with os.fdopen(fd,'w') as f: json.dump(a,f,sort_keys=True,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(tmp,p); sync_dir(p.parent)
if hook=='after-acceptance': raise SystemExit('cutover: test hook after acceptance')
if hook=='force-switch-failure':
 restore=launcher.parent/('.paygate-restore-'+str(os.getpid())); os.symlink(original,restore); os.replace(restore,launcher); sync_dir(launcher.parent)
 runtime_marker.unlink(); sync_dir(runtime_marker.parent)
 raise SystemExit('cutover: launcher switch failed and original launcher was restored')
try:
 os.rename(original_env,quarantine); sync_dir(quarantine.parent)
 qstat=quarantine.stat(); expected=r['python_environment_identity']; old=quarantine/r['python_paygate_relative']; oldstat=old.stat(); old_expected=r['python_paygate_identity']
 if original_env.exists() or original_env.is_symlink() or path_identity(quarantine)!=expected['stable'] or (qstat.st_dev,qstat.st_ino,qstat.st_uid,stat.S_IMODE(qstat.st_mode))!=(expected['dev'],expected['ino'],expected['uid'],expected['mode']) or not old.is_file() or old.is_symlink() or path_identity(old)!=old_expected['stable'] or (oldstat.st_dev,oldstat.st_ino,oldstat.st_uid,stat.S_IMODE(oldstat.st_mode),oldstat.st_size)!=(old_expected['dev'],old_expected['ino'],old_expected['uid'],old_expected['mode'],old_expected['size']) or hashlib.sha256(old.read_bytes()).hexdigest()!=old_expected['sha256']: raise RuntimeError('quarantine verification failed')
 env=os.environ.copy(); env.update(PAYGATE_OLD_ENTRY=str(original_env/r['python_paygate_relative']),PAYGATE_QUARANTINE_ENTRY=str(old),PAYGATE_RECORDED_WRAPPER=str(launcher),PAYGATE_IGNORE_PIDS=f'{os.getpid()},{os.getppid()}',PAYGATE_RECORDED_SUPERVISOR=r['supervisor'],PAYGATE_RUST_TARGET=r['installed_rust_launcher_target'],PAYGATE_RUNTIME_PHASE='installed')
 subprocess.run([str(script),'_supervisor-check'],env=env,check=True,timeout=8,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
except BaseException as error:
 if quarantine.exists() and not original_env.exists(): os.rename(quarantine,original_env); sync_dir(original_env.parent)
 restore=launcher.parent/('.paygate-restore-'+str(os.getpid())); os.symlink(original,restore); os.replace(restore,launcher); sync_dir(launcher.parent)
 runtime_marker.unlink(); sync_dir(runtime_marker.parent)
 raise SystemExit(f'cutover: quarantine failed and original deployment was restored: {error}')
if hook=='after-launcher': raise SystemExit('cutover: test hook after launcher and quarantine')
runtime_marker.unlink(); sync_dir(runtime_marker.parent)
PY
  echo "cutover install: PASS"; exit 0
fi

if [[ "$mode" == rollback ]]; then
  [[ -n "$rollback" && -f "$rollback/manifest.json" ]] || { echo "rollback: missing backup" >&2; exit 2; }
  if ! python3 "$(dirname "$0")/rollback-rust-paygate.py" "$rollback" "$record" "$0"; then
    echo "rollback: failed; if the runtime recovery marker exists, retain it and rerun this rollback command" >&2
    exit 1
  fi
  echo "rollback: PASS (Python paygate restored; no payment invoked)"; exit 0
fi

if [[ "$mode" == finalize ]]; then
  [[ -n "$repo" && -n "$candidate" && -n "$rollback" && -n "$acceptance" && -n "$recovery" && "$confirm" == FINALIZE_RUST_AND_RETAIN_QUARANTINE ]] || usage
  [[ "$repo" == /* && "$record" == /* && "$candidate" == /* && "$rollback" == /* && "$acceptance" == /* && "$recovery" == /* ]] || { echo "finalize: all paths must be absolute" >&2; exit 2; }
  repo=$(cd "$repo" && pwd -P); candidate=$(cd "$candidate" && pwd -P); candidate_check
  target=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["deployment"]["rust_target"])' "$record")
  "$repo/scripts/preflight-minimal-rust-cutover.sh" guard --for build --repo "$repo" --record "$record" --target "$target" >/dev/null
  set +e
  python3 - "$record" "$candidate" "$rollback" "$acceptance" "$recovery" "$0" <<'PY'
import fcntl,hashlib,json,os,pathlib,shutil,stat,sys,tempfile

pre_path,candidate_path,rb,acceptance,recovery,script=map(pathlib.Path,sys.argv[1:])
pre=json.load(open(pre_path)); manifest=json.load(open(candidate_path/'manifest.json'))
identity={k:manifest[k] for k in ('source_commit','cargo_lock_sha256','binary_sha256','rust_target')}
launcher=pathlib.Path(pre['deployment']['launcher']); marker=launcher.parent/'.paygate-runtime.lock.transaction.json'; uid=pre['deployment']['process_uid']; hook=os.environ.get('PAYGATE_CUTOVER_TEST_HOOK')
sys.path.insert(0,str(script.parent)); from runtime_lock_identity import descriptor_identity,path_identity
def sync_dir(path):
 fd=os.open(path,os.O_RDONLY)
 try: os.fsync(fd)
 finally: os.close(fd)
def read_bound(path,maximum,label,mode=0o600,owners=None):
 try:
  ls=path.lstat(); fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)); fs=os.fstat(fd); raw=os.read(fd,maximum+1); os.close(fd); data=json.loads(raw)
 except (OSError,ValueError): raise SystemExit(f'finalize: {label} is unsafe')
 if not stat.S_ISREG(fs.st_mode) or (ls.st_dev,ls.st_ino)!=(fs.st_dev,fs.st_ino) or fs.st_uid not in ({uid} if owners is None else owners) or fs.st_nlink!=1 or stat.S_IMODE(fs.st_mode)!=mode or fs.st_size!=len(raw) or not raw or len(raw)>maximum: raise SystemExit(f'finalize: {label} is unsafe')
 return raw,data
def expected_recovery(original,quarantine):
 return {'schema':'paygate-rust-recovery-boundary-v3','candidate_identity':identity,'python_paygate_deactivated':True,'python_environment_cleanup_required':True,'python_environment_original':original,'python_environment_quarantine':quarantine,'rollback_authority_retired':True,'rollback_directory':str(rb.resolve(strict=False))}
tombstones=list(rb.parent.glob('.'+rb.name+'.finalize-retired-*'))
if not marker.exists() and not marker.is_symlink():
 if tombstones: raise SystemExit('finalize: rollback retirement exists without recovery marker')
 if recovery.exists() or recovery.is_symlink():
  if rb.exists() or rb.is_symlink(): raise SystemExit('finalize: recovery record exists while rollback authority remains')
  recovery_raw,recovery_data=read_bound(recovery,16384,'recovery record')
  expected=expected_recovery(recovery_data.get('python_environment_original'),recovery_data.get('python_environment_quarantine'))
  original=pathlib.Path(recovery_data.get('python_environment_original','')); quarantine=pathlib.Path(recovery_data.get('python_environment_quarantine',''))
  if recovery_data!=expected or original.exists() or original.is_symlink() or not quarantine.is_dir() or quarantine.is_symlink() or not launcher.is_symlink() or os.readlink(launcher)!=str((candidate_path/'paygate').resolve()) or hashlib.sha256((candidate_path/'paygate').read_bytes()).hexdigest()!=identity['binary_sha256']: raise SystemExit('finalize: terminal recovery boundary mismatch')
  raise SystemExit(42)
 if not rb.is_dir() or rb.is_symlink(): raise SystemExit('finalize: rollback authority is missing')
 raise SystemExit(0)
marker_raw,journal=read_bound(marker,16384,'recovery marker')
keys={'schema','candidate_identity','cutover_session_id','install_session_id','process_uid','repository','preflight_sha256','runtime_lock','runtime_lock_dev','runtime_lock_ino','runtime_lock_uid','runtime_lock_mode','runtime_lock_identity','rollback_directory','rollback_retirement_path','rollback_identity','rollback_dev','rollback_ino','rollback_uid','rollback_mode','rollback_manifest_sha256','acceptance_record','acceptance_sha256','transaction_receipt','transaction_receipt_sha256','recovery_record','recovery_sha256','launcher','installed_rust_launcher_target','python_environment_original','python_environment_quarantine','python_environment_identity','python_paygate_identity'}
lock=pathlib.Path(journal.get('runtime_lock','')); tombstone=pathlib.Path(journal.get('rollback_retirement_path',''))
if set(journal)!=keys or journal.get('schema')!='paygate-rust-finalize-recovery-v1' or journal.get('candidate_identity')!=identity or journal.get('process_uid')!=uid or journal.get('repository')!=pre.get('repository') or journal.get('preflight_sha256')!=hashlib.sha256(pre_path.read_bytes()).hexdigest() or journal.get('rollback_directory')!=str(rb.resolve(strict=False)) or tombstone!=rb.parent/('.'+rb.name+'.finalize-retired-'+journal.get('install_session_id','')) or journal.get('acceptance_record')!=str(acceptance.resolve()) or journal.get('recovery_record')!=str(recovery.resolve(strict=False)) or journal.get('launcher')!=str(launcher) or journal.get('installed_rust_launcher_target')!=str((candidate_path/'paygate').resolve()) or lock!=launcher.parent/'.paygate-runtime.lock': raise SystemExit('finalize: recovery marker identity mismatch')
try: lock_fd=os.open(lock,os.O_RDWR|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
except OSError: raise SystemExit('finalize: deployment runtime lock is unavailable')
lock_fs=os.fstat(lock_fd); lock_ls=lock.lstat()
if not stat.S_ISREG(lock_fs.st_mode) or (lock_ls.st_dev,lock_ls.st_ino)!=(lock_fs.st_dev,lock_fs.st_ino) or (lock_fs.st_dev,lock_fs.st_ino,lock_fs.st_uid,stat.S_IMODE(lock_fs.st_mode))!=(journal['runtime_lock_dev'],journal['runtime_lock_ino'],journal['runtime_lock_uid'],journal['runtime_lock_mode']) or lock_fs.st_uid!=uid or lock_fs.st_nlink!=1 or stat.S_IMODE(lock_fs.st_mode)!=0o600 or descriptor_identity(lock_fd)!=journal['runtime_lock_identity']: raise SystemExit('finalize: deployment runtime lock identity mismatch')
try: fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError: raise SystemExit('finalize: Rust paygate is active')
acceptance_raw,_=read_bound(acceptance,16384,'acceptance record'); receipt=pathlib.Path(journal['transaction_receipt']); receipt_raw,_=read_bound(receipt,16384,'transaction receipt',0o400,{0,uid})
original=pathlib.Path(journal['python_environment_original']); quarantine=pathlib.Path(journal['python_environment_quarantine'])
if hashlib.sha256(acceptance_raw).hexdigest()!=journal['acceptance_sha256'] or hashlib.sha256(receipt_raw).hexdigest()!=journal['transaction_receipt_sha256'] or original.exists() or original.is_symlink() or not quarantine.is_dir() or quarantine.is_symlink() or path_identity(quarantine)!=journal['python_environment_identity'] or not launcher.is_symlink() or os.readlink(launcher)!=journal['installed_rust_launcher_target'] or hashlib.sha256(pathlib.Path(journal['installed_rust_launcher_target']).read_bytes()).hexdigest()!=identity['binary_sha256']: raise SystemExit('finalize: recovery journal binding mismatch')
recovery_data=expected_recovery(str(original),str(quarantine)); wanted_raw=(json.dumps(recovery_data,sort_keys=True,indent=2)+'\n').encode()
if hashlib.sha256(wanted_raw).hexdigest()!=journal['recovery_sha256']: raise SystemExit('finalize: recovery journal hash mismatch')
if recovery.exists() or recovery.is_symlink():
 recovery_raw,actual=read_bound(recovery,16384,'recovery record')
 if recovery_raw!=wanted_raw or actual!=recovery_data: raise SystemExit('finalize: recovery record identity mismatch')
else:
 if not rb.is_dir() or rb.is_symlink() or tombstone.exists() or tombstone.is_symlink(): raise SystemExit('finalize: recovery journal has no intact rollback authority')
 rb_stat=rb.stat()
 if path_identity(rb)!=journal['rollback_identity'] or (rb_stat.st_dev,rb_stat.st_ino,rb_stat.st_uid,stat.S_IMODE(rb_stat.st_mode))!=(journal['rollback_dev'],journal['rollback_ino'],journal['rollback_uid'],journal['rollback_mode']) or hashlib.sha256((rb/'manifest.json').read_bytes()).hexdigest()!=journal['rollback_manifest_sha256']: raise SystemExit('finalize: rollback authority identity mismatch')
 recovery_fd,tmp_name=tempfile.mkstemp(prefix=recovery.name+'.pending.',dir=recovery.parent); tmp=pathlib.Path(tmp_name); os.fchmod(recovery_fd,0o600)
 with os.fdopen(recovery_fd,'wb') as f: f.write(wanted_raw); f.flush(); os.fsync(f.fileno())
 os.replace(tmp,recovery); sync_dir(recovery.parent)
if hook=='after-finalize-recovery': raise SystemExit('finalize: test hook after recovery record publication')
if rb.exists() or rb.is_symlink():
 if tombstone.exists() or tombstone.is_symlink() or not rb.is_dir() or rb.is_symlink(): raise SystemExit('finalize: unsafe rollback retirement shape')
 rb_stat=rb.stat()
 if path_identity(rb)!=journal['rollback_identity'] or (rb_stat.st_dev,rb_stat.st_ino,rb_stat.st_uid,stat.S_IMODE(rb_stat.st_mode))!=(journal['rollback_dev'],journal['rollback_ino'],journal['rollback_uid'],journal['rollback_mode']) or hashlib.sha256((rb/'manifest.json').read_bytes()).hexdigest()!=journal['rollback_manifest_sha256']: raise SystemExit('finalize: rollback retirement identity mismatch')
 os.replace(rb,tombstone); sync_dir(tombstone.parent)
if tombstone.exists() or tombstone.is_symlink():
 if not tombstone.is_dir() or tombstone.is_symlink(): raise SystemExit('finalize: rollback retirement path is unsafe')
 tombstone_stat=tombstone.stat()
 if path_identity(tombstone)!=journal['rollback_identity'] or (tombstone_stat.st_dev,tombstone_stat.st_ino,tombstone_stat.st_uid,stat.S_IMODE(tombstone_stat.st_mode))!=(journal['rollback_dev'],journal['rollback_ino'],journal['rollback_uid'],journal['rollback_mode']): raise SystemExit('finalize: rollback retirement identity mismatch')
 if hook=='after-finalize-retirement': raise SystemExit('finalize: test hook after rollback retirement')
 if hook=='during-finalize-cleanup':
  partial=tombstone/'manifest.json'
  if partial.exists(): partial.unlink(); sync_dir(tombstone)
  raise SystemExit('finalize: test hook during rollback cleanup')
 shutil.rmtree(tombstone); sync_dir(tombstone.parent)
if rb.exists() or rb.is_symlink() or tombstone.exists() or tombstone.is_symlink(): raise SystemExit('finalize: rollback authority retirement failed')
if hook=='after-finalize-rollback': raise SystemExit('finalize: test hook after rollback retirement')
marker.unlink(); sync_dir(marker.parent); raise SystemExit(42)
PY
  finalize_recovery_status=$?
  set -e
  if (( finalize_recovery_status == 42 )); then
    echo "cutover finalize: PASS; Python environment quarantined for external cleanup at $recovery"; exit 0
  elif (( finalize_recovery_status != 0 )); then
    exit "$finalize_recovery_status"
  fi
  python3 - "$record" "$candidate" "$rollback" "$acceptance" "$recovery" "$0" <<'PY'
import fcntl,hashlib,json,os,pathlib,re,shlex,shutil,stat,subprocess,sys,tempfile
pre=json.load(open(sys.argv[1])); candidate,rb,acceptance,recovery=map(pathlib.Path,sys.argv[2:6]); script=pathlib.Path(sys.argv[6]); m=json.load(open(candidate/'manifest.json')); manifest_path=rb/'manifest.json'; r=json.load(open(manifest_path)); a=json.load(open(acceptance)); identity={k:m[k] for k in ('source_commit','cargo_lock_sha256','binary_sha256','rust_target')}
sys.path.insert(0,str(script.parent)); from runtime_lock_identity import path_identity
if r.get('schema')!='paygate-rust-rollback-v3' or r.get('candidate_identity')!=identity or r.get('acceptance_record')!=str(acceptance.resolve()) or r.get('rollback_directory')!=str(rb.resolve()) or r.get('repository')!=pre.get('repository') or r.get('supervisor')!=pre['deployment'].get('supervisor') or {x['key']:x['path'] for x in r.get('state',[])}!={k:pre['state'][k] for k in ('config','wallet_storage','credential_cache','ledger')}: raise SystemExit('finalize: rollback/preflight identity mismatch')
receipt=pathlib.Path(r['transaction_receipt']); ls=receipt.lstat(); fd=os.open(receipt,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)); fs=os.fstat(fd); receipt_raw=os.read(fd,16385); receipt_data=json.loads(receipt_raw); manifest_hash=hashlib.sha256(manifest_path.read_bytes()).hexdigest()
receipt_keys={'schema','candidate_identity','acceptance_record','cutover_session_id','install_session_id','installed_at_epoch','rollback_directory','rollback_manifest_sha256','python_launcher_target','installed_rust_launcher_target'}
if not stat.S_ISREG(fs.st_mode) or (ls.st_dev,ls.st_ino)!=(fs.st_dev,fs.st_ino) or fs.st_uid not in (0,pre['deployment']['process_uid']) or fs.st_nlink!=1 or stat.S_IMODE(fs.st_mode)!=0o400 or fs.st_size!=len(receipt_raw) or not receipt_raw or len(receipt_raw)>16384 or set(receipt_data)!=receipt_keys or receipt_data.get('schema')!='paygate-rust-cutover-receipt-v1' or receipt_data.get('candidate_identity')!=identity or receipt_data.get('acceptance_record')!=str(acceptance.resolve()) or receipt_data.get('rollback_directory')!=str(rb.resolve()) or receipt_data.get('rollback_manifest_sha256')!=manifest_hash or any(receipt_data.get(k)!=r.get(k) for k in ('cutover_session_id','install_session_id','installed_at_epoch','python_launcher_target','installed_rust_launcher_target')): raise SystemExit('finalize: receipt mismatch')
required=['fixture-oracle-pass','rust-product-tests-pass','candidate-doctor-pass','invoice-approved','invoice-pass','request-approved','request-pass','installed-doctor-pass','restart-cache-pass','runtime-only-pass']; entries=a.get('checkpoints'); installation=a.get('installation',{}); install_keys={'cutover_session_id','install_session_id','installed_at_epoch','rollback_manifest_sha256','transaction_receipt','transaction_receipt_sha256','installed_launcher'}
if set(a)!= {'schema','candidate_identity','cutover_session_id','phase','checkpoints','installation'} or a.get('schema')!='paygate-cutover-acceptance-v2' or a.get('phase')!='postinstall-accepted' or a.get('candidate_identity')!=identity or [x.get('gate') if isinstance(x,dict) else None for x in entries or []]!=required or a.get('cutover_session_id')!=r['cutover_session_id'] or set(installation)!=install_keys or any(installation.get(k)!=r.get(k) for k in ('cutover_session_id','install_session_id','installed_at_epoch')) or installation.get('rollback_manifest_sha256')!=manifest_hash or installation.get('transaction_receipt')!=str(receipt) or installation.get('transaction_receipt_sha256')!=hashlib.sha256(receipt_raw).hexdigest() or installation.get('installed_launcher')!=r['launcher']: raise SystemExit('finalize: acceptance/session mismatch')
witness_env=os.environ.copy(); witness_env.update(PAYGATE_WITNESS_DOCUMENT=str(acceptance),PAYGATE_WITNESS_ACCEPTANCE=str(acceptance),PAYGATE_WITNESS_EXPECTED='10',PAYGATE_WITNESS_MODE='check')
subprocess.run([str(script),'_witness-check'],env=witness_env,check=True,stdin=subprocess.DEVNULL,timeout=5)
def ident(v): return isinstance(v,str) and 0<len(v)<=128 and re.fullmatch(r'[A-Za-z0-9._:-]+',v) is not None
previous=0
for entry in entries:
 gate=entry['gate']; wanted={'gate','passed','recorded_at_epoch','operator','cutover_session_id'}|({'name','max_amount_sats','max_fee_sats','daily_cap_sats'} if gate=='invoice-approved' else {'name'} if gate=='request-approved' else {'result'})|(install_keys if gate in required[7:] else set())
 if set(entry)!=wanted or entry.get('passed') is not True or entry.get('cutover_session_id')!=a['cutover_session_id'] or not ident(entry.get('operator')): raise SystemExit('finalize: malformed checkpoint fields')
 timestamp=entry.get('recorded_at_epoch')
 if isinstance(timestamp,bool) or not isinstance(timestamp,int) or timestamp<=0 or timestamp<previous: raise SystemExit('finalize: malformed checkpoint timestamp')
 previous=timestamp
 if gate=='invoice-approved':
  if not ident(entry.get('name')) or any(isinstance(entry.get(k),bool) or not isinstance(entry.get(k),int) or entry[k]<=0 for k in ('max_amount_sats','max_fee_sats','daily_cap_sats')): raise SystemExit('finalize: malformed invoice approval')
 elif gate=='request-approved':
  if not ident(entry.get('name')): raise SystemExit('finalize: malformed request approval')
 elif entry.get('result')!='PASS': raise SystemExit('finalize: malformed PASS result')
 if gate in required[7:] and (timestamp<installation['installed_at_epoch'] or any(entry.get(k)!=installation.get(k) for k in install_keys)): raise SystemExit('finalize: stale installed checkpoint')
launcher=pathlib.Path(r['launcher']); rust=pathlib.Path(r['installed_rust_launcher_target']); original=pathlib.Path(r['python_environment_original']); quarantine=pathlib.Path(r['python_environment_quarantine']); q=quarantine.stat(); qe=r['python_environment_identity']; old=quarantine/r['python_paygate_relative']; olds=old.stat(); oe=r['python_paygate_identity']
if not launcher.is_symlink() or os.readlink(launcher)!=str(rust) or launcher.resolve()!=rust.resolve() or hashlib.sha256(rust.read_bytes()).hexdigest()!=identity['binary_sha256'] or original.exists() or original.is_symlink() or quarantine.is_symlink() or path_identity(quarantine)!=qe['stable'] or (q.st_uid,stat.S_IMODE(q.st_mode))!=(qe['uid'],qe['mode']) or old.is_symlink() or not old.is_file() or path_identity(old)!=oe['stable'] or (olds.st_uid,stat.S_IMODE(olds.st_mode),olds.st_size)!=(oe['uid'],oe['mode'],oe['size']) or hashlib.sha256(old.read_bytes()).hexdigest()!=oe['sha256']: raise SystemExit('finalize: Rust/quarantine identity mismatch')
def scan():
 env=os.environ.copy(); env.update(PAYGATE_RUNTIME_MANIFEST=str(manifest_path),PAYGATE_RUNTIME_CANDIDATE=str(candidate),PAYGATE_RUNTIME_WRAPPER=pre['deployment']['resolved_launcher'],PAYGATE_RUNTIME_SCRIPT=str(script),PAYGATE_RUNTIME_PHASE='finalize',PAYGATE_IGNORE_PIDS=f'{os.getpid()},{os.getppid()}')
 subprocess.run([str(script),'_runtime-check'],env=env,check=True,timeout=10,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
def sync_dir(path): fd=os.open(path,os.O_RDONLY); os.fsync(fd); os.close(fd)
scan()
if recovery.exists() or recovery.is_symlink() or not recovery.parent.is_dir(): raise SystemExit('finalize: unsafe recovery record')
tombstone=rb.parent/('.'+rb.name+'.finalize-retired-'+r['install_session_id'])
if tombstone.exists() or tombstone.is_symlink(): raise SystemExit('finalize: unsafe rollback retirement path')
rb_stat=rb.stat(); rb_identity=path_identity(rb)
data={'schema':'paygate-rust-recovery-boundary-v3','candidate_identity':identity,'python_paygate_deactivated':True,'python_environment_cleanup_required':True,'python_environment_original':str(original),'python_environment_quarantine':str(quarantine),'rollback_authority_retired':True,'rollback_directory':str(rb.resolve())}
recovery_raw=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode()
# Recheck directly at the boundary; quarantine is deliberately retained.
if original.exists() or not quarantine.is_dir() or os.readlink(launcher)!=str(rust): raise SystemExit('finalize: retirement state drift')
boundary_ls=receipt.lstat(); boundary_fd=os.open(receipt,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)); boundary_fs=os.fstat(boundary_fd); boundary_raw=os.read(boundary_fd,16385); os.close(boundary_fd)
if not stat.S_ISREG(boundary_fs.st_mode) or (boundary_ls.st_dev,boundary_ls.st_ino)!=(boundary_fs.st_dev,boundary_fs.st_ino) or boundary_fs.st_nlink!=1 or stat.S_IMODE(boundary_fs.st_mode)!=0o400 or boundary_raw!=receipt_raw or json.loads(boundary_raw)!=receipt_data: raise SystemExit('finalize: receipt drift at removal boundary')
if hashlib.sha256(rust.read_bytes()).hexdigest()!=identity['binary_sha256'] or original.exists() or not quarantine.is_dir() or path_identity(quarantine)!=qe['stable'] or old.is_symlink() or path_identity(old)!=oe['stable'] or hashlib.sha256(old.read_bytes()).hexdigest()!=oe['sha256']: raise SystemExit('finalize: runtime identity drift at removal boundary')
subprocess.run([str(script),'_witness-check'],env=witness_env,check=True,stdin=subprocess.DEVNULL,timeout=5)
scan(); scan()
runtime_path=pathlib.Path(r['runtime_lock']); runtime_marker=pathlib.Path(r['runtime_transaction_marker'])
try: runtime_fd=os.open(runtime_path,os.O_RDWR|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
except OSError: raise SystemExit('finalize: deployment runtime lock is unavailable')
runtime_fs=os.fstat(runtime_fd); runtime_ls=runtime_path.lstat()
if not stat.S_ISREG(runtime_fs.st_mode) or (runtime_ls.st_dev,runtime_ls.st_ino)!=(runtime_fs.st_dev,runtime_fs.st_ino) or runtime_fs.st_uid!=r['process_uid'] or runtime_fs.st_nlink!=1 or stat.S_IMODE(runtime_fs.st_mode)!=0o600 or runtime_fs.st_dev!=r['runtime_lock_dev'] or runtime_fs.st_ino!=r['runtime_lock_ino']: raise SystemExit('finalize: deployment runtime lock identity mismatch')
try: fcntl.flock(runtime_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError: raise SystemExit('finalize: Rust paygate is active')
runtime_ls=runtime_path.lstat()
if (runtime_ls.st_dev,runtime_ls.st_ino)!=(runtime_fs.st_dev,runtime_fs.st_ino) or runtime_marker.exists() or runtime_marker.is_symlink(): raise SystemExit('finalize: deployment recovery is required')
marker_data={'schema':'paygate-rust-finalize-recovery-v1','candidate_identity':identity,'cutover_session_id':r['cutover_session_id'],'install_session_id':r['install_session_id'],'process_uid':r['process_uid'],'repository':r['repository'],'preflight_sha256':hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest(),'runtime_lock':str(runtime_path),'runtime_lock_dev':runtime_fs.st_dev,'runtime_lock_ino':runtime_fs.st_ino,'runtime_lock_uid':runtime_fs.st_uid,'runtime_lock_mode':stat.S_IMODE(runtime_fs.st_mode),'runtime_lock_identity':r['runtime_lock_identity'],'rollback_directory':str(rb.resolve()),'rollback_retirement_path':str(tombstone),'rollback_identity':rb_identity,'rollback_dev':rb_stat.st_dev,'rollback_ino':rb_stat.st_ino,'rollback_uid':rb_stat.st_uid,'rollback_mode':stat.S_IMODE(rb_stat.st_mode),'rollback_manifest_sha256':manifest_hash,'acceptance_record':str(acceptance.resolve()),'acceptance_sha256':hashlib.sha256(acceptance.read_bytes()).hexdigest(),'transaction_receipt':str(receipt),'transaction_receipt_sha256':hashlib.sha256(receipt_raw).hexdigest(),'recovery_record':str(recovery.resolve(strict=False)),'recovery_sha256':hashlib.sha256(recovery_raw).hexdigest(),'launcher':str(launcher),'installed_rust_launcher_target':str(rust),'python_environment_original':str(original),'python_environment_quarantine':str(quarantine),'python_environment_identity':qe['stable'],'python_paygate_identity':oe['stable']}
pending_marker=runtime_marker.parent/(runtime_marker.name+'.pending-finalize-'+r['install_session_id'])
if pending_marker.exists() or pending_marker.is_symlink():
 pending_ls=pending_marker.lstat()
 if pending_marker.is_symlink() or not pending_marker.is_file() or pending_ls.st_uid!=r['process_uid'] or pending_ls.st_nlink!=1 or stat.S_IMODE(pending_ls.st_mode)!=0o600: raise SystemExit('finalize: unsafe pending recovery marker')
 pending_marker.unlink(); sync_dir(pending_marker.parent)
marker_fd=os.open(pending_marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
with os.fdopen(marker_fd,'w') as f: json.dump(marker_data,f,sort_keys=True,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(pending_marker,runtime_marker); sync_dir(runtime_marker.parent)
if os.environ.get('PAYGATE_CUTOVER_TEST_HOOK')=='after-finalize-marker': raise SystemExit('finalize: test hook after recovery marker publication')
recovery_fd,tmp_name=tempfile.mkstemp(prefix=recovery.name+'.pending.',dir=recovery.parent); tmp=pathlib.Path(tmp_name); os.fchmod(recovery_fd,0o600)
with os.fdopen(recovery_fd,'wb') as f: f.write(recovery_raw); f.flush(); os.fsync(f.fileno())
os.replace(tmp,recovery); sync_dir(recovery.parent)
if os.environ.get('PAYGATE_CUTOVER_TEST_HOOK')=='after-finalize-recovery': raise SystemExit('finalize: test hook after recovery record publication')
os.replace(rb,tombstone); sync_dir(rb.parent)
if os.environ.get('PAYGATE_CUTOVER_TEST_HOOK')=='after-finalize-retirement': raise SystemExit('finalize: test hook after rollback retirement')
if os.environ.get('PAYGATE_CUTOVER_TEST_HOOK')=='during-finalize-cleanup':
 (tombstone/'manifest.json').unlink(); sync_dir(tombstone); raise SystemExit('finalize: test hook during rollback cleanup')
shutil.rmtree(tombstone); sync_dir(tombstone.parent)
if rb.exists() or tombstone.exists() or original.exists() or not quarantine.is_dir() or hashlib.sha256(rust.read_bytes()).hexdigest()!=identity['binary_sha256']: raise SystemExit('finalize: recovery-boundary verification failed')
if os.environ.get('PAYGATE_CUTOVER_TEST_HOOK')=='after-finalize-rollback': raise SystemExit('finalize: test hook after rollback retirement')
runtime_marker.unlink(); sync_dir(runtime_marker.parent)
PY
  echo "cutover finalize: PASS; Python environment quarantined for external cleanup at $recovery"; exit 0
fi

usage
