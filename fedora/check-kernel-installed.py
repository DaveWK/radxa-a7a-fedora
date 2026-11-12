#!/usr/bin/env python3
# SUPERSEDED (Oct 15, 2026): private-kernel (a7artc1) path control, kept as history;
# not called by mkdevcard.sh or verify-devcard.sh. The image uses Fedora's own kernel.
"""Bind target RPM database and unsigned allowlist to exact private kernel inputs."""
import importlib.util,json,subprocess,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('inputs',Path(__file__).with_name('kernel-package-inputs.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root,manifest,packages=map(Path,sys.argv[1:]);data=json.loads(manifest.read_text());m.verify(data)
expected={x['metadata']['name']:x['metadata'] for x in data['packages']}
actual=subprocess.check_output(['rpm','--root',str(root.resolve()),'-qa','--qf','%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH}\\n'],text=True).splitlines()
found={}
for line in actual:
 name,epoch,version,release,arch=line.split()
 if name in expected:
  assert name not in found,'duplicate installed kernel package';found[name]={'name':name,'epoch':epoch,'version':version,'release':release,'arch':arch,'kernel_release':version+'-'+release+'.'+arch}
assert found==expected,(found,expected)
allowed={x['name']+'-'+x['epoch']+':'+x['version']+'-'+x['release']+'.'+x['arch'] for x in expected.values()}
for line in packages.read_text().splitlines():
 if '(none)' in line:
  name=line.split()[0];assert name.startswith(('cubie-a7a-','gpg-pubkey-')) or name in allowed,('unexpected unsigned package',name)
print('PASS actual installed private kernel NEVRAs and narrow unsigned-package allowlist')
