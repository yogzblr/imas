# Writes every PowerShell script in the repo (Ansible `script: |` blocks and *.ps1 files) to a directory,
# so that PowerShell on Windows can parse-check them: see packaging/README.md.
# Usage: python3 packaging/test/extract-powershell.py OUTDIR   (run from the repository root)
import sys, re, pathlib, textwrap
out = pathlib.Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
n = 0
for p in sorted(pathlib.Path('ansible').rglob('*.yml')) + sorted(pathlib.Path('uat').rglob('*.yml')):
    lines = p.read_text().split('\n')
    i = 0
    while i < len(lines):
        m = re.match(r'^(\s*)script:\s*[|>][-+]?\s*$', lines[i])
        if m:
            base = len(m.group(1)); j = i + 1; block = []
            while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > base):
                block.append(lines[j]); j += 1
            body = textwrap.dedent('\n'.join(block))
            if re.search(r'\$|Write-|Get-|\[CmdletBinding', body):
                n += 1
                name = re.sub(r'[^A-Za-z0-9]+', '_', str(p)) + f'_L{i+1}.ps1'
                (out / name).write_text(body.replace('{{', '{{') + '\n')
            i = j
        else:
            i += 1
for p in sorted(pathlib.Path('.').rglob('*.ps1')):
    if '.git' in p.parts: continue
    (out / ('file_' + re.sub(r'[^A-Za-z0-9]+', '_', str(p)))).write_text(p.read_text()); n += 1
print(n, 'scripts written to', out)
