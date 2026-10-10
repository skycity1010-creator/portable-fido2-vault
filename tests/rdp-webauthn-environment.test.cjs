const test = require('node:test');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const script = path.resolve('scripts/collect-rdp-webauthn-environment.ps1');
function ps(code) {
  const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `$ErrorActionPreference='Stop'; ${code}`], {encoding:'utf8'});
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stderr, '', 'metadata collection must not expose error text');
  return JSON.parse(r.stdout.replace(/^\uFEFF/, ''));
}
function record(metadata) {
  return ps(`. '${script}' -DefinitionsOnly; New-EnvironmentRecord ${metadata} | ConvertTo-Json -Depth 5 -Compress`);
}
function schema(x) {
  assert.deepEqual(Object.keys(x).sort(), ['api','client','os_build','policy','probe','schema_version']);
  assert.equal(x.schema_version, 1);
  assert.deepEqual(Object.keys(x.api).sort(), ['hmac_secret_api_supported','measured_in','version']);
  assert.equal(x.api.measured_in, 'collector-process');
  assert.deepEqual(Object.keys(x.probe).sort(), ['pid','session_id','session_kind']);
  assert.ok(['unknown','noninteractive'].includes(x.probe.session_kind));
  assert.deepEqual(Object.keys(x.client).sort(), ['binary','version']);
  assert.deepEqual(Object.keys(x.policy), ['fDisableWebAuthn']);
  for (const v of [x.os_build, x.client.version]) {
    if (v === null) continue;
    assert.equal(typeof v, 'string');
    const match = /^[0-9]+(\.[0-9]+)*/.exec(v);
    assert.ok(match !== null && match.index === 0 && match[0].length === v.length);
  }
  for (const v of [x.api.version,x.probe.pid,x.probe.session_id]) assert.ok(v === null || Number.isInteger(v) && v >= 0);
  assert.equal(x.api.hmac_secret_api_supported, x.api.version === null ? null : x.api.version >= 4);
  assert.ok(x.client.binary === null || x.client.binary === 'mstsc.exe');
  assert.ok(x.policy.fDisableWebAuthn === null || [0,1].includes(x.policy.fDisableWebAuthn));
}
test('schema_rejects_noncanonical_versions_directly', () => {
  const canonical = {schema_version:1,os_build:'26100.1',client:{binary:'mstsc.exe',version:'10.0'},probe:{pid:null,session_id:null,session_kind:'unknown'},api:{version:null,hmac_secret_api_supported:null,measured_in:'collector-process'},policy:{fDisableWebAuthn:null}};
  schema(canonical);
  for (const suffix of ['\n','\r\n',' ','\t','\n1']) {
    assert.throws(() => schema({...canonical,client:{binary:'mstsc.exe',version:`10.0${suffix}`}}), assert.AssertionError);
    assert.throws(() => schema({...canonical,os_build:`26100.1${suffix}`}), assert.AssertionError);
  }
  for (const prefix of [' ','\t']) {
    assert.throws(() => schema({...canonical,client:{binary:'mstsc.exe',version:`${prefix}10.0`}}), assert.AssertionError);
    assert.throws(() => schema({...canonical,os_build:`${prefix}26100.1`}), assert.AssertionError);
  }
});
test('serializer_empty_allowlist', () => {
  const x = record("@{secret='SENTINEL';account='SENTINEL';exception='SENTINEL'}");
  schema(x);
  assert.deepEqual(x, {schema_version:1,os_build:null,client:{binary:null,version:null},probe:{pid:null,session_id:null,session_kind:'unknown'},api:{version:null,hmac_secret_api_supported:null,measured_in:'collector-process'},policy:{fDisableWebAuthn:null}});
  assert.equal(JSON.stringify(x).includes('SENTINEL'), false);
});
test('serializer_api_boundaries', () => {
  for (const n of [0,1,3,4,9]) {
    const x = record(`@{api_version=[uint32]${n}}`);
    schema(x); assert.equal(x.api.version, n); assert.equal(x.api.hmac_secret_api_supported, n >= 4);
  }
  for (const v of ["$null", "-1", "'4'", "'SENTINEL'"]) assert.equal(record(`@{api_version=${v}}`).api.version, null);
});
test('serializer_process_unknown_and_noninteractive', () => {
  for (const [id,kind] of [[0,'noninteractive'],[2,'unknown']]) {
    const x = record(`@{pid=123;session_id=${id}}`);
    schema(x);assert.equal(x.probe.pid,123);assert.equal(x.probe.session_id,id);assert.equal(x.probe.session_kind,kind);
  }
  for (const value of ["$null", "-1", "'SENTINEL'"]) {
    const x = record(`@{pid=${value};session_id=${value};SESSIONNAME='RDP-Tcp'}`);
    assert.deepEqual(x.probe,{pid:null,session_id:null,session_kind:'unknown'});
  }
});
test('serializer_installed_client_only', () => {
  const x = record("@{client_version='10.0.26100.1';client_path='SENTINEL'}");
  schema(x);assert.deepEqual(x.client,{binary:'mstsc.exe',version:'10.0.26100.1'});
  for (const v of ["$null","''","'SENTINEL'","'1..2'"]) assert.deepEqual(record(`@{client_version=${v}}`).client,{binary:null,version:null});
});
test('serializer_policy_allowlist', () => {
  for (const value of [0,1]) {
    const x = record(`@{fDisableWebAuthn=${value};other_policy='SENTINEL'}`);
    schema(x);assert.equal(x.policy.fDisableWebAuthn,value);
  }
  for (const v of ["$null","2","-1","'1'","'SENTINEL'"]) assert.equal(record(`@{fDisableWebAuthn=${v}}`).policy.fDisableWebAuthn,null);
});
test('serializer_build_and_ubr', () => {
  for (const build of ["'26100'", "26100"]) {
    const x = record(`@{os_build=${build};ubr=6584}`);
    schema(x);assert.equal(x.os_build,'26100.6584');
  }
  assert.equal(record("@{os_build='26100';ubr=0}").os_build,'26100.0');
  for (const m of ["@{os_build='26100'}","@{ubr=1}","@{os_build='SENTINEL';ubr=1}","@{os_build='26100';ubr=-1}","@{os_build='26100';ubr='SENTINEL'}"]) assert.equal(record(m).os_build,null);
});
test('serializer_rejects_noncanonical_build', () => {
  for (const value of ['"26100`n"','"26100`r`n"',"' 26100'","'26100 '",'"26100`t"','"`t26100"','"26100`n1"']) {
    assert.equal(record(`@{os_build=${value};ubr=1}`).os_build, null, value);
  }
  assert.equal(record("@{os_build='26100';ubr=1}").os_build, '26100.1');
});
test('serializer_rejects_noncanonical_client_version', () => {
  for (const value of ['"10.0`n"','"10.0`r`n"',"' 10.0'","'10.0 '",'"10.0`t"','"`t10.0"','"10.0`n1"']) {
    assert.deepEqual(record(`@{client_version=${value}}`).client, {binary:null,version:null}, value);
  }
  assert.deepEqual(record("@{client_version='10.0'}").client, {binary:'mstsc.exe',version:'10.0'});
});
test('metadata_injected_providers', () => {
  const x = ps(`. '${script}' -DefinitionsOnly; $p=@{pid={123};session_id={0};api_version={[uint32]4};os_build={'26100'};ubr={6584};client_version={'10.0.1.2'};fDisableWebAuthn={0};secret={'SENTINEL'}}; New-EnvironmentRecord (Get-EnvironmentMetadata $p) | ConvertTo-Json -Depth 5 -Compress`);
  schema(x);assert.equal(x.probe.pid,123);assert.equal(x.probe.session_kind,'noninteractive');assert.equal(x.api.version,4);assert.equal(x.os_build,'26100.6584');assert.equal(x.client.binary,'mstsc.exe');assert.equal(x.policy.fDisableWebAuthn,0);assert.equal(JSON.stringify(x).includes('SENTINEL'),false);
});
test('metadata_failures_and_missing_sources', () => {
  const x = ps(`. '${script}' -DefinitionsOnly; $p=@{pid={123};api_version={throw 'SENTINEL'};os_build={Write-Error 'SENTINEL'};client_version={throw 'SENTINEL'};fDisableWebAuthn={throw 'SENTINEL'}}; New-EnvironmentRecord (Get-EnvironmentMetadata $p) | ConvertTo-Json -Depth 5 -Compress`);
  schema(x);assert.equal(x.probe.pid,123);assert.equal(x.api.version,null);assert.equal(x.os_build,null);assert.equal(x.client.binary,null);assert.equal(x.policy.fDisableWebAuthn,null);assert.equal(x.probe.session_id,null);assert.equal(JSON.stringify(x).includes('SENTINEL'),false);
  schema(ps(`. '${script}' -DefinitionsOnly; New-EnvironmentRecord (Get-EnvironmentMetadata @{}) | ConvertTo-Json -Depth 5 -Compress`));
});
test('actual_collector_metadata_and_parser', () => {
  assert.deepEqual([...fs.readFileSync(script).subarray(0,3)],[239,187,191]);
  const parsed = ps(`$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('${script}',[ref]$t,[ref]$e);@{errors=$e.Count;major=$PSVersionTable.PSVersion.Major;minor=$PSVersionTable.PSVersion.Minor}|ConvertTo-Json -Compress`);
  assert.deepEqual(parsed,{errors:0,major:5,minor:1});
  const x = ps(`$r=(& '${script}' | ConvertFrom-Json);$os=Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';@{expected_pid=$PID;expected_session=[System.Diagnostics.Process]::GetCurrentProcess().SessionId;expected_build=('{0}.{1}' -f $os.CurrentBuildNumber,$os.UBR);record=$r}|ConvertTo-Json -Depth 6 -Compress`);
  schema(x.record);assert.equal(x.record.probe.pid,x.expected_pid);assert.equal(x.record.probe.session_id,x.expected_session);assert.equal(x.record.os_build,x.expected_build);
  schema(ps(`& '${script}'`));
});
