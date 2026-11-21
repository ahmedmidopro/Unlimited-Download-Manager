const fs = require('fs');
const calls = [], cancelled = [], dls = {};
let udmUp = true;
const listeners = {};
const ev = (n) => ({addListener: (f) => { listeners[n] = f; }});
globalThis.chrome = {runtime: {id: 'x', onStartup: ev('s'), onInstalled: ev('i'), onMessage: ev('msg'), connectNative: () => { throw new Error('no native'); }},
  alarms: {create() {}, onAlarm: ev('alarm')}, cookies: {getAll: async () => [{name: 'a', value: '1'}]},
  downloads: {onCreated: ev('dl'), cancel: (id) => cancelled.push(id), erase() {}, search: async ({id}) => [dls[id]]},
  contextMenus: {create() {}, removeAll: (f) => f && f(), onClicked: ev('ctx')}, action: {setBadgeText() {}, setBadgeBackgroundColor() {}, onClicked: ev('act')},
  tabs: {get: async () => ({url: 'https://y', title: 't'}), onRemoved: ev('r'), onUpdated: ev('u')}, webRequest: {onHeadersReceived: ev('wr')}};
globalThis.fetch = async (url, opt) => {
  if (!udmUp) throw new Error('down');
  if (url.includes('/rules')) return {ok: true, json: async () => ({enabled: true, types: ['zip', 'exe'], excluded_types: [], excluded_sites: [], exceptions: [], large_mb: 5})};
  if (url.includes('/ext/pair')) return {ok: true, json: async () => ({token: 't'})};
  calls.push([url, opt && opt.body]); return {ok: true, json: async () => ({})};
};
globalThis.navigator = {userAgent: 'Chrome', brave: {isBrave: async () => true}};
eval(fs.readFileSync(process.argv[2] + '/background.js', 'utf8').replace(/^const /gm, 'var ').replace(/^let /gm, 'var '));
const run = async (name, item, up = true) => { udmUp = up; calls.length = 0; cancelled.length = 0; dls[item.id] = item.later || item; await listeners.dl(item); await new Promise(r => setTimeout(r, 50));
  const sent = calls.filter(c => c[0].endsWith('/add')).length; console.log(name.padEnd(52), sent ? 'CAPTURED' : 'left to browser', '|', lastCap.slice(11)); };
(async () => {
  await run('zip with name known', {id: 1, url: 'https://s/a.zip', filename: ''});
  await run('no extension in URL, name known only later (.exe)', {id: 2, url: 'https://s/get?id=5', filename: '', later: {id: 2, url: 'https://s/get?id=5', filename: 'C:\\d\\setup.exe', mime: 'application/octet-stream'}});
  await run('unknown type but big (80MB)', {id: 3, url: 'https://s/dl/abc', filename: '', totalBytes: 80e6, mime: 'application/octet-stream'});
  await run('unknown type, small (50KB html)', {id: 4, url: 'https://s/page', filename: '', totalBytes: 5e4, mime: 'text/html'});
  await run('UDM not reachable', {id: 5, url: 'https://s/a.zip', filename: ''}, false);
  udmUp = true; calls.length = 0;
  let reply; listeners.msg({udm: 'video', url: 'https://www.youtube.com/watch?v=1', title: 'T'}, {tab: {url: 'https://www.youtube.com/watch?v=1', title: 'T'}}, (r) => reply = r);
  await new Promise(r => setTimeout(r, 50)); console.log('video message ->', JSON.parse(calls.find(c => c[0].endsWith('/add'))[1]), reply);
})();
