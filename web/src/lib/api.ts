const BASE = '';

async function request(method: string, path: string, body?: unknown) {
  const opts: RequestInit = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(BASE + path, opts);
  if (r.status === 204) return null;
  const ct = r.headers.get('content-type') || '';
  if (!ct.includes('application/json')) {
    throw new Error(`API returned non-JSON (${r.status})`);
  }
  if (!r.ok) {
    const err = await r.json().catch(() => ({ error: r.statusText }));
    throw new Error(err.error || r.statusText);
  }
  return r.json();
}

export const api = {
  whoami: () => request('GET', '/api/whoami'),
  configNet: () => request('GET', '/api/config/net'),
  configReload: () => request('POST', '/api/config/reload'),
  configRaw: () => request('GET', '/api/config/raw'),
  dnsStats: () => request('GET', '/api/dns/stats'),
  proxyStats: () => request('GET', '/api/proxy/stats'),

  peersList: () => request('GET', '/api/peers'),
  peersGet: (pk: string) => request('GET', `/api/peers/${pk}`),
  peersAdd: (data: { pubkey: string; alias?: string; endpoint?: string }) => request('POST', '/api/peers', data),
  peersUpdate: (pk: string, data: Record<string, string>) => request('PUT', `/api/peers/${pk}`, data),
  peersRemove: (pk: string) => request('DELETE', `/api/peers/${pk}`),

  lansList: () => request('GET', '/api/lans'),
  lansJoin: (data: { domain: string; pubkey: string; endpoint: string }) => request('POST', '/api/lans', data),
  lansLeave: (domain: string) => request('DELETE', `/api/lans/${domain}`),

  policyShow: () => request('GET', '/api/policy'),
  policyAddRule: (rule: unknown) => request('POST', '/api/policy/rules', rule),
  policyRemoveRule: (name: string) => request('DELETE', `/api/policy/rules/${name}`),

  routesList: () => request('GET', '/api/routes'),
  routesAdd: (data: { domain: string; peer: string }) => request('POST', '/api/routes', data),
  routesRemove: (id: number) => request('DELETE', `/api/routes/${id}`),
};

export function short(s: string) { return s ? s.substring(0, 16) + '...' : '-'; }
export function fmtBytes(n: number) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + ' ' + u[i];
}
