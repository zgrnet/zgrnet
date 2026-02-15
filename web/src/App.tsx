import { useEffect, useState, useCallback } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogTrigger } from '@/components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api, short, fmtBytes } from '@/lib/api'

// ─── Types ──────────────────────────────────────────────────────────────────

interface WhoAmI { pubkey: string; tun_ip: string; uptime: string; uptime_sec: number }
interface Peer { pubkey: string; domain: string; alias: string; direct: string[]; relay: string[]; tun_ip?: string; state?: string; rx_bytes?: number; tx_bytes?: number; endpoint?: string }
interface Lan { domain: string; pubkey: string; endpoint: string }
interface Rule { name: string; match?: { pubkey?: { type?: string } }; services?: { proto: string; port: string }[]; action: string }
interface Route { domain?: string; domain_list?: string; peer: string }
interface DnsStats { total_queries: number; zigor_net_hits: number; fake_ip_hits: number; upstream_forwards: number; upstream_errors: number; errors: number }
interface ProxyStats { total_connections: number; active_connections: number; bytes_sent: number; bytes_received: number; errors: number }

// ─── Stat Card ──────────────────────────────────────────────────────────────

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <Card>
      <CardContent className="pt-4 pb-3">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-2xl font-bold font-mono">{value}</p>
      </CardContent>
    </Card>
  )
}

function StateBadge({ state }: { state?: string }) {
  const v: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
    established: 'default', new: 'outline', connecting: 'secondary', failed: 'destructive',
  }
  return <Badge variant={v[state || ''] || 'outline'}>{state || 'unknown'}</Badge>
}

// ─── App ────────────────────────────────────────────────────────────────────

export default function App() {
  const [info, setInfo] = useState<WhoAmI | null>(null)
  const [netCfg, setNetCfg] = useState<Record<string, unknown> | null>(null)
  const [peers, setPeers] = useState<Peer[]>([])
  const [lans, setLans] = useState<Lan[]>([])
  const [policy, setPolicy] = useState<{ default?: string; rules?: Rule[] }>({})
  const [routes, setRoutes] = useState<Route[]>([])
  const [dns, setDns] = useState<DnsStats | null>(null)
  const [proxy, setProxy] = useState<ProxyStats | null>(null)
  const [rawConfig, setRawConfig] = useState<string>('')

  const [offline, setOffline] = useState(false)

  const load = useCallback(async () => {
    try {
      setInfo(await api.whoami());
      setOffline(false);
    } catch {
      setOffline(true);
      return;
    }
    try { setNetCfg(await api.configNet()); } catch {}
    try { const p = await api.peersList(); if (Array.isArray(p)) setPeers(p); } catch {}
  }, [])

  useEffect(() => { load() }, [load])

  const loadPeers = async () => { try { const p = await api.peersList(); if (Array.isArray(p)) setPeers(p); } catch {} }
  const loadLans = async () => { try { const l = await api.lansList(); if (Array.isArray(l)) setLans(l); } catch {} }
  const loadPolicy = async () => { try { setPolicy(await api.policyShow()); } catch {} }
  const loadRoutes = async () => { try { const r = await api.routesList(); if (Array.isArray(r)) setRoutes(r); } catch {} }
  const loadDns = async () => { try { setDns(await api.dnsStats()); } catch {} }
  const loadProxy = async () => { try { setProxy(await api.proxyStats()); } catch {} }
  const loadConfig = async () => { try { const c = await api.configRaw(); setRawConfig(c?.content || JSON.stringify(c, null, 2)); } catch {} }

  const onlinePeers = peers.filter(p => p.state === 'established').length

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <div className="border-b px-6 py-3 flex items-center gap-4">
        <h1 className="text-lg font-semibold">zgrnet</h1>
        <code className="text-xs text-muted-foreground">{info ? short(info.pubkey) : '...'}</code>
        <span className="ml-auto text-sm text-muted-foreground">{info ? `up ${info.uptime}` : ''}</span>
      </div>

      <div className="max-w-5xl mx-auto p-4">
        {offline && (
          <Card className="mb-4 border-destructive">
            <CardContent className="pt-4 pb-3 text-sm text-destructive">
              zgrnetd is not running. Start it with <code className="bg-muted px-1 rounded">zgrnet up</code> then refresh.
            </CardContent>
          </Card>
        )}
        <Tabs defaultValue="overview" onValueChange={v => {
          if (v === 'peers') loadPeers();
          if (v === 'lans') loadLans();
          if (v === 'policy') loadPolicy();
          if (v === 'routes') loadRoutes();
          if (v === 'dns') loadDns();
          if (v === 'proxy') loadProxy();
          if (v === 'config') loadConfig();
        }}>
          <TabsList className="mb-4">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="peers">Peers</TabsTrigger>
            <TabsTrigger value="lans">Lans</TabsTrigger>
            <TabsTrigger value="policy">Policy</TabsTrigger>
            <TabsTrigger value="routes">Routes</TabsTrigger>
            <TabsTrigger value="dns">DNS</TabsTrigger>
            <TabsTrigger value="proxy">Proxy</TabsTrigger>
            <TabsTrigger value="config">Config</TabsTrigger>
          </TabsList>

          {/* Overview */}
          <TabsContent value="overview">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
              <Stat label="TUN IP" value={info?.tun_ip || '-'} />
              <Stat label="Peers" value={peers.length} />
              <Stat label="Online" value={onlinePeers} />
              <Stat label="Uptime" value={info?.uptime || '-'} />
            </div>
            <Card>
              <CardHeader><CardTitle className="text-sm">Network Config</CardTitle></CardHeader>
              <CardContent>
                <pre className="text-xs font-mono bg-muted p-3 rounded-md overflow-auto">{netCfg ? JSON.stringify(netCfg, null, 2) : offline ? 'Not available (zgrnetd offline)' : 'loading...'}</pre>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Peers */}
          <TabsContent value="peers">
            <div className="flex gap-2 mb-3">
              <AddPeerDialog onAdd={loadPeers} />
              <Button variant="outline" size="sm" onClick={loadPeers}>Refresh</Button>
            </div>
            <Card>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Alias</TableHead>
                    <TableHead>Public Key</TableHead>
                    <TableHead>TUN IP</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Traffic</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {peers.length === 0 && <TableRow><TableCell colSpan={6} className="text-center text-muted-foreground py-8">No peers</TableCell></TableRow>}
                  {peers.map(p => (
                    <TableRow key={p.pubkey}>
                      <TableCell>{p.alias || '-'}</TableCell>
                      <TableCell className="font-mono text-xs">{short(p.pubkey)}</TableCell>
                      <TableCell className="font-mono text-xs">{p.tun_ip || '-'}</TableCell>
                      <TableCell><StateBadge state={p.state} /></TableCell>
                      <TableCell className="text-xs">{fmtBytes(p.rx_bytes || 0)} / {fmtBytes(p.tx_bytes || 0)}</TableCell>
                      <TableCell><Button variant="destructive" size="sm" onClick={async () => { await api.peersRemove(p.pubkey); loadPeers(); }}>Remove</Button></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          </TabsContent>

          {/* Lans */}
          <TabsContent value="lans">
            <div className="flex gap-2 mb-3">
              <AddLanDialog onAdd={loadLans} />
              <Button variant="outline" size="sm" onClick={loadLans}>Refresh</Button>
            </div>
            <Card>
              <Table>
                <TableHeader><TableRow><TableHead>Domain</TableHead><TableHead>Pubkey</TableHead><TableHead>Endpoint</TableHead><TableHead /></TableRow></TableHeader>
                <TableBody>
                  {lans.length === 0 && <TableRow><TableCell colSpan={4} className="text-center text-muted-foreground py-8">No lans</TableCell></TableRow>}
                  {lans.map(l => (
                    <TableRow key={l.domain}>
                      <TableCell>{l.domain}</TableCell>
                      <TableCell className="font-mono text-xs">{short(l.pubkey)}</TableCell>
                      <TableCell className="font-mono text-xs">{l.endpoint}</TableCell>
                      <TableCell><Button variant="destructive" size="sm" onClick={async () => { await api.lansLeave(l.domain); loadLans(); }}>Leave</Button></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          </TabsContent>

          {/* Policy */}
          <TabsContent value="policy">
            <div className="flex gap-2 mb-3">
              <AddRuleDialog onAdd={loadPolicy} />
              <Button variant="outline" size="sm" onClick={loadPolicy}>Refresh</Button>
            </div>
            {policy.default && <p className="text-sm text-muted-foreground mb-2">Default: <Badge variant="outline">{policy.default}</Badge></p>}
            <Card>
              <Table>
                <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Match</TableHead><TableHead>Services</TableHead><TableHead>Action</TableHead><TableHead /></TableRow></TableHeader>
                <TableBody>
                  {(!policy.rules || policy.rules.length === 0) && <TableRow><TableCell colSpan={5} className="text-center text-muted-foreground py-8">No rules</TableCell></TableRow>}
                  {(policy.rules || []).map(r => (
                    <TableRow key={r.name}>
                      <TableCell>{r.name}</TableCell>
                      <TableCell className="text-xs">{r.match?.pubkey?.type || '-'}</TableCell>
                      <TableCell className="text-xs font-mono">{(r.services || []).map(s => `${s.proto}:${s.port}`).join(', ') || '*'}</TableCell>
                      <TableCell><Badge variant={r.action === 'allow' ? 'default' : 'destructive'}>{r.action}</Badge></TableCell>
                      <TableCell><Button variant="destructive" size="sm" onClick={async () => { await api.policyRemoveRule(r.name); loadPolicy(); }}>Remove</Button></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          </TabsContent>

          {/* Routes */}
          <TabsContent value="routes">
            <div className="flex gap-2 mb-3">
              <AddRouteDialog onAdd={loadRoutes} />
              <Button variant="outline" size="sm" onClick={loadRoutes}>Refresh</Button>
            </div>
            <Card>
              <Table>
                <TableHeader><TableRow><TableHead>#</TableHead><TableHead>Domain</TableHead><TableHead>Peer</TableHead><TableHead /></TableRow></TableHeader>
                <TableBody>
                  {routes.length === 0 && <TableRow><TableCell colSpan={4} className="text-center text-muted-foreground py-8">No routes</TableCell></TableRow>}
                  {routes.map((r, i) => (
                    <TableRow key={i}>
                      <TableCell>{i}</TableCell>
                      <TableCell className="font-mono text-xs">{r.domain || r.domain_list || '-'}</TableCell>
                      <TableCell>{r.peer}</TableCell>
                      <TableCell><Button variant="destructive" size="sm" onClick={async () => { await api.routesRemove(i); loadRoutes(); }}>Remove</Button></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          </TabsContent>

          {/* DNS */}
          <TabsContent value="dns">
            <div className="flex gap-2 mb-3"><Button variant="outline" size="sm" onClick={loadDns}>Refresh</Button></div>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <Stat label="Total Queries" value={dns?.total_queries ?? 0} />
              <Stat label="zigor.net Hits" value={dns?.zigor_net_hits ?? 0} />
              <Stat label="Fake IP Hits" value={dns?.fake_ip_hits ?? 0} />
              <Stat label="Upstream Forwards" value={dns?.upstream_forwards ?? 0} />
              <Stat label="Upstream Errors" value={dns?.upstream_errors ?? 0} />
              <Stat label="Errors" value={dns?.errors ?? 0} />
            </div>
          </TabsContent>

          {/* Proxy */}
          <TabsContent value="proxy">
            <div className="flex gap-2 mb-3"><Button variant="outline" size="sm" onClick={loadProxy}>Refresh</Button></div>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <Stat label="Total Connections" value={proxy?.total_connections ?? 0} />
              <Stat label="Active" value={proxy?.active_connections ?? 0} />
              <Stat label="Bytes Sent" value={fmtBytes(proxy?.bytes_sent ?? 0)} />
              <Stat label="Bytes Received" value={fmtBytes(proxy?.bytes_received ?? 0)} />
              <Stat label="Errors" value={proxy?.errors ?? 0} />
            </div>
          </TabsContent>

          {/* Config */}
          <TabsContent value="config">
            <div className="flex gap-2 mb-3">
              <Button variant="outline" size="sm" onClick={loadConfig}>Refresh</Button>
              <Button variant="outline" size="sm" onClick={async () => { await api.configReload(); loadConfig(); }}>Reload from Disk</Button>
            </div>
            <Card>
              <CardHeader><CardTitle className="text-sm">config.yaml</CardTitle></CardHeader>
              <CardContent>
                <pre className="text-xs font-mono bg-muted p-4 rounded-md overflow-auto max-h-[600px] whitespace-pre-wrap">{rawConfig || (offline ? 'Not available (zgrnetd offline)' : 'loading...')}</pre>
              </CardContent>
            </Card>
          </TabsContent>

        </Tabs>
      </div>
    </div>
  )
}

// ─── Dialogs ────────────────────────────────────────────────────────────────

function AddPeerDialog({ onAdd }: { onAdd: () => void }) {
  const [open, setOpen] = useState(false)
  const [pk, setPk] = useState(''); const [alias, setAlias] = useState(''); const [ep, setEp] = useState('')
  const submit = async () => {
    if (!pk) return; await api.peersAdd({ pubkey: pk, alias, endpoint: ep }); setOpen(false); setPk(''); setAlias(''); setEp(''); onAdd()
  }
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild><Button size="sm">Add Peer</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Add Peer</DialogTitle></DialogHeader>
        <div className="grid gap-3 py-2">
          <div className="grid gap-1"><Label>Public Key</Label><Input placeholder="64-char hex" value={pk} onChange={e => setPk(e.target.value)} /></div>
          <div className="grid gap-1"><Label>Alias</Label><Input placeholder="optional" value={alias} onChange={e => setAlias(e.target.value)} /></div>
          <div className="grid gap-1"><Label>Endpoint</Label><Input placeholder="host:port" value={ep} onChange={e => setEp(e.target.value)} /></div>
        </div>
        <DialogFooter><Button onClick={submit}>Add</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function AddLanDialog({ onAdd }: { onAdd: () => void }) {
  const [open, setOpen] = useState(false)
  const [domain, setDomain] = useState(''); const [pk, setPk] = useState(''); const [ep, setEp] = useState('')
  const submit = async () => {
    if (!domain || !pk || !ep) return; await api.lansJoin({ domain, pubkey: pk, endpoint: ep }); setOpen(false); setDomain(''); setPk(''); setEp(''); onAdd()
  }
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild><Button size="sm">Join Lan</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Join Lan</DialogTitle></DialogHeader>
        <div className="grid gap-3 py-2">
          <div className="grid gap-1"><Label>Domain</Label><Input placeholder="company.zigor.net" value={domain} onChange={e => setDomain(e.target.value)} /></div>
          <div className="grid gap-1"><Label>Pubkey</Label><Input placeholder="64-char hex" value={pk} onChange={e => setPk(e.target.value)} /></div>
          <div className="grid gap-1"><Label>Endpoint</Label><Input placeholder="host:port" value={ep} onChange={e => setEp(e.target.value)} /></div>
        </div>
        <DialogFooter><Button onClick={submit}>Join</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function AddRuleDialog({ onAdd }: { onAdd: () => void }) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState(''); const [matchType, setMatchType] = useState('any'); const [action, setAction] = useState('allow')
  const submit = async () => {
    if (!name) return
    await api.policyAddRule({ name, match: { pubkey: { type: matchType } }, services: [{ proto: '*', port: '*' }], action })
    setOpen(false); setName(''); onAdd()
  }
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild><Button size="sm">Add Rule</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Add Policy Rule</DialogTitle></DialogHeader>
        <div className="grid gap-3 py-2">
          <div className="grid gap-1"><Label>Name</Label><Input value={name} onChange={e => setName(e.target.value)} /></div>
          <div className="grid gap-1"><Label>Match Type</Label>
            <Select value={matchType} onValueChange={setMatchType}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="any">any</SelectItem><SelectItem value="whitelist">whitelist</SelectItem><SelectItem value="zgrlan">zgrlan</SelectItem></SelectContent></Select>
          </div>
          <div className="grid gap-1"><Label>Action</Label>
            <Select value={action} onValueChange={setAction}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="allow">allow</SelectItem><SelectItem value="deny">deny</SelectItem></SelectContent></Select>
          </div>
        </div>
        <DialogFooter><Button onClick={submit}>Add</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function AddRouteDialog({ onAdd }: { onAdd: () => void }) {
  const [open, setOpen] = useState(false)
  const [domain, setDomain] = useState(''); const [peer, setPeer] = useState('')
  const submit = async () => {
    if (!domain || !peer) return; await api.routesAdd({ domain, peer }); setOpen(false); setDomain(''); setPeer(''); onAdd()
  }
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild><Button size="sm">Add Route</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Add Route</DialogTitle></DialogHeader>
        <div className="grid gap-3 py-2">
          <div className="grid gap-1"><Label>Domain</Label><Input placeholder="*.google.com" value={domain} onChange={e => setDomain(e.target.value)} /></div>
          <div className="grid gap-1"><Label>Peer</Label><Input placeholder="peer alias" value={peer} onChange={e => setPeer(e.target.value)} /></div>
        </div>
        <DialogFooter><Button onClick={submit}>Add</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
