// Copyright 2026 Carlos Ganoza
// SPDX-License-Identifier: Apache-2.0
import type { Company } from '../types/report'
import type { TaggedHost } from './hostTable'

export type NodeType = 'company' | 'domain' | 'subdomain' | 'ip'

export interface GNode {
  id: string
  type: NodeType
  label: string
  risk: string
  r: number
  company: string
  domain: string
  detail: string
  x: number
  y: number
  vx: number
  vy: number
  pinned: boolean
  deg: number
  shared: boolean
  cross: boolean
}

export interface GLink {
  a: GNode
  b: GNode
  kind: 'own' | 'ip'
  len: number
}

export interface Graph {
  nodes: GNode[]
  links: GLink[]
}

const RISK_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const rank = (r: string) => RISK_RANK[r] ?? 0
const worst = (a: string, b: string) => (rank(b) > rank(a) ? b : a)

const NODE_CAP = 420

/**
 * Builds the constellation from the host inventory: company -> domain ->
 * subdomain, plus IP nodes linked to every host that resolves to them. An IP
 * reached by several hosts is "shared"; one reached by hosts of different
 * domains is "cross" — shared infrastructure across ownership boundaries.
 */
export function buildGraph(
  hosts: TaggedHost[],
  companies: Company[],
  focusDomain: string | null,
  showIps: boolean,
  perDomainCap = focusDomain ? 80 : 14,
): Graph {
  const nodes = new Map<string, GNode>()
  const links: GLink[] = []

  const add = (id: string, type: NodeType, label: string, risk: string, company: string, domain: string, r: number, detail: string) => {
    let n = nodes.get(id)
    if (!n) {
      n = { id, type, label, risk, r, company, domain, detail, x: 0, y: 0, vx: 0, vy: 0, pinned: false, deg: 0, shared: false, cross: false }
      nodes.set(id, n)
    }
    return n
  }
  const link = (a: GNode, b: GNode, kind: 'own' | 'ip', len: number) => {
    links.push({ a, b, kind, len })
    a.deg++
    b.deg++
  }

  const byDomain = new Map<string, TaggedHost[]>()
  for (const h of hosts) {
    if (h.kind === 'ip') continue
    const dom = h.kind === 'domain' ? h.value : h.domain
    if (!dom) continue
    if (focusDomain && dom.toLowerCase() !== focusDomain.toLowerCase()) continue
    const list = byDomain.get(dom) ?? []
    list.push(h)
    byDomain.set(dom, list)
  }

  const companyOf = new Map(companies.map((c) => [c.name, c]))
  for (const [dom, list] of byDomain) {
    const companyName = list[0].company ?? ''
    const domainHost = list.find((h) => h.kind === 'domain')
    const subs = list
      .filter((h) => h.kind === 'subdomain')
      .sort((a, b) => rank(b.risk) - rank(a.risk) || (b.endpoints?.length ?? 0) - (a.endpoints?.length ?? 0))
    const kept = subs.slice(0, perDomainCap)
    const domRisk = list.reduce<string>((acc, h) => worst(acc, h.risk), domainHost?.risk ?? 'low')

    const cNode = add(`c:${companyName}`, 'company', companyName, 'low', companyName, '', 14,
      `${companyOf.get(companyName)?.domains.length ?? 0} domains`)
    const dNode = add(`d:${dom}`, 'domain', dom, domRisk, companyName, dom, 9,
      `${subs.length} subdomains · ${domainHost?.open_ports?.length ?? 0} open ports`)
    cNode.risk = worst(cNode.risk, domRisk)
    link(cNode, dNode, 'own', 95)

    const shown: TaggedHost[] = domainHost ? [domainHost] : []
    for (const s of kept) {
      const sNode = add(`s:${s.value}`, 'subdomain', s.value, s.risk, companyName, dom, 4 + Math.min(s.endpoints?.length ?? 0, 30) * 0.08,
        `${s.endpoints?.length ?? 0} endpoints · ${s.open_ports?.length ?? 0} open ports · ${s.technologies?.length ?? 0} technologies`)
      link(dNode, sNode, 'own', 52)
      shown.push(s)
    }
    if (showIps) {
      for (const h of shown) {
        const hostNode = nodes.get(h.kind === 'domain' ? `d:${h.value}` : `s:${h.value}`)
        if (!hostNode) continue
        for (const ip of h.ips ?? []) {
          const ipNode = add(`i:${ip}`, 'ip', ip, 'info', companyName, dom, 3.2, '')
          link(hostNode, ipNode, 'ip', 42)
        }
      }
    }
  }

  // Shared / cross-ownership IPs
  const ipHosts = new Map<string, GNode[]>()
  for (const l of links) {
    if (l.kind !== 'ip') continue
    const arr = ipHosts.get(l.b.id) ?? []
    arr.push(l.a)
    ipHosts.set(l.b.id, arr)
  }
  for (const [ipId, attached] of ipHosts) {
    const ipNode = nodes.get(ipId)!
    if (attached.length < 2) continue
    const domains = new Set(attached.map((n) => n.domain))
    ipNode.shared = true
    ipNode.cross = domains.size > 1
    ipNode.r = ipNode.cross ? 6 : 4.6
    ipNode.detail = `${attached.length} hosts · ${domains.size} domain${domains.size === 1 ? '' : 's'}: ${attached.slice(0, 4).map((n) => n.label).join(', ')}${attached.length > 4 ? '…' : ''}`
  }

  if (nodes.size > NODE_CAP && perDomainCap > 5) {
    return buildGraph(hosts, companies, focusDomain, showIps, Math.max(5, Math.floor(perDomainCap / 2)))
  }
  return { nodes: [...nodes.values()], links }
}

/** Places nodes around their parents so the simulation starts close to a good layout. */
export function seedPositions(g: Graph, w: number, h: number): void {
  const cx = w / 2
  const cy = h / 2
  const companies = g.nodes.filter((n) => n.type === 'company')
  companies.forEach((c, i) => {
    const angle = (i / Math.max(companies.length, 1)) * Math.PI * 2
    const rad = companies.length === 1 ? 0 : Math.min(w, h) * 0.28
    c.x = cx + Math.cos(angle) * rad
    c.y = cy + Math.sin(angle) * rad
  })
  const jitter = () => (Math.random() - 0.5) * 60
  for (const n of g.nodes) {
    if (n.type === 'company') continue
    const parent = g.links.find((l) => l.b === n && l.kind === 'own')?.a
      ?? g.links.find((l) => l.b === n)?.a
    n.x = (parent?.x ?? cx) + jitter()
    n.y = (parent?.y ?? cy) + jitter()
  }
}

const CHARGE: Record<NodeType, number> = { company: 900, domain: 260, subdomain: 70, ip: 45 }

/** One physics step (repulsion + springs + centering). Returns nothing; mutates nodes. */
export function stepLayout(g: Graph, alpha: number, w: number, h: number): void {
  const { nodes, links } = g
  const n = nodes.length
  const cx = w / 2
  const cy = h / 2
  for (let i = 0; i < n; i++) {
    const a = nodes[i]
    for (let j = i + 1; j < n; j++) {
      const b = nodes[j]
      let dx = a.x - b.x
      let dy = a.y - b.y
      let d2 = dx * dx + dy * dy
      if (d2 > 32400) continue // > 180px: negligible
      if (d2 < 1) {
        dx = Math.random() - 0.5
        dy = Math.random() - 0.5
        d2 = 1
      }
      const d = Math.sqrt(d2)
      const f = (Math.sqrt(CHARGE[a.type] * CHARGE[b.type]) * 0.55 * alpha) / Math.max(d2, 60)
      const fx = (dx / d) * f * d
      const fy = (dy / d) * f * d
      // (force divided by mass-ish radius so big nodes push small ones, not vice versa)
      const ma = a.type === 'company' ? 4 : a.type === 'domain' ? 2 : 1
      const mb = b.type === 'company' ? 4 : b.type === 'domain' ? 2 : 1
      a.vx += fx / ma
      a.vy += fy / ma
      b.vx -= fx / mb
      b.vy -= fy / mb
    }
  }
  for (const l of links) {
    const dx = l.b.x - l.a.x
    const dy = l.b.y - l.a.y
    const d = Math.sqrt(dx * dx + dy * dy) || 1
    const k = (l.kind === 'ip' ? 0.02 : 0.05) * alpha
    const f = (d - l.len) * k
    const fx = (dx / d) * f
    const fy = (dy / d) * f
    l.a.vx += fx
    l.a.vy += fy
    l.b.vx -= fx
    l.b.vy -= fy
  }
  for (const nd of nodes) {
    nd.vx += (cx - nd.x) * 0.0016 * alpha
    nd.vy += (cy - nd.y) * 0.0016 * alpha
    if (nd.pinned) {
      nd.vx = 0
      nd.vy = 0
      continue
    }
    nd.vx *= 0.82
    nd.vy *= 0.82
    nd.x += nd.vx
    nd.y += nd.vy
    const pad = nd.r + 6
    nd.x = Math.max(pad, Math.min(w - pad, nd.x))
    nd.y = Math.max(pad, Math.min(h - pad, nd.y))
  }
}
