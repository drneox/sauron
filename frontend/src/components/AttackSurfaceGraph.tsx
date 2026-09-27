// Copyright 2026 Carlos Ganoza
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import clsx from 'clsx'
import { ChevronDown, ChevronRight, Network, X } from 'lucide-react'
import type { Company } from '../types/report'
import type { TaggedHost } from './hostTable'
import { buildGraph, seedPositions, stepLayout, type Graph, type GNode } from './graphLayout'

// Same severity palette as the dashboard charts; brand violet for structure.
const RISK_COLOR: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#94a3b8',
  info: '#cbd5e1',
}
const BRAND = '#9333ea'
const IP_COLOR = '#cbd5e1'
// Vendor-managed endpoints (e.g. Microsoft 365 autodiscover): shared, but not a relation
const PROVIDER_COLOR = '#0ea5e9'
const HEIGHT = 440
const DRAG_THRESHOLD = 5 // px
const OPEN_KEY = 'asm.nodeMap.open'

// Remembered per browser; the map is heavy to animate, so people fold it away.
function readOpen(): boolean {
  try { return localStorage.getItem(OPEN_KEY) !== '0' } catch { return true }
}

export type IpGroup = 'cross' | 'shared' | 'provider'

interface Props {
  /** The whole scope: source of the header counts and of the IP classification */
  hosts: TaggedHost[]
  /** What to draw: the same array as `hosts` when nothing is focused, else the focused subset */
  drawHosts: TaggedHost[]
  companies: Company[]
  focusDomain: string | null
  /** Node currently used to filter the dashboard's host list, drawn with a ring */
  selected: { kind: 'host' | 'ip' | 'ipset'; value: string; values?: string[] } | null
  onSelectCompany: (companyName: string) => void
  onSelectDomain: (companyName: string, domain: string) => void
  onSelectHost: (host: string, companyName: string) => void
  onSelectIp: (ip: string) => void
  /** A whole class of IPs (the header chips): cross-company, shared, or vendor-managed */
  onSelectIpGroup: (group: IpGroup, ips: string[]) => void
  /** Something (company, domain or node) is narrowing the dashboard */
  filtered: boolean
  onClearFilters: () => void
}

export default function AttackSurfaceGraph({ hosts, drawHosts, companies, focusDomain, selected, onSelectCompany, onSelectDomain, onSelectHost, onSelectIp, onSelectIpGroup, filtered, onClearFilters }: Props) {
  const { t } = useTranslation()
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const [width, setWidth] = useState(900)
  const [showIps, setShowIps] = useState(true)
  const [open, setOpen] = useState(readOpen)
  const [hover, setHover] = useState<{ node: GNode; x: number; y: number } | null>(null)
  const graphRef = useRef<Graph | null>(null)
  const hoverRef = useRef<GNode | null>(null)
  const alphaRef = useRef(1)
  const dragRef = useRef<{ node: GNode; moved: boolean; x0: number; y0: number } | null>(null)
  const selectedRef = useRef(selected)
  selectedRef.current = selected
  const stars = useRef(
    Array.from({ length: 70 }, () => ({ x: Math.random(), y: Math.random(), r: Math.random() * 1.2 + 0.3, p: Math.random() * 6 })),
  )

  const fullGraph = useMemo(
    () => buildGraph(hosts, companies, focusDomain, showIps),
    [hosts, companies, focusDomain, showIps],
  )
  // A focused map draws only the picked hosts, but IPs keep the class they have
  // in the whole scope (a lone host would otherwise make its shared IP look private).
  const graph = useMemo(() => {
    if (drawHosts === hosts) return fullGraph
    const g = buildGraph(drawHosts, companies, focusDomain, showIps)
    const classed = new Map(fullGraph.nodes.filter((n) => n.type === 'ip').map((n) => [n.label, n]))
    for (const n of g.nodes) {
      const full = n.type === 'ip' ? classed.get(n.label) : undefined
      if (full) Object.assign(n, { shared: full.shared, cross: full.cross, provider: full.provider, detail: full.detail, r: full.r })
    }
    return g
  }, [drawHosts, hosts, fullGraph, companies, focusDomain, showIps])

  // (Re)seed the simulation whenever the graph content changes
  useEffect(() => {
    seedPositions(graph, width, HEIGHT)
    graphRef.current = graph
    alphaRef.current = 1
    hoverRef.current = null
    setHover(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph])

  useEffect(() => {
    const el = wrapRef.current
    if (!el) return
    const ro = new ResizeObserver(() => setWidth(Math.max(320, Math.floor(el.clientWidth))))
    ro.observe(el)
    setWidth(Math.max(320, Math.floor(el.clientWidth)))
    return () => ro.disconnect()
  }, [open])

  // Animation loop: physics + drawing. The floor on alpha keeps the map drifting gently.
  // Folded away, the canvas is unmounted so nothing animates in the background.
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    const dpr = window.devicePixelRatio || 1
    canvas.width = width * dpr
    canvas.height = HEIGHT * dpr
    let raf = 0
    let t0 = performance.now()

    const draw = (now: number) => {
      raf = requestAnimationFrame(draw)
      if (document.hidden) return
      const g = graphRef.current
      if (!g) return
      const time = (now - t0) / 1000
      alphaRef.current = Math.max(0.035, alphaRef.current * 0.987)
      stepLayout(g, alphaRef.current, width, HEIGHT)
      // a whisper of Brownian drift so idle nodes still breathe
      for (const n of g.nodes) {
        if (!n.pinned) {
          n.x += Math.sin(time * 0.6 + n.x * 0.013) * 0.08
          n.y += Math.cos(time * 0.5 + n.y * 0.013) * 0.08
        }
      }

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      const bg = ctx.createRadialGradient(width / 2, HEIGHT / 2, 20, width / 2, HEIGHT / 2, Math.max(width, HEIGHT) * 0.75)
      bg.addColorStop(0, '#ffffff')
      bg.addColorStop(1, '#f5f3ff')
      ctx.fillStyle = bg
      ctx.fillRect(0, 0, width, HEIGHT)
      for (const s of stars.current) {
        ctx.globalAlpha = 0.2 + 0.2 * Math.sin(time * 0.8 + s.p)
        ctx.fillStyle = '#a78bfa'
        ctx.beginPath()
        ctx.arc(s.x * width, s.y * HEIGHT, s.r, 0, Math.PI * 2)
        ctx.fill()
      }
      ctx.globalAlpha = 1

      const hovered = hoverRef.current
      for (const l of g.links) {
        const hot = hovered && (l.a === hovered || l.b === hovered)
        ctx.strokeStyle = l.kind === 'ip'
          ? (hot ? 'rgba(147,51,234,0.8)' : l.b.shared ? 'rgba(147,51,234,0.32)' : l.b.provider ? 'rgba(14,165,233,0.3)' : 'rgba(100,116,139,0.12)')
          : (hot ? 'rgba(51,65,85,0.7)' : 'rgba(100,116,139,0.28)')
        ctx.lineWidth = hot ? 1.4 : 1
        ctx.beginPath()
        ctx.moveTo(l.a.x, l.a.y)
        ctx.lineTo(l.b.x, l.b.y)
        ctx.stroke()
      }
      for (const n of g.nodes) {
        const color = n.type === 'ip' ? (n.shared ? '#a78bfa' : n.provider ? PROVIDER_COLOR : IP_COLOR)
          : n.type === 'company' ? BRAND
          : RISK_COLOR[n.risk] ?? RISK_COLOR.low
        const glow = n.type !== 'ip' && (n.risk === 'critical' || n.risk === 'high')
        ctx.shadowColor = color
        ctx.shadowBlur = glow ? 9 : n.type === 'company' ? 8 : 0
        ctx.fillStyle = color
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.r + (hovered === n ? 2 : 0), 0, Math.PI * 2)
        ctx.fill()
        ctx.shadowBlur = 0
        if (n.type === 'company') {
          ctx.strokeStyle = n.risk === 'low' || n.risk === 'info' ? '#d8b4fe' : RISK_COLOR[n.risk]
          ctx.lineWidth = 2.5
          ctx.beginPath()
          ctx.arc(n.x, n.y, n.r + 3, 0, Math.PI * 2)
          ctx.stroke()
        }
        const sel = selectedRef.current
        if (sel && ((sel.kind === 'ip' && n.type === 'ip' && n.label === sel.value)
          || (sel.kind === 'ipset' && n.type === 'ip' && (sel.values ?? []).includes(n.label))
          || (sel.kind === 'host' && n.type === 'subdomain' && n.label === sel.value))) {
          ctx.strokeStyle = '#7e22ce'
          ctx.lineWidth = 2.5
          ctx.beginPath()
          ctx.arc(n.x, n.y, n.r + 6, 0, Math.PI * 2)
          ctx.stroke()
        }
        if (n.cross) {
          ctx.strokeStyle = 'rgba(147,51,234,0.7)'
          ctx.lineWidth = 1.2
          ctx.beginPath()
          ctx.arc(n.x, n.y, n.r + 3.5 + Math.sin(time * 2 + n.x) * 1.2, 0, Math.PI * 2)
          ctx.stroke()
        }
        if (n.type === 'company' || n.type === 'domain' || hovered === n) {
          ctx.font = n.type === 'company' ? '600 12px ui-sans-serif, system-ui' : '11px ui-monospace, monospace'
          ctx.fillStyle = n.type === 'company' ? '#3b0764' : '#475569'
          ctx.textAlign = 'center'
          // Above the node, or below it when it sits against the top edge
          const above = n.y - n.r - 18 > 4
          ctx.fillText(n.label, n.x, above ? n.y - n.r - (n.type === 'company' ? 8 : 6) : n.y + n.r + 15)
        }
      }
    }
    raf = requestAnimationFrame(draw)
    return () => cancelAnimationFrame(raf)
  }, [width, graph, open])

  const pick = (clientX: number, clientY: number): { node: GNode | null; x: number; y: number } => {
    const rect = canvasRef.current!.getBoundingClientRect()
    const x = clientX - rect.left
    const y = clientY - rect.top
    const g = graphRef.current
    let found: GNode | null = null
    if (g) {
      for (let i = g.nodes.length - 1; i >= 0; i--) {
        const n = g.nodes[i]
        const dx = n.x - x
        const dy = n.y - y
        if (dx * dx + dy * dy <= (n.r + 4) ** 2) {
          found = n
          break
        }
      }
    }
    return { node: found, x, y }
  }

  const onMove = (e: React.PointerEvent) => {
    const { node, x, y } = pick(e.clientX, e.clientY)
    const drag = dragRef.current
    if (drag) {
      // A click is never perfectly still: only a real displacement counts as a drag
      if (!drag.moved && Math.hypot(x - drag.x0, y - drag.y0) < DRAG_THRESHOLD) return
      drag.moved = true
      drag.node.x = x
      drag.node.y = y
      alphaRef.current = Math.max(alphaRef.current, 0.25)
      return
    }
    if (node !== hoverRef.current) {
      hoverRef.current = node
      setHover(node ? { node, x, y } : null)
    } else if (node) {
      setHover({ node, x, y })
    }
  }
  const onDown = (e: React.PointerEvent) => {
    const { node, x, y } = pick(e.clientX, e.clientY)
    if (!node) return
    node.pinned = true
    dragRef.current = { node, moved: false, x0: x, y0: y }
    ;(e.target as HTMLElement).setPointerCapture(e.pointerId)
  }
  const onUp = () => {
    const d = dragRef.current
    dragRef.current = null
    if (!d) return
    d.node.pinned = false
    if (!d.moved) {
      if (d.node.type === 'company') onSelectCompany(d.node.company)
      else if (d.node.type === 'domain') onSelectDomain(d.node.company, d.node.domain)
      else if (d.node.type === 'subdomain') onSelectHost(d.node.label, d.node.company)
      else onSelectIp(d.node.label)
    }
  }

  const toggle = () => {
    const next = !open
    setOpen(next)
    if (next) alphaRef.current = 1
    try { localStorage.setItem(OPEN_KEY, next ? '1' : '0') } catch { /* storage unavailable */ }
  }

  const cross = fullGraph.nodes.filter((n) => n.cross).length
  const shared = fullGraph.nodes.filter((n) => n.shared && !n.cross).length
  const provider = fullGraph.nodes.filter((n) => n.provider).length
  const ipsOf = (pick: (n: GNode) => boolean) => fullGraph.nodes.filter((n) => n.type === 'ip' && pick(n)).map((n) => n.label)
  const chipClass = (group: IpGroup, tone: string) => clsx(
    'text-[11px] px-2 py-0.5 rounded-full border transition-shadow cursor-pointer hover:shadow-sm',
    tone,
    selected?.kind === 'ipset' && selected.value === group && 'ring-2 ring-offset-1 ring-cyber-500',
  )

  return (
    <div className="card space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={toggle}
          aria-expanded={open}
          title={open ? t('nodeMap.collapse') : t('nodeMap.expand')}
          className="text-[15px] font-semibold tracking-tight text-dark-100 flex items-center gap-2 flex-1 min-w-[200px] text-left"
        >
          {open ? <ChevronDown className="w-4 h-4 text-dark-500" /> : <ChevronRight className="w-4 h-4 text-dark-500" />}
          <Network className="w-4 h-4 text-cyber-600" />
          {t('nodeMap.title')}
        </button>
        {cross > 0 && (
          <button type="button" title={t('nodeMap.chipFilter')}
            onClick={() => onSelectIpGroup('cross', ipsOf((n) => n.cross))}
            className={chipClass('cross', 'border-cyber-200 bg-cyber-50 text-cyber-700 font-semibold')}>
            {t('nodeMap.crossIps', { count: cross })}
          </button>
        )}
        {shared > 0 && (
          <button type="button" title={t('nodeMap.chipFilter')}
            onClick={() => onSelectIpGroup('shared', ipsOf((n) => n.shared && !n.cross))}
            className={chipClass('shared', 'border-dark-700 bg-dark-900 text-dark-300')}>
            {t('nodeMap.sharedIps', { count: shared })}
          </button>
        )}
        {provider > 0 && (
          <button type="button" title={`${t('nodeMap.providerHint')} ${t('nodeMap.chipFilter')}`}
            onClick={() => onSelectIpGroup('provider', ipsOf((n) => n.provider))}
            className={chipClass('provider', 'border-sky-200 bg-sky-50 text-sky-700')}>
            {t('nodeMap.providerIps', { count: provider })}
          </button>
        )}
        {filtered && (
          <button
            type="button"
            onClick={onClearFilters}
            className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full border border-red-200 bg-red-50 text-red-700 font-semibold hover:bg-red-100"
          >
            <X className="w-3 h-3" /> {t('nodeMap.clearFilters')}
          </button>
        )}
        {open && (
          <label className="inline-flex items-center gap-1.5 text-xs text-dark-400 cursor-pointer">
            <input type="checkbox" checked={showIps} onChange={(e) => setShowIps(e.target.checked)} className="accent-cyber-600" />
            {t('nodeMap.showIps')}
          </label>
        )}
      </div>

      {open && (<>
      <div ref={wrapRef} className="relative rounded-xl overflow-hidden border border-dark-800" style={{ height: HEIGHT }}>
        {graph.nodes.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center text-sm text-dark-500 bg-dark-950">
            {t('nodeMap.empty')}
          </div>
        ) : (
          <canvas
            ref={canvasRef}
            style={{ width, height: HEIGHT, display: 'block', touchAction: 'none', cursor: hover ? 'pointer' : 'default' }}
            onPointerMove={onMove}
            onPointerDown={onDown}
            onPointerUp={onUp}
            onPointerLeave={() => { hoverRef.current = null; setHover(null) }}
          />
        )}
        {hover && (
          <div
            className="pointer-events-none absolute z-10 max-w-[260px] rounded-lg border border-dark-700 bg-white/95 px-2.5 py-1.5 text-xs shadow-lg"
            style={{ left: Math.min(hover.x + 14, width - 270), top: Math.max(hover.y - 10, 4) }}
          >
            <div className="font-semibold text-dark-100 break-all">{hover.node.label}</div>
            <div className="text-dark-500">
              {t(`nodeMap.type.${hover.node.type}`)}
              {hover.node.type !== 'ip' && ` · ${hover.node.risk}`}
              {hover.node.type !== 'company' && hover.node.company ? ` · ${hover.node.company}` : ''}
            </div>
            {hover.node.detail && <div className="text-dark-400 mt-0.5">{hover.node.detail}</div>}
            <div className="text-cyber-700 mt-0.5">
              {t(hover.node.type === 'ip' || hover.node.type === 'subdomain' ? 'nodeMap.clickToFilterHosts' : 'nodeMap.clickToFilter')}
            </div>
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-dark-500">
        {(['critical', 'high', 'medium', 'low'] as const).map((r) => (
          <span key={r} className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: RISK_COLOR[r] }} />
            {r}
          </span>
        ))}
        <span className="inline-flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full" style={{ background: BRAND }} />{t('nodeMap.type.company')}</span>
        <span className="inline-flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full border border-cyber-600" style={{ background: '#a78bfa' }} />{t('nodeMap.legendShared')}</span>
        <span className="inline-flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full" style={{ background: PROVIDER_COLOR }} />{t('nodeMap.legendProvider')}</span>
        <span className="ml-auto">{t('nodeMap.hint')}</span>
      </div>
      </>)}
    </div>
  )
}
