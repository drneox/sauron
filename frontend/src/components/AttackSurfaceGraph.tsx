// Copyright 2026 Carlos Ganoza
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Sparkles } from 'lucide-react'
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
const HEIGHT = 440

interface Props {
  hosts: TaggedHost[]
  companies: Company[]
  focusDomain: string | null
  onSelectCompany: (companyName: string) => void
  onSelectDomain: (companyName: string, domain: string) => void
}

export default function AttackSurfaceGraph({ hosts, companies, focusDomain, onSelectCompany, onSelectDomain }: Props) {
  const { t } = useTranslation()
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const [width, setWidth] = useState(900)
  const [showIps, setShowIps] = useState(true)
  const [hover, setHover] = useState<{ node: GNode; x: number; y: number } | null>(null)
  const graphRef = useRef<Graph | null>(null)
  const hoverRef = useRef<GNode | null>(null)
  const alphaRef = useRef(1)
  const dragRef = useRef<{ node: GNode; moved: boolean } | null>(null)
  const stars = useRef(
    Array.from({ length: 70 }, () => ({ x: Math.random(), y: Math.random(), r: Math.random() * 1.2 + 0.3, p: Math.random() * 6 })),
  )

  const graph = useMemo(
    () => buildGraph(hosts, companies, focusDomain, showIps),
    [hosts, companies, focusDomain, showIps],
  )

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
  }, [])

  // Animation loop: physics + drawing. The floor on alpha keeps the constellation drifting gently.
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
          ? (hot ? 'rgba(147,51,234,0.8)' : l.b.shared ? 'rgba(147,51,234,0.32)' : 'rgba(100,116,139,0.12)')
          : (hot ? 'rgba(51,65,85,0.7)' : 'rgba(100,116,139,0.28)')
        ctx.lineWidth = hot ? 1.4 : 1
        ctx.beginPath()
        ctx.moveTo(l.a.x, l.a.y)
        ctx.lineTo(l.b.x, l.b.y)
        ctx.stroke()
      }
      for (const n of g.nodes) {
        const color = n.type === 'ip' ? (n.shared ? '#a78bfa' : IP_COLOR)
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
  }, [width, graph])

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
    if (dragRef.current) {
      dragRef.current.node.x = x
      dragRef.current.node.y = y
      dragRef.current.moved = true
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
    const { node } = pick(e.clientX, e.clientY)
    if (!node) return
    node.pinned = true
    dragRef.current = { node, moved: false }
    ;(e.target as HTMLElement).setPointerCapture(e.pointerId)
  }
  const onUp = () => {
    const d = dragRef.current
    dragRef.current = null
    if (!d) return
    d.node.pinned = false
    if (!d.moved) {
      if (d.node.type === 'company') onSelectCompany(d.node.company)
      else if (d.node.type === 'domain' || d.node.type === 'subdomain') onSelectDomain(d.node.company, d.node.domain)
    }
  }

  const cross = graph.nodes.filter((n) => n.cross).length
  const shared = graph.nodes.filter((n) => n.shared && !n.cross).length

  return (
    <div className="card space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <h3 className="text-[15px] font-semibold tracking-tight text-dark-100 flex items-center gap-2 flex-1 min-w-[200px]">
          <Sparkles className="w-4 h-4 text-cyber-600" />
          {t('constellation.title')}
        </h3>
        {cross > 0 && (
          <span className="text-[11px] px-2 py-0.5 rounded-full border border-cyber-200 bg-cyber-50 text-cyber-700 font-semibold">
            {t('constellation.crossIps', { count: cross })}
          </span>
        )}
        {shared > 0 && (
          <span className="text-[11px] px-2 py-0.5 rounded-full border border-dark-700 bg-dark-900 text-dark-300">
            {t('constellation.sharedIps', { count: shared })}
          </span>
        )}
        <label className="inline-flex items-center gap-1.5 text-xs text-dark-400 cursor-pointer">
          <input type="checkbox" checked={showIps} onChange={(e) => setShowIps(e.target.checked)} className="accent-cyber-600" />
          {t('constellation.showIps')}
        </label>
      </div>

      <div ref={wrapRef} className="relative rounded-xl overflow-hidden border border-dark-800" style={{ height: HEIGHT }}>
        {graph.nodes.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center text-sm text-dark-500 bg-dark-950">
            {t('constellation.empty')}
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
              {t(`constellation.type.${hover.node.type}`)}
              {hover.node.type !== 'ip' && ` · ${hover.node.risk}`}
              {hover.node.type !== 'company' && hover.node.company ? ` · ${hover.node.company}` : ''}
            </div>
            {hover.node.detail && <div className="text-dark-400 mt-0.5">{hover.node.detail}</div>}
            {(hover.node.type === 'company' || hover.node.type === 'domain') && (
              <div className="text-cyber-700 mt-0.5">{t('constellation.clickToFilter')}</div>
            )}
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
        <span className="inline-flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full" style={{ background: BRAND }} />{t('constellation.type.company')}</span>
        <span className="inline-flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full border border-cyber-600" style={{ background: '#a78bfa' }} />{t('constellation.legendShared')}</span>
        <span className="ml-auto">{t('constellation.hint')}</span>
      </div>
    </div>
  )
}
