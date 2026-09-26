// Copyright 2026 Carlos Ganoza
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react'

let cached: string | null = null
let inflight: Promise<string | null> | null = null

// The running backend is the source of truth for the version (GET /health, public).
function loadVersion(): Promise<string | null> {
  if (cached) return Promise.resolve(cached)
  inflight ??= fetch('/health')
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      cached = typeof d?.version === 'string' ? d.version : null
      return cached
    })
    .catch(() => null)
  return inflight
}

export function useAppVersion(): string | null {
  const [version, setVersion] = useState<string | null>(cached)
  useEffect(() => {
    let alive = true
    loadVersion().then((v) => alive && setVersion(v))
    return () => { alive = false }
  }, [])
  return version
}
