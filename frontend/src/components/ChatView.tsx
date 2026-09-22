import { useEffect, useRef, useState } from 'react'
import axios from 'axios'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import { Maximize2, Minimize2, Send, ShieldCheck, Wrench, X } from 'lucide-react'
import SauronBotIcon from './SauronBotIcon'
import { ChatMessage, ChatResponse, ChatToolUse } from '../types/report'

// ── Minimal markdown rendering (bold, bullets, numbered lists, headers, code) ──
function renderInline(text: string, keyPrefix: string) {
  const parts = text.split(/(\*\*.+?\*\*|`[^`]+`)/g)
  return parts.map((p, i) => {
    if (p.startsWith('**') && p.endsWith('**')) {
      return <strong key={`${keyPrefix}-${i}`} className="text-dark-50 font-semibold">{p.slice(2, -2)}</strong>
    }
    if (p.startsWith('`') && p.endsWith('`') && p.length > 2) {
      return (
        <code key={`${keyPrefix}-${i}`} className="font-mono text-[12px] bg-dark-900 border border-dark-800 rounded px-1 py-px text-cyber-700">
          {p.slice(1, -1)}
        </code>
      )
    }
    return <span key={`${keyPrefix}-${i}`}>{p}</span>
  })
}

function MarkdownBlock({ text }: { text: string }) {
  const lines = text.split('\n')
  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        const trimmed = line.trim()
        if (!trimmed) return null
        if (trimmed.startsWith('### ')) {
          return (
            <p key={i} className="text-sm font-bold text-dark-100 pt-1">
              {renderInline(trimmed.slice(4), `h${i}`)}
            </p>
          )
        }
        if (trimmed.startsWith('## ') || trimmed.startsWith('# ')) {
          const cut = trimmed.startsWith('## ') ? 3 : 2
          return (
            <p key={i} className="text-[15px] font-bold text-dark-100 pt-1.5">
              {renderInline(trimmed.slice(cut), `h${i}`)}
            </p>
          )
        }
        if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
          return (
            <div key={i} className="flex gap-2 text-sm text-dark-200">
              <span className="text-cyber-600 shrink-0">•</span>
              <span>{renderInline(trimmed.slice(2), `l${i}`)}</span>
            </div>
          )
        }
        const numbered = trimmed.match(/^(\d+)[.)]\s+(.*)$/)
        if (numbered) {
          return (
            <div key={i} className="flex gap-2 text-sm text-dark-200">
              <span className="text-cyber-600 shrink-0 font-mono">{numbered[1]}.</span>
              <span>{renderInline(numbered[2], `n${i}`)}</span>
            </div>
          )
        }
        return (
          <p key={i} className="text-sm text-dark-200 leading-relaxed">
            {renderInline(trimmed, `l${i}`)}
          </p>
        )
      })}
    </div>
  )
}

interface ConversationEntry extends ChatMessage {
  tools_used?: ChatToolUse[]
  redacted_secrets?: number
}

// Suggestion chips: the visible label and the hidden prompt sent to the model
// both follow the active UI language (chat.sug.* / chat.prompt.*).
const SUGGESTION_IDS = ['howManyAssets', 'newSubs', 'exposedEmails', 'worstGrade'] as const

const HISTORY_CAP = 10

// Floating SauronBot widget — mounted globally for authenticated users.
export default function ChatView() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [fullscreen, setFullscreen] = useState(false)
  const [messages, setMessages] = useState<ConversationEntry[]>([])
  const [input, setInput] = useState('')
  const [thinking, setThinking] = useState(false)
  const [error, setError] = useState('')
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (open) bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, thinking, open])

  const send = async (raw: string) => {
    const text = raw.trim()
    if (!text || thinking) return
    setError('')
    setInput('')
    const userEntry: ConversationEntry = { role: 'user', content: text }
    const nextMessages = [...messages, userEntry]
    setMessages(nextMessages)
    setThinking(true)
    try {
      const history: ChatMessage[] = nextMessages
        .slice(-(HISTORY_CAP + 1), -1)
        .map(({ role, content }) => ({ role, content }))
      const { data } = await axios.post<ChatResponse>('/api/chat', {
        message: text,
        history,
      })
      // Guardrail rejections (blocked: true) arrive as a normal assistant reply.
      setMessages([...nextMessages, {
        role: 'assistant',
        content: data.reply,
        tools_used: data.tools_used,
        redacted_secrets: data.redacted_secrets,
      }])
    } catch (err: unknown) {
      const msg = axios.isAxiosError(err)
        ? err.response?.data?.detail || err.message
        : t('common.unknownError')
      setError(msg)
    } finally {
      setThinking(false)
    }
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        title={t('chat.open')}
        className="fixed bottom-5 right-5 z-50 w-14 h-14 rounded-full bg-purple-600 hover:bg-purple-500 shadow-lg shadow-purple-600/30 flex items-center justify-center transition-transform duration-150 hover:scale-105 text-white"
      >
        <SauronBotIcon className="w-8 h-8" />
      </button>
    )
  }

  return (
    <div
      className={clsx(
        'z-50 card !p-0 shadow-2xl flex flex-col overflow-hidden',
        fullscreen
          ? 'fixed inset-4 md:inset-8'
          : 'fixed bottom-20 right-5 w-[380px] max-w-[calc(100vw-2.5rem)] h-[70vh] max-h-[640px]',
      )}
    >
      {/* Header */}
      <div className="bg-purple-600 px-4 py-3 flex items-center gap-2.5 shrink-0">
        <div className="w-8 h-8 rounded-full bg-white/15 flex items-center justify-center shrink-0 text-white">
          <SauronBotIcon className="w-6 h-6" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-semibold text-white tracking-tight">SauronBot</div>
          <div className="text-[11px] text-purple-200">{t('chat.subtitle')}</div>
        </div>
        <button
          onClick={() => setFullscreen((f) => !f)}
          title={fullscreen ? t('chat.collapse') : t('chat.expand')}
          className="w-7 h-7 rounded-full flex items-center justify-center text-purple-200 hover:text-white hover:bg-white/15 transition-colors duration-150"
        >
          {fullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
        </button>
        <button
          onClick={() => { setOpen(false); setFullscreen(false) }}
          title={t('common.close')}
          className="w-7 h-7 rounded-full flex items-center justify-center text-purple-200 hover:text-white hover:bg-white/15 transition-colors duration-150"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4 min-h-0">
        {messages.length === 0 && !thinking && (
          <div className="h-full flex flex-col items-center justify-center gap-4 text-center">
            <p className="text-sm text-dark-500">
              {t('chat.emptyHint')}
            </p>
            <div className="flex flex-wrap justify-center gap-2">
              {SUGGESTION_IDS.map((id) => (
                <button
                  key={id}
                  onClick={() => send(t(`chat.prompt.${id}`))}
                  className="chip bg-cyber-50 text-cyber-700 border-cyber-200 hover:bg-cyber-100 transition-colors duration-150"
                >
                  {t(`chat.sug.${id}`)}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((m, i) => (
          <div key={i} className={clsx('flex', m.role === 'user' ? 'justify-end' : 'justify-start')}>
            {m.role === 'user' ? (
              <div className="max-w-[75%] bg-cyber-100 text-cyber-900 rounded-2xl rounded-br-md px-4 py-2.5 text-sm whitespace-pre-wrap">
                {m.content}
              </div>
            ) : (
              <div className="max-w-[85%] space-y-1.5">
                <div className="card !p-4 !rounded-2xl !rounded-tl-md">
                  <MarkdownBlock text={m.content} />
                </div>
                {m.tools_used && m.tools_used.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pl-1">
                    {m.tools_used.map((t, j) => (
                      <span
                        key={j}
                        title={JSON.stringify(t.args)}
                        className="chip bg-dark-900 text-dark-500 border-dark-800 font-normal"
                      >
                        <Wrench className="w-3 h-3" />
                        {t.tool}
                        <span className="text-dark-600">({t.result_count})</span>
                      </span>
                    ))}
                  </div>
                )}
                {(m.redacted_secrets ?? 0) > 0 && (
                  <div className="flex items-center gap-1 pl-1 text-[10px] text-dark-500">
                    <ShieldCheck className="w-3 h-3" />
                    {t('chat.redacted')}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}

        {thinking && (
          <div className="flex justify-start">
            <div className="card !p-4 !rounded-2xl !rounded-tl-md text-sm text-dark-500 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyber-500 animate-pulse" />
              {t('chat.thinking')}
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {error && (
        <div className="mx-4 mb-2 px-3 py-2 rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs">
          {error}
        </div>
      )}

      <form
        onSubmit={(e) => { e.preventDefault(); send(input) }}
        className="border-t border-dark-800 px-4 py-3 flex items-center gap-2 shrink-0"
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={t('chat.inputPlaceholder')}
          disabled={thinking}
          className="flex-1 bg-dark-950 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 placeholder:text-dark-600 focus:border-cyber-400 disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={thinking || !input.trim()}
          className="btn-secondary !bg-cyber-600 !text-white !border-cyber-600 hover:!bg-cyber-700 !px-3 !py-2"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  )
}
