/**
 * Rendering primitives for untrusted content.
 *
 * Everything on this console originates in a log line, an advisory, or a model's
 * output, and none of those are trustworthy (invariant #3). React escapes text
 * by default, which handles the common case; these components handle the two
 * places where it does not.
 *
 * A URL in an `href` is the first. `javascript:` and `data:` URLs execute when
 * clicked, and a citation's URL is attacker-reachable — a crafted advisory or a
 * poisoned knowledge source can put one there. `SafeLink` renders only http(s)
 * as a link and shows anything else as inert text, visibly refused rather than
 * silently dropped, because a citation that quietly vanishes looks like a claim
 * with no source.
 *
 * Markdown is the second. Report bodies are Markdown quoting raw log content;
 * converting them to HTML in the browser is how quoted log content becomes
 * executable. They are rendered as preformatted text, and the lint config
 * forbids `dangerouslySetInnerHTML` so nobody can quietly change that.
 */

import type { ReactElement } from 'react'

const SAFE_PROTOCOLS = new Set(['http:', 'https:'])

/** Whether a URL is safe to put in an `href`. */
export function isSafeUrl(candidate: string | null | undefined): boolean {
  if (!candidate) return false
  try {
    return SAFE_PROTOCOLS.has(new URL(candidate, window.location.origin).protocol)
  } catch {
    return false
  }
}

export interface SafeLinkProps {
  href: string | null | undefined
  children: string
  className?: string
}

export function SafeLink({ href, children, className }: SafeLinkProps): ReactElement {
  if (!isSafeUrl(href)) {
    return (
      <span className={className} title="This link was refused: only http and https are followed.">
        {children} <span className="refused">(unsafe link refused)</span>
      </span>
    )
  }
  return (
    <a
      className={className}
      href={href ?? undefined}
      // `noopener` stops the target page from reaching back through
      // `window.opener`; `noreferrer` keeps investigation URLs out of a third
      // party's referrer logs.
      rel="noopener noreferrer"
      target="_blank"
    >
      {children}
    </a>
  )
}

/**
 * Render document text as text.
 *
 * A report body is Markdown that quotes log lines. Presented in a `<pre>` it is
 * readable and inert; passed through a Markdown-to-HTML renderer it is a script
 * host. Readability is worth less than that.
 */
export function DocumentText({ children }: { children: string }): ReactElement {
  return <pre className="document">{children}</pre>
}
