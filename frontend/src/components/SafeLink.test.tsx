/**
 * Escaping tests — the console's XSS boundary.
 *
 * Everything rendered here originated in a log line, an advisory, or a model
 * (invariant #3). React escapes text; these tests pin the two places where
 * escaping is not automatic — URLs in `href`, and document bodies that a
 * Markdown renderer would happily turn into markup.
 */

import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import type { Citation } from '../api/types'
import { CitationList, ProvenanceList } from './Indicators'
import { DocumentText, SafeLink, isSafeUrl } from './SafeLink'

function citation(url: string | null): Citation {
  return {
    source_id: 'nvd',
    source: 'NVD',
    url,
    title: 'CVE-2021-44228',
    trust_tier: 'authoritative',
    published_at: null,
  }
}

describe('isSafeUrl', () => {
  it.each(['http://example.com', 'https://nvd.nist.gov/vuln/detail/CVE-1', '/relative/path'])(
    'permits %s',
    (url) => {
      expect(isSafeUrl(url)).toBe(true)
    },
  )

  it.each([
    'javascript:alert(1)',
    'JavaScript:alert(1)',
    '  javascript:alert(1)',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'vbscript:msgbox(1)',
    'file:///etc/passwd',
  ])('refuses %s', (url) => {
    expect(isSafeUrl(url)).toBe(false)
  })

  it('refuses an absent url rather than rendering a dead link', () => {
    expect(isSafeUrl(null)).toBe(false)
    expect(isSafeUrl('')).toBe(false)
  })
})

describe('SafeLink', () => {
  it('renders a real link for an http url', () => {
    render(<SafeLink href="https://nvd.nist.gov/x">NVD entry</SafeLink>)
    const link = screen.getByRole('link', { name: 'NVD entry' })
    expect(link).toHaveAttribute('href', 'https://nvd.nist.gov/x')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('renders a refused scheme as inert text, visibly refused', () => {
    render(<SafeLink href="javascript:alert(1)">Advisory</SafeLink>)

    expect(screen.queryByRole('link')).toBeNull()
    expect(screen.getByText(/unsafe link refused/i)).toBeInTheDocument()
    // Refused, not silently dropped: a citation that vanishes reads as a claim
    // with no source at all.
    expect(screen.getByText(/Advisory/)).toBeInTheDocument()
  })
})

describe('CitationList', () => {
  it('says so when a claim has no source', () => {
    render(<CitationList citations={[]} />)
    expect(screen.getByText('No source cited.')).toBeInTheDocument()
  })

  it('refuses a hostile citation url without dropping the citation', () => {
    render(<CitationList citations={[citation('javascript:alert(1)')]} />)

    expect(screen.queryByRole('link')).toBeNull()
    expect(screen.getByText(/CVE-2021-44228/)).toBeInTheDocument()
  })
})

describe('DocumentText', () => {
  it('renders report markup as text, never as markup', () => {
    const hostile = '# Report\n<img src=x onerror="alert(1)">\n<script>alert(2)</script>'
    const { container } = render(<DocumentText>{hostile}</DocumentText>)

    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText(/onerror/)).toBeInTheDocument()
  })
})

describe('ProvenanceList', () => {
  it('renders hostile provenance values as text', () => {
    const { container } = render(
      <ProvenanceList provenance={{ host: '<script>alert(1)</script>', confidence: 0.9 }} />,
    )

    expect(container.querySelector('script')).toBeNull()
    expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument()
  })

  it('states the absence of provenance rather than rendering nothing', () => {
    render(<ProvenanceList provenance={{}} />)
    expect(screen.getByText('No provenance recorded.')).toBeInTheDocument()
  })
})
