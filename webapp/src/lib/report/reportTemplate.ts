export * from './reportTemplateBase'

import type { ReportData } from './reportData'
import {
  generateReportHtml as generateReportHtmlBase,
  type LLMNarratives,
} from './reportTemplateBase'

/**
 * Weak-TLS checks are intentionally one finding per affected port. The base
 * report prefers `target`/`host` before `matchedAt`, which makes 443, 2083 and
 * 8443 findings for the same hostname look like duplicate rows. For rendering,
 * prefer the already-recorded matchedAt value so the port remains visible.
 */
export function withPortSpecificTlsTargets(data: ReportData): ReportData {
  return {
    ...data,
    vulnerabilities: {
      ...data.vulnerabilities,
      findings: data.vulnerabilities.findings.map((finding) =>
        finding.category === 'tls_weak_cipher' && finding.matchedAt
          ? { ...finding, target: finding.matchedAt }
          : finding,
      ),
    },
  }
}

export function generateReportHtml(
  data: ReportData,
  narratives: LLMNarratives | null,
): string {
  return generateReportHtmlBase(withPortSpecificTlsTargets(data), narratives)
}
