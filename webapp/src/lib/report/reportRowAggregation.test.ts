import { describe, expect, it } from 'vitest'

import { AGGREGATED_TOP_FINDINGS_QUERY } from './reportData'
import { withPortSpecificTlsTargets } from './reportTemplate'
import type { ReportData } from './reportData'


describe('report row aggregation', () => {
  it('aggregates FOUND_ON targets before returning ChainFinding rows', () => {
    expect(AGGREGATED_TOP_FINDINGS_QUERY).toContain(
      'collect(DISTINCT COALESCE(target.address, target.name, target.url))',
    )
    expect(AGGREGATED_TOP_FINDINGS_QUERY).toContain('reduce(s = \'\'')
    expect(AGGREGATED_TOP_FINDINGS_QUERY).not.toContain(
      'WITH f, COALESCE(target.address, target.name) AS targetHost',
    )
  })

  it('renders weak-cipher findings with the port-specific matchedAt target', () => {
    const input = {
      vulnerabilities: {
        findings: [
          {
            name: 'Weak Cipher Suites Detection',
            severity: 'low',
            source: 'nuclei',
            category: 'tls_weak_cipher',
            cvssScore: null,
            matchedAt: 'https://auth.example.test:8443',
            host: 'auth.example.test',
            targetIp: null,
            targetPort: 8443,
            target: 'auth.example.test',
            parentType: null,
            endpointPath: null,
            paramName: null,
            findingSource: 'nuclei',
          },
        ],
      },
    } as unknown as ReportData

    const output = withPortSpecificTlsTargets(input)
    expect(output.vulnerabilities.findings[0].target).toBe(
      'https://auth.example.test:8443',
    )
    expect(input.vulnerabilities.findings[0].target).toBe('auth.example.test')
  })
})
