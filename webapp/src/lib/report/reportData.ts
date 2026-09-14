export * from './reportDataBase'

import { getGraphSession } from '@/app/api/graph/neo4j'
import type { ReportData } from './reportDataBase'
import { gatherReportData as gatherReportDataBase } from './reportDataBase'

export const AGGREGATED_TOP_FINDINGS_QUERY = `
MATCH (f:ChainFinding {project_id: $pid})
OPTIONAL MATCH (f)-[:FOUND_ON]->(target)
WITH f, [x IN collect(DISTINCT COALESCE(target.address, target.name, target.url))
         WHERE x IS NOT NULL] AS targetHosts
WITH f, reduce(s = '', x IN targetHosts |
         s + CASE WHEN s = '' THEN '' ELSE ', ' END + x) AS targetHost
RETURN f.title AS title, f.severity AS severity, f.finding_type AS findingType,
       f.evidence AS evidence,
       CASE WHEN targetHost = '' THEN null ELSE targetHost END AS targetHost
ORDER BY CASE f.severity
           WHEN 'critical' THEN 0
           WHEN 'high' THEN 1
           WHEN 'medium' THEN 2
           WHEN 'low' THEN 3
           ELSE 4
         END
LIMIT 20
`

/**
 * Gather the normal report payload, then replace the ChainFinding table with a
 * finding-scoped query. The legacy query expanded one row per FOUND_ON target,
 * so a single finding attached to a hostname and one or more IPs appeared two
 * or three times in reports.
 */
export async function gatherReportData(projectId: string): Promise<ReportData> {
  const data = await gatherReportDataBase(projectId)
  const session = getGraphSession()

  try {
    const result = await session.run(AGGREGATED_TOP_FINDINGS_QUERY, { pid: projectId })
    data.attackChains.topFindings = result.records.map((r: any) => ({
      title: (r.get('title') as string) || 'Untitled',
      severity: (r.get('severity') as string) || 'unknown',
      findingType: (r.get('findingType') as string) || 'unknown',
      evidence: r.get('evidence') as string | null,
      targetHost: r.get('targetHost') as string | null,
    }))
  } finally {
    await session.close()
  }

  return data
}
