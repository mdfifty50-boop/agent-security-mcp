/**
 * Security Report Generator
 *
 * Generates comprehensive security assessment reports for agent deployments.
 */

/**
 * Generate a security assessment report from collected scan and audit results.
 */
export function generateSecurityReport(agentName, configs, auditResults) {
  const allIssues = [];
  let totalRiskScore = 0;
  let scanCount = 0;

  // Collect issues from config scans
  if (configs && Array.isArray(configs)) {
    for (const config of configs) {
      scanCount++;
      const parsed = typeof config === 'string' ? JSON.parse(config) : config;
      if (parsed.risk_score) totalRiskScore += parsed.risk_score;
      if (parsed.issues_found) {
        for (const issue of parsed.issues_found) {
          allIssues.push({
            source: 'config_scan',
            server: parsed.server_name || 'unknown',
            ...issue,
          });
        }
      }
    }
  }

  // Collect issues from audit results
  if (auditResults && Array.isArray(auditResults)) {
    for (const audit of auditResults) {
      scanCount++;
      const parsed = typeof audit === 'string' ? JSON.parse(audit) : audit;
      if (parsed.risk_score) totalRiskScore += parsed.risk_score;
      if (parsed.over_privileged) {
        for (const item of parsed.over_privileged) {
          allIssues.push({
            source: 'permission_audit',
            severity: item.risk || 'medium',
            title: item.type,
            description: item.message,
          });
        }
      }
      if (parsed.principle_of_least_privilege_violations) {
        for (const v of parsed.principle_of_least_privilege_violations) {
          allIssues.push({
            source: 'polp_audit',
            severity: 'high',
            title: v.principle,
            description: v.violation,
            recommendation: v.recommendation,
          });
        }
      }
    }
  }

  // Calculate overall risk
  const avgRisk = scanCount > 0 ? Math.round(totalRiskScore / scanCount) : 0;
  const overallRisk = avgRisk >= 70 ? 'critical' : avgRisk >= 40 ? 'high' : avgRisk >= 20 ? 'medium' : 'low';

  // Sort issues by severity for remediation priority
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  allIssues.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

  // Group by severity for summary
  const bySeverity = {
    critical: allIssues.filter(i => i.severity === 'critical').length,
    high: allIssues.filter(i => i.severity === 'high').length,
    medium: allIssues.filter(i => i.severity === 'medium').length,
    low: allIssues.filter(i => i.severity === 'low').length,
  };

  // Generate remediation priority
  const remediation = allIssues
    .filter(i => i.severity === 'critical' || i.severity === 'high')
    .map((issue, idx) => ({
      priority: idx + 1,
      severity: issue.severity,
      source: issue.source,
      issue: issue.title || issue.description?.substring(0, 100),
      action: issue.recommendation || `Review and address: ${issue.description?.substring(0, 80)}`,
    }));

  // Summary text
  const summaryParts = [];
  if (bySeverity.critical > 0) summaryParts.push(`${bySeverity.critical} CRITICAL`);
  if (bySeverity.high > 0) summaryParts.push(`${bySeverity.high} HIGH`);
  if (bySeverity.medium > 0) summaryParts.push(`${bySeverity.medium} MEDIUM`);
  if (bySeverity.low > 0) summaryParts.push(`${bySeverity.low} LOW`);

  const summary = allIssues.length === 0
    ? `Security assessment for "${agentName}" found no issues. The agent configuration appears secure.`
    : `Security assessment for "${agentName}" found ${allIssues.length} issue(s): ${summaryParts.join(', ')}. Overall risk level: ${overallRisk.toUpperCase()}.`;

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        report_id: `sec-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
        agent_name: agentName,
        generated_at: new Date().toISOString(),
        overall_risk_level: overallRisk,
        overall_risk_score: avgRisk,
        summary,
        issue_counts: bySeverity,
        total_issues: allIssues.length,
        scans_performed: scanCount,
        detailed_findings: allIssues,
        remediation_priority: remediation,
        compliance_notes: [
          'OWASP LLM Top 10 — Covers LLM01 (Prompt Injection), LLM02 (Insecure Output Handling), LLM06 (Sensitive Information Disclosure)',
          'Principle of Least Privilege — All agent permissions audited against role expectations',
          'Secret Management — Credentials and API keys checked for exposure',
        ],
      }, null, 2),
    }],
  };
}
