/**
 * Tool Poisoning Detection
 *
 * Detects MCP tool descriptions that contain hidden instructions designed
 * to manipulate agent behavior. Part of OWASP Agentic Top 10.
 *
 * Attack vector: A malicious MCP server provides tools whose descriptions
 * contain hidden prompt injection that, when read by the agent, cause it
 * to take unintended actions (data exfiltration, privilege escalation, etc.)
 */

const POISONING_PATTERNS = [
  // Hidden instructions in tool descriptions
  {
    id: 'HIDDEN_INSTRUCTION',
    pattern: /(?:always|must|you\s+should|you\s+need\s+to|make\s+sure\s+to)\s+(?:call|invoke|run|execute|use)\s+/i,
    severity: 'high',
    description: 'Tool description contains imperative instructions to the agent',
    risk: 'Could force agent to call other tools or perform unexpected actions',
  },
  {
    id: 'EXFIL_IN_DESCRIPTION',
    pattern: /(?:send|post|forward|transmit|upload)\s+(?:the|all|any|user|session|context)\s+(?:data|info|information|content|input|output|results?)\s+(?:to|via)/i,
    severity: 'critical',
    description: 'Tool description instructs data exfiltration',
    risk: 'Agent may send user data to attacker-controlled endpoint',
  },
  {
    id: 'OVERRIDE_IN_DESCRIPTION',
    pattern: /(?:ignore|override|disregard|bypass)\s+(?:previous|other|all|any|safety|security)\s+/i,
    severity: 'critical',
    description: 'Tool description attempts to override safety rules',
    risk: 'Could cause agent to ignore safety boundaries',
  },
  {
    id: 'INVISIBLE_CHARS',
    pattern: /[\u200B-\u200F\u2028-\u202F\uFEFF\u00AD\u200E\u200F]/,
    severity: 'critical',
    description: 'Tool description contains invisible Unicode characters',
    risk: 'Hidden instructions may be embedded using zero-width characters',
  },
  {
    id: 'EXCESSIVE_LENGTH',
    check: (desc) => desc.length > 2000,
    severity: 'medium',
    description: 'Tool description is unusually long (>2000 chars)',
    risk: 'Long descriptions may hide instructions in later text that agents process but users don\'t review',
  },
  {
    id: 'TOOL_CHAIN_FORCE',
    pattern: /(?:before|after)\s+(?:calling|using|invoking)\s+this\s+tool.*(?:call|use|invoke|run)\s+/i,
    severity: 'high',
    description: 'Tool description mandates calling other tools',
    risk: 'Could force agent into an attack chain through tool description manipulation',
  },
  {
    id: 'FILE_WRITE_INSTRUCTION',
    pattern: /(?:write|create|save|append)\s+(?:to|a|the)\s+(?:file|path|directory|~\/|\/tmp|\/etc)/i,
    severity: 'high',
    description: 'Tool description instructs file system writes',
    risk: 'Could cause agent to write malicious files via tool description manipulation',
  },
  {
    id: 'CREDENTIAL_ACCESS',
    pattern: /(?:read|access|get|retrieve|extract)\s+(?:the\s+)?(?:api\s+key|token|secret|password|credential|\.env|config)/i,
    severity: 'critical',
    description: 'Tool description instructs credential access',
    risk: 'Could cause agent to leak secrets through tool description manipulation',
  },
  {
    id: 'NETWORK_CALL',
    pattern: /(?:fetch|curl|wget|request|connect\s+to|http|https:\/\/)/i,
    severity: 'medium',
    description: 'Tool description references external network calls',
    risk: 'Tool may make external network requests — verify the target is legitimate',
  },
  {
    id: 'SHELL_EXECUTION',
    pattern: /(?:exec|eval|system|subprocess|child_process|spawn|shell|bash\s+-c|sh\s+-c)/i,
    severity: 'high',
    description: 'Tool description references shell/code execution',
    risk: 'Tool may execute arbitrary shell commands',
  },
];

/**
 * Analyze an MCP tool definition for poisoning indicators.
 */
export function detectToolPoisoning(toolDefinition) {
  const { name, description, inputSchema } = toolDefinition;
  const findings = [];

  // Check the description
  for (const rule of POISONING_PATTERNS) {
    if (rule.pattern) {
      const match = rule.pattern.exec(description || '');
      if (match) {
        findings.push({
          pattern_id: rule.id,
          severity: rule.severity,
          description: rule.description,
          risk: rule.risk,
          matched_text: match[0].substring(0, 100),
          location: 'tool_description',
        });
      }
    }
    if (rule.check && rule.check(description || '')) {
      findings.push({
        pattern_id: rule.id,
        severity: rule.severity,
        description: rule.description,
        risk: rule.risk,
        location: 'tool_description',
      });
    }
  }

  // Check parameter descriptions for hidden instructions
  if (inputSchema?.properties) {
    for (const [paramName, paramDef] of Object.entries(inputSchema.properties)) {
      const paramDesc = paramDef.description || '';
      for (const rule of POISONING_PATTERNS) {
        if (rule.pattern) {
          const match = rule.pattern.exec(paramDesc);
          if (match) {
            findings.push({
              pattern_id: rule.id,
              severity: rule.severity,
              description: `${rule.description} (in parameter "${paramName}")`,
              risk: rule.risk,
              matched_text: match[0].substring(0, 100),
              location: `parameter.${paramName}`,
            });
          }
        }
      }
    }
  }

  // Calculate risk score
  const severityScores = { critical: 95, high: 75, medium: 50, low: 25 };
  let maxScore = 0;
  for (const f of findings) {
    const score = severityScores[f.severity] || 0;
    if (score > maxScore) maxScore = score;
  }

  let riskLevel = 'safe';
  if (maxScore >= 90) riskLevel = 'critical';
  else if (maxScore >= 70) riskLevel = 'high';
  else if (maxScore >= 40) riskLevel = 'medium';
  else if (maxScore > 0) riskLevel = 'low';

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        tool_name: name,
        risk_level: riskLevel,
        risk_score: maxScore,
        poisoning_indicators: findings,
        total_patterns_checked: POISONING_PATTERNS.length,
        verdict: findings.length === 0
          ? `Tool "${name}" appears safe. No poisoning indicators detected.`
          : `Tool "${name}" has ${findings.length} poisoning indicator(s). Highest severity: ${findings[0]?.severity}. Review before allowing agent to use this tool.`,
      }, null, 2),
    }],
  };
}
