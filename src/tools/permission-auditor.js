/**
 * Agent Permission Auditor
 *
 * Audits agent configurations for over-privileged access and
 * principle of least privilege violations.
 */

/**
 * Risk classification for tool categories.
 */
const TOOL_RISK = {
  // Critical risk — can cause irreversible damage
  Bash: { risk: 'critical', category: 'execution', justification_required: true },
  execute: { risk: 'critical', category: 'execution', justification_required: true },
  shell: { risk: 'critical', category: 'execution', justification_required: true },
  terminal: { risk: 'critical', category: 'execution', justification_required: true },
  Write: { risk: 'high', category: 'filesystem_write', justification_required: true },
  Edit: { risk: 'high', category: 'filesystem_write', justification_required: true },
  delete: { risk: 'critical', category: 'filesystem_write', justification_required: true },

  // High risk — can leak or modify data
  WebFetch: { risk: 'medium', category: 'network', justification_required: false },
  WebSearch: { risk: 'low', category: 'network', justification_required: false },
  fetch: { risk: 'medium', category: 'network', justification_required: false },

  // Medium risk — information access
  Read: { risk: 'low', category: 'filesystem_read', justification_required: false },
  Glob: { risk: 'low', category: 'filesystem_read', justification_required: false },
  Grep: { risk: 'low', category: 'filesystem_read', justification_required: false },

  // MCP tools
  mcp: { risk: 'medium', category: 'mcp_access', justification_required: false },

  // Task spawning
  Task: { risk: 'high', category: 'agent_spawning', justification_required: true },
  Agent: { risk: 'high', category: 'agent_spawning', justification_required: true },
};

/**
 * Role-based expected tool profiles.
 * Defines what tools each role typically needs.
 */
const ROLE_PROFILES = {
  researcher: {
    expected: ['Read', 'Glob', 'Grep', 'WebSearch', 'WebFetch'],
    suspicious: ['Bash', 'Write', 'Edit', 'delete', 'Task'],
    max_file_access: 'read_only',
    max_network: 'outbound_readonly',
  },
  analyst: {
    expected: ['Read', 'Glob', 'Grep', 'WebSearch'],
    suspicious: ['Bash', 'Write', 'delete', 'Task'],
    max_file_access: 'read_only',
    max_network: 'outbound_readonly',
  },
  developer: {
    expected: ['Read', 'Glob', 'Grep', 'Write', 'Edit', 'Bash'],
    suspicious: ['delete'],
    max_file_access: 'read_write',
    max_network: 'full',
  },
  reviewer: {
    expected: ['Read', 'Glob', 'Grep'],
    suspicious: ['Write', 'Edit', 'Bash', 'delete', 'Task'],
    max_file_access: 'read_only',
    max_network: 'none',
  },
  orchestrator: {
    expected: ['Read', 'Glob', 'Grep', 'Task', 'Agent'],
    suspicious: ['Bash', 'delete'],
    max_file_access: 'read_write',
    max_network: 'outbound_readonly',
  },
  monitor: {
    expected: ['Read', 'Glob', 'Grep'],
    suspicious: ['Write', 'Edit', 'Bash', 'delete', 'Task', 'WebFetch'],
    max_file_access: 'read_only',
    max_network: 'none',
  },
};

/**
 * Audit agent permissions against its declared role.
 */
export function auditAgentPermissions(agentConfig, role) {
  const { tools, file_access, network_access, env_vars } = agentConfig;
  const overPrivileged = [];
  const recommendations = [];
  const polViolations = []; // Principle of Least Privilege

  const profile = ROLE_PROFILES[role?.toLowerCase()];

  // Analyze tools
  if (tools && Array.isArray(tools)) {
    for (const tool of tools) {
      const toolInfo = TOOL_RISK[tool] || { risk: 'unknown', category: 'unknown', justification_required: false };

      // Check against role profile
      if (profile && profile.suspicious.includes(tool)) {
        overPrivileged.push({
          type: 'suspicious_tool',
          tool,
          risk: toolInfo.risk,
          category: toolInfo.category,
          message: `Tool "${tool}" is suspicious for role "${role}". This role typically doesn't need ${toolInfo.category} access.`,
        });
        polViolations.push({
          principle: 'least_privilege',
          violation: `"${role}" role has "${tool}" tool which grants ${toolInfo.category} access beyond typical needs.`,
          recommendation: `Remove "${tool}" unless there is a documented justification.`,
        });
      }

      // Flag critical tools that need justification
      if (toolInfo.justification_required && toolInfo.risk === 'critical') {
        recommendations.push(`Tool "${tool}" has CRITICAL risk level. Ensure this access is justified and logged.`);
      }
    }

    // Check for wildcard tool access
    if (tools.includes('*') || tools.includes('all')) {
      overPrivileged.push({
        type: 'wildcard_tools',
        tool: '*',
        risk: 'critical',
        category: 'all',
        message: 'Agent has wildcard tool access. This grants access to ALL tools including destructive ones.',
      });
      polViolations.push({
        principle: 'least_privilege',
        violation: 'Wildcard tool access violates principle of least privilege.',
        recommendation: 'Explicitly list only the tools this agent needs.',
      });
    }
  }

  // Analyze file access
  if (file_access) {
    if (Array.isArray(file_access)) {
      for (const path of file_access) {
        if (path === '/' || path === '~' || path === '*' || path === '**') {
          overPrivileged.push({
            type: 'broad_file_access',
            path,
            risk: 'critical',
            message: `File access pattern "${path}" grants access to the entire filesystem.`,
          });
          polViolations.push({
            principle: 'least_privilege',
            violation: `File access "${path}" is unrestricted.`,
            recommendation: 'Restrict file access to specific directories needed by this agent.',
          });
        }
      }
    }

    // Check against role expectations
    if (profile) {
      if (profile.max_file_access === 'read_only' && tools?.some(t => ['Write', 'Edit', 'delete'].includes(t))) {
        polViolations.push({
          principle: 'least_privilege',
          violation: `Role "${role}" should have read-only file access but has write tools.`,
          recommendation: 'Remove write/edit tools or change the role classification.',
        });
      }
    }
  }

  // Analyze network access
  if (network_access) {
    if (profile && profile.max_network === 'none' && network_access !== 'none' && network_access !== false) {
      overPrivileged.push({
        type: 'unnecessary_network',
        risk: 'medium',
        message: `Role "${role}" typically doesn't need network access, but it is enabled.`,
      });
      polViolations.push({
        principle: 'least_privilege',
        violation: `Network access enabled for "${role}" role which typically needs none.`,
        recommendation: 'Disable network access unless justified.',
      });
    }
  }

  // Analyze env vars for secret exposure
  if (env_vars && Array.isArray(env_vars)) {
    const secretVars = env_vars.filter(v =>
      /(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)/i.test(v)
    );
    if (secretVars.length > 0) {
      overPrivileged.push({
        type: 'secret_env_access',
        risk: 'high',
        vars: secretVars,
        message: `Agent has access to ${secretVars.length} secret environment variable(s): ${secretVars.join(', ')}`,
      });
      recommendations.push('Review whether this agent needs access to these secret environment variables. Apply principle of least privilege.');
    }
  }

  // Calculate risk score
  const riskWeights = { critical: 30, high: 20, medium: 10, low: 5, unknown: 15 };
  const rawScore = overPrivileged.reduce((sum, item) => sum + (riskWeights[item.risk] || 10), 0)
    + polViolations.length * 8;
  const riskScore = Math.min(100, rawScore);

  // Add general recommendations
  if (riskScore === 0) {
    recommendations.push('Agent permissions appear well-scoped for its role.');
  }
  if (!profile) {
    recommendations.push(`Role "${role}" is not in the standard role profiles. Consider using: ${Object.keys(ROLE_PROFILES).join(', ')}`);
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        risk_score: riskScore,
        risk_level: riskScore >= 70 ? 'critical' : riskScore >= 40 ? 'high' : riskScore >= 20 ? 'medium' : 'low',
        role,
        role_profile_matched: !!profile,
        over_privileged: overPrivileged,
        principle_of_least_privilege_violations: polViolations,
        recommendations,
        agent_summary: {
          tools_count: tools?.length ?? 0,
          file_access_paths: Array.isArray(file_access) ? file_access.length : (file_access ? 1 : 0),
          network_access: network_access ?? 'not_specified',
          env_vars_count: env_vars?.length ?? 0,
        },
      }, null, 2),
    }],
  };
}
