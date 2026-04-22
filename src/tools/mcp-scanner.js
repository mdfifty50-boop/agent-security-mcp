/**
 * MCP Configuration Scanner
 *
 * Scans MCP server configurations for security issues, misconfigurations,
 * and potential attack vectors.
 */

const CONFIG_RULES = [
  // Command safety
  {
    id: 'DANGEROUS_COMMAND',
    check: (config) => {
      const dangerous = ['rm', 'dd', 'mkfs', 'fdisk', 'format', 'shutdown', 'reboot'];
      const cmd = config.command?.toLowerCase() || '';
      return dangerous.some(d => cmd.includes(d));
    },
    severity: 'critical',
    category: 'command_safety',
    title: 'Dangerous system command',
    description: 'The MCP server command includes a potentially destructive system command.',
    recommendation: 'Review whether this command is necessary. Use a sandboxed environment or restricted shell.',
  },
  {
    id: 'SHELL_EXEC',
    check: (config) => {
      const cmd = config.command?.toLowerCase() || '';
      return ['bash', 'sh', 'zsh', 'cmd', 'powershell', 'pwsh'].includes(cmd) &&
        config.args?.some(a => ['-c', '/c', '-Command'].includes(a));
    },
    severity: 'high',
    category: 'command_safety',
    title: 'Shell execution with inline command',
    description: 'The server runs a shell with inline command execution, which increases injection risk.',
    recommendation: 'Run the target program directly instead of via shell -c. If shell is needed, validate all arguments.',
  },
  {
    id: 'UNKNOWN_BINARY',
    check: (config) => {
      const known = ['node', 'npx', 'python', 'python3', 'uvx', 'docker', 'deno', 'bun', 'cargo'];
      const cmd = config.command?.split('/').pop()?.toLowerCase() || '';
      return !known.includes(cmd);
    },
    severity: 'medium',
    category: 'command_safety',
    title: 'Unknown binary',
    description: 'The server command is not a commonly recognized MCP runtime.',
    recommendation: 'Verify the binary is from a trusted source. Check its integrity and permissions.',
  },

  // Environment variable security
  {
    id: 'ENV_SECRETS_EXPOSED',
    check: (config) => {
      if (!config.env) return false;
      const secretKeys = Object.keys(config.env).filter(k =>
        /(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)/i.test(k)
      );
      return secretKeys.length > 0;
    },
    severity: 'high',
    category: 'env_security',
    title: 'Secrets in environment configuration',
    description: 'API keys or secrets are passed via environment variables in the configuration.',
    recommendation: 'Use a secrets manager or .env file with restricted permissions. Avoid hardcoding secrets in MCP config files.',
    details: (config) => {
      const secretKeys = Object.keys(config.env || {}).filter(k =>
        /(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)/i.test(k)
      );
      return { exposed_keys: secretKeys };
    },
  },
  {
    id: 'ENV_PATH_OVERRIDE',
    check: (config) => {
      return config.env && ('PATH' in config.env || 'LD_LIBRARY_PATH' in config.env);
    },
    severity: 'high',
    category: 'env_security',
    title: 'PATH or library path override',
    description: 'The configuration overrides PATH or LD_LIBRARY_PATH, which could be used to hijack binary resolution.',
    recommendation: 'Avoid overriding PATH. If necessary, prepend to existing PATH rather than replacing it.',
  },

  // Network exposure
  {
    id: 'NETWORK_PORT',
    check: (config) => {
      const args = (config.args || []).join(' ');
      return /--port|--listen|--host\s+0\.0\.0\.0|-p\s+\d+/i.test(args);
    },
    severity: 'medium',
    category: 'network',
    title: 'Network port exposure',
    description: 'The server appears to listen on a network port, potentially exposing it beyond localhost.',
    recommendation: 'Bind to 127.0.0.1 only. Use stdio transport instead of HTTP where possible. Add authentication if network exposure is required.',
  },
  {
    id: 'HTTP_TRANSPORT',
    check: (config) => {
      const args = (config.args || []).join(' ');
      return /--transport\s+(?:http|sse)|--sse/i.test(args);
    },
    severity: 'medium',
    category: 'network',
    title: 'HTTP/SSE transport',
    description: 'Using HTTP or SSE transport exposes the server to network-based attacks.',
    recommendation: 'Prefer stdio transport for local use. If HTTP is needed, use TLS and authentication.',
  },

  // File system access
  {
    id: 'BROAD_FILE_ACCESS',
    check: (config) => {
      const args = (config.args || []).join(' ');
      return /[\/\\]$|\*|--allow-all|--unrestricted/i.test(args) || args.includes('/');
    },
    severity: 'medium',
    category: 'filesystem',
    title: 'Broad file system access',
    description: 'The server configuration suggests broad file system access.',
    recommendation: 'Restrict file access to specific directories needed by the server. Use allowlists instead of denylists.',
  },

  // Docker / container
  {
    id: 'DOCKER_PRIVILEGED',
    check: (config) => {
      const args = (config.args || []).join(' ');
      return args.includes('--privileged') || args.includes('--cap-add');
    },
    severity: 'critical',
    category: 'container',
    title: 'Privileged container mode',
    description: 'Running with --privileged or added capabilities breaks container isolation.',
    recommendation: 'Remove --privileged flag. Grant only specific capabilities needed with --cap-add.',
  },
  {
    id: 'DOCKER_HOST_MOUNT',
    check: (config) => {
      const args = (config.args || []).join(' ');
      return /(?:-v|--volume)\s+[\/\\]/.test(args);
    },
    severity: 'medium',
    category: 'container',
    title: 'Host filesystem mount',
    description: 'Mounting host directories into the container gives the server access to the host filesystem.',
    recommendation: 'Mount only the minimum directories needed. Use read-only mounts (:ro) where possible.',
  },
];

/**
 * Scan an MCP server configuration for security issues.
 */
export function scanMcpConfig(config, serverName) {
  const issues = [];

  for (const rule of CONFIG_RULES) {
    try {
      if (rule.check(config)) {
        const issue = {
          rule_id: rule.id,
          severity: rule.severity,
          category: rule.category,
          title: rule.title,
          description: rule.description,
          recommendation: rule.recommendation,
        };
        if (rule.details) {
          issue.details = rule.details(config);
        }
        issues.push(issue);
      }
    } catch {
      // Skip rules that error on this config shape
    }
  }

  // Calculate risk score
  const severityScores = { critical: 30, high: 20, medium: 10, low: 5 };
  const rawScore = issues.reduce((sum, i) => sum + severityScores[i.severity], 0);
  const riskScore = Math.min(100, rawScore);

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  issues.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const recommendations = [
    ...issues.map(i => i.recommendation),
    ...(riskScore === 0 ? ['Configuration appears secure. Continue monitoring for changes.'] : []),
    'Regularly update the MCP server package to get security patches.',
    'Monitor server logs for unexpected tool invocations.',
  ];

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        server_name: serverName,
        risk_score: riskScore,
        risk_level: riskScore >= 70 ? 'critical' : riskScore >= 40 ? 'high' : riskScore >= 20 ? 'medium' : 'low',
        issues_found: issues,
        total_rules_checked: CONFIG_RULES.length,
        recommendations: [...new Set(recommendations)],
        config_summary: {
          command: config.command,
          args_count: config.args?.length ?? 0,
          env_vars_count: Object.keys(config.env || {}).length,
        },
      }, null, 2),
    }],
  };
}
