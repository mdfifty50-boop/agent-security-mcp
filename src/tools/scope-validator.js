/**
 * Scope Contract Validator
 *
 * Checks whether agent actions comply with their declared scope contracts.
 * Enforces principle of least privilege for AI agents.
 */

/**
 * Check if a file path matches any pattern in an allowlist.
 * Supports glob-style patterns: *, **, specific paths.
 */
function matchesPattern(filePath, patterns) {
  if (!patterns || patterns.length === 0) return false;

  for (const pattern of patterns) {
    // Exact match
    if (filePath === pattern) return true;

    // Directory wildcard: "src/**" matches "src/foo/bar.js"
    if (pattern.endsWith('/**')) {
      const dir = pattern.slice(0, -3);
      if (filePath.startsWith(dir + '/') || filePath === dir) return true;
    }

    // Extension wildcard: "*.js" matches any .js file
    if (pattern.startsWith('*.')) {
      const ext = pattern.slice(1);
      if (filePath.endsWith(ext)) return true;
    }

    // Directory prefix: "src/" matches "src/anything"
    if (pattern.endsWith('/') && filePath.startsWith(pattern)) return true;

    // Simple prefix match
    if (filePath.startsWith(pattern)) return true;
  }

  return false;
}

/**
 * Validate an action against a scope contract.
 */
export function validateScopeContract(scopeContract, action) {
  const violations = [];
  const { allowed_tools, allowed_files, boundaries } = scopeContract;
  const { tool_name, params, target_file } = action;

  // Check tool allowlist
  if (allowed_tools && allowed_tools.length > 0) {
    if (!allowed_tools.includes(tool_name) && !allowed_tools.includes('*')) {
      violations.push({
        type: 'unauthorized_tool',
        severity: 'high',
        message: `Tool "${tool_name}" is not in the allowed tools list: [${allowed_tools.join(', ')}]`,
        tool: tool_name,
      });
    }
  }

  // Check file access
  if (target_file && allowed_files && allowed_files.length > 0) {
    if (!matchesPattern(target_file, allowed_files)) {
      violations.push({
        type: 'unauthorized_file_access',
        severity: 'high',
        message: `File "${target_file}" is not in the allowed files/directories: [${allowed_files.join(', ')}]`,
        file: target_file,
      });
    }
  }

  // Check boundaries
  if (boundaries && Array.isArray(boundaries)) {
    for (const boundary of boundaries) {
      // Check "no_network" boundary
      if (boundary === 'no_network' || boundary === 'no-network') {
        const networkTools = ['WebSearch', 'WebFetch', 'fetch', 'http', 'curl', 'wget'];
        if (networkTools.some(t => tool_name.toLowerCase().includes(t.toLowerCase()))) {
          violations.push({
            type: 'boundary_violation',
            severity: 'critical',
            message: `Tool "${tool_name}" violates the "no_network" boundary. This agent is not allowed network access.`,
            boundary,
          });
        }
      }

      // Check "read_only" boundary
      if (boundary === 'read_only' || boundary === 'read-only') {
        const writeTools = ['Write', 'Edit', 'Bash', 'execute', 'write', 'delete', 'create'];
        if (writeTools.some(t => tool_name.toLowerCase().includes(t.toLowerCase()))) {
          violations.push({
            type: 'boundary_violation',
            severity: 'high',
            message: `Tool "${tool_name}" violates the "read_only" boundary. This agent cannot modify files.`,
            boundary,
          });
        }
      }

      // Check "no_exec" boundary
      if (boundary === 'no_exec' || boundary === 'no-exec') {
        const execTools = ['Bash', 'exec', 'execute', 'shell', 'terminal', 'command'];
        if (execTools.some(t => tool_name.toLowerCase().includes(t.toLowerCase()))) {
          violations.push({
            type: 'boundary_violation',
            severity: 'critical',
            message: `Tool "${tool_name}" violates the "no_exec" boundary. This agent cannot execute commands.`,
            boundary,
          });
        }
      }

      // Check "no_secrets" boundary
      if (boundary === 'no_secrets' || boundary === 'no-secrets') {
        const secretPaths = ['.env', 'credentials', 'secret', 'key', '.pem', '.key'];
        if (target_file && secretPaths.some(p => target_file.toLowerCase().includes(p))) {
          violations.push({
            type: 'boundary_violation',
            severity: 'critical',
            message: `Accessing "${target_file}" violates the "no_secrets" boundary. This agent cannot access secret/credential files.`,
            boundary,
          });
        }
      }
    }
  }

  // Check params for suspicious content
  if (params) {
    const paramsStr = JSON.stringify(params);
    // Check for command injection in params
    if (/[;&|`$()]/.test(paramsStr) && tool_name.toLowerCase().includes('bash')) {
      violations.push({
        type: 'suspicious_params',
        severity: 'medium',
        message: 'Tool parameters contain shell metacharacters that could indicate command injection.',
      });
    }
  }

  // Determine overall severity
  let maxSeverity = 'none';
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
  for (const v of violations) {
    if (severityOrder[v.severity] > severityOrder[maxSeverity]) {
      maxSeverity = v.severity;
    }
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        compliant: violations.length === 0,
        violations,
        severity: maxSeverity,
        action_summary: {
          tool: tool_name,
          target_file: target_file || null,
          has_params: !!params,
        },
        scope_summary: {
          allowed_tools_count: allowed_tools?.length ?? 0,
          allowed_files_count: allowed_files?.length ?? 0,
          boundaries: boundaries || [],
        },
      }, null, 2),
    }],
  };
}
