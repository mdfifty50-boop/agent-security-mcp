#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { scanMcpConfig } from './tools/mcp-scanner.js';
import { detectPromptInjection } from './tools/prompt-injection.js';
import { validateScopeContract } from './tools/scope-validator.js';
import { scanSecrets } from './tools/secret-scanner.js';
import { auditAgentPermissions } from './tools/permission-auditor.js';
import { generateSecurityReport } from './tools/report-generator.js';

const server = new McpServer({
  name: 'agent-security-mcp',
  version: '0.1.0',
  description: 'Security scanning, prompt injection detection, secret leak detection, and agent permission auditing for AI agent workflows',
});

// ═══════════════════════════════════════════
// MCP CONFIGURATION SCANNER
// ═══════════════════════════════════════════

server.tool(
  'scan_mcp_config',
  'Scan an MCP server configuration for security issues including dangerous commands, exposed secrets, network exposure, and container misconfigurations. Returns a risk score (0-100), issues found, and actionable recommendations.',
  {
    config: z.object({
      command: z.string().describe('The command used to start the MCP server'),
      args: z.array(z.string()).optional().describe('Command arguments'),
      env: z.record(z.string()).optional().describe('Environment variables passed to the server'),
    }).describe('MCP server configuration object'),
    server_name: z.string().describe('Name of the MCP server being scanned'),
  },
  async ({ config, server_name }) => scanMcpConfig(config, server_name)
);

// ═══════════════════════════════════════════
// PROMPT INJECTION DETECTOR
// ═══════════════════════════════════════════

server.tool(
  'detect_prompt_injection',
  'Analyze text for prompt injection attempts. Detects instruction overrides, identity manipulation, system prompt extraction, data exfiltration, delimiter attacks, encoded injections, and privilege escalation. Context-aware risk scoring.',
  {
    text: z.string().min(1).describe('The text to analyze for prompt injection patterns'),
    context: z.enum(['user_input', 'tool_result', 'system_prompt', 'agent_output']).describe('Where this text originates — affects risk scoring (user_input is highest risk)'),
  },
  async ({ text, context }) => detectPromptInjection(text, context)
);

// ═══════════════════════════════════════════
// SCOPE CONTRACT VALIDATOR
// ═══════════════════════════════════════════

server.tool(
  'validate_scope_contract',
  'Check if an agent action complies with its scope contract. Validates tool usage against allowlists, file access against permitted paths, and boundary constraints (no_network, read_only, no_exec, no_secrets).',
  {
    scope_contract: z.object({
      allowed_tools: z.array(z.string()).optional().describe('List of tools the agent is permitted to use'),
      allowed_files: z.array(z.string()).optional().describe('File paths or glob patterns the agent can access'),
      boundaries: z.array(z.string()).optional().describe('Boundary constraints: no_network, read_only, no_exec, no_secrets'),
    }).describe('The agent scope contract defining permitted actions'),
    action: z.object({
      tool_name: z.string().describe('Name of the tool being invoked'),
      params: z.any().optional().describe('Parameters passed to the tool'),
      target_file: z.string().optional().describe('File path being accessed, if applicable'),
    }).describe('The action to validate against the scope contract'),
  },
  async ({ scope_contract, action }) => validateScopeContract(scope_contract, action)
);

// ═══════════════════════════════════════════
// SECRET SCANNER
// ═══════════════════════════════════════════

server.tool(
  'scan_secrets',
  'Detect leaked secrets and credentials in text or code. Identifies API keys (OpenAI, AWS, GitHub, GCP, Stripe, Slack, Telegram), JWT tokens, database connection strings, private keys, and .env patterns. All values are masked in output.',
  {
    content: z.string().min(1).describe('The text or code content to scan for secrets'),
    content_type: z.enum(['code', 'log', 'config', 'output']).describe('Type of content being scanned — affects detection sensitivity'),
  },
  async ({ content, content_type }) => scanSecrets(content, content_type)
);

// ═══════════════════════════════════════════
// AGENT PERMISSION AUDITOR
// ═══════════════════════════════════════════

server.tool(
  'audit_agent_permissions',
  'Audit an agent configuration for over-privileged access. Compares granted permissions against role-based expectations (researcher, analyst, developer, reviewer, orchestrator, monitor). Flags principle of least privilege violations.',
  {
    agent_config: z.object({
      tools: z.array(z.string()).optional().describe('List of tools available to the agent'),
      file_access: z.union([z.array(z.string()), z.string()]).optional().describe('File access paths or patterns'),
      network_access: z.union([z.string(), z.boolean()]).optional().describe('Network access level'),
      env_vars: z.array(z.string()).optional().describe('Environment variables the agent can access'),
    }).describe('Agent configuration to audit'),
    role: z.string().describe('The declared role of the agent (researcher, analyst, developer, reviewer, orchestrator, monitor)'),
  },
  async ({ agent_config, role }) => auditAgentPermissions(agent_config, role)
);

// ═══════════════════════════════════════════
// SECURITY REPORT GENERATOR
// ═══════════════════════════════════════════

server.tool(
  'generate_security_report',
  'Generate a comprehensive security assessment report for an agent deployment. Aggregates results from config scans and permission audits into a prioritized remediation plan with OWASP LLM Top 10 compliance notes.',
  {
    agent_name: z.string().describe('Name of the agent or deployment being assessed'),
    configs: z.array(z.any()).optional().describe('Array of scan_mcp_config results to include in the report'),
    audit_results: z.array(z.any()).optional().describe('Array of audit_agent_permissions results to include in the report'),
  },
  async ({ agent_name, configs, audit_results }) => generateSecurityReport(agent_name, configs, audit_results)
);

// ═══════════════════════════════════════════
// RESOURCES
// ═══════════════════════════════════════════

server.resource(
  'owasp-llm-top10',
  'security://owasp-llm-top10',
  async () => ({
    contents: [{
      uri: 'security://owasp-llm-top10',
      mimeType: 'text/markdown',
      text: `# OWASP Top 10 for LLM Applications (2025)

## LLM01: Prompt Injection
Manipulating LLMs via crafted inputs to cause unintended actions. Includes direct injection (user input) and indirect injection (from external content).

**Mitigations:**
- Input validation and sanitization
- Privilege separation between system and user content
- Output filtering for sensitive data
- Least privilege for LLM tool access

## LLM02: Insecure Output Handling
Failing to validate/sanitize LLM outputs before passing to downstream systems. Can lead to XSS, SSRF, code execution.

**Mitigations:**
- Treat LLM output as untrusted
- Apply output encoding
- Validate before passing to interpreters/APIs

## LLM03: Training Data Poisoning
Manipulation of training data to introduce vulnerabilities, biases, or backdoors.

## LLM04: Model Denial of Service
Crafted inputs causing excessive resource consumption.

## LLM05: Supply Chain Vulnerabilities
Compromised components in the LLM supply chain (plugins, models, training data).

## LLM06: Sensitive Information Disclosure
LLMs inadvertently revealing confidential data through responses.

**Mitigations:**
- Data sanitization in training/fine-tuning
- Input/output filtering for PII
- Least privilege data access
- Secret scanning in outputs

## LLM07: Insecure Plugin Design
LLM plugins with inadequate access controls, input validation, or unsafe permissions.

**Mitigations:**
- Plugin sandboxing
- Strict input validation
- Authentication for plugin actions
- Scope contracts for each plugin

## LLM08: Excessive Agency
Granting LLMs too many capabilities, permissions, or autonomy without adequate controls.

**Mitigations:**
- Principle of least privilege
- Human-in-the-loop for sensitive actions
- Scope contracts and boundary enforcement
- Action logging and audit trails

## LLM09: Overreliance
Blindly trusting LLM outputs without verification, leading to misinformation or security issues.

## LLM10: Model Theft
Unauthorized access, extraction, or replication of proprietary LLM models.

---
Source: OWASP LLM Top 10 Project (https://owasp.org/www-project-top-10-for-large-language-model-applications/)
`,
    }],
  })
);

server.resource(
  'mcp-security-checklist',
  'security://mcp-security-checklist',
  async () => ({
    contents: [{
      uri: 'security://mcp-security-checklist',
      mimeType: 'text/markdown',
      text: `# MCP Server Security Checklist

## Transport Security
- [ ] Use stdio transport for local servers (avoid HTTP when possible)
- [ ] If HTTP/SSE: bind to 127.0.0.1, not 0.0.0.0
- [ ] If HTTP/SSE: enable TLS with valid certificates
- [ ] If HTTP/SSE: implement authentication (API key, OAuth, mTLS)

## Command & Execution
- [ ] Use direct binary execution, not shell -c
- [ ] Validate all tool input parameters with strict schemas (use Zod)
- [ ] Never pass user input directly to shell commands
- [ ] Sanitize file paths to prevent traversal attacks

## Secrets Management
- [ ] Never hardcode secrets in source code
- [ ] Use environment variables or secrets managers for credentials
- [ ] Rotate API keys regularly
- [ ] Audit which env vars each server has access to

## File System Access
- [ ] Restrict access to specific directories (allowlist)
- [ ] Use read-only access where write is not needed
- [ ] Validate file paths against allowlist before operations
- [ ] Log all file operations for audit

## Network Security
- [ ] Restrict outbound network access to known endpoints
- [ ] Validate URLs before making requests
- [ ] Implement request rate limiting
- [ ] Log all network operations

## Agent Permissions
- [ ] Apply principle of least privilege to all tool grants
- [ ] Define scope contracts for each agent
- [ ] Validate actions against scope contracts at runtime
- [ ] Implement boundary enforcement (no_network, read_only, no_exec)

## Monitoring & Audit
- [ ] Log all tool invocations with timestamps
- [ ] Monitor for prompt injection patterns in inputs
- [ ] Scan outputs for secret/credential leaks
- [ ] Set up alerts for anomalous tool usage patterns
- [ ] Regular security assessments of all MCP configurations

## Supply Chain
- [ ] Pin MCP server package versions
- [ ] Verify package integrity (checksums)
- [ ] Monitor for vulnerabilities in dependencies
- [ ] Review source code before installing new MCP servers
`,
    }],
  })
);

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Agent Security MCP Server running on stdio');
}

main().catch(console.error);
