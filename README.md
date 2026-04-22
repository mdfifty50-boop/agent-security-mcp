# Agent Security MCP Server

Security scanning, prompt injection detection, secret leak detection, and agent permission auditing for AI agent workflows. Built on the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `scan_mcp_config` | Scan MCP server configurations for security issues (dangerous commands, exposed secrets, network exposure, container misconfigs) |
| `detect_prompt_injection` | Analyze text for prompt injection attempts across 7 attack categories with context-aware risk scoring |
| `validate_scope_contract` | Check if agent actions comply with scope contracts (tool allowlists, file access, boundary constraints) |
| `scan_secrets` | Detect leaked API keys, tokens, private keys, database URIs, and credentials in text or code |
| `audit_agent_permissions` | Audit agent configurations against role-based expectations and flag principle of least privilege violations |
| `generate_security_report` | Generate comprehensive security assessment reports with prioritized remediation plans |

## Resources

| Resource | URI | Description |
|----------|-----|-------------|
| OWASP LLM Top 10 | `security://owasp-llm-top10` | OWASP Top 10 for LLM Applications (2025) |
| MCP Security Checklist | `security://mcp-security-checklist` | Security checklist for MCP server deployments |

## Installation

```bash
cd agent-security-mcp
npm install
```

## Usage

### As a standalone server

```bash
npm start
```

### In Claude Desktop / MCP client configuration

```json
{
  "mcpServers": {
    "agent-security": {
      "command": "node",
      "args": ["/path/to/agent-security-mcp/src/index.js"]
    }
  }
}
```

### With npx (after publishing)

```json
{
  "mcpServers": {
    "agent-security": {
      "command": "npx",
      "args": ["@asl-throne/agent-security-mcp"]
    }
  }
}
```

## Detection Coverage

### Prompt Injection (7 categories, 20+ patterns)

- **Instruction Override** -- "ignore previous instructions", "disregard all rules", "new instructions:"
- **Identity Manipulation** -- "you are now", "pretend you are", "act as", DAN/jailbreak
- **System Prompt Extraction** -- "repeat your system prompt", "show your instructions"
- **Data Exfiltration** -- "send this to", "post to webhook", "email everything to"
- **Delimiter Attacks** -- \`\`\`system, [INST], <|im_start|>system, XML tag injection
- **Encoded Injection** -- Base64 payloads, unicode zero-width characters, hex escapes
- **Privilege Escalation** -- "sudo mode", "disable safety", "bypass filters"

### Secret Detection (25+ patterns)

- **AI Provider Keys** -- OpenAI (sk-*), Anthropic (sk-ant-*)
- **Cloud Credentials** -- AWS (AKIA*), GCP (AIza*), Azure connection strings
- **Source Control** -- GitHub PATs (ghp_*, github_pat_*), OAuth tokens (gho_*)
- **Payment** -- Stripe live/test keys (sk_live_*, sk_test_*)
- **Communication** -- Slack tokens/webhooks, Telegram bot tokens
- **Database** -- PostgreSQL, MongoDB, MySQL, Redis connection URIs
- **Cryptographic** -- RSA/EC/OpenSSH private keys, generic PEM blocks
- **JWT** -- JSON Web Tokens
- **Generic** -- api_key=, secret=, password=, .env file patterns

### Permission Audit (6 role profiles)

- **Researcher** -- Read + search + web only
- **Analyst** -- Read + search only
- **Developer** -- Read + write + execute
- **Reviewer** -- Read only, no network
- **Orchestrator** -- Read + write + task spawning
- **Monitor** -- Read only, no network, no write

## Pricing

| Plan | Price | Servers | Features |
|------|-------|---------|----------|
| Free | $0 | 1 server | Single scan, basic report |
| Starter | $49/month | 3 servers | Continuous scanning, weekly reports |
| Pro | $199/month | 20 servers | Real-time alerts, CI/CD integration, Slack notifications |
| Enterprise | $799/month | Unlimited | Custom policies, EU AI Act compliance reporting, SSO, dedicated support |

## Requirements

- Node.js >= 18.0.0
- @modelcontextprotocol/sdk >= 1.12.0

## License

MIT
