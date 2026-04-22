/**
 * Secret/Credential Scanner
 *
 * Detects leaked API keys, tokens, private keys, and other credentials in text or code.
 */

const SECRET_PATTERNS = [
  // OpenAI / AI provider keys
  {
    id: 'OPENAI_KEY',
    pattern: /sk-[a-zA-Z0-9]{20,}/g,
    type: 'OpenAI API Key',
    severity: 'critical',
    mask_after: 6,
  },
  {
    id: 'ANTHROPIC_KEY',
    pattern: /sk-ant-[a-zA-Z0-9\-]{20,}/g,
    type: 'Anthropic API Key',
    severity: 'critical',
    mask_after: 10,
  },

  // AWS
  {
    id: 'AWS_ACCESS_KEY',
    pattern: /AKIA[0-9A-Z]{16}/g,
    type: 'AWS Access Key ID',
    severity: 'critical',
    mask_after: 8,
  },
  {
    id: 'AWS_SECRET_KEY',
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9\/+=]{40}/g,
    type: 'AWS Secret Access Key',
    severity: 'critical',
    mask_after: 20,
  },

  // GitHub
  {
    id: 'GITHUB_PAT',
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    type: 'GitHub Personal Access Token',
    severity: 'critical',
    mask_after: 7,
  },
  {
    id: 'GITHUB_FINE_GRAINED',
    pattern: /github_pat_[a-zA-Z0-9_]{82}/g,
    type: 'GitHub Fine-Grained PAT',
    severity: 'critical',
    mask_after: 15,
  },
  {
    id: 'GITHUB_OAUTH',
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    type: 'GitHub OAuth Token',
    severity: 'critical',
    mask_after: 7,
  },

  // Google Cloud
  {
    id: 'GCP_API_KEY',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    type: 'Google Cloud API Key',
    severity: 'critical',
    mask_after: 8,
  },
  {
    id: 'GCP_SERVICE_ACCOUNT',
    pattern: /"type"\s*:\s*"service_account"/g,
    type: 'GCP Service Account JSON',
    severity: 'critical',
    mask_after: 0,
  },

  // Azure
  {
    id: 'AZURE_STORAGE_KEY',
    pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{88}/g,
    type: 'Azure Storage Connection String',
    severity: 'critical',
    mask_after: 40,
  },

  // JWT
  {
    id: 'JWT_TOKEN',
    pattern: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
    type: 'JWT Token',
    severity: 'high',
    mask_after: 20,
  },

  // Private keys
  {
    id: 'RSA_PRIVATE_KEY',
    pattern: /-----BEGIN RSA PRIVATE KEY-----/g,
    type: 'RSA Private Key',
    severity: 'critical',
    mask_after: 0,
  },
  {
    id: 'EC_PRIVATE_KEY',
    pattern: /-----BEGIN EC PRIVATE KEY-----/g,
    type: 'EC Private Key',
    severity: 'critical',
    mask_after: 0,
  },
  {
    id: 'PRIVATE_KEY_GENERIC',
    pattern: /-----BEGIN PRIVATE KEY-----/g,
    type: 'Private Key (Generic)',
    severity: 'critical',
    mask_after: 0,
  },
  {
    id: 'OPENSSH_PRIVATE_KEY',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    type: 'OpenSSH Private Key',
    severity: 'critical',
    mask_after: 0,
  },

  // Database connection strings
  {
    id: 'POSTGRES_URI',
    pattern: /postgres(?:ql)?:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/g,
    type: 'PostgreSQL Connection String',
    severity: 'critical',
    mask_after: 15,
  },
  {
    id: 'MONGODB_URI',
    pattern: /mongodb(?:\+srv)?:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/g,
    type: 'MongoDB Connection String',
    severity: 'critical',
    mask_after: 15,
  },
  {
    id: 'MYSQL_URI',
    pattern: /mysql:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/g,
    type: 'MySQL Connection String',
    severity: 'critical',
    mask_after: 10,
  },
  {
    id: 'REDIS_URI',
    pattern: /redis:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/g,
    type: 'Redis Connection String',
    severity: 'high',
    mask_after: 10,
  },

  // Stripe
  {
    id: 'STRIPE_SECRET',
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    type: 'Stripe Secret Key (Live)',
    severity: 'critical',
    mask_after: 12,
  },
  {
    id: 'STRIPE_TEST',
    pattern: /sk_test_[a-zA-Z0-9]{24,}/g,
    type: 'Stripe Secret Key (Test)',
    severity: 'medium',
    mask_after: 12,
  },

  // Slack
  {
    id: 'SLACK_TOKEN',
    pattern: /xox[bpors]-[a-zA-Z0-9\-]{10,}/g,
    type: 'Slack Token',
    severity: 'high',
    mask_after: 8,
  },
  {
    id: 'SLACK_WEBHOOK',
    pattern: /hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g,
    type: 'Slack Webhook URL',
    severity: 'high',
    mask_after: 30,
  },

  // Telegram
  {
    id: 'TELEGRAM_BOT_TOKEN',
    pattern: /\d{8,10}:[A-Za-z0-9_-]{35}/g,
    type: 'Telegram Bot Token',
    severity: 'critical',
    mask_after: 12,
  },

  // Generic patterns
  {
    id: 'GENERIC_API_KEY',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]?[a-zA-Z0-9\-_]{20,}['"]?/gi,
    type: 'Generic API Key',
    severity: 'high',
    mask_after: 15,
  },
  {
    id: 'GENERIC_SECRET',
    pattern: /(?:secret|password|passwd|token)\s*[=:]\s*['"]?[^\s'"]{8,}['"]?/gi,
    type: 'Generic Secret/Password',
    severity: 'medium',
    mask_after: 10,
  },

  // .env file patterns
  {
    id: 'ENV_FILE_LINE',
    pattern: /^[A-Z][A-Z0-9_]*(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_CREDENTIAL)\s*=\s*.+$/gm,
    type: '.env Secret Assignment',
    severity: 'high',
    mask_after: 15,
  },
];

/**
 * Get the line number for a match position.
 */
function getLineNumber(content, position) {
  return content.substring(0, position).split('\n').length;
}

/**
 * Create a masked preview of the secret value.
 */
function maskValue(value, maskAfter) {
  if (maskAfter === 0) return '[REDACTED]';
  if (value.length <= maskAfter) return '*'.repeat(value.length);
  return value.substring(0, maskAfter) + '*'.repeat(Math.min(value.length - maskAfter, 20));
}

/**
 * Scan content for leaked secrets.
 */
export function scanSecrets(content, contentType) {
  const findings = [];

  for (const rule of SECRET_PATTERNS) {
    // Reset lastIndex for global patterns
    rule.pattern.lastIndex = 0;

    let match;
    while ((match = rule.pattern.exec(content)) !== null) {
      findings.push({
        type: rule.type,
        pattern_id: rule.id,
        severity: rule.severity,
        value_preview: maskValue(match[0], rule.mask_after),
        line_number: getLineNumber(content, match.index),
        position: match.index,
        length: match[0].length,
      });
    }
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        clean: findings.length === 0,
        content_type: contentType,
        secrets_found: findings,
        total_patterns_checked: SECRET_PATTERNS.length,
        summary: findings.length === 0
          ? 'No secrets or credentials detected.'
          : `Found ${findings.length} potential secret(s). Critical: ${findings.filter(f => f.severity === 'critical').length}, High: ${findings.filter(f => f.severity === 'high').length}, Medium: ${findings.filter(f => f.severity === 'medium').length}.`,
      }, null, 2),
    }],
  };
}
