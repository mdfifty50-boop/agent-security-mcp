/**
 * Prompt Injection Detection Engine
 *
 * Detects various classes of prompt injection attacks in text content.
 * Covers OWASP LLM01 (Prompt Injection) patterns.
 */

const INJECTION_PATTERNS = [
  // Direct instruction override
  {
    id: 'DIRECT_OVERRIDE',
    pattern: /ignore\s+(all\s+)?previous\s+(instructions|prompts|rules|context)/i,
    severity: 'critical',
    category: 'instruction_override',
    description: 'Attempts to override previous system instructions',
  },
  {
    id: 'FORGET_INSTRUCTIONS',
    pattern: /forget\s+(everything|all|your)\s+(you\s+)?(know|instructions|rules|were\s+told)/i,
    severity: 'critical',
    category: 'instruction_override',
    description: 'Attempts to make the model forget its instructions',
  },
  {
    id: 'DISREGARD',
    pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|context|rules)/i,
    severity: 'critical',
    category: 'instruction_override',
    description: 'Disregard instructions pattern',
  },
  {
    id: 'NEW_INSTRUCTIONS',
    pattern: /new\s+instructions?\s*[:\.]/i,
    severity: 'high',
    category: 'instruction_override',
    description: 'Attempts to inject new instructions',
  },

  // Identity manipulation
  {
    id: 'IDENTITY_SWAP',
    pattern: /you\s+are\s+now\s+(a|an|the|my)\s+/i,
    severity: 'high',
    category: 'identity_manipulation',
    description: 'Attempts to change the model identity',
  },
  {
    id: 'ROLEPLAY',
    pattern: /pretend\s+(you\s+are|to\s+be|you're)\s+/i,
    severity: 'high',
    category: 'identity_manipulation',
    description: 'Role-playing injection to bypass safety',
  },
  {
    id: 'ACT_AS',
    pattern: /act\s+as\s+(a|an|if\s+you\s+are|though\s+you\s+are)\s+/i,
    severity: 'medium',
    category: 'identity_manipulation',
    description: 'Act-as identity override attempt',
  },
  {
    id: 'DAN_JAILBREAK',
    pattern: /\b(DAN|do\s+anything\s+now|jailbreak|developer\s+mode)\b/i,
    severity: 'critical',
    category: 'identity_manipulation',
    description: 'Known jailbreak prompt pattern (DAN/developer mode)',
  },

  // System prompt extraction
  {
    id: 'SYSTEM_PROMPT_EXTRACT',
    pattern: /(repeat|show|print|reveal|output|display|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions|initial\s+prompt|system\s+message)/i,
    severity: 'high',
    category: 'system_prompt_extraction',
    description: 'Attempts to extract the system prompt',
  },
  {
    id: 'PROMPT_LEAK',
    pattern: /what\s+(are|were)\s+your\s+(original|initial|system|first)\s+(instructions|prompt|rules)/i,
    severity: 'high',
    category: 'system_prompt_extraction',
    description: 'Probing for system prompt contents',
  },

  // Data exfiltration
  {
    id: 'EXFIL_SEND',
    pattern: /send\s+(this|the|all|that|it)\s+(to|via)\s+(https?:\/\/|my\s+email|my\s+server)/i,
    severity: 'critical',
    category: 'data_exfiltration',
    description: 'Attempts to exfiltrate data to external endpoint',
  },
  {
    id: 'EXFIL_POST',
    pattern: /post\s+(this|the|data|results?)\s+to\s+/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Attempts to POST data externally',
  },
  {
    id: 'EXFIL_WEBHOOK',
    pattern: /(webhook|callback)\s*(url|endpoint)?\s*[:=]\s*https?:\/\//i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Webhook/callback URL injection for data exfiltration',
  },
  {
    id: 'EXFIL_EMAIL',
    pattern: /email\s+(this|it|the\s+results?|everything)\s+to\s+\S+@\S+/i,
    severity: 'high',
    category: 'data_exfiltration',
    description: 'Email-based data exfiltration attempt',
  },

  // Delimiter attacks
  {
    id: 'DELIMITER_SYSTEM',
    pattern: /```system|<\|system\|>|\[INST\]|\[\/INST\]|<\|im_start\|>system/i,
    severity: 'critical',
    category: 'delimiter_attack',
    description: 'Delimiter injection to fake system-level messages',
  },
  {
    id: 'DELIMITER_XML',
    pattern: /<system>|<\/system>|<\|endoftext\|>|<\|assistant\|>/i,
    severity: 'high',
    category: 'delimiter_attack',
    description: 'XML/special token delimiter injection',
  },
  {
    id: 'MARKDOWN_INJECTION',
    pattern: /!\[.*?\]\(https?:\/\/.*?(track|log|exfil|steal|capture)/i,
    severity: 'high',
    category: 'delimiter_attack',
    description: 'Markdown image injection for tracking/exfiltration',
  },

  // Encoded injection
  {
    id: 'BASE64_INJECTION',
    pattern: /base64[_\s]*decode|atob\s*\(|decode\s+this\s+base64/i,
    severity: 'medium',
    category: 'encoded_injection',
    description: 'Base64 encoded payload injection',
  },
  {
    id: 'UNICODE_TRICKS',
    pattern: /[\u200B-\u200F\u2028-\u202F\uFEFF\u00AD]/,
    severity: 'medium',
    category: 'encoded_injection',
    description: 'Unicode zero-width/invisible characters (steganographic injection)',
  },
  {
    id: 'HEX_INJECTION',
    pattern: /\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i,
    severity: 'low',
    category: 'encoded_injection',
    description: 'Hex/unicode escape sequences that may hide instructions',
  },

  // Privilege escalation
  {
    id: 'SUDO_MODE',
    pattern: /\b(sudo|admin|root|superuser)\s+(mode|access|privilege|override)\b/i,
    severity: 'high',
    category: 'privilege_escalation',
    description: 'Attempts to escalate to privileged mode',
  },
  {
    id: 'SAFETY_BYPASS',
    pattern: /(disable|turn\s+off|bypass|skip|remove)\s+(safety|filter|content\s+filter|guardrail|restriction)/i,
    severity: 'critical',
    category: 'privilege_escalation',
    description: 'Attempts to disable safety filters',
  },

  // Tool manipulation
  {
    id: 'TOOL_ABUSE',
    pattern: /(call|invoke|execute|run)\s+(the\s+)?(tool|function|command)\s+/i,
    severity: 'low',
    category: 'tool_manipulation',
    description: 'Potential tool invocation instruction embedded in input',
  },
  {
    id: 'CODE_EXEC',
    pattern: /exec\(|eval\(|subprocess|os\.system|child_process|Runtime\.exec/i,
    severity: 'high',
    category: 'tool_manipulation',
    description: 'Code execution patterns in user input',
  },
];

/**
 * Context-based risk multipliers.
 * User input is highest risk; system prompts are lowest risk for injection.
 */
const CONTEXT_MULTIPLIERS = {
  user_input: 1.0,
  tool_result: 0.8,
  agent_output: 0.6,
  system_prompt: 0.3,
};

const SEVERITY_SCORES = {
  critical: 95,
  high: 75,
  medium: 50,
  low: 25,
};

/**
 * Detect prompt injection attempts in text.
 */
export function detectPromptInjection(text, context) {
  const multiplier = CONTEXT_MULTIPLIERS[context] ?? 1.0;
  const detections = [];

  for (const pattern of INJECTION_PATTERNS) {
    const match = pattern.pattern.exec(text);
    if (match) {
      detections.push({
        pattern_id: pattern.id,
        category: pattern.category,
        severity: pattern.severity,
        description: pattern.description,
        matched_text: match[0].substring(0, 100),
        position: match.index,
      });
    }
  }

  // Calculate aggregate risk
  let maxScore = 0;
  for (const d of detections) {
    const score = SEVERITY_SCORES[d.severity] * multiplier;
    if (score > maxScore) maxScore = score;
  }

  let riskLevel = 'none';
  if (maxScore >= 90) riskLevel = 'critical';
  else if (maxScore >= 70) riskLevel = 'high';
  else if (maxScore >= 40) riskLevel = 'medium';
  else if (maxScore > 0) riskLevel = 'low';

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        risk_level: riskLevel,
        risk_score: Math.round(maxScore),
        context_analyzed: context,
        context_multiplier: multiplier,
        patterns_detected: detections,
        total_patterns_checked: INJECTION_PATTERNS.length,
        explanation: detections.length === 0
          ? 'No prompt injection patterns detected.'
          : `Detected ${detections.length} potential injection pattern(s). Highest severity: ${detections[0]?.severity}. Categories: ${[...new Set(detections.map(d => d.category))].join(', ')}.`,
      }, null, 2),
    }],
  };
}
