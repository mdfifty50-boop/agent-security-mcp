import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanSecrets } from './secret-scanner.js';

describe('Secret Scanner', () => {
  describe('detects API keys', () => {
    it('catches OpenAI API keys', () => {
      const result = scanSecrets('const key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"', 'code');
      const data = JSON.parse(result.content[0].text);
      assert.equal(data.clean, false);
      assert.ok(data.secrets_found.some(s => s.pattern_id === 'OPENAI_KEY'));
    });

    it('catches Anthropic API keys', () => {
      const result = scanSecrets('ANTHROPIC_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz', 'env');
      const data = JSON.parse(result.content[0].text);
      assert.equal(data.clean, false);
      assert.ok(data.secrets_found.some(s => s.pattern_id === 'ANTHROPIC_KEY'));
    });

    it('catches AWS access keys', () => {
      const result = scanSecrets('aws_access_key_id = AKIAIOSFODNN7EXAMPLE', 'config');
      const data = JSON.parse(result.content[0].text);
      assert.equal(data.clean, false);
      assert.ok(data.secrets_found.some(s => s.pattern_id === 'AWS_ACCESS_KEY'));
    });

    it('catches GitHub PATs', () => {
      const result = scanSecrets('token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij', 'config');
      const data = JSON.parse(result.content[0].text);
      assert.equal(data.clean, false);
      assert.ok(data.secrets_found.some(s => s.pattern_id === 'GITHUB_PAT'));
    });

    it('catches Slack tokens', () => {
      const result = scanSecrets('SLACK_TOKEN=xoxb-abcdefghij-klmnopqrst', 'env');
      const data = JSON.parse(result.content[0].text);
      assert.equal(data.clean, false);
      assert.ok(data.secrets_found.some(s => s.pattern_id === 'SLACK_TOKEN'));
    });
  });

  describe('detects private keys', () => {
    it('catches RSA private key headers', () => {
      const result = scanSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...', 'code');
      const data = JSON.parse(result.content[0].text);
      assert.ok(data.secrets_found.some(s => s.type === 'RSA Private Key'));
    });
  });

  describe('detects database URIs', () => {
    it('catches PostgreSQL connection strings', () => {
      const result = scanSecrets('DATABASE_URL=postgresql://user:password@host:5432/db', 'env');
      const data = JSON.parse(result.content[0].text);
      assert.ok(data.secrets_found.some(s => s.pattern_id === 'POSTGRES_URI'));
    });

    it('catches MongoDB connection strings', () => {
      const result = scanSecrets('MONGO_URI=mongodb+srv://admin:secret@cluster.mongodb.net/db', 'env');
      const data = JSON.parse(result.content[0].text);
      assert.ok(data.secrets_found.some(s => s.pattern_id === 'MONGODB_URI'));
    });
  });

  describe('masking', () => {
    it('masks secret values in preview', () => {
      const result = scanSecrets('sk-abcdefghijklmnopqrstuvwxyz1234567890', 'code');
      const data = JSON.parse(result.content[0].text);
      const finding = data.secrets_found[0];
      assert.ok(finding.value_preview.includes('*'), 'Should contain masked characters');
      assert.ok(!finding.value_preview.includes('1234567890'), 'Should not show full secret');
    });
  });

  describe('clean content', () => {
    it('returns clean for normal code', () => {
      const result = scanSecrets('const x = 42;\nfunction hello() { return "world"; }', 'code');
      const data = JSON.parse(result.content[0].text);
      assert.equal(data.clean, true);
      assert.equal(data.secrets_found.length, 0);
    });
  });

  describe('severity sorting', () => {
    it('sorts critical findings first', () => {
      const code = `
        AKIAIOSFODNN7EXAMPLE1
        api_key = "some-less-important-key-value-here"
      `;
      const result = scanSecrets(code, 'code');
      const data = JSON.parse(result.content[0].text);
      if (data.secrets_found.length >= 2) {
        const severities = data.secrets_found.map(s => s.severity);
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        for (let i = 1; i < severities.length; i++) {
          assert.ok(order[severities[i]] >= order[severities[i-1]], 'Should be sorted by severity');
        }
      }
    });
  });
});
