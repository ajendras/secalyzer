<?php

declare(strict_types=1);

namespace Src\Analyzer;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Src\Model\Vulnerability;

/**
 * Uses OpenAI's Chat API to perform contextual security analysis on
 * focused code snippets. Returns Vulnerability objects with LLM-derived
 * confidence scores. Only invoked on files that already triggered static rules.
 */
final class AiAnalyzer
{
    private const API_URL = 'https://api.openai.com/v1/chat/completions';
    private const MODEL = 'gpt-4o-mini';

    /**
     * Analyzes a code snippet with an LLM for additional security issues.
     *
     * @param string $snippet Extracted code context (may contain a leading file comment)
     * @param string $apiKey  Valid OpenAI API key (must start with sk-)
     * @return list<Vulnerability>
     */
    public function analyze(string $snippet, string $apiKey): array
    {
        $snippet = trim($snippet);
        if ($snippet === '') {
            return [];
        }

        if (!str_starts_with($apiKey, 'sk-')) {
            throw new \InvalidArgumentException('Invalid OpenAI API key format. Must start with "sk-".');
        }

        $file = $this->extractFileFromSnippet($snippet);
        $prompt = $this->buildPrompt($snippet, $file);

        $client = new Client([
            'timeout' => 20,
            'http_errors' => false,
        ]);

        try {
            $response = $client->post(self::API_URL, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $apiKey,
                    'Content-Type' => 'application/json',
                ],
                'json' => [
                    'model' => self::MODEL,
                    'messages' => [
                        [
                            'role' => 'system',
                            'content' => 'You are an expert PHP security auditor focused on CMS plugins, themes and custom web applications. '
                                . 'Only report genuine vulnerabilities with accurate line numbers and concrete remediation steps. '
                                . 'Never hallucinate findings.',
                        ],
                        [
                            'role' => 'user',
                            'content' => $prompt,
                        ],
                    ],
                    'temperature' => 0.0,
                    'max_tokens' => 600,
                ],
            ]);

            $status = $response->getStatusCode();
            if ($status !== 200) {
                return [];
            }

            $body = (string) $response->getBody();
            $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

            if (!isset($data['choices'][0]['message']['content'])) {
                return [];
            }

            $content = $data['choices'][0]['message']['content'];
            return $this->parseAiResponse($content, $file);
        } catch (GuzzleException) {
            // Network or API errors are non-fatal; static analysis remains authoritative.
            return [];
        } catch (\JsonException) {
            return [];
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * Builds a precise, security-focused prompt that requests strict JSON output.
     */
    private function buildPrompt(string $snippet, string $file): string
    {
        return <<<PROMPT
File: {$file}

Analyze the following PHP code snippet for security vulnerabilities. Focus on context, data flow, and CMS-specific patterns.

```php
{$snippet}
```

Return ONLY a valid JSON array of objects. Each object must have exactly these keys:
- type: string (e.g. "xss", "sqli", "insecure-deserialization", "weak-randomness", "signature-bypass")
- line: integer (best guess from the snippet)
- severity: string ("critical", "high", "medium", or "low")
- message: string (clear, concise description)
- suggested_fix: string (ready-to-apply code or patch suggestion)
- confidence: number between 0.0 and 1.0

Example:
[
  {
    "type": "xss",
    "line": 23,
    "severity": "high",
    "message": "User-controlled data from \$_GET is echoed without escaping.",
    "suggested_fix": "echo htmlspecialchars(\$input, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');",
    "confidence": 0.85
  }
]

If no issues are found, return an empty array: []. Do not include any explanation or markdown outside the JSON.
PROMPT;
    }

    /**
     * Attempts to extract the original filename from a comment at the top of the snippet.
     * Falls back to a generic name when the file cannot be determined.
     */
    private function extractFileFromSnippet(string $snippet): string
    {
        $lines = preg_split('/\r?\n/', $snippet);
        foreach ($lines as $line) {
            $line = trim($line);
            if (str_starts_with($line, '// File:')) {
                return trim(substr($line, 8));
            }
            if (preg_match('/^\/\*\*?\s*File:\s*(.+?)(?:\s*\*\/)?$/i', $line, $m)) {
                return trim($m[1]);
            }
        }

        return 'ai-analyzed-snippet.php';
    }

    /**
     * Parses the LLM response (expected to be JSON) into Vulnerability objects.
     *
     * @return list<Vulnerability>
     */
    private function parseAiResponse(string $responseText, string $file): array
    {
        // Strip possible markdown code fences
        $text = trim($responseText);
        if (str_starts_with($text, '```json')) {
            $text = substr($text, 7);
        }
        if (str_starts_with($text, '```')) {
            $text = substr($text, 3);
        }
        if (str_ends_with($text, '```')) {
            $text = substr($text, 0, -3);
        }
        $text = trim($text);

        try {
            $findings = json_decode($text, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            // Try to locate JSON inside the text as a last resort
            if (preg_match('/(\[.*\])/s', $text, $matches)) {
                try {
                    $findings = json_decode($matches[1], true, 512, JSON_THROW_ON_ERROR);
                } catch (\JsonException) {
                    return [];
                }
            } else {
                return [];
            }
        }

        if (!is_array($findings)) {
            return [];
        }

        $vulnerabilities = [];
        foreach ($findings as $item) {
            if (!is_array($item) || !isset($item['type'], $item['message'])) {
                continue;
            }

            $line = isset($item['line']) && is_numeric($item['line'])
                ? (int) $item['line']
                : 1;

            $severity = in_array(($item['severity'] ?? ''), ['critical', 'high', 'medium', 'low'], true)
                ? (string) $item['severity']
                : 'medium';

            $confidence = isset($item['confidence']) && is_numeric($item['confidence'])
                ? max(0.0, min(1.0, (float) $item['confidence']))
                : 0.65;

            $suggestedFix = isset($item['suggested_fix']) && is_string($item['suggested_fix'])
                ? $item['suggested_fix']
                : (isset($item['fix']) && is_string($item['fix']) ? $item['fix'] : 'Review and apply proper escaping/validation.');

            $vulnerabilities[] = new Vulnerability(
                (string) $item['type'],
                $file,
                $line,
                $severity,
                (string) $item['message'],
                $suggestedFix,
                $confidence
            );
        }

        return $vulnerabilities;
    }
}
