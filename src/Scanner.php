<?php

declare(strict_types=1);

namespace Src;

use Src\Analyzer\AiAnalyzer;
use Src\Analyzer\StaticAnalyzer;
use Src\Model\Vulnerability;
use Src\Report;
use Src\Rule\RuleInterface;
use Src\Rule\SignatureRule;
use Src\Rule\XssRule;

/**
 * Main orchestrator for the security scan.
 *
 * Discovers PHP files (respecting ignore patterns from .secalyzer.json),
 * runs StaticAnalyzer on each, optionally runs AiAnalyzer on files with findings,
 * deduplicates, filters by severity threshold, and assembles the Report.
 */
final class Scanner
{
    private AiAnalyzer $aiAnalyzer;

    public function __construct()
    {
        $this->aiAnalyzer = new AiAnalyzer();
    }

    /**
     * @param string $path Directory or file to scan
     * @param array<string, mixed> $options Configuration options including ignore, severity_threshold, rules, ai_key etc.
     */
    public function scan(string $path, array $options = []): Report
    {
        $aiKey = $options['ai_key'] ?? null;
        $ignore = $options['ignore'] ?? ['vendor', 'tests', 'node_modules'];
        $severityThreshold = $options['severity_threshold'] ?? 'medium';
        $ruleClasses = $options['rules'] ?? null;

        $staticAnalyzer = new StaticAnalyzer();
        if (is_array($ruleClasses) && $ruleClasses !== []) {
            $rules = $this->instantiateRules($ruleClasses);
            $staticAnalyzer = new StaticAnalyzer($rules);
        }

        $phpFiles = $this->findPhpFiles($path, $ignore);

        $allVulnerabilities = [];
        foreach ($phpFiles as $file) {
            try {
                $staticVulns = $staticAnalyzer->analyze($file);
                $allVulnerabilities = array_merge($allVulnerabilities, $staticVulns);

                if ($aiKey !== null && $staticVulns !== []) {
                    $snippet = $this->prepareSnippetForAi($file, $staticVulns);
                    $aiVulns = $this->aiAnalyzer->analyze($snippet, $aiKey);
                    $allVulnerabilities = array_merge($allVulnerabilities, $aiVulns);
                }
            } catch (\Throwable) {
                continue; // skip files with parse or permission errors
            }
        }

        $uniqueVulns = $this->deduplicateVulnerabilities($allVulnerabilities);
        $filteredVulns = $this->filterBySeverity($uniqueVulns, $severityThreshold);

        $reportOptions = [
            'ai_key' => $aiKey !== null ? '[REDACTED]' : null,
            'format' => $options['format'] ?? 'console',
            'fix' => $options['fix'] ?? false,
            'severity_threshold' => $severityThreshold,
            'ignore' => $ignore,
            'rules' => $ruleClasses,
            'config_used' => true,
            'scanned_files' => count($phpFiles),
            'config_path' => $options['config_path'] ?? null,
        ];

        return new Report($filteredVulns, $reportOptions);
    }

    /**
     * @param list<class-string<RuleInterface>|string> $ruleClassNames
     * @return list<RuleInterface>
     */
    private function instantiateRules(array $ruleClassNames): array
    {
        $rules = [];
        foreach ($ruleClassNames as $className) {
            if (!is_string($className) || !class_exists($className)) {
                continue;
            }
            $rule = new $className();
            if ($rule instanceof RuleInterface) {
                $rules[] = $rule;
            }
        }

        if ($rules === []) {
            // fallback to built-in set
            return [
                new XssRule(),
                new SignatureRule(),
            ];
        }

        return $rules;
    }

    private function findPhpFiles(string $path, array $ignorePatterns): array
    {
        $files = [];
        $realPath = realpath($path) ?: $path;

        if (is_file($realPath)) {
            if (str_ends_with(strtolower($realPath), '.php')) {
                $files[] = $realPath;
            }
            return $files;
        }

        if (!is_dir($realPath)) {
            return [];
        }

        $directoryIterator = new \RecursiveDirectoryIterator(
            $realPath,
            \RecursiveDirectoryIterator::SKIP_DOTS | \RecursiveDirectoryIterator::FOLLOW_SYMLINKS
        );
        $iterator = new \RecursiveIteratorIterator($directoryIterator);

        $rootPath = rtrim($realPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

        foreach ($iterator as $fileInfo) {
            if (!$fileInfo->isFile() || !str_ends_with(strtolower($fileInfo->getFilename()), '.php')) {
                continue;
            }

            $filePath = $fileInfo->getPathname();
            $relativePath = str_replace($rootPath, '', $filePath);
            $pathParts = explode(DIRECTORY_SEPARATOR, $relativePath);

            $isIgnored = false;
            foreach ($ignorePatterns as $pattern) {
                if (in_array($pattern, $pathParts, true) || str_starts_with($relativePath, $pattern . DIRECTORY_SEPARATOR)) {
                    $isIgnored = true;
                    break;
                }
            }

            if (!$isIgnored) {
                $files[] = $filePath;
            }
        }

        return $files;
    }

    private function prepareSnippetForAi(string $file, array $vulns): string
    {
        $content = @file_get_contents($file);
        if ($content === false || trim($content) === '') {
            return '// File: ' . basename($file);
        }

        $lines = preg_split('/\r?\n/', $content);

        $lineNumbers = [];
        foreach ($vulns as $vuln) {
            if ($vuln instanceof Vulnerability) {
                $lineNumbers[] = $vuln->getLine();
            }
        }
        if ($lineNumbers === []) {
            $lineNumbers = [1];
        }

        $start = max(0, min($lineNumbers) - 5);
        $end = min(count($lines), max($lineNumbers) + 25);
        $snippetLines = array_slice($lines, $start, $end - $start);

        $header = '// File: ' . basename($file) . "\n// Lines approx " . ($start + 1) . '-' . $end . "\n";
        return $header . implode("\n", $snippetLines);
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @return list<Vulnerability>
     */
    private function deduplicateVulnerabilities(array $vulnerabilities): array
    {
        $seen = [];
        $unique = [];
        foreach ($vulnerabilities as $vuln) {
            if (!$vuln instanceof Vulnerability) {
                continue;
            }
            $key = $vuln->getType() . ':' .
                   $vuln->getFile() . ':' .
                   $vuln->getLine() . ':' .
                   md5($vuln->getMessage());
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $unique[] = $vuln;
            }
        }
        return $unique;
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @return list<Vulnerability>
     */
    private function filterBySeverity(array $vulnerabilities, string $threshold): array
    {
        $levelMap = [
            'critical' => 4,
            'high' => 3,
            'medium' => 2,
            'low' => 1,
        ];

        $threshold = strtolower(trim($threshold));
        $minLevel = $levelMap[$threshold] ?? 2;

        $filtered = [];
        foreach ($vulnerabilities as $vuln) {
            if ($vuln instanceof Vulnerability) {
                $level = $levelMap[$vuln->getSeverity()] ?? 0;
                if ($level >= $minLevel) {
                    $filtered[] = $vuln;
                }
            }
        }
        return $filtered;
    }
}
