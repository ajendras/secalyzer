<?php

declare(strict_types=1);

namespace Src;

use Src\Analyzer\AiAnalyzer;
use Src\Analyzer\StaticAnalyzer;
use Src\Model\Vulnerability;
use Src\Report;

/**
 * Orchestrates static analysis, optional AI analysis, deduplication
 * and assembles a final Report.
 */
final class Scanner
{
    /**
     * Scans a path (file or directory) and returns a Report.
     *
     * @param string $path   Directory or single PHP file
     * @param array<string,mixed> $options
     */
    public function scan(string $path, array $options = []): Report
    {
        $staticAnalyzer = new StaticAnalyzer();

        $aiKey = $options['ai_key'] ?? null;
        $useAi = $aiKey !== null && is_string($aiKey) && str_starts_with($aiKey, 'sk-');

        $vulnerabilities = [];
        $files = $this->findPhpFiles($path);

        foreach ($files as $file) {
            $staticVulns = $staticAnalyzer->analyze($file);
            $vulnerabilities = array_merge($vulnerabilities, $staticVulns);

            if ($useAi && $staticVulns !== []) {
                // Only run AI on files that already triggered static rules (cost optimization)
                $snippet = $this->extractFocusedSnippet($file, $staticVulns);
                if ($snippet !== '') {
                    $aiAnalyzer = new AiAnalyzer();
                    $aiVulns = $aiAnalyzer->analyze($snippet, $aiKey);
                    $vulnerabilities = array_merge($vulnerabilities, $aiVulns);
                }
            }
        }

        $vulnerabilities = $this->deduplicate($vulnerabilities);

        return new Report($vulnerabilities, $options);
    }

    /**
     * Recursively finds all PHP files, skipping common dependency directories.
     *
     * @return list<string>
     */
    private function findPhpFiles(string $path): array
    {
        $files = [];

        if (is_file($path)) {
            if (pathinfo($path, PATHINFO_EXTENSION) === 'php' && is_readable($path)) {
                return [$path];
            }
            return [];
        }

        if (!is_dir($path)) {
            return [];
        }

        $directoryIterator = new \RecursiveDirectoryIterator(
            $path,
            \RecursiveDirectoryIterator::SKIP_DOTS | \RecursiveDirectoryIterator::FOLLOW_SYMLINKS
        );

        $iterator = new \RecursiveIteratorIterator($directoryIterator);

        foreach ($iterator as $fileInfo) {
            if (!$fileInfo->isFile() || $fileInfo->getExtension() !== 'php') {
                continue;
            }

            $realPath = $fileInfo->getRealPath();
            if ($realPath === false) {
                continue;
            }

            // Skip common noise directories
            if (preg_match('#/(vendor|node_modules|tests|tmp|cache|build|dist)/#i', $realPath)) {
                continue;
            }

            $files[] = $realPath;
        }

        return $files;
    }

    /**
     * Extracts a focused code snippet around detected vulnerabilities.
     * Limits context to reduce token usage for the LLM.
     */
    private function extractFocusedSnippet(string $file, array $vulnerabilities): string
    {
        if (!is_readable($file)) {
            return '';
        }

        $lines = @file($file, FILE_IGNORE_NEW_LINES);
        if ($lines === false || $lines === []) {
            return '';
        }

        // Collect line numbers from all vulnerabilities in this file
        $lineNumbers = [];
        foreach ($vulnerabilities as $vuln) {
            if ($vuln->getFile() === $file) {
                $lineNumbers[] = $vuln->getLine();
            }
        }

        if ($lineNumbers === []) {
            // fallback: first 40 lines
            return implode("\n", array_slice($lines, 0, 40));
        }

        $startLine = max(0, min($lineNumbers) - 8);
        $endLine = min(count($lines), max($lineNumbers) + 12);

        return implode("\n", array_slice($lines, $startLine, $endLine - $startLine));
    }

    /**
     * Removes duplicate findings based on file + line + message hash.
     *
     * @param list<Vulnerability> $vulnerabilities
     * @return list<Vulnerability>
     */
    private function deduplicate(array $vulnerabilities): array
    {
        $seen = [];
        $unique = [];

        foreach ($vulnerabilities as $vuln) {
            $key = sprintf(
                '%s:%d:%s',
                $vuln->getFile(),
                $vuln->getLine(),
                substr(hash('xxh3', $vuln->getMessage()), 0, 12)
            );

            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $unique[] = $vuln;
            }
        }

        return $unique;
    }
}
