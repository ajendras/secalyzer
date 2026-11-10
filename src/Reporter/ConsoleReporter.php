<?php

declare(strict_types=1);

namespace Src\Reporter;

use Src\Model\Vulnerability;
use Src\Report;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Helper\TableCell;
use Symfony\Component\Console\Helper\TableSeparator;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Renders a beautiful, color-coded terminal report using SymfonyStyle.
 *
 * Features:
 * - Summary with severity counts and visual gauge bars
 * - Color-coded findings table (type, location, severity, confidence)
 * - Detailed remediation hints with ready-to-apply code patches
 * - Responsive layout that works in narrow terminals
 */
final class ConsoleReporter
{
    private SymfonyStyle $io;

    public function __construct(SymfonyStyle $io)
    {
        $this->io = $io;
    }

    /**
     * Outputs the complete scan report to the terminal.
     */
    public function report(Report $report): void
    {
        $this->printHeader();
        $this->printSummary($report);

        $vulnerabilities = $report->getVulnerabilities();

        if ($vulnerabilities === []) {
            $this->io->newLine();
            $this->io->success('No vulnerabilities found. Your code appears secure.');
            return;
        }

        $this->printFindingsTable($vulnerabilities);
        $this->printSeverityGauges($report);
        $this->printRemediationSection($vulnerabilities);
    }

    private function printHeader(): void
    {
        $this->io->title('Secalyzer — PHP CMS Security Scanner');
        $this->io->writeln('  <fg=yellow>Static AST analysis + optional AI-powered contextual review</>');
        $this->io->newLine();
    }

    private function printSummary(Report $report): void
    {
        $total = count($report->getVulnerabilities());
        $critical = $report->countBySeverity('critical');
        $high = $report->countBySeverity('high');
        $medium = $report->countBySeverity('medium');
        $low = $report->countBySeverity('low');

        $this->io->section('Scan Summary');

        $this->io->table(
            ['Metric', 'Value'],
            [
                ['Total findings', (string) $total],
                ['Critical', "<fg=red>{$critical}</>"],
                ['High', "<fg=yellow>{$high}</>"],
                ['Medium', "<fg=cyan>{$medium}</>"],
                ['Low', "<fg=green>{$low}</>"],
            ]
        );
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     */
    private function printFindingsTable(array $vulnerabilities): void
    {
        $this->io->section('Findings');

        $rows = [];
        foreach ($vulnerabilities as $vuln) {
            $severityColor = match ($vuln->getSeverity()) {
                'critical' => 'red',
                'high' => 'yellow',
                'medium' => 'cyan',
                'low' => 'green',
                default => 'white',
            };

            $severityBadge = sprintf(
                '<fg=%s;options=bold>%s</>',
                $severityColor,
                strtoupper($vuln->getSeverity())
            );

            $location = sprintf(
                '%s<fg=gray>:%d</>',
                basename($vuln->getFile()),
                $vuln->getLine()
            );

            $confidence = sprintf(
                '<fg=green>%d%%</>',
                (int) round($vuln->getConfidence() * 100)
            );

            $rows[] = [
                sprintf('<fg=magenta>%s</>', strtoupper($vuln->getType())),
                $location,
                $severityBadge,
                $confidence,
                $this->truncate($vuln->getMessage(), 65),
            ];
        }

        $table = new Table($this->io);
        $table->setHeaders(['Type', 'Location', 'Severity', 'Confidence', 'Description']);
        $table->setRows($rows);
        $table->setStyle('box');
        $table->setColumnMaxWidth(4, 65);
        $table->render();

        $this->io->newLine();
    }

    /**
     * Renders visual severity distribution using Unicode block characters.
     */
    private function printSeverityGauges(Report $report): void
    {
        $this->io->section('Severity Distribution');

        $total = count($report->getVulnerabilities());
        if ($total === 0) {
            return;
        }

        $severities = [
            'critical' => ['color' => 'red', 'icon' => '🚨'],
            'high' => ['color' => 'yellow', 'icon' => '⚠️'],
            'medium' => ['color' => 'cyan', 'icon' => '📍'],
            'low' => ['color' => 'green', 'icon' => 'ℹ️'],
        ];

        foreach ($severities as $severity => $meta) {
            $count = $report->countBySeverity($severity);
            if ($count === 0) {
                continue;
            }

            $percentage = (int) round(($count / $total) * 100);
            $barLength = (int) round(($count / $total) * 25);
            $bar = str_repeat('█', max($barLength, 1));

            $this->io->writeln(sprintf(
                '  %s <fg=%s>%s</> %s <fg=gray>%d%% (%d)</>',
                $meta['icon'],
                $meta['color'],
                $bar,
                str_pad(ucfirst($severity), 8),
                $percentage,
                $count
            ));
        }

        $this->io->newLine();
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     */
    private function printRemediationSection(array $vulnerabilities): void
    {
        $this->io->section('Remediation Guidance');

        foreach ($vulnerabilities as $vuln) {
            $this->io->writeln(sprintf(
                "<fg=white;options=bold>%s</> <fg=gray>in</> <info>%s:%d</info>",
                strtoupper($vuln->getType()),
                basename($vuln->getFile()),
                $vuln->getLine()
            ));

            $this->io->writeln('  <comment>' . $vuln->getMessage() . '</comment>');

            $fix = $vuln->getSuggestedFix();
            $this->io->writeln('  <fg=green>Fix:</>');
            foreach (explode("\n", $fix) as $line) {
                if (trim($line) !== '') {
                    $this->io->writeln('    <fg=green>' . $line . '</>');
                }
            }

            $this->io->newLine();
        }

        $this->io->note(
            'Run with --fix to generate patch files in a future version. ' .
            'Always review AI-suggested fixes before applying.'
        );
    }

    private function truncate(string $text, int $maxLength): string
    {
        if (mb_strlen($text) <= $maxLength) {
            return $text;
        }

        return mb_substr($text, 0, $maxLength - 3) . '...';
    }
}
