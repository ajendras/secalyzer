<?php

declare(strict_types=1);

namespace Src\Command;

use Src\Report;
use Src\Reporter\ConsoleReporter;
use Src\Scanner;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Symfony Console command that parses user options and orchestrates
 * the Scanner + appropriate Reporter.
 *
 * Supports --path, --ai-key, --format, --fix and --config.
 */
final class ScanCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('scan')
            ->setDescription('Scan a PHP project for security vulnerabilities using static rules and optional AI.')
            ->setHelp(<<<'HELP'
                Scans the provided path (or current directory) for common web vulnerabilities.
                Static analysis is always performed. AI analysis is enabled by providing --ai-key.

                Examples:
                  secalyzer scan ./plugin
                  secalyzer scan ./theme --ai-key sk-...
                  secalyzer scan . --format=json > report.json
                HELP)
            ->addArgument(
                'path',
                InputArgument::OPTIONAL,
                'Directory or file to scan',
                getcwd()
            )
            ->addOption(
                'ai-key',
                'k',
                InputOption::VALUE_REQUIRED,
                'OpenAI API key to enable contextual LLM analysis'
            )
            ->addOption(
                'format',
                'f',
                InputOption::VALUE_REQUIRED,
                'Output format (console, html, json, sarif)',
                'console'
            )
            ->addOption(
                'fix',
                null,
                InputOption::VALUE_NONE,
                'Include ready-to-apply fix suggestions'
            )
            ->addOption(
                'config',
                'c',
                InputOption::VALUE_REQUIRED,
                'Path to JSON config file (ignore paths, severity threshold, custom rules)'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        /** @var string $rawPath */
        $rawPath = $input->getArgument('path');
        $aiKey = $input->getOption('ai-key');
        /** @var string $format */
        $format = $input->getOption('format');
        $fix = (bool) $input->getOption('fix');
        $configPath = $input->getOption('config');

        $allowedFormats = ['console', 'html', 'json', 'sarif'];
        if (!in_array($format, $allowedFormats, true)) {
            $io->error(sprintf(
                'Invalid format "%s". Allowed values: %s.',
                $format,
                implode(', ', $allowedFormats)
            ));
            return Command::INVALID;
        }

        if (!is_readable($rawPath)) {
            $io->error(sprintf('Cannot read path "%s". Please check permissions or existence.', $rawPath));
            return Command::FAILURE;
        }

        $path = realpath($rawPath) ?: $rawPath;

        if ($configPath !== null && !is_readable($configPath)) {
            $io->warning(sprintf('Config file "%s" not found or not readable. Using defaults.', $configPath));
            $configPath = null;
        }

        $options = [
            'ai_key' => is_string($aiKey) && $aiKey !== '' ? $aiKey : null,
            'format' => $format,
            'fix' => $fix,
            'config' => $configPath,
            'severity_threshold' => 'medium', // default, can be overridden via config
        ];

        $io->title('Secalyzer — PHP CMS Security Scanner');
        $io->text(sprintf('Target: <info>%s</info>', $path));
        if ($options['ai_key'] !== null) {
            $io->text('AI-assisted analysis enabled (focused snippets only).');
        }

        $scanner = new Scanner();
        $report = $scanner->scan($path, $options);

        if ($format === 'console') {
            $reporter = new ConsoleReporter($io);
            $reporter->report($report);
        } else {
            $extension = $format === 'html' ? 'html' : $format;
            $filename = sprintf('secalyzer-report.%s', $extension);

            $content = match ($format) {
                'json' => $report->toJson(),
                'sarif' => $report->toSarif(),
                'html' => $report->toHtml(),
                default => '{}',
            };

            if (file_put_contents($filename, $content) === false) {
                $io->error('Failed to write report file.');
                return Command::FAILURE;
            }

            $io->success(sprintf('Report written to %s', $filename));
            if ($format === 'json' || $format === 'sarif') {
                $io->writeln($content);
            } else {
                $io->text(sprintf('Open <info>%s</info> in your browser.', $filename));
            }
        }

        $critical = $report->countBySeverity('critical');
        $high = $report->countBySeverity('high');
        if ($critical + $high > 0) {
            $io->error(sprintf(
                'Scan completed with %d critical and %d high severity findings.',
                $critical,
                $high
            ));
            return Command::FAILURE;
        }

        $io->success('Scan completed successfully. No critical or high severity issues found.');
        return Command::SUCCESS;
    }
}
