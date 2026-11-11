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
 * Automatically discovers and loads .secalyzer.json when present.
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
                Configuration is loaded from .secalyzer.json (auto-detected) or --config.

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
                'Path to JSON config file (falls back to .secalyzer.json)'
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

        // Load configuration (CLI --config takes precedence over auto-discovery)
        $config = $this->loadConfiguration($configPath, $path, $io);

        $options = [
            'ai_key' => is_string($aiKey) && $aiKey !== '' ? $aiKey : null,
            'format' => $format,
            'fix' => $fix,
            'severity_threshold' => $config['severity_threshold'] ?? 'medium',
            'ignore' => $config['ignore'] ?? ['vendor', 'tests', 'node_modules'],
            'rules' => $config['rules'] ?? null,
            'config_path' => $config['config_path'] ?? null,
        ];

        $io->title('Secalyzer — PHP CMS Security Scanner');
        $io->text(sprintf('Target: <info>%s</info>', $path));
        if ($options['ai_key'] !== null) {
            $io->text('AI-assisted analysis enabled (focused snippets only).');
        }
        if ($options['config_path'] !== null) {
            $io->text(sprintf('Config: <info>%s</info>', basename($options['config_path'])));
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

    /**
     * Load configuration from explicit path, auto-discovered .secalyzer.json,
     * or return defaults.
     *
     * @return array<string,mixed>
     */
    private function loadConfiguration(?string $configPath, string $scanPath, SymfonyStyle $io): array
    {
        if ($configPath !== null) {
            if (is_readable($configPath)) {
                return $this->parseConfigFile($configPath, $io);
            }
            $io->warning(sprintf('Config file "%s" not found or not readable. Using defaults.', $configPath));
            return [];
        }

        $defaultPath = $this->findDefaultConfigPath($scanPath);
        if ($defaultPath !== null) {
            $config = $this->parseConfigFile($defaultPath, $io);
            $config['config_path'] = $defaultPath;
            return $config;
        }

        return [];
    }

    private function findDefaultConfigPath(string $scanPath): ?string
    {
        $candidates = [
            rtrim($scanPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.secalyzer.json',
        ];

        if (!is_dir($scanPath)) {
            $candidates[] = dirname($scanPath) . DIRECTORY_SEPARATOR . '.secalyzer.json';
        }

        $candidates[] = getcwd() . DIRECTORY_SEPARATOR . '.secalyzer.json';

        foreach (array_unique($candidates) as $candidate) {
            if (is_file($candidate) && is_readable($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * @return array<string,mixed>
     */
    private function parseConfigFile(string $path, SymfonyStyle $io): array
    {
        $content = file_get_contents($path);
        if ($content === false) {
            $io->warning(sprintf('Could not read config file "%s".', $path));
            return [];
        }

        try {
            $config = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($config)) {
                $io->warning('Config file must contain a JSON object.');
                return [];
            }

            $normalized = [];

            if (isset($config['ignore']) && is_array($config['ignore'])) {
                $normalized['ignore'] = array_values(array_filter($config['ignore'], 'is_string'));
            }

            if (isset($config['severity_threshold']) && is_string($config['severity_threshold'])) {
                $valid = ['critical', 'high', 'medium', 'low'];
                $thresh = strtolower(trim($config['severity_threshold']));
                if (in_array($thresh, $valid, true)) {
                    $normalized['severity_threshold'] = $thresh;
                } else {
                    $io->warning('Invalid severity_threshold in config; falling back to "medium".');
                    $normalized['severity_threshold'] = 'medium';
                }
            }

            if (isset($config['rules']) && is_array($config['rules'])) {
                $normalized['rules'] = array_values(array_filter($config['rules'], 'is_string'));
            }

            return $normalized;
        } catch (\JsonException $e) {
            $io->warning(sprintf('Invalid JSON in "%s": %s', basename($path), $e->getMessage()));
            return [];
        }
    }
}
