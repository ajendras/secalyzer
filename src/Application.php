<?php

declare(strict_types=1);

namespace Src;

use Src\Command\ScanCommand;
use Symfony\Component\Console\Application as SymfonyConsoleApplication;

/**
 * Bootstraps and runs the Symfony Console application for Secalyzer.
 *
 * Registers the primary ScanCommand and configures the application
 * name and version.
 */
final class Application
{
    private const NAME = 'secalyzer';
    private const VERSION = '0.1.0';

    /**
     * Runs the CLI application.
     *
     * This is the single entry point called by bin/secalyzer.
     */
    public static function run(): void
    {
        $app = new SymfonyConsoleApplication(self::NAME, self::VERSION);
        $app->add(new ScanCommand());

        // The ScanCommand is registered with name 'scan'. We make it the
        // default so both `secalyzer scan ...` and `secalyzer ...` work.
        $app->setDefaultCommand('scan');

        $app->run();
    }
}
