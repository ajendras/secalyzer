<?php

declare(strict_types=1);

namespace Src\Rule;

use PhpParser\Node;
use Src\Model\Vulnerability;

/**
 * Contract that all security rules must implement.
 *
 * Rules are applied to every node in the AST produced by nikic/php-parser.
 * A rule returns a Vulnerability when it detects a problem, otherwise null.
 */
interface RuleInterface
{
    /**
     * Returns the human-readable name of the rule.
     */
    public function getName(): string;

    /**
     * Returns the default severity of findings produced by this rule.
     *
     * Must be one of: critical, high, medium, low.
     */
    public function getSeverity(): string;

    /**
     * Inspects a single AST node and returns a Vulnerability if one is detected.
     *
     * @param Node   $node The AST node currently being visited
     * @param string $file Absolute path to the file being scanned
     * @return Vulnerability|null
     */
    public function check(Node $node, string $file): ?Vulnerability;
}
