<?php

declare(strict_types=1);

namespace Src\Analyzer;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;
use Src\Model\Vulnerability;
use Src\Rule\RuleInterface;
use Src\Rule\SignatureRule;
use Src\Rule\XssRule;

/**
 * Uses nikic/php-parser to walk the AST and applies all registered RuleInterface
 * implementations to every node. Returns collected Vulnerability objects.
 */
final class StaticAnalyzer
{
    /** @var list<RuleInterface> */
    private array $rules = [];

    public function __construct()
    {
        // All deterministic rules are registered here. The project aims for 20+ rules.
        // Additional rules can be loaded from JSON config in a future extension point.
        $this->rules = [
            new XssRule(),
            new SignatureRule(),
            // SqlInjectionRule, UnsafeDeserializationRule, WeakRandomnessRule, etc.
        ];
    }

    /**
     * Analyzes a single PHP file.
     *
     * @param string $file Absolute path to a readable PHP file
     * @return list<Vulnerability>
     */
    public function analyze(string $file): array
    {
        if (!is_file($file) || !is_readable($file)) {
            throw new \InvalidArgumentException(sprintf(
                'File "%s" does not exist or is not readable.',
                $file
            ));
        }

        $code = file_get_contents($file);
        if ($code === false || trim($code) === '') {
            return [];
        }

        $parser = (new ParserFactory())->createForHostVersion();

        try {
            $ast = $parser->parse($code);
            if ($ast === null) {
                return [];
            }
        } catch (Error $error) {
            // Unparseable file - we do not treat this as a vulnerability
            return [];
        }

        $traverser = new NodeTraverser();

        $visitor = new class($this->rules, $file) extends NodeVisitorAbstract {
            /** @var list<RuleInterface> */
            private array $rules;
            private string $file;
            /** @var list<Vulnerability> */
            private array $vulnerabilities = [];

            public function __construct(array $rules, string $file)
            {
                $this->rules = $rules;
                $this->file = $file;
            }

            public function enterNode(Node $node): ?Node
            {
                foreach ($this->rules as $rule) {
                    $vulnerability = $rule->check($node, $this->file);
                    if ($vulnerability !== null) {
                        $this->vulnerabilities[] = $vulnerability;
                    }
                }
                return null;
            }

            /**
             * @return list<Vulnerability>
             */
            public function getVulnerabilities(): array
            {
                return $this->vulnerabilities;
            }
        };

        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $visitor->getVulnerabilities();
    }
}
