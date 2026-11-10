<?php

declare(strict_types=1);

namespace Src\Rule;

use PhpParser\Node;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Print_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Echo_;
use Src\Model\Vulnerability;

/**
 * Detects potential XSS by looking for echo/print statements that output
 * unsanitized data from superglobals ($_GET, $_POST, etc.).
 *
 * Uses AST awareness to avoid flagging properly escaped output (e.g. via
 * htmlspecialchars). Supports common CMS sanitizers.
 */
final class XssRule implements RuleInterface
{
    private const SUPERGLOBALS = ['_GET', '_POST', '_REQUEST', '_COOKIE', '_SERVER', '_FILES'];

    private const SANITIZERS = [
        'htmlspecialchars',
        'htmlentities',
        'esc_html',
        'esc_attr',
        'sanitize_text_field',
        'filter_var',
        'wp_kses',
        'wp_kses_post',
    ];

    public function getName(): string
    {
        return 'Cross-Site Scripting (XSS)';
    }

    public function getSeverity(): string
    {
        return 'high';
    }

    public function check(Node $node, string $file): ?Vulnerability
    {
        if (!$node instanceof Echo_ && !$node instanceof Print_) {
            return null;
        }

        $expressions = $node instanceof Echo_ ? $node->exprs : [$node->expr];

        foreach ($expressions as $expr) {
            if ($this->containsTaintedData($expr) && !$this->isSanitized($expr)) {
                return new Vulnerability(
                    'xss',
                    $file,
                    $node->getStartLine(),
                    $this->getSeverity(),
                    'Potential XSS: unsanitized output of data originating from a superglobal.',
                    "Wrap the output with a sanitizer:\n" .
                    "echo htmlspecialchars(\$data, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');\n\n" .
                    "Consider using a template engine with automatic escaping.",
                    0.85
                );
            }
        }

        return null;
    }

    /**
     * Recursively determines whether an expression contains data from a superglobal.
     */
    private function containsTaintedData(Node $node): bool
    {
        if ($node instanceof Variable && is_string($node->name)) {
            return in_array($node->name, self::SUPERGLOBALS, true);
        }

        if ($node instanceof ArrayDimFetch) {
            return $this->containsTaintedData($node->var);
        }

        if ($node instanceof Concat) {
            return $this->containsTaintedData($node->left)
                || $this->containsTaintedData($node->right);
        }

        // Function calls to non-sanitizers may still be tainted (conservative)
        if ($node instanceof FuncCall && $node->name instanceof Name) {
            $func = strtolower($node->name->toString());
            if (in_array($func, ['trim', 'strtolower', 'strtoupper', 'strip_tags'], true)) {
                // These do not protect against XSS
                foreach ($node->getArgs() as $arg) {
                    if ($this->containsTaintedData($arg->value)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Returns true if the top-level expression is a recognized sanitizer call.
     */
    private function isSanitized(Node $node): bool
    {
        if (!$node instanceof FuncCall || !$node->name instanceof Name) {
            return false;
        }

        $functionName = strtolower($node->name->toString());

        return in_array($functionName, self::SANITIZERS, true);
    }
}
