<?php

declare(strict_types=1);

namespace Src\Rule;

use PhpParser\Node;
use PhpParser\Node\Expr\BinaryOp\Equal;
use PhpParser\Node\Expr\BinaryOp\Identical;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use Src\Model\Vulnerability;

/**
 * Detects weak signature verification patterns common in CMS plugin/theme
 * update mechanisms. Flags weak hashes (md5/sha1), non-constant-time
 * comparisons, and related signing bypass risks.
 */
final class SignatureRule implements RuleInterface
{
    public function getName(): string
    {
        return 'Insecure Signature Verification';
    }

    public function getSeverity(): string
    {
        return 'critical';
    }

    public function check(Node $node, string $file): ?Vulnerability
    {
        // Weak hash functions used for signatures
        if ($node instanceof FuncCall && $node->name instanceof Name) {
            $funcName = strtolower($node->name->toString());

            if (in_array($funcName, ['md5', 'sha1', 'crc32'], true)) {
                return new Vulnerability(
                    'weak-signature',
                    $file,
                    $node->getStartLine(),
                    $this->getSeverity(),
                    'Weak cryptographic hash function used for signature generation or verification.',
                    "Replace with a strong HMAC construction:\n" .
                    "hash_hmac('sha256', \$data, \$secretKey, true)\n\n" .
                    "For asymmetric signatures prefer openssl_sign() + openssl_verify().",
                    0.90
                );
            }

            if (in_array($funcName, ['strcmp', 'strcasecmp'], true)) {
                return new Vulnerability(
                    'signature-bypass',
                    $file,
                    $node->getStartLine(),
                    $this->getSeverity(),
                    'Insecure string comparison used for signature validation (timing attack possible).',
                    "Use the constant-time hash_equals() function:\n" .
                    "if (hash_equals(\$expectedSignature, \$receivedSignature)) {\n" .
                    "    // signature valid\n" .
                    "}",
                    0.95
                );
            }

            // hash() called with weak algorithm
            if ($funcName === 'hash' && count($node->getArgs()) >= 1) {
                $algoNode = $node->getArgs()[0]->value;
                if ($algoNode instanceof String_ && in_array(strtolower($algoNode->value), ['md5', 'sha1'], true)) {
                    return new Vulnerability(
                        'weak-signature',
                        $file,
                        $node->getStartLine(),
                        $this->getSeverity(),
                        'Weak algorithm supplied to hash() for what appears to be a signature.',
                        "Use a strong algorithm with HMAC:\n" .
                        "hash_hmac('sha256', \$payload, \$key, true)",
                        0.85
                    );
                }
            }
        }

        // Direct equality comparison on values that look like signatures
        if ($node instanceof Equal || $node instanceof Identical) {
            if ($this->looksLikeSignatureComparison($node->left) || $this->looksLikeSignatureComparison($node->right)) {
                return new Vulnerability(
                    'signature-bypass',
                    $file,
                    $node->getStartLine(),
                    $this->getSeverity(),
                    'Signature comparison uses direct equality operator instead of constant-time function.',
                    "Replace direct comparison with:\n" .
                    "if (hash_equals(\$expected, \$actual)) {\n" .
                    "    // signature is valid\n" .
                    "}",
                    0.75
                );
            }
        }

        return null;
    }

    /**
     * Heuristic that returns true when a node appears to be part of a signature/hash.
     */
    private function looksLikeSignatureComparison(Node $node): bool
    {
        if ($node instanceof FuncCall && $node->name instanceof Name) {
            $name = strtolower($node->name->toString());
            return in_array($name, ['md5', 'sha1', 'hash', 'hash_hmac', 'openssl_verify'], true);
        }

        if ($node instanceof Node\Expr\Variable && is_string($node->name)) {
            $varName = strtolower((string) $node->name);
            return str_contains($varName, 'sign')
                || str_contains($varName, 'hash')
                || str_contains($varName, 'hmac')
                || str_contains($varName, 'signature');
        }

        return false;
    }
}
