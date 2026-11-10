<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;
use Src\Analyzer\StaticAnalyzer;
use Src\Model\Vulnerability;
use Src\Rule\RuleInterface;
use Src\Rule\SignatureRule;
use Src\Rule\XssRule;

/**
 * Comprehensive tests for StaticAnalyzer, XssRule and SignatureRule.
 *
 * Uses data providers to cover normal cases, edge cases (safe code, empty files),
 * parse errors, and direct rule validation via temporary PHP files.
 */
final class StaticAnalyzerTest extends TestCase
{
    private StaticAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new StaticAnalyzer();
    }

    /**
     * @dataProvider provideXssCases
     */
    public function testXssRule(string $code, int $expectedCount, string $expectedType = 'xss'): void
    {
        $file = $this->createTemporaryFile($code);
        $vulnerabilities = $this->analyzer->analyze($file);

        $this->assertCount($expectedCount, $vulnerabilities, 'Unexpected number of vulnerabilities');

        if ($expectedCount > 0) {
            $this->assertSame($expectedType, $vulnerabilities[0]->getType());
            $this->assertGreaterThanOrEqual(1, $vulnerabilities[0]->getLine());
            $this->assertSame('high', $vulnerabilities[0]->getSeverity());
        }

        unlink($file);
    }

    public function provideXssCases(): array
    {
        return [
            'unsanitized echo of GET' => [
                '<?php echo $_GET["id"];',
                1,
            ],
            'unsanitized print of POST' => [
                '<?php print $_POST["comment"]; ?>',
                1,
            ],
            'concatenated tainted data' => [
                '<?php echo "User input: " . $_GET["name"];',
                1,
            ],
            'htmlspecialchars protects' => [
                '<?php echo htmlspecialchars($_GET["id"], ENT_QUOTES);',
                0,
            ],
            'esc_html from CMS protects' => [
                '<?php echo esc_html($_POST["content"]);',
                0,
            ],
            'wp_kses_post protects' => [
                '<?php echo wp_kses_post($_GET["html"]);',
                0,
            ],
            'strip_tags does NOT protect against XSS' => [
                '<?php echo strip_tags($_GET["input"]);',
                1,
            ],
            'static string is safe' => [
                '<?php echo "Hello, world!";',
                0,
            ],
            'variable that is not a superglobal is ignored' => [
                '<?php $safe = "ok"; echo $safe;',
                0,
            ],
        ];
    }

    /**
     * @dataProvider provideSignatureCases
     */
    public function testSignatureRule(string $code, int $expectedCount, string $expectedType = 'signature-bypass'): void
    {
        $file = $this->createTemporaryFile($code);
        $vulnerabilities = $this->analyzer->analyze($file);

        $matching = array_filter(
            $vulnerabilities,
            static fn(Vulnerability $v): bool => in_array(
                $v->getType(),
                ['weak-signature', 'signature-bypass'],
                true
            )
        );

        $this->assertCount(
            $expectedCount,
            $matching,
            sprintf('Expected %d signature issues, got %d', $expectedCount, count($matching))
        );

        if ($expectedCount > 0) {
            $first = reset($matching);
            $this->assertContains($first->getType(), ['weak-signature', 'signature-bypass']);
            $this->assertSame('critical', $first->getSeverity());
        }

        unlink($file);
    }

    public function provideSignatureCases(): array
    {
        return [
            'md5 used for signature' => [
                '<?php $sig = md5($payload);',
                1,
                'weak-signature',
            ],
            'sha1 used for signature' => [
                '<?php if (sha1($data) === $hash) {}',
                2, // weak hash + comparison
                'weak-signature',
            ],
            'strcmp on signatures' => [
                '<?php if (strcmp($a, $b) === 0) {}',
                1,
                'signature-bypass',
            ],
            'direct equality on hash result' => [
                '<?php if ($received === hash("sha256", $data)) {}',
                1,
                'signature-bypass',
            ],
            'hash_equals is safe' => [
                '<?php if (hash_equals($expected, $received)) {}',
                0,
            ],
            'hash() with weak algorithm' => [
                '<?php $h = hash("md5", $data);',
                1,
                'weak-signature',
            ],
            'openssl_verify is considered safe' => [
                '<?php openssl_verify($data, $sig, $key, OPENSSL_ALGO_SHA256);',
                0,
            ],
        ];
    }

    public function testAnalyzerReturnsEmptyArrayForEmptyFile(): void
    {
        $file = $this->createTemporaryFile('<?php');
        $result = $this->analyzer->analyze($file);
        $this->assertSame([], $result);
        unlink($file);
    }

    public function testAnalyzerReturnsEmptyArrayForUnparseableFile(): void
    {
        $file = $this->createTemporaryFile('<?php echo "unclosed string;');
        $result = $this->analyzer->analyze($file);
        $this->assertSame([], $result);
        unlink($file);
    }

    public function testAnalyzerThrowsForNonExistentFile(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('does not exist or is not readable');
        $this->analyzer->analyze('/path/that/does/not/exist.php');
    }

    public function testAnalyzerIgnoresNonPhpFiles(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'test_');
        file_put_contents($file, 'not php content');
        $result = $this->analyzer->analyze($file);
        $this->assertSame([], $result);
        unlink($file);
    }

    public function testRulesImplementRuleInterface(): void
    {
        $xss = new XssRule();
        $sig = new SignatureRule();

        $this->assertInstanceOf(RuleInterface::class, $xss);
        $this->assertInstanceOf(RuleInterface::class, $sig);

        $this->assertSame('Cross-Site Scripting (XSS)', $xss->getName());
        $this->assertSame('high', $xss->getSeverity());

        $this->assertSame('Insecure Signature Verification', $sig->getName());
        $this->assertSame('critical', $sig->getSeverity());
    }

    public function testMultipleRulesCanTriggerOnSameFile(): void
    {
        $code = <<<'PHP'
<?php
echo $_GET['x'];
if (md5($payload) === $sig) {}
PHP;

        $file = $this->createTemporaryFile($code);
        $vulnerabilities = $this->analyzer->analyze($file);

        $this->assertGreaterThanOrEqual(2, count($vulnerabilities));

        $types = array_map(static fn(Vulnerability $v): string => $v->getType(), $vulnerabilities);
        $this->assertContains('xss', $types);
        $this->assertContains('weak-signature', $types);

        unlink($file);
    }

    private function createTemporaryFile(string $content): string
    {
        $tmp = tempnam(sys_get_temp_dir(), 'secalyzer_test_');
        if ($tmp === false) {
            throw new \RuntimeException('Failed to create temporary file');
        }

        $path = $tmp . '.php';
        if (!rename($tmp, $path)) {
            throw new \RuntimeException('Failed to rename temporary file');
        }

        if (file_put_contents($path, $content) === false) {
            throw new \RuntimeException('Failed to write test PHP content');
        }

        return $path;
    }
}
