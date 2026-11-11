<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use Src\Analyzer\StaticAnalyzer;
use Src\Model\Vulnerability;
use Src\Rule\RuleInterface;
use Src\Rule\SignatureRule;
use Src\Rule\XssRule;

class StaticAnalyzerTest extends TestCase
{
    private StaticAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new StaticAnalyzer();
    }

    public function testDefaultRulesAreRegistered(): void
    {
        $reflection = new \ReflectionClass($this->analyzer);
        $property = $reflection->getProperty('rules');
        $property->setAccessible(true);
        $rules = $property->getValue($this->analyzer);

        $this->assertCount(2, $rules);
        $this->assertInstanceOf(XssRule::class, $rules[0]);
        $this->assertInstanceOf(SignatureRule::class, $rules[1]);
    }

    public function testCustomRulesCanBeProvided(): void
    {
        $customRule = new SignatureRule();
        $customRules = [$customRule];
        $analyzer = new StaticAnalyzer($customRules);

        $reflection = new \ReflectionClass($analyzer);
        $property = $reflection->getProperty('rules');
        $property->setAccessible(true);

        $this->assertSame($customRules, $property->getValue($analyzer));
    }

    public function testRejectsInvalidRule(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('All provided rules must implement RuleInterface');

        new StaticAnalyzer([new \stdClass()]);
    }

    /**
     * @dataProvider provideSignatureVulnerableCode
     */
    public function testDetectsSignatureVulnerabilities(string $code, string $expectedType): void
    {
        $file = tempnam(sys_get_temp_dir(), 'test_') . '.php';
        file_put_contents($file, "<?php\n" . $code);

        $vulnerabilities = $this->analyzer->analyze($file);
        unlink($file);

        $this->assertNotEmpty($vulnerabilities);
        $this->assertInstanceOf(Vulnerability::class, $vulnerabilities[0]);
        $this->assertSame($expectedType, $vulnerabilities[0]->getType());
        $this->assertGreaterThan(0, $vulnerabilities[0]->getLine());
    }

    public static function provideSignatureVulnerableCode(): array
    {
        return [
            'weak md5 signature' => [
                '$sig = md5($payload);',
                'weak-signature',
            ],
            'insecure strcmp for signature' => [
                'if (strcmp($sig1, $sig2) === 0) {}',
                'signature-bypass',
            ],
        ];
    }

    public function testHandlesUnreadableFile(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->analyzer->analyze('/non/existent/file.php');
    }

    public function testEmptyFileReturnsNoVulnerabilities(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'empty_') . '.php';
        file_put_contents($file, '');
        $vulnerabilities = $this->analyzer->analyze($file);
        unlink($file);

        $this->assertEmpty($vulnerabilities);
    }
}
