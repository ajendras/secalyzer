<?php

declare(strict_types=1);

namespace Src;

use Src\Model\Vulnerability;

/**
 * Immutable container for all vulnerabilities discovered during a scan.
 *
 * Provides multiple output formats including beautiful self-contained HTML
 * (with dark/light mode, responsive tables, severity gauges and JS filtering),
 * JSON, SARIF (for GitHub Code Scanning), and a console-friendly string.
 */
final class Report
{
    /** @var list<Vulnerability> */
    private array $vulnerabilities;

    /** @var array<string,mixed> */
    private array $options;

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param array<string,mixed> $options Scan options (ai_key, format, etc.)
     */
    public function __construct(array $vulnerabilities, array $options = [])
    {
        foreach ($vulnerabilities as $item) {
            if (!$item instanceof Vulnerability) {
                throw new \InvalidArgumentException(
                    'All elements must be instances of Src\Model\Vulnerability.'
                );
            }
        }

        $this->vulnerabilities = array_values($vulnerabilities);
        $this->options = $options;
    }

    /**
     * @return list<Vulnerability>
     */
    public function getVulnerabilities(): array
    {
        return $this->vulnerabilities;
    }

    public function countBySeverity(string $severity): int
    {
        $severity = strtolower(trim($severity));
        $count = 0;

        foreach ($this->vulnerabilities as $vuln) {
            if ($vuln->getSeverity() === $severity) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Structured array representation used by JSON and HTML reports.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return [
            'vulnerabilities' => array_map(
                static fn(Vulnerability $v): array => $v->toArray(),
                $this->vulnerabilities
            ),
            'summary' => [
                'total' => count($this->vulnerabilities),
                'critical' => $this->countBySeverity('critical'),
                'high' => $this->countBySeverity('high'),
                'medium' => $this->countBySeverity('medium'),
                'low' => $this->countBySeverity('low'),
            ],
            'scan_options' => $this->options,
            'generated_at' => date('c'),
        ];
    }

    public function toJson(): string
    {
        return json_encode(
            $this->toArray(),
            JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES
        );
    }

    public function toSarif(): string
    {
        $results = [];

        foreach ($this->vulnerabilities as $vuln) {
            $level = match ($vuln->getSeverity()) {
                'critical', 'high' => 'error',
                'medium' => 'warning',
                'low' => 'note',
                default => 'warning',
            };

            $results[] = [
                'ruleId' => strtoupper($vuln->getType()),
                'level' => $level,
                'message' => [
                    'text' => $vuln->getMessage(),
                ],
                'locations' => [
                    [
                        'physicalLocation' => [
                            'artifactLocation' => [
                                'uri' => basename($vuln->getFile()),
                                'uriBaseId' => '%SRCROOT%',
                            ],
                            'region' => [
                                'startLine' => $vuln->getLine(),
                            ],
                        ],
                    ],
                ],
                'properties' => [
                    'severity' => $vuln->getSeverity(),
                    'confidence' => $vuln->getConfidence(),
                    'suggestedFix' => $vuln->getSuggestedFix(),
                    'tool' => 'secalyzer',
                ],
            ];
        }

        $sarif = [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'Secalyzer',
                            'version' => '0.1.0',
                            'informationUri' => 'https://github.com/secalyzer/secalyzer',
                            'rules' => [],
                        ],
                    ],
                    'results' => $results,
                ],
            ],
        ];

        return json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Returns a complete, self-contained HTML document with modern Tailwind-based
     * UI, dark/light mode support, interactive table, severity cards, search,
     * and export options. No external dependencies except the Tailwind CDN.
     */
    public function toHtml(): string
    {
        $vulnsJson = json_encode(
            array_map(static fn(Vulnerability $v): array => $v->toArray(), $this->vulnerabilities),
            JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT
        );

        $summary = [
            'total' => count($this->vulnerabilities),
            'critical' => $this->countBySeverity('critical'),
            'high' => $this->countBySeverity('high'),
            'medium' => $this->countBySeverity('medium'),
            'low' => $this->countBySeverity('low'),
        ];

        $html = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secalyzer Security Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&amp;family=Space+Grotesk:wght@500;600&amp;display=swap');
        
        :root {
            --primary: 234 179 8;
        }
        
        .dark {
            color-scheme: dark;
        }
        
        body {
            font-family: 'Inter', system_ui, sans-serif;
        }
        
        .title-font {
            font-family: 'Space Grotesk', sans-serif;
        }

        .severity-critical { background-color: #b91c1c; color: white; }
        .severity-high { background-color: #c2410c; color: white; }
        .severity-medium { background-color: #a16207; color: white; }
        .severity-low { background-color: #15803d; color: white; }

        .card {
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .card:hover {
            transform: translateY(-6px);
            box-shadow: 0 25px 50px -12px rgb(0 0 0 / 0.25);
        }

        table tr {
            transition: background-color 0.2s ease;
        }
        
        .dark table tr:hover {
            background-color: #1f2937;
        }
        
        .gauge {
            height: 6px;
            background: linear-gradient(90deg, #eab308, #84cc16);
            border-radius: 9999px;
        }
    </style>
</head>
<body class="bg-zinc-100 dark:bg-neutral-950 text-neutral-900 dark:text-neutral-200">
    <div class="max-w-screen-2xl mx-auto p-8">
        <!-- Header -->
        <div class="flex items-center justify-between mb-10">
            <div class="flex items-center gap-x-4">
                <div class="w-11 h-11 bg-yellow-400 text-neutral-900 rounded-2xl flex items-center justify-center text-3xl font-bold shadow-inner">S</div>
                <div>
                    <h1 class="title-font text-5xl font-semibold tracking-tighter">secalyzer</h1>
                    <p class="text-yellow-600 dark:text-yellow-500 text-sm -mt-1">PHP CMS Security Scanner</p>
                </div>
            </div>
            <div class="flex items-center gap-x-6">
                <button onclick="toggleTheme()" 
                        class="px-5 py-2.5 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 hover:border-yellow-300 rounded-3xl text-sm font-medium flex items-center gap-x-2 transition-colors">
                    <span id="theme-icon" class="text-lg">☀️</span>
                    <span id="theme-label">Light mode</span>
                </button>
                <div class="text-xs text-neutral-400 font-mono">
                    GENERATED<br>
                    <span id="timestamp" class="text-neutral-500 dark:text-neutral-400"></span>
                </div>
            </div>
        </div>

        <!-- Summary gauges -->
        <div class="grid grid-cols-5 gap-6 mb-12">
            <div onclick="filterSeverity(null)" class="card bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-3xl p-7 cursor-pointer hover:border-yellow-400">
                <div class="flex justify-between items-start">
                    <div>
                        <div class="uppercase text-xs tracking-[0.5px] font-medium text-neutral-400">Total</div>
                        <div id="total-count" class="text-6xl font-semibold title-font tracking-tighter mt-3">{$summary['total']}</div>
                    </div>
                    <div class="text-5xl opacity-10">📊</div>
                </div>
                <div class="mt-8 h-1.5 bg-neutral-200 dark:bg-neutral-700 rounded-3xl overflow-hidden">
                    <div class="gauge w-full"></div>
                </div>
            </div>
            
            <div onclick="filterSeverity('critical')" class="card bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-3xl p-7 cursor-pointer hover:border-red-400">
                <div class="flex justify-between items-start">
                    <div>
                        <div class="flex items-center gap-x-2">
                            <div class="w-3 h-3 bg-red-500 rounded-full"></div>
                            <div class="uppercase text-xs tracking-[0.5px] font-medium text-red-500">Critical</div>
                        </div>
                        <div id="critical-count" class="text-6xl font-semibold title-font tracking-tighter mt-3 text-red-600 dark:text-red-400">{$summary['critical']}</div>
                    </div>
                    <div class="text-5xl">🚨</div>
                </div>
            </div>
            
            <div onclick="filterSeverity('high')" class="card bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-3xl p-7 cursor-pointer hover:border-orange-400">
                <div class="flex justify-between items-start">
                    <div>
                        <div class="flex items-center gap-x-2">
                            <div class="w-3 h-3 bg-orange-500 rounded-full"></div>
                            <div class="uppercase text-xs tracking-[0.5px] font-medium text-orange-500">High</div>
                        </div>
                        <div id="high-count" class="text-6xl font-semibold title-font tracking-tighter mt-3 text-orange-600 dark:text-orange-400">{$summary['high']}</div>
                    </div>
                    <div class="text-5xl">⚠️</div>
                </div>
            </div>
            
            <div onclick="filterSeverity('medium')" class="card bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-3xl p-7 cursor-pointer hover:border-amber-400">
                <div class="flex justify-between items-start">
                    <div>
                        <div class="flex items-center gap-x-2">
                            <div class="w-3 h-3 bg-amber-500 rounded-full"></div>
                            <div class="uppercase text-xs tracking-[0.5px] font-medium text-amber-500">Medium</div>
                        </div>
                        <div id="medium-count" class="text-6xl font-semibold title-font tracking-tighter mt-3 text-amber-600 dark:text-amber-400">{$summary['medium']}</div>
                    </div>
                    <div class="text-5xl">📍</div>
                </div>
            </div>
            
            <div onclick="filterSeverity('low')" class="card bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-3xl p-7 cursor-pointer hover:border-emerald-400">
                <div class="flex justify-between items-start">
                    <div>
                        <div class="flex items-center gap-x-2">
                            <div class="w-3 h-3 bg-emerald-500 rounded-full"></div>
                            <div class="uppercase text-xs tracking-[0.5px] font-medium text-emerald-500">Low</div>
                        </div>
                        <div id="low-count" class="text-6xl font-semibold title-font tracking-tighter mt-3 text-emerald-600 dark:text-emerald-400">{$summary['low']}</div>
                    </div>
                    <div class="text-5xl">ℹ️</div>
                </div>
            </div>
        </div>

        <!-- Findings table -->
        <div class="bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-3xl shadow">
            <div class="px-8 py-6 border-b border-neutral-100 dark:border-neutral-800 flex items-center justify-between">
                <div class="font-semibold text-lg">Findings <span class="font-normal text-neutral-400 text-base">({$summary['total']})</span></div>
                <input id="search" 
                       type="text" 
                       placeholder="Filter by type, message or file..." 
                       onkeyup="applyFilters()"
                       class="bg-neutral-100 dark:bg-neutral-800 border-0 focus:ring-2 focus:ring-yellow-400 rounded-3xl px-6 py-3 w-80 text-sm placeholder:text-neutral-400 outline-none">
            </div>
            
            <div class="overflow-x-auto">
                <table class="w-full min-w-full" id="results-table">
                    <thead>
                        <tr class="border-b border-neutral-100 dark:border-neutral-800 text-xs font-medium text-neutral-400 dark:text-neutral-500">
                            <th class="px-8 py-5 text-left">TYPE</th>
                            <th class="px-8 py-5 text-left">FILE</th>
                            <th class="px-8 py-5 text-left">SEVERITY</th>
                            <th class="px-8 py-5 text-left w-5/12">DESCRIPTION</th>
                            <th class="px-8 py-5 text-left">CONFIDENCE</th>
                            <th class="px-8 py-5 text-left">REMEDIATION</th>
                        </tr>
                    </thead>
                    <tbody id="table-body" class="text-sm divide-y divide-neutral-100 dark:divide-neutral-800">
                        <!-- populated by JavaScript -->
                    </tbody>
                </table>
            </div>
            
            <div class="px-8 py-5 border-t border-neutral-100 dark:border-neutral-800 text-xs text-neutral-400 flex items-center justify-between font-mono">
                <div>Secalyzer v0.1.0 • AST + LLM powered</div>
                <div class="flex items-center gap-x-6">
                    <a href="#" onclick="exportAs('json'); return false" class="hover:text-yellow-400 transition-colors">JSON</a>
                    <a href="#" onclick="exportAs('sarif'); return false" class="hover:text-yellow-400 transition-colors">SARIF</a>
                    <a href="#" onclick="window.print(); return false" class="hover:text-yellow-400 transition-colors">PRINT</a>
                </div>
            </div>
        </div>
    </div>

    <script>
        const vulnerabilities = {$vulnsJson};
        let currentSeverityFilter = null;
        let currentSearchTerm = '';

        function renderTable(data) {
            const tbody = document.getElementById('table-body');
            tbody.innerHTML = '';
            
            if (data.length === 0) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td colspan="6" class="px-8 py-20 text-center">
                        <div class="mx-auto w-16 h-16 flex items-center justify-center bg-neutral-100 dark:bg-neutral-800 rounded-3xl mb-6 text-4xl">🔎</div>
                        <div class="text-neutral-400">No matching vulnerabilities found</div>
                    </td>
                `;
                tbody.appendChild(row);
                return;
            }
            
            data.forEach(vuln => {
                const row = document.createElement('tr');
                row.className = 'group hover:bg-yellow-50 dark:hover:bg-neutral-800 transition-colors';
                row.innerHTML = `
                    <td class="px-8 py-7 font-mono text-xs uppercase tracking-widest text-violet-500">
                        ${vuln.type}
                    </td>
                    <td class="px-8 py-7">
                        <div class="font-medium text-neutral-700 dark:text-neutral-300">${vuln.file.split('/').pop() || vuln.file}</div>
                        <div class="text-xs text-neutral-400 mt-0.5">line ${vuln.line}</div>
                    </td>
                    <td class="px-8 py-7">
                        <span class="inline-block px-5 py-1 text-[10px] font-semibold rounded-3xl severity-${vuln.severity}">
                            ${vuln.severity.toUpperCase()}
                        </span>
                    </td>
                    <td class="px-8 py-7 text-neutral-600 dark:text-neutral-400 leading-snug">
                        ${vuln.message}
                    </td>
                    <td class="px-8 py-7">
                        <div class="flex items-center gap-x-4">
                            <div class="flex-1 h-2 bg-neutral-200 dark:bg-neutral-700 rounded-3xl overflow-hidden">
                                <div class="h-2 bg-emerald-400 rounded-3xl transition-all" style="width: ${Math.round(vuln.confidence * 100)}%"></div>
                            </div>
                            <span class="font-mono text-xs text-emerald-500 tabular-nums">${Math.round(vuln.confidence * 100)}%</span>
                        </div>
                    </td>
                    <td class="px-8 py-7 text-xs text-amber-700 dark:text-amber-300 leading-relaxed max-w-xs">
                        ${vuln.suggested_fix.replace(/\n/g, '<br>')}
                    </td>
                `;
                tbody.append(row);
            });
        }

        function applyFilters() {
            currentSearchTerm = document.getElementById('search').value.toLowerCase().trim();
            
            let filtered = vulnerabilities;
            
            if (currentSeverityFilter) {
                filtered = filtered.filter(v => v.severity === currentSeverityFilter);
            }
            
            if (currentSearchTerm !== '') {
                filtered = filtered.filter(v => 
                    v.message.toLowerCase().includes(currentSearchTerm) ||
                    v.type.toLowerCase().includes(currentSearchTerm) ||
                    (v.file && v.file.toLowerCase().includes(currentSearchTerm))
                );
            }
            
            renderTable(filtered);
        }

        function filterSeverity(severity) {
            currentSeverityFilter = severity;
            applyFilters();
            
            // subtle highlight on active card
            document.querySelectorAll('.card').forEach(card => {
                card.style.borderColor = (severity === null || card.getAttribute('onclick').includes(severity)) 
                    ? '#facc15' : '';
            });
        }

        function toggleTheme() {
            const html = document.documentElement;
            const isDark = !html.classList.contains('dark');
            
            if (isDark) {
                html.classList.add('dark');
                document.getElementById('theme-icon').textContent = '🌙';
                document.getElementById('theme-label').textContent = 'Dark mode';
                localStorage.theme = 'dark';
            } else {
                html.classList.remove('dark');
                document.getElementById('theme-icon').textContent = '☀️';
                document.getElementById('theme-label').textContent = 'Light mode';
                localStorage.theme = 'light';
            }
        }

        function exportAs(format) {
            if (format === 'json') {
                const reportData = {
                    total: {$summary['total']},
                    vulnerabilities: vulnerabilities,
                    generated_at: new Date().toISOString()
                };
                const dataStr = JSON.stringify(reportData, null, 2);
                const blob = new Blob([dataStr], {type: 'application/json'});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'secalyzer-report.json';
                a.click();
                URL.revokeObjectURL(url);
            } else if (format === 'sarif') {
                alert('Run the CLI with --format=sarif to obtain a SARIF report.');
            }
        }

        // Initialize everything
        window.onload = function() {
            // Render initial table
            renderTable(vulnerabilities);
            
            // Timestamp
            const now = new Date();
            document.getElementById('timestamp').textContent = now.toLocaleString('en-US', {
                month: 'short',
                day: 'numeric',
                year: 'numeric',
                hour: 'numeric',
                minute: '2-digit'
            });
            
            // Tailwind runtime config
            tailwind.config = {
                content: [],
                theme: {
                    extend: {}
                }
            };
            
            // Restore theme preference
            if (localStorage.theme === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                document.documentElement.classList.add('dark');
                document.getElementById('theme-icon').textContent = '🌙';
                document.getElementById('theme-label').textContent = 'Dark mode';
            }
            
            // Keyboard shortcut for search
            document.addEventListener('keydown', e => {
                if (e.key === '/' && document.getElementById('search') !== document.activeElement) {
                    e.preventDefault();
                    document.getElementById('search').focus();
                }
            });
        };
    </script>
</body>
</html>
HTML;

        return $html;
    }

    public function toConsole(): string
    {
        $lines = [
            "\033[1;36mSecalyzer Report\033[0m",
            str_repeat('─', 60),
            sprintf(
                "Findings: \033[1m%d total\033[0m • Critical: \033[31m%d\033[0m • High: \033[33m%d\033[0m",
                count($this->vulnerabilities),
                $this->countBySeverity('critical'),
                $this->countBySeverity('high')
            ),
            '',
        ];

        if ($this->vulnerabilities === []) {
            $lines[] = "\033[32m✓ No vulnerabilities found.\033[0m";
            return implode("\n", $lines);
        }

        foreach ($this->vulnerabilities as $vuln) {
            $color = match ($vuln->getSeverity()) {
                'critical' => "\033[31m",
                'high' => "\033[33m",
                'medium' => "\033[35m",
                default => "\033[36m",
            };

            $lines[] = sprintf(
                "%s[%s]\033[0m \033[1m%s:%d\033[0m",
                $color,
                strtoupper($vuln->getType()),
                basename($vuln->getFile()),
                $vuln->getLine()
            );
            $lines[] = '   ' . $vuln->getMessage();
            $lines[] = '   Fix → ' . str_replace("\n", ' ', $vuln->getSuggestedFix());
            $lines[] = '   Confidence: ' . round($vuln->getConfidence() * 100) . '%';
            $lines[] = '';
        }

        return implode("\n", $lines);
    }
}
