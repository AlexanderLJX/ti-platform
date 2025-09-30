/**
 * Service for communicating with the Threat Intelligence Platform CLI
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as vscode from 'vscode';

const execAsync = promisify(exec);

export class TIPlatformService {
    private readonly cliPath: string;

    constructor() {
        // Get CLI path from configuration or use default
        const config = vscode.workspace.getConfiguration('ti-platform');
        this.cliPath = config.get('cliPath') || 'ti-platform';
    }

    async getAvailableSources(): Promise<string[]> {
        try {
            const { stdout } = await execAsync(`${this.cliPath} plugins list`);
            // Parse output to extract scraper sources
            const sources: string[] = [];
            const lines = stdout.split('\n');
            
            for (const line of lines) {
                if (line.includes('Scraper') && line.includes('Available')) {
                    const match = line.match(/Scraper\\s+(\\w+)\\s+Available/);
                    if (match) {
                        sources.push(match[1]);
                    }
                }
            }
            
            return sources;
        } catch (error) {
            console.error('Failed to get available sources:', error);
            return ['mandiant', 'crowdstrike']; // fallback
        }
    }

    async scrape(source: string, dryRun: boolean = false): Promise<{ totalIndicators: number }> {
        try {
            const dryRunFlag = dryRun ? '--dry-run' : '';
            const { stdout } = await execAsync(`${this.cliPath} scrape --source ${source} ${dryRunFlag}`);
            
            // Parse output for results
            const indicatorMatch = stdout.match(/Total indicators: (\\d+)/);
            const totalIndicators = indicatorMatch ? parseInt(indicatorMatch[1]) : 0;
            
            return { totalIndicators };
        } catch (error) {
            throw new Error(`Scraping failed: ${error}`);
        }
    }

    async enrichFile(filePath: string): Promise<{ processedCount: number }> {
        try {
            const { stdout } = await execAsync(`${this.cliPath} process-iocs --file "${filePath}" --enrich`);
            
            // Parse output for results
            const processedMatch = stdout.match(/Successfully processed (\\d+) IOCs/);
            const processedCount = processedMatch ? parseInt(processedMatch[1]) : 0;
            
            return { processedCount };
        } catch (error) {
            throw new Error(`Enrichment failed: ${error}`);
        }
    }

    async exportData(format: string, inputPath: string, outputPath: string): Promise<void> {
        try {
            await execAsync(`${this.cliPath} export --format ${format} --input "${inputPath}" --output "${outputPath}"`);
        } catch (error) {
            throw new Error(`Export failed: ${error}`);
        }
    }

    async analyzeThreats(timeframe: string): Promise<any> {
        try {
            const { stdout } = await execAsync(`${this.cliPath} analyze-threats --timeframe ${timeframe}`);
            
            // For now, return mock data since analyze-threats command is placeholder
            return {
                timeframe,
                totalIndicators: 1500,
                activeThreatActors: 25,
                topActors: [
                    { name: 'APT28', indicators: 245 },
                    { name: 'Lazarus', indicators: 198 },
                    { name: 'FIN7', indicators: 156 }
                ],
                distribution: {
                    ips: 450,
                    domains: 623,
                    hashes: 312,
                    urls: 115
                },
                geographic: [
                    { country: 'Russia', count: 234 },
                    { country: 'China', count: 189 },
                    { country: 'North Korea', count: 156 }
                ]
            };
        } catch (error) {
            throw new Error(`Analysis failed: ${error}`);
        }
    }

    async validateIOCs(text: string): Promise<{ valid: any[], invalid: any[] }> {
        // Simple IOC validation - in practice this would call the CLI
        const lines = text.split('\\n');
        const valid: any[] = [];
        const invalid: any[] = [];
        
        let position = 0;
        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed) {
                if (this.isValidIOC(trimmed)) {
                    valid.push({
                        value: trimmed,
                        type: this.detectIOCType(trimmed),
                        position
                    });
                } else {
                    invalid.push({
                        value: trimmed,
                        type: 'unknown',
                        reason: 'Invalid format',
                        position
                    });
                }
            }
            position += line.length + 1; // +1 for newline
        }
        
        return { valid, invalid };
    }

    async listPlugins(): Promise<any[]> {
        try {
            const { stdout } = await execAsync(`${this.cliPath} plugins list`);
            
            // Parse plugin list output
            const plugins: any[] = [];
            const lines = stdout.split('\\n');
            
            for (const line of lines) {
                const match = line.match(/(\\w+)\\s+(\\w+)\\s+(\\w+)/);
                if (match) {
                    plugins.push({
                        type: match[1],
                        name: match[2],
                        status: match[3]
                    });
                }
            }
            
            return plugins;
        } catch (error) {
            console.error('Failed to list plugins:', error);
            return [];
        }
    }

    async getPluginStatus(): Promise<any[]> {
        try {
            const { stdout } = await execAsync(`${this.cliPath} plugin-status`);
            
            // Mock plugin status for now
            return [
                {
                    name: 'Mandiant Scraper',
                    type: 'scraper',
                    status: 'active',
                    version: '1.0.0',
                    health: 'healthy'
                },
                {
                    name: 'CrowdStrike Scraper', 
                    type: 'scraper',
                    status: 'active',
                    version: '1.0.0',
                    health: 'healthy'
                },
                {
                    name: 'STIX Exporter',
                    type: 'exporter', 
                    status: 'active',
                    version: '1.0.0',
                    health: 'healthy'
                }
            ];
        } catch (error) {
            console.error('Failed to get plugin status:', error);
            return [];
        }
    }

    async installPlugin(pluginPath: string): Promise<void> {
        try {
            await execAsync(`${this.cliPath} plugins install --plugin-file "${pluginPath}"`);
        } catch (error) {
            throw new Error(`Plugin installation failed: ${error}`);
        }
    }

    async enrichIOC(ioc: string): Promise<any> {
        // Mock enrichment data for now
        return {
            value: ioc,
            type: this.detectIOCType(ioc),
            geolocation: ioc.match(/^\\d+\\.\\d+\\.\\d+\\.\\d+$/) ? {
                country: 'United States',
                city: 'New York',
                latitude: 40.7128,
                longitude: -74.0060
            } : null,
            reputation: {
                score: Math.floor(Math.random() * 100),
                maliciousCount: Math.floor(Math.random() * 10),
                totalSources: Math.floor(Math.random() * 50) + 10
            }
        };
    }

    async lookupIOC(ioc: string): Promise<any> {
        // Mock IOC lookup data
        return {
            value: ioc,
            type: this.detectIOCType(ioc),
            confidence: 'high',
            source: 'mandiant',
            threatActor: 'APT28',
            enrichment: await this.enrichIOC(ioc)
        };
    }

    private isValidIOC(value: string): boolean {
        // Basic IOC validation patterns
        const patterns = {
            ip: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
            domain: /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}$/,
            url: /^https?:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&//=]*)$/,
            email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/,
            md5: /^[a-fA-F0-9]{32}$/,
            sha1: /^[a-fA-F0-9]{40}$/,
            sha256: /^[a-fA-F0-9]{64}$/
        };

        return Object.values(patterns).some(pattern => pattern.test(value));
    }

    private detectIOCType(value: string): string {
        if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(value)) {
            return 'ip';
        } else if (/^https?:\\/\\//.test(value)) {
            return 'url';
        } else if (/@/.test(value)) {
            return 'email';
        } else if (/^[a-fA-F0-9]{32}$/.test(value)) {
            return 'md5';
        } else if (/^[a-fA-F0-9]{40}$/.test(value)) {
            return 'sha1';
        } else if (/^[a-fA-F0-9]{64}$/.test(value)) {
            return 'sha256';
        } else if (/\\./.test(value)) {
            return 'domain';
        }
        return 'unknown';
    }
}