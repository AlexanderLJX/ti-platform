/**
 * VS Code Extension for Threat Intelligence Platform
 */

import * as vscode from 'vscode';
import * as path from 'path';
import { SourcesTreeProvider } from './providers/sourcesTreeProvider';
import { JobsTreeProvider } from './providers/jobsTreeProvider';
import { IndicatorsTreeProvider } from './providers/indicatorsTreeProvider';
import { TIPlatformService } from './services/tiPlatformService';
import { IOCDetector } from './services/iocDetector';
import { StatusBarManager } from './services/statusBarManager';

export function activate(context: vscode.ExtensionContext) {
    console.log('Threat Intelligence Platform extension is now active!');

    // Initialize services
    const tiService = new TIPlatformService();
    const iocDetector = new IOCDetector(tiService);
    const statusBar = new StatusBarManager();

    // Initialize tree data providers
    const sourcesProvider = new SourcesTreeProvider(tiService);
    const jobsProvider = new JobsTreeProvider(tiService);
    const indicatorsProvider = new IndicatorsTreeProvider(tiService);

    // Register tree views
    vscode.window.createTreeView('ti-platform.sources', {
        treeDataProvider: sourcesProvider,
        showCollapseAll: true
    });

    vscode.window.createTreeView('ti-platform.jobs', {
        treeDataProvider: jobsProvider,
        showCollapseAll: true
    });

    vscode.window.createTreeView('ti-platform.indicators', {
        treeDataProvider: indicatorsProvider,
        showCollapseAll: true
    });

    // Register commands
    const commands = [
        vscode.commands.registerCommand('ti-platform.scrape', () => {
            showScrapeDialog(tiService);
        }),

        vscode.commands.registerCommand('ti-platform.enrich', () => {
            showEnrichDialog(tiService);
        }),

        vscode.commands.registerCommand('ti-platform.export', () => {
            showExportDialog(tiService);
        }),

        vscode.commands.registerCommand('ti-platform.analyze', () => {
            showAnalyzeDialog(tiService);
        }),

        vscode.commands.registerCommand('ti-platform.validate', () => {
            validateCurrentFile(tiService);
        }),

        vscode.commands.registerCommand('ti-platform.plugins', () => {
            showPluginManager(tiService);
        }),

        // Context menu commands
        vscode.commands.registerCommand('ti-platform.enrichSelection', () => {
            enrichSelectedText(tiService);
        }),

        vscode.commands.registerCommand('ti-platform.lookupIOC', (ioc: string) => {
            lookupIOC(tiService, ioc);
        }),

        // Tree view commands
        vscode.commands.registerCommand('ti-platform.refreshSources', () => {
            sourcesProvider.refresh();
        }),

        vscode.commands.registerCommand('ti-platform.refreshJobs', () => {
            jobsProvider.refresh();
        }),

        vscode.commands.registerCommand('ti-platform.refreshIndicators', () => {
            indicatorsProvider.refresh();
        })
    ];

    // Register hover provider for IOC enrichment
    const hoverProvider = vscode.languages.registerHoverProvider(
        { scheme: 'file' },
        {
            provideHover(document, position, token) {
                return iocDetector.provideHover(document, position, token);
            }
        }
    );

    // Register document symbol provider for IOCs
    const documentSymbolProvider = vscode.languages.registerDocumentSymbolProvider(
        { scheme: 'file' },
        {
            provideDocumentSymbols(document, token) {
                return iocDetector.provideDocumentSymbols(document, token);
            }
        }
    );

    // Register text document change listener for real-time IOC detection
    const documentChangeListener = vscode.workspace.onDidChangeTextDocument((event) => {
        if (vscode.workspace.getConfiguration('ti-platform').get('highlightIOCs')) {
            iocDetector.updateDecorations(event.document);
        }
    });

    // Register active editor change listener
    const activeEditorChangeListener = vscode.window.onDidChangeActiveTextEditor((editor) => {
        if (editor && vscode.workspace.getConfiguration('ti-platform').get('highlightIOCs')) {
            iocDetector.updateDecorations(editor.document);
        }
    });

    // Set context for views
    vscode.commands.executeCommand('setContext', 'ti-platform.active', true);

    // Initialize status bar
    statusBar.initialize();

    // Add to subscriptions for cleanup
    context.subscriptions.push(
        ...commands,
        hoverProvider,
        documentSymbolProvider,
        documentChangeListener,
        activeEditorChangeListener,
        statusBar
    );

    // Show welcome message on first activation
    if (!context.globalState.get('ti-platform.welcomed')) {
        showWelcomeMessage();
        context.globalState.update('ti-platform.welcomed', true);
    }
}

export function deactivate() {
    console.log('Threat Intelligence Platform extension is now deactivated');
}

async function showScrapeDialog(tiService: TIPlatformService) {
    const sources = await tiService.getAvailableSources();
    
    const selectedSource = await vscode.window.showQuickPick(
        ['all', ...sources],
        {
            placeHolder: 'Select source to scrape',
            canPickMany: false
        }
    );

    if (selectedSource) {
        const dryRun = await vscode.window.showQuickPick(
            ['No', 'Yes'],
            {
                placeHolder: 'Dry run (preview only)?',
                canPickMany: false
            }
        );

        const isDryRun = dryRun === 'Yes';

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `Scraping threat intelligence from ${selectedSource}`,
            cancellable: true
        }, async (progress, token) => {
            try {
                const result = await tiService.scrape(selectedSource, isDryRun);
                vscode.window.showInformationMessage(
                    `Scraping completed! Found ${result.totalIndicators} indicators`
                );
            } catch (error) {
                vscode.window.showErrorMessage(`Scraping failed: ${error}`);
            }
        });
    }
}

async function showEnrichDialog(tiService: TIPlatformService) {
    const fileUri = await vscode.window.showOpenDialog({
        canSelectMany: false,
        openLabel: 'Select IOC file',
        filters: {
            'IOC Files': ['csv', 'json', 'txt']
        }
    });

    if (fileUri && fileUri[0]) {
        const filePath = fileUri[0].fsPath;
        
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Enriching IOCs',
            cancellable: true
        }, async (progress, token) => {
            try {
                const result = await tiService.enrichFile(filePath);
                vscode.window.showInformationMessage(
                    `Enrichment completed! Processed ${result.processedCount} IOCs`
                );
            } catch (error) {
                vscode.window.showErrorMessage(`Enrichment failed: ${error}`);
            }
        });
    }
}

async function showExportDialog(tiService: TIPlatformService) {
    const format = await vscode.window.showQuickPick(
        ['csv', 'json', 'stix', 'misp', 'openioc'],
        {
            placeHolder: 'Select export format',
            canPickMany: false
        }
    );

    if (format) {
        const inputUri = await vscode.window.showOpenDialog({
            canSelectMany: false,
            openLabel: 'Select input file',
            filters: {
                'Data Files': ['csv', 'json']
            }
        });

        if (inputUri && inputUri[0]) {
            const saveUri = await vscode.window.showSaveDialog({
                saveLabel: 'Export to',
                filters: {
                    [format.toUpperCase()]: [format]
                }
            });

            if (saveUri) {
                try {
                    await tiService.exportData(format, inputUri[0].fsPath, saveUri.fsPath);
                    vscode.window.showInformationMessage(`Data exported to ${format.toUpperCase()} format`);
                } catch (error) {
                    vscode.window.showErrorMessage(`Export failed: ${error}`);
                }
            }
        }
    }
}

async function showAnalyzeDialog(tiService: TIPlatformService) {
    const timeframe = await vscode.window.showQuickPick(
        ['7d', '30d', '90d', '1y'],
        {
            placeHolder: 'Select analysis timeframe',
            canPickMany: false
        }
    );

    if (timeframe) {
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Analyzing threat intelligence',
            cancellable: false
        }, async (progress, token) => {
            try {
                const analysis = await tiService.analyzeThreats(timeframe);
                
                // Show analysis results in a new document
                const doc = await vscode.workspace.openTextDocument({
                    content: formatAnalysisResults(analysis),
                    language: 'markdown'
                });
                
                await vscode.window.showTextDocument(doc);
            } catch (error) {
                vscode.window.showErrorMessage(`Analysis failed: ${error}`);
            }
        });
    }
}

async function validateCurrentFile(tiService: TIPlatformService) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No file is currently open');
        return;
    }

    const document = editor.document;
    const text = document.getText();

    try {
        const validation = await tiService.validateIOCs(text);
        
        const diagnostics: vscode.Diagnostic[] = validation.invalid.map(invalid => {
            const range = new vscode.Range(
                document.positionAt(invalid.position),
                document.positionAt(invalid.position + invalid.value.length)
            );
            
            return new vscode.Diagnostic(
                range,
                `Invalid ${invalid.type}: ${invalid.reason}`,
                vscode.DiagnosticSeverity.Error
            );
        });

        const diagnosticCollection = vscode.languages.createDiagnosticCollection('ti-platform');
        diagnosticCollection.set(document.uri, diagnostics);
        
        vscode.window.showInformationMessage(
            `Validation complete: ${validation.valid.length} valid, ${validation.invalid.length} invalid IOCs`
        );
    } catch (error) {
        vscode.window.showErrorMessage(`Validation failed: ${error}`);
    }
}

async function showPluginManager(tiService: TIPlatformService) {
    const action = await vscode.window.showQuickPick(
        ['List Plugins', 'Plugin Status', 'Install Plugin'],
        {
            placeHolder: 'Select plugin action',
            canPickMany: false
        }
    );

    if (action === 'List Plugins') {
        const plugins = await tiService.listPlugins();
        const pluginList = plugins.map(p => `${p.type}: ${p.name} (${p.status})`).join('\\n');
        
        vscode.window.showInformationMessage(pluginList);
    } else if (action === 'Plugin Status') {
        const status = await tiService.getPluginStatus();
        
        const doc = await vscode.workspace.openTextDocument({
            content: formatPluginStatus(status),
            language: 'markdown'
        });
        
        await vscode.window.showTextDocument(doc);
    } else if (action === 'Install Plugin') {
        const fileUri = await vscode.window.showOpenDialog({
            canSelectMany: false,
            openLabel: 'Select plugin file',
            filters: {
                'Python Files': ['py']
            }
        });

        if (fileUri && fileUri[0]) {
            try {
                await tiService.installPlugin(fileUri[0].fsPath);
                vscode.window.showInformationMessage('Plugin installed successfully');
            } catch (error) {
                vscode.window.showErrorMessage(`Plugin installation failed: ${error}`);
            }
        }
    }
}

async function enrichSelectedText(tiService: TIPlatformService) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const selection = editor.selection;
    const selectedText = editor.document.getText(selection);

    if (selectedText) {
        try {
            const enrichment = await tiService.enrichIOC(selectedText);
            
            // Show enrichment in hover-like popup
            const markdown = formatEnrichmentInfo(enrichment);
            vscode.window.showInformationMessage(markdown);
        } catch (error) {
            vscode.window.showErrorMessage(`Enrichment failed: ${error}`);
        }
    }
}

async function lookupIOC(tiService: TIPlatformService, ioc: string) {
    try {
        const info = await tiService.lookupIOC(ioc);
        
        // Show detailed IOC information
        const doc = await vscode.workspace.openTextDocument({
            content: formatIOCInfo(info),
            language: 'markdown'
        });
        
        await vscode.window.showTextDocument(doc);
    } catch (error) {
        vscode.window.showErrorMessage(`IOC lookup failed: ${error}`);
    }
}

function showWelcomeMessage() {
    vscode.window.showInformationMessage(
        'Welcome to Threat Intelligence Platform! Ready to collect and analyze threat intelligence.',
        'Get Started',
        'View Documentation'
    ).then(selection => {
        if (selection === 'Get Started') {
            vscode.commands.executeCommand('ti-platform.scrape');
        } else if (selection === 'View Documentation') {
            vscode.env.openExternal(vscode.Uri.parse('https://github.com/your-repo/ti-platform'));
        }
    });
}

function formatAnalysisResults(analysis: any): string {
    return `# Threat Intelligence Analysis

## Summary
- **Time Period**: ${analysis.timeframe}
- **Total Indicators**: ${analysis.totalIndicators}
- **Active Threat Actors**: ${analysis.activeThreatActors}

## Top Threat Actors
${analysis.topActors.map((actor: any, i: number) => `${i + 1}. ${actor.name} (${actor.indicators} indicators)`).join('\\n')}

## IOC Distribution
- **IPs**: ${analysis.distribution.ips}
- **Domains**: ${analysis.distribution.domains}  
- **Hashes**: ${analysis.distribution.hashes}
- **URLs**: ${analysis.distribution.urls}

## Geographic Distribution
${analysis.geographic.map((geo: any) => `- ${geo.country}: ${geo.count} indicators`).join('\\n')}
`;
}

function formatPluginStatus(status: any): string {
    return `# Plugin Status Report

${status.map((plugin: any) => `
## ${plugin.name} (${plugin.type})
- **Status**: ${plugin.status}
- **Version**: ${plugin.version}
- **Health**: ${plugin.health}
`).join('\\n')}
`;
}

function formatEnrichmentInfo(enrichment: any): string {
    let info = `IOC: ${enrichment.value}\\n`;
    
    if (enrichment.geolocation) {
        info += `Location: ${enrichment.geolocation.city}, ${enrichment.geolocation.country}\\n`;
    }
    
    if (enrichment.reputation) {
        info += `Reputation: ${enrichment.reputation.score}/100\\n`;
    }
    
    return info;
}

function formatIOCInfo(info: any): string {
    return `# IOC Information: ${info.value}

## Basic Info
- **Type**: ${info.type}
- **Confidence**: ${info.confidence}
- **Source**: ${info.source}
- **Threat Actor**: ${info.threatActor}

## Enrichment Data
${info.enrichment ? formatEnrichmentData(info.enrichment) : 'No enrichment data available'}
`;
}

function formatEnrichmentData(enrichment: any): string {
    let data = '';
    
    if (enrichment.geolocation) {
        data += `### Geographic Information
- **Country**: ${enrichment.geolocation.country}
- **City**: ${enrichment.geolocation.city}
- **Coordinates**: ${enrichment.geolocation.latitude}, ${enrichment.geolocation.longitude}

`;
    }
    
    if (enrichment.reputation) {
        data += `### Reputation
- **Score**: ${enrichment.reputation.score}/100
- **Malicious Sources**: ${enrichment.reputation.maliciousCount}
- **Total Sources**: ${enrichment.reputation.totalSources}

`;
    }
    
    return data;
}