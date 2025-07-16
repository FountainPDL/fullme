// Background service worker for Fountain Scan
// This handles real-time scanning, notifications, and background tasks

class FountainScanBackground {
  constructor() {
    this.knownScamDomains = new Set();
    this.scanCache = new Map();
    this.settings = {
      alertsEnabled: true,
      blockingEnabled: false,
      realTimeScanning: true,
      autoUpdate: true
    };
    
    this.init();
  }

  init() {
    console.log('Fountain Scan Background Service Worker Started');
    
    // Load settings and data
    this.loadSettings();
    this.loadScamDatabase();
    
    // Set up event listeners
    this.setupEventListeners();
    
    // Start periodic tasks
    this.startPeriodicTasks();
  }

  setupEventListeners() {
    // Tab navigation listener
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete' && tab.url) {
        this.handleTabUpdate(tabId, tab);
      }
    });

    // Tab activation listener
    chrome.tabs.onActivated.addListener((activeInfo) => {
      chrome.tabs.get(activeInfo.tabId, (tab) => {
        if (tab.url) {
          this.handleTabActivation(tab);
        }
      });
    });

    // Installation/startup listener
    chrome.runtime.onInstalled.addListener((details) => {
      this.handleInstallation(details);
    });

    // Message listener for communication with popup/content scripts
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      this.handleMessage(request, sender, sendResponse);
      return true; // Keep message channel open for async responses
    });

    // Alarm listener for periodic tasks
    chrome.alarms.onAlarm.addListener((alarm) => {
      this.handleAlarm(alarm);
    });

    // Context menu listener
    chrome.contextMenus.onClicked.addListener((info, tab) => {
      this.handleContextMenu(info, tab);
    });
  }

  async handleTabUpdate(tabId, tab) {
    if (!this.settings.realTimeScanning) return;
    
    try {
      const url = tab.url;
      if (!this.shouldScanUrl(url)) return;

      // Perform background scan
      const scanResult = await this.performBackgroundScan(url);
      
      // Store scan result
      this.scanCache.set(url, {
        result: scanResult,
        timestamp: Date.now()
      });

      // Handle high-risk sites
      if (scanResult.riskLevel === 'high') {
        await this.handleHighRiskSite(tabId, tab, scanResult);
      }

      // Update badge
      this.updateBadge(tabId, scanResult);

    } catch (error) {
      console.error('Error in handleTabUpdate:', error);
    }
  }

  async handleTabActivation(tab) {
    if (!tab.url || !this.shouldScanUrl(tab.url)) return;

    // Check if we have cached scan results
    const cached = this.scanCache.get(tab.url);
    if (cached && (Date.now() - cached.timestamp) < 300000) { // 5 minutes
      this.updateBadge(tab.id, cached.result);
      return;
    }

    // Perform fresh scan
    const scanResult = await this.performBackgroundScan(tab.url);
    this.scanCache.set(tab.url, {
      result: scanResult,
      timestamp: Date.now()
    });
    
    this.updateBadge(tab.id, scanResult);
  }

  handleInstallation(details) {
    if (details.reason === 'install') {
      // First-time installation
      this.setupDefaultSettings();
      this.createContextMenus();
      this.showWelcomeNotification();
    } else if (details.reason === 'update') {
      // Extension updated
      this.migrateSettings();
      this.updateScamDatabase();
    }
  }

  async handleMessage(request, sender, sendResponse) {
    try {
      switch (request.action) {
        case 'scanUrl':
          const scanResult = await this.performBackgroundScan(request.url);
          sendResponse({ success: true, result: scanResult });
          break;

        case 'reportSite':
          await this.handleSiteReport(request.data);
          sendResponse({ success: true });
          break;

        case 'updateSettings':
          await this.updateSettings(request.settings);
          sendResponse({ success: true });
          break;

        case 'getScamDatabase':
          const database = await this.getScamDatabase();
          sendResponse({ success: true, database });
          break;

        case 'addToWhitelist':
          await this.addToWhitelist(request.domain);
          sendResponse({ success: true });
          break;

        case 'addToBlacklist':
          await this.addToBlacklist(request.domain);
          sendResponse({ success: true });
          break;

        default:
          sendResponse({ success: false, error: 'Unknown action' });
      }
    } catch (error) {
      console.error('Error handling message:', error);
      sendResponse({ success: false, error: error.message });
    }
  }

  handleAlarm(alarm) {
    switch (alarm.name) {
      case 'updateScamDatabase':
        this.updateScamDatabase();
        break;
      case 'cleanupCache':
        this.cleanupCache();
        break;
      case 'generateReport':
        this.generateSecurityReport();
        break;
    }
  }

  handleContextMenu(info, tab) {
    switch (info.menuItemId) {
      case 'scanThisPage':
        this.scanPageFromContextMenu(tab);
        break;
      case 'reportAsScam':
        this.reportPageAsScam(tab);
        break;
      case 'addToWhitelist':
        this.addPageToWhitelist(tab);
        break;
    }
  }

  shouldScanUrl(url) {
    if (!url) return false;
    
    // Skip internal browser pages
    if (url.startsWith('chrome://') || 
        url.startsWith('chrome-extension://') ||
        url.startsWith('about:') ||
        url.startsWith('moz-extension://')) {
      return false;
    }

    return true;
  }

  async performBackgroundScan(url) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();
      
      let riskScore = 0;
      const issues = [];
      const warnings = [];

      // Check against known scam domains
      if (this.knownScamDomains.has(domain)) {
        riskScore += 10;
        issues.push('Known scam domain');
      }

      // Check blacklist
      const blacklist = await this.getBlacklist();
      if (blacklist.some(d => domain.includes(d.toLowerCase()))) {
        riskScore += 10;
        issues.push('Blacklisted domain');
      }

      // Check whitelist (overrides other checks)
      const whitelist = await this.getWhitelist();
      if (whitelist.some(d => domain.includes(d.toLowerCase()))) {
        return {
          riskLevel: 'safe',
          riskScore: 0,
          status: 'Whitelisted',
          issues: [],
          warnings: []
        };
      }

      // Security checks
      if (urlObj.protocol !== 'https:') {
        riskScore += 3;
        issues.push('No HTTPS encryption');
      }

      // Nigerian-specific scholarship scam patterns
      const nigerianScamPatterns = [
        /nigeria.*scholarship.*free/i,
        /guaranteed.*scholarship.*nigeria/i,
        /instant.*admission.*nigeria/i,
        /free.*university.*admission/i,
        /no.*exam.*required.*scholarship/i,
        /apply.*now.*scholarship.*nigeria/i,
        /100%.*scholarship.*guarantee/i
      ];

      nigerianScamPatterns.forEach(pattern => {
        if (pattern.test(url) || pattern.test(domain)) {
          riskScore += 4;
          issues.push('Nigerian scholarship scam pattern detected');
        }
      });

      // Suspicious keywords
      const suspiciousKeywords = [
        'free-money', 'instant-cash', 'guaranteed-loan',
        'work-from-home', 'get-rich-quick', 'easy-money',
        'no-experience-required', 'make-money-fast',
        'scholarship-guaranteed', 'admission-assured'
      ];

      const urlLower = url.toLowerCase();
      suspiciousKeywords.forEach(keyword => {
        if (urlLower.includes(keyword)) {
          riskScore += 2;
          warnings.push(`Suspicious keyword: ${keyword}`);
        }
      });

      // Check for suspicious TLDs
      const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top'];
      suspiciousTlds.forEach(tld => {
        if (domain.endsWith(tld)) {
          riskScore += 3;
          warnings.push(`Suspicious domain extension: ${tld}`);
        }
      });

      // Check for URL shorteners
      const shorteners = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
        'tiny.cc', 'ow.ly', 'buff.ly'
      ];
      shorteners.forEach(shortener => {
        if (domain.includes(shortener)) {
          riskScore += 2;
          warnings.push('URL shortener detected');
        }
      });

      // Check domain age and reputation (simulated)
      if (await this.isNewDomain(domain)) {
        riskScore += 2;
        warnings.push('Recently registered domain');
      }

      // Check for phishing patterns
      const phishingPatterns = [
        /login.*verify.*account/i,
        /suspended.*account.*verify/i,
        /urgent.*action.*required/i,
        /click.*here.*immediately/i
      ];

      phishingPatterns.forEach(pattern => {
        if (pattern.test(url)) {
          riskScore += 3;
          issues.push('Phishing pattern detected');
        }
      });

      // Determine risk level
      let riskLevel = 'safe';
      let status = 'Safe';

      if (riskScore >= 8) {
        riskLevel = 'high';
        status = 'High Risk - Potential Scam';
      } else if (riskScore >= 5) {
        riskLevel = 'medium';
        status = 'Medium Risk - Suspicious';
      } else if (riskScore >= 2) {
        riskLevel = 'low';
        status = 'Low Risk - Minor Concerns';
      }

      return {
        riskLevel,
        riskScore,
        status,
        issues,
        warnings,
        scanTime: new Date().toISOString()
      };

    } catch (error) {
      console.error('Background scan error:', error);
      return {
        riskLevel: 'unknown',
        riskScore: 0,
        status: 'Scan Error',
        issues: ['Unable to scan URL'],
        warnings: [],
        scanTime: new Date().toISOString()
      };
    }
  }

  async handleHighRiskSite(tabId, tab, scanResult) {
    if (!this.settings.alertsEnabled) return;

    // Create notification
    const notificationOptions = {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Fountain Scan Security Alert',
      message: `High-risk website detected: ${scanResult.status}\nIssues: ${scanResult.issues.join(', ')}`
    };

    chrome.notifications.create(`alert-${tabId}`, notificationOptions);

    // If blocking is enabled, redirect to warning page
    if (this.settings.blockingEnabled) {
      const warningUrl = chrome.runtime.getURL('warning.html') + 
                        `?url=${encodeURIComponent(tab.url)}&issues=${encodeURIComponent(scanResult.issues.join(', '))}`;
      
      chrome.tabs.update(tabId, { url: warningUrl });
    }
  }

  updateBadge(tabId, scanResult) {
    let badgeText = '';
    let badgeColor = '#4CAF50'; // Green for safe

    switch (scanResult.riskLevel) {
      case 'high':
        badgeText = '!';
        badgeColor = '#F44336'; // Red
        break;
      case 'medium':
        badgeText = '?';
        badgeColor = '#FF9800'; // Orange
        break;
      case 'low':
        badgeText = '~';
        badgeColor = '#FFC107'; // Yellow
        break;
    }

    chrome.action.setBadgeText({ text: badgeText, tabId });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.local.get(['settings']);
      if (result.settings) {
        this.settings = { ...this.settings, ...result.settings };
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  }

  async updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
    await chrome.storage.local.set({ settings: this.settings });
  }

  async loadScamDatabase() {
    try {
      // Load known scam domains (in production, this would come from a remote API)
      const knownScams = [
        'fakescholarship.ng',
        'free-scholarship-nigeria.com',
        'guaranteed-admission.ng',
        'instant-scholarship.com',
        'easy-university-admission.ng',
        'scholarship-scam.com',
        'fake-education.ng'
      ];

      knownScams.forEach(domain => {
        this.knownScamDomains.add(domain);
      });

      console.log(`Loaded ${this.knownScamDomains.size} known scam domains`);
    } catch (error) {
      console.error('Error loading scam database:', error);
    }
  }

  async updateScamDatabase() {
    // In production, this would fetch from a remote API
    console.log('Updating scam database...');
    // Simulated update
    await new Promise(resolve => setTimeout(resolve, 1000));
    console.log('Scam database updated');
  }

  async getWhitelist() {
    try {
      const result = await chrome.storage.local.get(['whitelist']);
      return result.whitelist || [];
    } catch (error) {
      console.error('Error getting whitelist:', error);
      return [];
    }
  }

  async getBlacklist() {
    try {
      const result = await chrome.storage.local.get(['blacklist']);
      return result.blacklist || [];
    } catch (error) {
      console.error('Error getting blacklist:', error);
      return [];
    }
  }

  async addToWhitelist(domain) {
    try {
      const whitelist = await this.getWhitelist();
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        await chrome.storage.local.set({ whitelist });
      }
    } catch (error) {
      console.error('Error adding to whitelist:', error);
    }
  }

  async addToBlacklist(domain) {
    try {
      const blacklist = await this.getBlacklist();
      if (!blacklist.includes(domain)) {
        blacklist.push(domain);
        await chrome.storage.local.set({ blacklist });
        this.knownScamDomains.add(domain);
      }
    } catch (error) {
      console.error('Error adding to blacklist:', error);
    }
  }

  async isNewDomain(domain) {
    // Simulated domain age check
    // In production, this would query a domain age API
    return Math.random() < 0.1; // 10% chance of being "new"
  }

  setupDefaultSettings() {
    chrome.storage.local.set({
      settings: this.settings,
      whitelist: [],
      blacklist: [],
      installDate: new Date().toISOString()
    });
  }

  createContextMenus() {
    chrome.contextMenus.create({
      id: 'scanThisPage',
      title: 'Scan this page with Fountain Scan',
      contexts: ['page']
    });

    chrome.contextMenus.create({
      id: 'reportAsScam',
      title: 'Report as suspicious',
      contexts: ['page']
    });

    chrome.contextMenus.create({
      id: 'addToWhitelist',
      title: 'Add to trusted sites',
      contexts: ['page']
    });
  }

  startPeriodicTasks() {
    // Update scam database every 24 hours
    chrome.alarms.create('updateScamDatabase', {
      delayInMinutes: 60, // First update in 1 hour
      periodInMinutes: 1440 // Then every 24 hours
    });

    // Clean up cache every 6 hours
    chrome.alarms.create('cleanupCache', {
      delayInMinutes: 30, // First cleanup in 30 minutes
      periodInMinutes: 360 // Then every 6 hours
    });

    // Generate security report weekly
    chrome.alarms.create('generateReport', {
      delayInMinutes: 10080, // First report in 1 week
      periodInMinutes: 10080 // Then every week
    });
  }

  showWelcomeNotification() {
    chrome.notifications.create('welcome', {
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Welcome to Fountain Scan!',
      message: 'Your protection against scholarship scams and fraudulent websites is now active.'
    });
  }

  migrateSettings() {
    // Handle settings migration for updates
    console.log('Migrating settings for update...');
  }

  cleanupCache() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    for (const [url, data] of this.scanCache.entries()) {
      if (now - data.timestamp > maxAge) {
        this.scanCache.delete(url);
      }
    }

    console.log(`Cache cleaned up. ${this.scanCache.size} entries remaining.`);
  }

  async handleSiteReport(reportData) {
    // In production, this would send to a backend service
    console.log('Site report received:', reportData);
    
    // Store locally for now
    const reports = await this.getStoredReports();
    reports.push({
      ...reportData,
      timestamp: new Date().toISOString(),
      id: crypto.randomUUID()
    });
    
    await chrome.storage.local.set({ reports });
  }

  async getStoredReports() {
    try {
      const result = await chrome.storage.local.get(['reports']);
      return result.reports || [];
    } catch (error) {
      console.error('Error getting reports:', error);
      return [];
    }
  }

  async generateSecurityReport() {
    const reports = await this.getStoredReports();
    const scanCount = this.scanCache.size;
    
    console.log(`Weekly Security Report:
      - Sites scanned: ${scanCount}
      - Reports submitted: ${reports.length}
      - Cache size: ${this.scanCache.size}
      - Known scam domains: ${this.knownScamDomains.size}`);
  }

  async scanPageFromContextMenu(tab) {
    const scanResult = await this.performBackgroundScan(tab.url);
    
    chrome.notifications.create(`scan-${tab.id}`, {
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Fountain Scan Results',
      message: `${tab.url}\nStatus: ${scanResult.status}\nRisk Level: ${scanResult.riskLevel}`
    });
  }

  async reportPageAsScam(tab) {
    await this.handleSiteReport({
      url: tab.url,
      reason: 'Reported via context menu',
      source: 'context_menu'
    });

    chrome.notifications.create(`report-${tab.id}`, {
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Report Submitted',
      message: 'Thank you for reporting this suspicious site!'
    });
  }

  async addPageToWhitelist(tab) {
    const domain = new URL(tab.url).hostname;
    await this.addToWhitelist(domain);

    chrome.notifications.create(`whitelist-${tab.id}`, {
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Added to Trusted Sites',
      message: `${domain} has been added to your trusted sites list.`
    });
  }
}

// Initialize the background service
const fountainScanBG = new FountainScanBackground();