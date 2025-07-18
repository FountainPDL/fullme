// Extension state management
const FountainScan = {
  currentUrl: '',
  settings: {
    theme: 'light',
    alertsEnabled: true,
    blockingEnabled: false,
    systemLang: 'en-NG',
    alertLang: 'en'
  },
  whitelist: [],
  blacklist: [],
  
  // Initialize extension
  init() {
    this.loadSettings();
    this.loadLists();
    this.setupEventListeners();
    this.switchTab('home');
    this.scanCurrentSite();
  },

  // Load settings from storage
  loadSettings() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['settings'], (result) => {
          if (result.settings) {
            this.settings = { ...this.settings, ...result.settings };
            this.applySettings();
          }
        });
      } else {
        // Fallback for testing without chrome extension API
        const saved = localStorage.getItem('fountainScanSettings');
        if (saved) {
          this.settings = { ...this.settings, ...JSON.parse(saved) };
          this.applySettings();
        }
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  },

  // Save settings to storage
  saveSettings() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ settings: this.settings });
      } else {
        localStorage.setItem('fountainScanSettings', JSON.stringify(this.settings));
      }
      this.showMessage('Settings saved successfully!', 'success');
    } catch (error) {
      console.error('Error saving settings:', error);
      this.showMessage('Error saving settings', 'error');
    }
  },

  // Load whitelist/blacklist from storage
  loadLists() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['whitelist', 'blacklist'], (result) => {
          this.whitelist = result.whitelist || [];
          this.blacklist = result.blacklist || [];
          this.renderLists();
        });
      } else {
        // Fallback for testing
        this.whitelist = JSON.parse(localStorage.getItem('fountainScanWhitelist') || '[]');
        this.blacklist = JSON.parse(localStorage.getItem('fountainScanBlacklist') || '[]');
        this.renderLists();
      }
    } catch (error) {
      console.error('Error loading lists:', error);
    }
  },

  // Save lists to storage
  saveLists() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ 
          whitelist: this.whitelist, 
          blacklist: this.blacklist 
        });
      } else {
        localStorage.setItem('fountainScanWhitelist', JSON.stringify(this.whitelist));
        localStorage.setItem('fountainScanBlacklist', JSON.stringify(this.blacklist));
      }
    } catch (error) {
      console.error('Error saving lists:', error);
    }
  },

  // Setup event listeners
  setupEventListeners() {
    // Navigation buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const targetTab = e.target.dataset.tab;
        this.switchTab(targetTab);
      });
    });

    // Action buttons
    const rescanBtn = document.getElementById('rescanBtn');
    const addWhitelistBtn = document.getElementById('addWhitelistBtn');
    const addBlacklistBtn = document.getElementById('addBlacklistBtn');
    const reportBtn = document.getElementById('reportBtn');
    const saveSettingsBtn = document.getElementById('saveSettingsBtn');

    if (rescanBtn) {
      rescanBtn.addEventListener('click', () => this.rescanSite());
    }
    if (addWhitelistBtn) {
      addWhitelistBtn.addEventListener('click', () => this.addToList('whitelist'));
    }
    if (addBlacklistBtn) {
      addBlacklistBtn.addEventListener('click', () => this.addToList('blacklist'));
    }
    if (reportBtn) {
      reportBtn.addEventListener('click', () => this.reportSite());
    }
    if (saveSettingsBtn) {
      saveSettingsBtn.addEventListener('click', () => this.saveSettingsFromForm());
    }

    // Enter key support for input fields
    const whitelistInput = document.getElementById('whitelistInput');
    const blacklistInput = document.getElementById('blacklistInput');
    if (whitelistInput) {
      whitelistInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          this.addToList('whitelist');
        }
      });
    }
    if (blacklistInput) {
      blacklistInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          this.addToList('blacklist');
        }
      });
    }

    // Theme change listeners
    document.querySelectorAll("input[name='theme']").forEach(radio => {
      radio.addEventListener("change", (e) => {
        this.settings.theme = e.target.value;
        this.applyTheme(e.target.value);
      });
    });

    // Settings change listeners
    const alertToggle = document.getElementById('alertToggle');
    const blockToggle = document.getElementById('blockToggle');
    if (alertToggle) {
      alertToggle.addEventListener('change', (e) => {
        this.settings.alertsEnabled = e.target.checked;
      });
    }
    if (blockToggle) {
      blockToggle.addEventListener('change', (e) => {
        this.settings.blockingEnabled = e.target.checked;
      });
    }

    // Input validation
    document.querySelectorAll('input[type="text"], input[type="url"]').forEach(input => {
      input.addEventListener('input', this.validateInput.bind(this));
    });
  },

  // Enhanced domain matching for whitelist/blacklist
  domainMatches(currentDomain, listDomain) {
    // Remove protocol and www if present
    const cleanDomain = listDomain.replace(/^(https?:\/\/)?(www\.)?/, '').toLowerCase();
    const cleanCurrent = currentDomain.replace(/^(www\.)?/, '').toLowerCase();
    
    // Exact match
    if (cleanCurrent === cleanDomain) return true;
    
    // Subdomain match (e.g., sub.example.com matches example.com)
    if (cleanCurrent.endsWith('.' + cleanDomain)) return true;
    
    // Wildcard support (e.g., *.example.com)
    if (cleanDomain.startsWith('*.')) {
      const baseDomain = cleanDomain.substring(2);
      return cleanCurrent.endsWith('.' + baseDomain) || cleanCurrent === baseDomain;
    }
    
    return false;
  },

  // Validate base domain format
  isValidBaseDomain(domain) {
    // Basic domain regex with support for international domains
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
    
    // Check basic format
    if (!domainRegex.test(domain)) return false;
    
    // Additional checks
    if (domain.length > 253) return false; // Max domain length
    if (domain.includes('..')) return false; // No consecutive dots
    if (domain.startsWith('-') || domain.endsWith('-')) return false; // No leading/trailing hyphens
    
    return true;
  },

  // Enhanced domain validation
  isValidDomain(domain) {
    // Clean the domain
    const cleanDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, '').toLowerCase();
    
    // Check for wildcard pattern
    if (cleanDomain.startsWith('*.')) {
      const baseDomain = cleanDomain.substring(2);
      return this.isValidBaseDomain(baseDomain);
    }
    
    return this.isValidBaseDomain(cleanDomain);
  },

  // Normalize domain input
  normalizeDomain(input) {
    if (!input) return '';
    
    // Remove protocol, www, and trailing slash
    let domain = input.toLowerCase()
      .replace(/^(https?:\/\/)?(www\.)?/, '')
      .replace(/\/$/, '');
    
    // Remove path, query, and fragment
    domain = domain.split('/')[0].split('?')[0].split('#')[0];
    
    // Remove port if present
    domain = domain.split(':')[0];
    
    return domain.trim();
  },

  // Enhanced input validation with real-time feedback
  validateInput(event) {
    const input = event.target;
    const value = input.value.trim();
    const errorElement = input.parentElement.querySelector('.input-error');
    
    // Remove existing error message
    if (errorElement) {
      errorElement.remove();
    }
    
    let isValid = true;
    let errorMessage = '';
    
    if (value) {
      if (input.type === 'url') {
        if (!this.isValidUrl(value)) {
          isValid = false;
          errorMessage = 'Please enter a valid URL (e.g., https://example.com)';
        }
      } else if (input.id.includes('Input')) {
        const normalizedDomain = this.normalizeDomain(value);
        if (!this.isValidDomain(normalizedDomain)) {
          isValid = false;
          errorMessage = 'Please enter a valid domain (e.g., example.com or *.example.com)';
        }
      }
    }
    
    // Update input styling and validation
    if (isValid) {
      input.setCustomValidity('');
      input.classList.remove('invalid');
      input.classList.add('valid');
    } else {
      input.setCustomValidity(errorMessage);
      input.classList.remove('valid');
      input.classList.add('invalid');
      
      // Show error message
      const errorDiv = document.createElement('div');
      errorDiv.className = 'input-error';
      errorDiv.textContent = errorMessage;
      input.parentElement.appendChild(errorDiv);
    }
  },

  // Validate URL format
  isValidUrl(string) {
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  },

  // Apply theme and settings
  applySettings() {
    this.applyTheme(this.settings.theme);
    
    // Update UI elements
    const alertToggle = document.getElementById('alertToggle');
    const blockToggle = document.getElementById('blockToggle');
    const systemLang = document.getElementById('systemLang');
    const alertLang = document.getElementById('alertLang');
    
    if (alertToggle) alertToggle.checked = this.settings.alertsEnabled;
    if (blockToggle) blockToggle.checked = this.settings.blockingEnabled;
    if (systemLang) systemLang.value = this.settings.systemLang;
    if (alertLang) alertLang.value = this.settings.alertLang;
    
    // Update theme radio buttons
    const themeRadio = document.querySelector(`input[name="theme"][value="${this.settings.theme}"]`);
    if (themeRadio) themeRadio.checked = true;
  },

  // Apply theme
  applyTheme(theme) {
    document.body.className = theme;
    this.settings.theme = theme;
  },

  // Switch between tabs
  switchTab(targetId) {
    // Remove active class from all tabs and nav buttons
    document.querySelectorAll(".tab").forEach(tab => {
      tab.classList.remove("active");
    });
    document.querySelectorAll(".nav-btn").forEach(btn => {
      btn.classList.remove("active");
    });
    
    // Add active class to target tab and nav button
    const targetTab = document.getElementById(targetId);
    const targetBtn = document.querySelector(`[data-tab="${targetId}"]`);
    
    if (targetTab) {
      targetTab.classList.add("active");
    }
    if (targetBtn) {
      targetBtn.classList.add("active");
    }
  },

  // Get current tab URL
  getCurrentUrl() {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          resolve(tabs[0]?.url || 'about:blank');
        });
      } else {
        // Fallback for testing
        resolve(window.location.href);
      }
    });
  },

  // Scan current site
  async scanCurrentSite() {
    try {
      const url = await this.getCurrentUrl();
      this.currentUrl = url;
      
      // Update UI
      const urlElement = document.getElementById('url');
      const statusElement = document.getElementById('status');
      const reasonElement = document.getElementById('reason');
      
      if (urlElement) urlElement.textContent = url;
      
      // Perform scan
      const scanResult = this.performScan(url);
      
      // Update status
      if (statusElement) {
        statusElement.textContent = scanResult.status;
        statusElement.className = `status-${scanResult.level}`;
      }
      
      if (reasonElement) {
        reasonElement.textContent = scanResult.issues.length > 0 ? 
          scanResult.issues.join(', ') : 'No issues detected';
      }
      
      // Show alert if needed
      if (scanResult.level === 'danger' && this.settings.alertsEnabled) {
        this.showAlert(scanResult);
      }
      
    } catch (error) {
      console.error('Error scanning site:', error);
      this.showMessage('Error scanning current site', 'error');
    }
  },

  // Enhanced keyword detection patterns
  getDetectionPatterns() {
    return {
      // High-risk scholarship scam patterns
      scholarshipScams: {
        keywords: [
          'free-scholarship', 'guaranteed-scholarship', 'instant-scholarship',
          'scholarship-winner', 'congratulations-scholarship', 'scholarship-alert',
          'urgent-scholarship', 'limited-scholarship', 'scholarship-opportunity',
          'scholarship-grant', 'education-grant', 'student-aid-program',
          'free scholarship', 'instant money', 'guaranteed loan',
          'easy cash', 'work from home', 'get rich quick',
          'no-experience-required', 'make-money-fast', 
          'nin', 'bvn', 'guaranteed', 'National Identity Number', 
          'free', 'Bank Verification Number', 'payment verification', 'pin'
        ],
        score: 4,
        message: 'Potential scholarship scam detected'
      },
      
      // Financial fraud patterns
      financialFraud: {
        keywords: [
          'instant-money', 'guaranteed-loan', 'easy-cash', 'quick-loan',
          'no-collateral', 'emergency-loan', 'same-day-loan', 'payday-loan',
          'cash-advance', 'loan-approved', 'credit-repair', 'debt-relief'
        ],
        score: 3,
        message: 'Financial fraud pattern detected'
      },
      
      // Work-from-home scams
      workScams: {
        keywords: [
          'work-from-home', 'make-money-online', 'earn-from-home',
          'no-experience-required', 'easy-job', 'online-jobs',
          'part-time-income', 'flexible-hours', 'remote-work-opportunity'
        ],
        score: 2,
        message: 'Work-from-home scam pattern detected'
      },
      
      // Investment/crypto scams
      investmentScams: {
        keywords: [
          'investment-opportunity', 'crypto-trading', 'forex-trading',
          'get-rich-quick', 'guaranteed-returns', 'high-yield',
          'bitcoin-investment', 'trading-signals', 'profit-guaranteed'
        ],
        score: 3,
        message: 'Investment scam pattern detected'
      },
      
      // Nigerian-specific scam patterns
      nigerianScams: {
        keywords: [
          'npower', 'jamb-result', 'waec-result', 'inec-recruitment',
          'nnpc-recruitment', 'cbn-recruitment', 'federal-government',
          'state-government', 'local-government', 'ministry-recruitment',
          'nddc-scholarship', 'tetfund', 'ptdf-scholarship'
        ],
        score: 3,
        message: 'Nigerian institution impersonation detected'
      },
      
      // Urgency and pressure tactics
      urgencyTactics: {
        keywords: [
          'urgent', 'limited-time', 'expires-soon', 'act-now',
          'dont-miss-out', 'last-chance', 'hurry', 'immediate',
          'deadline-today', 'offer-expires', 'while-supplies-last'
        ],
        score: 1,
        message: 'Urgency pressure tactic detected'
      },
      
      // Phishing indicators
      phishingPatterns: {
        keywords: [
          'verify-account', 'update-information', 'confirm-identity',
          'security-alert', 'account-suspended', 'login-required',
          'click-here', 'download-now', 'install-app'
        ],
        score: 2,
        message: 'Phishing attempt detected'
      }
    };
  },

  // Perform security scan
  performScan(url) {
    const issues = [];
    let score = 0;
    
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();
      const fullUrl = url.toLowerCase();
      
      // Check if domain is whitelisted
      if (this.whitelist.some(d => this.domainMatches(domain, d.toLowerCase()))) {
        return {
          status: 'Trusted (Whitelisted)',
          level: 'safe',
          issues: [],
          score: 0
        };
      }
      
      // Check if domain is blacklisted
      if (this.blacklist.some(d => this.domainMatches(domain, d.toLowerCase()))) {
        return {
          status: 'Blocked (Blacklisted)',
          level: 'danger',
          issues: ['Domain is blacklisted'],
          score: 10
        };
      }
      
      // Security checks
      if (urlObj.protocol !== 'https:') {
        score += 3;
        issues.push('No HTTPS encryption');
      }
      
      // Enhanced keyword detection
      const patterns = this.getDetectionPatterns();
      
      Object.entries(patterns).forEach(([category, pattern]) => {
        const foundKeywords = pattern.keywords.filter(keyword => 
          fullUrl.includes(keyword) || domain.includes(keyword)
        );
        
        if (foundKeywords.length > 0) {
          score += pattern.score;
          issues.push(`${pattern.message}: ${foundKeywords.join(', ')}`);
        }
      });
      
      // Check for suspicious TLDs
      const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click'];
      suspiciousTlds.forEach(tld => {
        if (domain.endsWith(tld)) {
          score += 2;
          issues.push(`Suspicious domain extension: ${tld}`);
        }
      });
      
      // Check for URL shorteners
      const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link', 'ow.ly'];
      shorteners.forEach(shortener => {
        if (domain.includes(shortener)) {
          score += 1;
          issues.push('URL shortener detected');
        }
      });
      
      // Check for suspicious domain characteristics
      if (domain.includes('xn--')) {
        score += 2;
        issues.push('Internationalized domain (potential homograph attack)');
      }
      
      // Check for excessive subdomains
      const subdomains = domain.split('.');
      if (subdomains.length > 4) {
        score += 1;
        issues.push('Excessive subdomains detected');
      }
      
      // Check for suspicious port numbers
      if (urlObj.port && !['80', '443', '8080', '8443'].includes(urlObj.port)) {
        score += 1;
        issues.push(`Suspicious port: ${urlObj.port}`);
      }
      
      // Determine risk level
      let level = 'safe';
      let status = 'Safe';
      
      if (score >= 6) {
        level = 'danger';
        status = 'High Risk';
      } else if (score >= 3) {
        level = 'warning';
        status = 'Medium Risk';
      }
      
      return { status, level, issues, score };
      
    } catch (error) {
      console.error('Scan error:', error);
      return {
        status: 'Error',
        level: 'warning',
        issues: ['Unable to scan URL'],
        score: 0
      };
    }
  },

  // Show security alert
  showAlert(scanResult) {
    const message = `Security Alert!\n\nWebsite: ${this.currentUrl}\nRisk Level: ${scanResult.status}\nIssues: ${scanResult.issues.join(', ')}\n\nDo you want to continue?`;
    
    if (confirm(message)) {
      // User chose to continue
      console.log('User chose to continue despite warning');
    } else if (this.settings.blockingEnabled) {
      // User chose to leave and blocking is enabled
      window.close();
    }
  },

  // Show message to user
  showMessage(text, type = 'info') {
    // Remove existing messages
    document.querySelectorAll('.message').forEach(msg => msg.remove());
    
    const message = document.createElement('div');
    message.className = `message ${type}`;
    message.textContent = text;
    
    // Insert at the top of the current tab
    const activeTab = document.querySelector('.tab.active');
    if (activeTab) {
      activeTab.insertBefore(message, activeTab.firstChild);
      
      // Auto-remove after 3 seconds
      setTimeout(() => {
        message.remove();
      }, 3000);
    }
  },

  // Enhanced add domain to whitelist/blacklist
  addToList(listType) {
    const input = document.getElementById(`${listType}Input`);
    if (!input) return;
    const rawDomain = input.value.trim();
    if (!rawDomain) {
      this.showMessage('Please enter a domain', 'error');
      return;
    }
    const domain = this.normalizeDomain(rawDomain);
    if (!domain) {
      this.showMessage('Please enter a valid domain', 'error');
      return;
    }
    if (!this.isValidDomain(domain)) {
      this.showMessage('Please enter a valid domain format (e.g., example.com or *.example.com)', 'error');
      return;
    }
    const list = listType === 'whitelist' ? this.whitelist : this.blacklist;
    const otherList = listType === 'whitelist' ? this.blacklist : this.whitelist;
    if (list.some(d => d.toLowerCase() === domain.toLowerCase())) {
      this.showMessage('Domain already exists in this list', 'error');
      return;
    }
    if (otherList.some(d => d.toLowerCase() === domain.toLowerCase())) {
      const otherListName = listType === 'whitelist' ? 'blacklist' : 'whitelist';
      this.showMessage(`Domain exists in ${otherListName}. Remove it from there first.`, 'warning');
      return;
    }
    list.push(domain);
    this.saveLists();
    this.renderLists();
    input.value = '';
    input.classList.remove('valid', 'invalid');
    const errorElement = input.parentElement.querySelector('.input-error');
    if (errorElement) errorElement.remove();
    this.showMessage(`${domain} added to ${listType}`, 'success');
    if (listType === 'whitelist') {
      setTimeout(() => this.scanCurrentSite(), 500);
    }
  },

  // Enhanced remove domain from list with confirmation
  removeFromList(listType, domain) {
    if (confirm(`Are you sure you want to remove "${domain}" from the ${listType}?`)) {
      const list = listType === 'whitelist' ? this.whitelist : this.blacklist;
      const index = list.findIndex(d => d.toLowerCase() === domain.toLowerCase());
      if (index > -1) {
        list.splice(index, 1);
        this.saveLists();
        this.renderLists();
        this.showMessage(`${domain} removed from ${listType}`, 'success');
        if (listType === 'whitelist') {
          setTimeout(() => this.scanCurrentSite(), 500);
        }
      }
    }
  },

  // Enhanced render lists with better formatting
  renderLists() {
    ['whitelist', 'blacklist'].forEach(listType => {
      const ul = document.getElementById(`${listType}Items`);
      if (!ul) return;
      
      ul.innerHTML = '';
      const list = listType === 'whitelist' ? this.whitelist : this.blacklist;
      
      if (list.length === 0) {
        const li = document.createElement('li');
        li.className = 'empty-list';
        li.textContent = `No domains in ${listType}`;
        ul.appendChild(li);
        return;
      }
      
      // Sort domains alphabetically
      const sortedList = [...list].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
      
      sortedList.forEach(domain => {
        const li = document.createElement('li');
        li.className = 'domain-item';
        
        const domainSpan = document.createElement('span');
        domainSpan.className = 'domain-name';
        domainSpan.textContent = domain;
        
        // Add wildcard indicator
        if (domain.startsWith('*.')) {
          domainSpan.classList.add('wildcard');
          domainSpan.title = 'Wildcard pattern - matches all subdomains';
        }
        
        const removeBtn = document.createElement('button');
        removeBtn.className = 'remove-btn';
        removeBtn.textContent = 'Remove';
        removeBtn.title = `Remove ${domain} from ${listType}`;
        
        li.appendChild(domainSpan);
        li.appendChild(removeBtn);
        ul.appendChild(li);
        
        // Add event listener to the remove button
        removeBtn.addEventListener('click', () => {
          this.removeFromList(listType, domain);
        });
      });
    });
  },

  // Escape HTML to prevent XSS
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  // Report suspicious site
  reportSite() {
    const urlInput = document.getElementById('reportUrl');
    const reasonInput = document.getElementById('reportReason');
    if (!urlInput || !reasonInput) {
      this.showMessage('Report form elements not found', 'error');
      return;
    }

    const url = urlInput.value.trim();
    const reason = reasonInput.value.trim();

    if (!url) {
      this.showMessage('Please enter a URL to report', 'error');
      return;
    }
    if (!reason) {
      this.showMessage('Please provide a reason for reporting', 'error');
      return;
    }
    if (!this.isValidUrl(url)) {
      this.showMessage('Please enter a valid URL', 'error');
      return;
    }

    // Send report to backend API
    fetch('https://mlzusrxqbaphwkwcdxta.supabase.co/functions/v1/report', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url, reason })
    })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          this.showMessage('Report submitted successfully! Thank you for helping keep users safe.', 'success');
          urlInput.value = '';
          reasonInput.value = '';
        } else {
          this.showMessage('Failed to submit report: ' + (data.error || 'Unknown error'), 'error');
        }
      })
      .catch(error => {
        console.error('Error submitting report:', error);
        this.showMessage('Error submitting report', 'error');
      });
  },

  // Save settings from form
  saveSettingsFromForm() {
    const systemLang = document.getElementById('systemLang');
    const alertLang = document.getElementById('alertLang');
    if (systemLang && systemLang.value.trim()) this.settings.systemLang = systemLang.value.trim();
    if (alertLang && alertLang.value.trim()) this.settings.alertLang = alertLang.value.trim();
    this.saveSettings();
  },

  // Rescan current site
  rescanSite() {
    this.scanCurrentSite();
    this.showMessage('Site rescanned', 'success');
  }
};

// Expose for debugging
window.FountainScan = FountainScan;

// Initialize when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  FountainScan.init();
});