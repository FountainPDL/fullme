// Content script for Fountain Scan Extension
// This script runs on every webpage to analyze content for fraud patterns

(function() {
  'use strict';

  // Prevent multiple injections
  if (window.fountainScanInjected) {
    return;
  }
  window.fountainScanInjected = true;

  // Configuration
  const CONFIG = {
    // Nigerian scholarship scam patterns
    SCAM_KEYWORDS: [
      'free scholarship', 'guaranteed scholarship', 'instant scholarship',
      'no application fee', 'processing fee required', 'registration fee',
      'urgent scholarship', 'limited time offer', 'act now',
      'government scholarship', 'federal scholarship', 'state scholarship',
      'university scholarship', 'foreign scholarship', 'international scholarship',
      'study abroad free', 'full funding', 'stipend included',
      'cash reward', 'monetary prize', 'financial assistance',
      'click here to apply', 'apply now', 'hurry up',
      'congratulations you have won', 'you are selected',
      'final notice', 'your application is approved', 'atm pin'
    ],
    
    SUSPICIOUS_PHRASES: [
      'send money', 'transfer funds', 'pay processing fee',
      'bank details required', 'account information needed',
      'western union', 'money gram', 'bitcoin payment',
      'gift card payment', 'itunes card', 'google play card',
      'social security number', 'national insurance number',
      'passport copy required', 'urgent response required',
      'confidential', 'do not tell anyone', 'keep secret'
    ],
    
    FORM_RISKS: [
      'bank account', 'credit card', 'ssn', 'social security',
      'passport number', 'driver license', 'nin', 'bvn',
      'mothers maiden name', 'place of birth', 'blood type', 'atm pin'
    ],
    
    SUSPICIOUS_DOMAINS: [
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
      'free-scholarship', 'easy-money', 'quick-cash',
      'government-grants', 'federal-aid', 'student-loans'
    ],
    
    RISK_THRESHOLDS: {
      LOW: 2,
      MEDIUM: 4,
      HIGH: 6
    }
  };

  // Main analyzer class
  class FountainScanAnalyzer {
    constructor() {
      this.riskScore = 0;
      this.detectedIssues = [];
      this.pageAnalyzed = false;
      this.settings = {
        alertsEnabled: true,
        blockingEnabled: false
      };
      
      this.init();
    }

    // Initialize analyzer
    init() {
      this.loadSettings();
      this.analyzePage();
      this.monitorPageChanges();
      this.setupFormMonitoring();
    }

    // Load settings from storage
    loadSettings() {
      try {
        chrome.storage.local.get(['settings'], (result) => {
          if (result.settings) {
            this.settings = { ...this.settings, ...result.settings };
          }
        });
      } catch (error) {
        console.error('FountainScan: Error loading settings:', error);
      }
    }

    // Main page analysis function
    analyzePage() {
      if (this.pageAnalyzed) return;
      
      const url = window.location.href;
      const domain = window.location.hostname;
      const pageText = this.getPageText();
      
      // Reset analysis
      this.riskScore = 0;
      this.detectedIssues = [];
      
      // Perform various checks
      this.checkUrl(url, domain);
      this.checkPageContent(pageText);
      this.checkForms();
      this.checkLinks();
      this.checkImages();
      this.checkScripts();
      
      // Determine risk level and take action
      this.processResults();
      
      this.pageAnalyzed = true;
    }

    // Get all text content from page
    getPageText() {
      const clone = document.cloneNode(true);
      // Remove script and style elements
      const scripts = clone.querySelectorAll('script, style, noscript');
      scripts.forEach(el => el.remove());
      
      return clone.textContent || clone.innerText || '';
    }

    // Check URL for suspicious patterns
    checkUrl(url, domain) {
      const urlLower = url.toLowerCase();
      
      // Check for non-HTTPS
      if (!url.startsWith('https://')) {
        this.addIssue('No HTTPS encryption', 1);
      }
      
      // Check for suspicious domain patterns
      CONFIG.SUSPICIOUS_DOMAINS.forEach(suspiciousDomain => {
        if (domain.includes(suspiciousDomain)) {
          this.addIssue(`Suspicious domain pattern: ${suspiciousDomain}`, 2);
        }
      });
      
      // Check for URL shorteners
      const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly'];
      shorteners.forEach(shortener => {
        if (domain.includes(shortener)) {
          this.addIssue('URL shortener detected', 1);
        }
      });
      
      // Check for suspicious TLDs
      const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.pw'];
      suspiciousTlds.forEach(tld => {
        if (domain.endsWith(tld)) {
          this.addIssue(`Suspicious domain extension: ${tld}`, 2);
        }
      });
      
      // Check for scholarship-related scam patterns in URL
      if (urlLower.includes('scholarship') || urlLower.includes('grant')) {
        if (urlLower.includes('free') || urlLower.includes('guaranteed')) {
          this.addIssue('Potential scholarship scam URL pattern', 2);
        }
      }
    }

    // Check page content for scam indicators
    checkPageContent(pageText) {
      const textLower = pageText.toLowerCase();
      
      // Check for scam keywords
      CONFIG.SCAM_KEYWORDS.forEach(keyword => {
        if (textLower.includes(keyword)) {
          this.addIssue(`Scam keyword detected: "${keyword}"`, 1);
        }
      });
      
      // Check for suspicious phrases
      CONFIG.SUSPICIOUS_PHRASES.forEach(phrase => {
        if (textLower.includes(phrase)) {
          this.addIssue(`Suspicious phrase detected: "${phrase}"`, 2);
        }
      });
      
      // Check for urgency indicators
      const urgencyWords = ['urgent', 'hurry', 'limited time', 'expires soon', 'act now', 'immediate'];
      urgencyWords.forEach(word => {
        if (textLower.includes(word)) {
          this.addIssue(`Urgency pressure detected: "${word}"`, 1);
        }
      });
      
      // Check for money-related requests
      const moneyRequests = ['send money', 'transfer funds', 'processing fee', 'registration fee'];
      moneyRequests.forEach(request => {
        if (textLower.includes(request)) {
          this.addIssue(`Money request detected: "${request}"`, 3);
        }
      });
      
      // Check for Nigerian-specific scam patterns
      this.checkNigerianScamPatterns(textLower);
    }

    // Check for Nigerian-specific scam patterns
    checkNigerianScamPatterns(textLower) {
      const nigerianPatterns = [
        'nigerian government', 'federal ministry', 'nnpc scholarship',
        'petroleum trust fund', 'ptf scholarship', 'tetfund',
        'jamb scholarship', 'waec scholarship', 'neco scholarship',
        'lagos state scholarship', 'kano state scholarship',
        'rivers state scholarship', 'ogun state scholarship',
        'presidential scholarship', 'governors scholarship',
        'dangote scholarship', 'mtn scholarship', 'gtbank scholarship',
        'shell scholarship', 'chevron scholarship', 'mobil scholarship',
        'atm pin'
      ];
      
      nigerianPatterns.forEach(pattern => {
        if (textLower.includes(pattern)) {
          // Higher risk if combined with suspicious elements
          const riskLevel = this.checkForAdditionalRisks(textLower) ? 2 : 1;
          this.addIssue(`Nigerian scholarship pattern: "${pattern}"`, riskLevel);
        }
      });
    }

    // Check for additional risk factors
    checkForAdditionalRisks(textLower) {
      const additionalRisks = [
        'processing fee', 'registration fee', 'application fee',
        'send money', 'bank details', 'urgent response'
      ];
      
      return additionalRisks.some(risk => textLower.includes(risk));
    }

    // Check forms for suspicious input requests
    checkForms() {
      const forms = document.querySelectorAll('form');
      
      forms.forEach(form => {
        const inputs = form.querySelectorAll('input, textarea, select');
        
        inputs.forEach(input => {
          const inputText = (input.name + ' ' + input.placeholder + ' ' + input.id).toLowerCase();
          
          CONFIG.FORM_RISKS.forEach(risk => {
            if (inputText.includes(risk)) {
              this.addIssue(`Suspicious form field: ${risk}`, 2);
            }
          });
          
          // Check for financial information requests
          if (inputText.includes('bank') || inputText.includes('account') || 
              inputText.includes('card') || inputText.includes('payment')) {
            this.addIssue('Financial information requested', 3);
          }
        });
      });
    }

    // Check links for suspicious destinations
    checkLinks() {
      const links = document.querySelectorAll('a[href]');
      let suspiciousLinks = 0;
      
      links.forEach(link => {
        const href = link.href.toLowerCase();
        
        // Check for external links to suspicious domains
        CONFIG.SUSPICIOUS_DOMAINS.forEach(domain => {
          if (href.includes(domain)) {
            suspiciousLinks++;
          }
        });
        
        // Check for download links
        if (href.includes('download') || href.includes('.exe') || 
            href.includes('.zip') || href.includes('.rar')) {
          this.addIssue('Suspicious download link detected', 1);
        }
      });
      
      if (suspiciousLinks > 3) {
        this.addIssue(`Multiple suspicious external links (${suspiciousLinks})`, 2);
      }
    }

    // Check images for suspicious content
    checkImages() {
      const images = document.querySelectorAll('img');
      
      images.forEach(img => {
        const alt = (img.alt || '').toLowerCase();
        const src = (img.src || '').toLowerCase();
        
        // Check for fake government logos or seals
        if (alt.includes('government') || alt.includes('official') || 
            alt.includes('seal') || alt.includes('logo')) {
          this.addIssue('Potentially fake official imagery', 1);
        }
        
        // Check for suspicious image sources
        if (src.includes('fake') || src.includes('scam') || src.includes('phishing')) {
          this.addIssue('Suspicious image source', 2);
        }
      });
    }

    // Check scripts for suspicious behavior
    checkScripts() {
      const scripts = document.querySelectorAll('script');
      let suspiciousScripts = 0;
      
      scripts.forEach(script => {
        const src = script.src ? script.src.toLowerCase() : '';
        
        // Check for suspicious script sources
        if (src.includes('malware') || src.includes('phishing') || 
            src.includes('scam') || src.includes('fraud')) {
          suspiciousScripts++;
        }
        
        // Check for obfuscated scripts
        if (script.textContent && script.textContent.length > 1000) {
          const obfuscationIndicators = ['eval(', 'unescape(', 'fromCharCode('];
          obfuscationIndicators.forEach(indicator => {
            if (script.textContent.includes(indicator)) {
              suspiciousScripts++;
            }
          });
        }
      });
      
      if (suspiciousScripts > 0) {
        this.addIssue(`Suspicious scripts detected (${suspiciousScripts})`, 2);
      }
    }

    // Add an issue to the list
    addIssue(issue, score) {
      this.detectedIssues.push(issue);
      this.riskScore += score;
    }

    // Process analysis results
    processResults() {
      const riskLevel = this.getRiskLevel();
      
      // Send results to background script
      this.sendResultsToBackground(riskLevel);
      
      // Take action based on risk level
      if (riskLevel === 'HIGH' && this.settings.alertsEnabled) {
        this.showWarning();
      } else if (riskLevel === 'MEDIUM' && this.settings.alertsEnabled) {
        this.showCaution();
      }
    }

    // Determine risk level
    getRiskLevel() {
      if (this.riskScore >= CONFIG.RISK_THRESHOLDS.HIGH) {
        return 'HIGH';
      } else if (this.riskScore >= CONFIG.RISK_THRESHOLDS.MEDIUM) {
        return 'MEDIUM';
      } else if (this.riskScore >= CONFIG.RISK_THRESHOLDS.LOW) {
        return 'LOW';
      }
      return 'SAFE';
    }

    // Send results to background script
    sendResultsToBackground(riskLevel) {
      try {
        chrome.runtime.sendMessage({
          action: 'pageAnalyzed',
          data: {
            url: window.location.href,
            domain: window.location.hostname,
            riskLevel: riskLevel,
            riskScore: this.riskScore,
            issues: this.detectedIssues,
            timestamp: new Date().toISOString()
          }
        });
      } catch (error) {
        console.error('FountainScan: Error sending results:', error);
      }
    }

    // Show high-risk warning
    showWarning() {
      const warningDiv = this.createWarningElement(
        'HIGH RISK WEBSITE DETECTED',
        'This website shows multiple signs of being a scam. Please be very careful!',
        '#f44336'
      );
      
      document.body.insertBefore(warningDiv, document.body.firstChild);
    }

    // Show medium-risk caution
    showCaution() {
      const cautionDiv = this.createWarningElement(
        'CAUTION: POTENTIALLY SUSPICIOUS WEBSITE',
        'This website has some suspicious characteristics. Please verify before providing personal information.',
        '#ff9800'
      );
      
      document.body.insertBefore(cautionDiv, document.body.firstChild);
    }

    // Create warning element
    createWarningElement(title, message, color) {
      const warningDiv = document.createElement('div');
      warningDiv.id = 'fountain-scan-warning';
      warningDiv.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        background: ${color};
        color: white;
        padding: 10px;
        text-align: center;
        font-family: Arial, sans-serif;
        font-size: 14px;
        font-weight: bold;
        z-index: 999999;
        box-shadow: 0 2px 10px rgba(0,0,0,0.3);
      `;
      
      warningDiv.innerHTML = `
        <div style="max-width: 1200px; margin: 0 auto;">
          <div style="font-size: 16px; margin-bottom: 5px;">${title}</div>
          <div style="font-size: 12px; font-weight: normal;">${message}</div>
          <div style="font-size: 11px; margin-top: 5px;">
            Issues: ${this.detectedIssues.slice(0, 3).join(', ')}
            ${this.detectedIssues.length > 3 ? '...' : ''}
          </div>
          <button onclick="this.parentElement.parentElement.remove()" 
                  style="margin-top: 5px; padding: 5px 10px; background: rgba(255,255,255,0.2); 
                         color: white; border: none; border-radius: 3px; cursor: pointer;">
            Dismiss
          </button>
        </div>
      `;
      
      return warningDiv;
    }

    // Monitor page changes (for SPAs)
    monitorPageChanges() {
      let lastUrl = location.href;
      
      const observer = new MutationObserver(() => {
        if (location.href !== lastUrl) {
          lastUrl = location.href;
          this.pageAnalyzed = false;
          setTimeout(() => this.analyzePage(), 1000);
        }
      });
      
      observer.observe(document.body, { childList: true, subtree: true });
    }

    // Setup form monitoring
    setupFormMonitoring() {
      document.addEventListener('submit', (event) => {
        const form = event.target;
        if (form.tagName === 'FORM') {
          this.analyzeFormSubmission(form);
        }
      });
    }

    // Analyze form submission
    analyzeFormSubmission(form) {
      const inputs = form.querySelectorAll('input, textarea, select');
      let riskyInputs = 0;
      
      inputs.forEach(input => {
        const inputText = (input.name + ' ' + input.placeholder + ' ' + input.id).toLowerCase();
        
        CONFIG.FORM_RISKS.forEach(risk => {
          if (inputText.includes(risk)) {
            riskyInputs++;
          }
        });
      });
      
      if (riskyInputs > 2 && this.settings.alertsEnabled) {
        const proceed = confirm(
          'WARNING: This form is requesting sensitive information that could be used for identity theft or fraud.\n\n' +
          'Are you sure you want to submit this form?'
        );
        
        if (!proceed) {
          event.preventDefault();
        }
      }
    }
  }

  // Initialize analyzer when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      new FountainScanAnalyzer();
    });
  } else {
    new FountainScanAnalyzer();
  }

  // Message listener for popup communication
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getPageAnalysis') {
      sendResponse({
        url: window.location.href,
        domain: window.location.hostname,
        riskScore: window.fountainScanAnalyzer?.riskScore || 0,
        issues: window.fountainScanAnalyzer?.detectedIssues || [],
        riskLevel: window.fountainScanAnalyzer?.getRiskLevel() || 'SAFE'
      });
    }
  });

})();