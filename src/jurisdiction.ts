/**
 * Jurisdiction Detection Module
 * Detects applicable legal jurisdictions based on TLD, IP geolocation, and page language
 */

// TLD to jurisdiction mapping
const TLD_JURISDICTION_MAP: Record<string, string[]> = {
  // India
  'in': ['IN'],
  'co.in': ['IN'],
  'org.in': ['IN'],
  'gov.in': ['IN'],
  
  // European Union
  'eu': ['EU'],
  'de': ['EU', 'DE'],
  'fr': ['EU', 'FR'],
  'it': ['EU', 'IT'],
  'es': ['EU', 'ES'],
  'nl': ['EU', 'NL'],
  'be': ['EU', 'BE'],
  'at': ['EU', 'AT'],
  'pl': ['EU', 'PL'],
  'cz': ['EU', 'CZ'],
  'dk': ['EU', 'DK'],
  'fi': ['EU', 'FI'],
  'ie': ['EU', 'IE'],
  'pt': ['EU', 'PT'],
  'se': ['EU', 'SE'],
  'gr': ['EU', 'GR'],
  'hu': ['EU', 'HU'],
  'ro': ['EU', 'RO'],
  'bg': ['EU', 'BG'],
  'hr': ['EU', 'HR'],
  'sk': ['EU', 'SK'],
  'lt': ['EU', 'LT'],
  'lv': ['EU', 'LV'],
  'ee': ['EU', 'EE'],
  'mt': ['EU', 'MT'],
  'cy': ['EU', 'CY'],
  'lu': ['EU', 'LU'],
  
  // United States
  'us': ['US'],
  'com': ['US'], // Default assumption for .com
  'net': ['US'],
  'org': ['US'],
  'gov': ['US'],
  'edu': ['US'],
  
  // Other major jurisdictions
  'uk': ['UK'],
  'co.uk': ['UK'],
  'ca': ['CA'],
  'au': ['AU'],
  'com.au': ['AU'],
  'jp': ['JP'],
  'cn': ['CN'],
  'br': ['BR'],
  'mx': ['MX'],
  'sg': ['SG'],
  'hk': ['HK'],
  'ae': ['AE'],
  'za': ['ZA'],
  'nz': ['NZ'],
  'ch': ['CH'],
  'no': ['NO'],
  'is': ['IS'],
  'il': ['IL'],
  'kr': ['KR'],
  'tw': ['TW'],
  'vn': ['VN'],
  'th': ['TH'],
  'id': ['ID'],
  'my': ['MY'],
  'ph': ['PH'],
};

export interface JurisdictionResult {
  primary: string;
  all: string[];
  confidence: 'high' | 'medium' | 'low';
  sources: {
    tld: string | null;
    ipGeo: string | null;
    language: string | null;
  };
}

export interface JurisdictionRequirements {
  jurisdiction: string;
  requiredPolicies: RequiredPolicy[];
  optionalPolicies: string[];
}

export interface RequiredPolicy {
  id: string;
  name: string;
  regulation: string;
  description: string;
  severity: 'critical' | 'important' | 'recommended';
  minWordCount: number;
  requiredSections: string[];
}

// Jurisdiction requirements database
const JURISDICTION_REQUIREMENTS: Record<string, JurisdictionRequirements> = {
  IN: {
    jurisdiction: 'IN',
    requiredPolicies: [
      {
        id: 'privacy-policy',
        name: 'Privacy Policy',
        regulation: 'DPDP Act 2023, IT Act 2000',
        description: 'Mandatory under Digital Personal Data Protection Act 2023 and IT Rules 2011',
        severity: 'critical',
        minWordCount: 800,
        requiredSections: [
          'Data Controller Details',
          'Categories of Personal Data',
          'Purpose of Processing',
          'Legal Basis',
          'Data Subject Rights',
          'Data Retention',
          'Third-Party Sharing',
          'Grievance Officer Contact',
          'Data Transfer',
          'Security Measures'
        ]
      },
      {
        id: 'terms-of-service',
        name: 'Terms of Service',
        regulation: 'IT Act 2000, Consumer Protection Act 2019',
        description: 'Required for intermediary liability safe harbor and consumer protection',
        severity: 'critical',
        minWordCount: 1000,
        requiredSections: [
          'Acceptance of Terms',
          'User Obligations',
          'Prohibited Activities',
          'Intellectual Property',
          'Limitation of Liability',
          'Termination',
          'Governing Law',
          'Dispute Resolution'
        ]
      },
      {
        id: 'grievance-redressal',
        name: 'Grievance Redressal Mechanism',
        regulation: 'IT Rules 2021, DPDP Act 2023',
        description: 'Mandatory grievance officer and redressal mechanism',
        severity: 'critical',
        minWordCount: 300,
        requiredSections: [
          'Grievance Officer Details',
          'Complaint Process',
          'Timelines',
          'Escalation'
        ]
      }
    ],
    optionalPolicies: [
      'Cookie Policy',
      'Refund Policy',
      'Shipping Policy',
      'Cancellation Policy'
    ]
  },
  
  EU: {
    jurisdiction: 'EU',
    requiredPolicies: [
      {
        id: 'privacy-policy',
        name: 'Privacy Policy',
        regulation: 'GDPR Articles 12-14, 24-34',
        description: 'Comprehensive privacy notice under GDPR',
        severity: 'critical',
        minWordCount: 1500,
        requiredSections: [
          'Controller Identity',
          'DPO Contact',
          'Legal Basis',
          'Data Categories',
          'Purposes',
          'Recipients',
          'International Transfers',
          'Retention Periods',
          'Data Subject Rights (Arts 15-22)',
          'Right to Withdraw Consent',
          'Lodging Complaints (Art 77)',
          'Automated Decision Making (Art 22)',
          'Security Measures (Art 32)'
        ]
      },
      {
        id: 'cookie-policy',
        name: 'Cookie Policy',
        regulation: 'ePrivacy Directive, GDPR Art. 6',
        description: 'Required for cookie consent compliance',
        severity: 'critical',
        minWordCount: 500,
        requiredSections: [
          'Cookie Categories',
          'Purpose',
          'Duration',
          'Third Parties',
          'Consent Management',
          'How to Reject'
        ]
      },
      {
        id: 'terms-of-service',
        name: 'Terms of Service',
        regulation: 'Consumer Rights Directive, GDPR',
        description: 'Contract terms with consumers',
        severity: 'critical',
        minWordCount: 1000,
        requiredSections: [
          'Provider Identity',
          'Contract Formation',
          'Digital Content',
          'Right of Withdrawal',
          'Warranties',
          'Liability',
          'Dispute Resolution'
        ]
      },
      {
        id: 'dpa',
        name: 'Data Processing Agreement',
        regulation: 'GDPR Article 28',
        description: 'Required when using processors',
        severity: 'important',
        minWordCount: 800,
        requiredSections: [
          'Scope',
          'Processor Obligations',
          'Security Measures',
          'Sub-processing',
          'Data Subject Rights Support',
          'Deletion/Return',
          'Audits'
        ]
      }
    ],
    optionalPolicies: [
      'DPO Contact Page',
      'Records of Processing Activities (ROPA)',
      'Data Breach Notification Procedure'
    ]
  },
  
  US: {
    jurisdiction: 'US',
    requiredPolicies: [
      {
        id: 'privacy-policy',
        name: 'Privacy Policy',
        regulation: 'CalOPPA, Various State Laws',
        description: 'Required by California Online Privacy Protection Act',
        severity: 'critical',
        minWordCount: 800,
        requiredSections: [
          'Categories Collected',
          'Sources',
          'Business Purpose',
          'Third Parties',
          'Sale/Sharing',
          'Consumer Rights',
          'Contact Info',
          'Effective Date'
        ]
      },
      {
        id: 'terms-of-service',
        name: 'Terms of Service',
        regulation: 'General Contract Law',
        description: 'Binding agreement with users',
        severity: 'critical',
        minWordCount: 1000,
        requiredSections: [
          'Acceptance',
          'User Conduct',
          'IP Rights',
          'Disclaimers',
          'Liability Limits',
          'Termination',
          'Governing Law'
        ]
      }
    ],
    optionalPolicies: [
      'Cookie Policy',
      'CCPA Notice',
      'Return/Refund Policy',
      'Shipping Policy'
    ]
  },
  
  UK: {
    jurisdiction: 'UK',
    requiredPolicies: [
      {
        id: 'privacy-policy',
        name: 'Privacy Policy',
        regulation: 'UK GDPR, Data Protection Act 2018',
        description: 'UK GDPR compliance',
        severity: 'critical',
        minWordCount: 1500,
        requiredSections: [
          'Controller Details',
          'DPO Contact',
          'Lawful Basis',
          'Categories',
          'Purposes',
          'Recipients',
          'International Transfers',
          'Retention',
          'Rights',
          'Complaints (ICO)',
          'Automated Decisions',
          'Security'
        ]
      },
      {
        id: 'cookie-policy',
        name: 'Cookie Policy',
        regulation: 'PECR, UK GDPR',
        description: 'Cookie consent requirements',
        severity: 'critical',
        minWordCount: 500,
        requiredSections: [
          'Types',
          'Purposes',
          'Duration',
          'Third Parties',
          'Consent Control'
        ]
      },
      {
        id: 'terms-of-service',
        name: 'Terms of Service',
        regulation: 'Consumer Rights Act 2015',
        description: 'Consumer contract terms',
        severity: 'critical',
        minWordCount: 1000,
        requiredSections: [
          'Contract Formation',
          'Digital Content Rights',
          'Cancellation',
          'Liability',
          'Disputes'
        ]
      }
    ],
    optionalPolicies: [
      'Accessibility Statement',
      'Modern Slavery Statement'
    ]
  },
  
  CA: {
    jurisdiction: 'CA',
    requiredPolicies: [
      {
        id: 'privacy-policy',
        name: 'Privacy Policy',
        regulation: 'PIPEDA, Quebec Law 25',
        description: 'Canadian privacy law compliance',
        severity: 'critical',
        minWordCount: 800,
        requiredSections: [
          'Accountability',
          'Identifying Purposes',
          'Consent',
          'Limiting Collection',
          'Limiting Use/Disclosure/Retention',
          'Accuracy',
          'Safeguards',
          'Openness',
          'Individual Access',
          'Challenging Compliance'
        ]
      },
      {
        id: 'terms-of-service',
        name: 'Terms of Service',
        regulation: 'Consumer Protection Laws',
        description: 'Terms of use',
        severity: 'critical',
        minWordCount: 1000,
        requiredSections: [
          'Contract Terms',
          'Consumer Rights',
          'Cancellation',
          'Refunds',
          'Disputes'
        ]
      }
    ],
    optionalPolicies: [
      'Cookie Policy',
      'Accessibility Policy'
    ]
  },
  
  AU: {
    jurisdiction: 'AU',
    requiredPolicies: [
      {
        id: 'privacy-policy',
        name: 'Privacy Policy',
        regulation: 'Privacy Act 1988 (Cth), APPs',
        description: 'Australian Privacy Principles compliance',
        severity: 'critical',
        minWordCount: 800,
        requiredSections: [
          'APP 1: Open & Transparent Management',
          'APP 2: Anonymity & Pseudonymity',
          'APP 3: Collection',
          'APP 4: Unsolicited Information',
          'APP 5: Notification',
          'APP 6: Use/Disclosure',
          'APP 7: Direct Marketing',
          'APP 8: Cross-border Disclosure',
          'APP 9-10: Quality & Security',
          'APP 11: Security',
          'APP 12-13: Access & Correction'
        ]
      },
      {
        id: 'terms-of-service',
        name: 'Terms of Service',
        regulation: 'Australian Consumer Law',
        description: 'Consumer guarantees and terms',
        severity: 'critical',
        minWordCount: 1000,
        requiredSections: [
          'Consumer Guarantees',
          'Refunds',
          'Delivery',
          'Warranties',
          'Dispute Resolution'
        ]
      }
    ],
    optionalPolicies: [
      'Cookie Policy',
      'Shipping Policy'
    ]
  },
  
  // Default/fallback
  DEFAULT: {
    jurisdiction: 'DEFAULT',
    requiredPolicies: [
      {
        id: 'privacy-policy',
        name: 'Privacy Policy',
        regulation: 'General Best Practice',
        description: 'Basic privacy notice',
        severity: 'critical',
        minWordCount: 500,
        requiredSections: [
          'What Data',
          'How Used',
          'Sharing',
          'Rights',
          'Contact'
        ]
      },
      {
        id: 'terms-of-service',
        name: 'Terms of Service',
        regulation: 'General Contract Law',
        description: 'Basic terms',
        severity: 'critical',
        minWordCount: 500,
        requiredSections: [
          'Acceptance',
          'Rules',
          'IP',
          'Liability',
          'Termination'
        ]
      }
    ],
    optionalPolicies: [
      'Cookie Policy',
      'Refund Policy'
    ]
  }
};

export function detectJurisdiction(
  url: string,
  options?: {
    ipCountry?: string;
    pageLanguage?: string;
    htmlLang?: string;
  }
): JurisdictionResult {
  const tld = extractTLD(url);
  const tldJurisdictions = tld ? TLD_JURISDICTION_MAP[tld.toLowerCase()] || [] : [];
  
  let ipJurisdictions: string[] = [];
  if (options?.ipCountry) {
    ipJurisdictions = mapCountryCodeToJurisdiction(options.ipCountry);
  }
  
  let languageJurisdictions: string[] = [];
  const lang = options?.pageLanguage || options?.htmlLang;
  if (lang) {
    languageJurisdictions = mapLanguageToJurisdiction(lang);
  }
  
  // Score each jurisdiction
  const scores: Record<string, { score: number; sources: JurisdictionResult['sources'] }> = {};
  
  // TLD is strongest signal
  for (const j of tldJurisdictions) {
    if (!scores[j]) scores[j] = { score: 0, sources: { tld: null, ipGeo: null, language: null } };
    scores[j].score += 50;
    scores[j].sources.tld = tld;
  }
  
  // IP geo is strong signal
  for (const j of ipJurisdictions) {
    if (!scores[j]) scores[j] = { score: 0, sources: { tld: null, ipGeo: null, language: null } };
    scores[j].score += 30;
    scores[j].sources.ipGeo = options?.ipCountry || null;
  }
  
  // Language is weakest signal
  for (const j of languageJurisdictions) {
    if (!scores[j]) scores[j] = { score: 0, sources: { tld: null, ipGeo: null, language: null } };
    scores[j].score += 10;
    scores[j].sources.language = lang || null;
  }
  
  // Find highest scoring
  let primary = 'DEFAULT';
  let maxScore = 0;
  for (const [jur, data] of Object.entries(scores)) {
    if (data.score > maxScore) {
      maxScore = data.score;
      primary = jur;
    }
  }
  
  // Default to US if .com with no other signals
  if (primary === 'DEFAULT' && tld === 'com') {
    primary = 'US';
  }
  
  const allJurisdictions = Object.keys(scores).length > 0 
    ? Object.keys(scores).sort((a, b) => scores[b].score - scores[a].score)
    : ['DEFAULT'];
  
  const confidence: 'high' | 'medium' | 'low' = 
    maxScore >= 50 ? 'high' : maxScore >= 20 ? 'medium' : 'low';
  
  return {
    primary,
    all: allJurisdictions,
    confidence,
    sources: scores[primary]?.sources || { tld: null, ipGeo: null, language: null }
  };
}

function extractTLD(url: string): string | null {
  try {
    const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
    const hostname = parsed.hostname.toLowerCase();
    const parts = hostname.split('.');
    
    // Handle multi-part TLDs
    if (parts.length >= 2) {
      const lastTwo = parts.slice(-2).join('.');
      if (TLD_JURISDICTION_MAP[lastTwo]) {
        return lastTwo;
      }
    }
    return parts[parts.length - 1];
  } catch {
    return null;
  }
}

function mapCountryCodeToJurisdiction(countryCode: string): string[] {
  const mapping: Record<string, string[]> = {
    'IN': ['IN'],
    'US': ['US'],
    'GB': ['UK'],
    'DE': ['EU', 'DE'],
    'FR': ['EU', 'FR'],
    'IT': ['EU', 'IT'],
    'ES': ['EU', 'ES'],
    'NL': ['EU', 'NL'],
    'BE': ['EU', 'BE'],
    'AT': ['EU', 'AT'],
    'PL': ['EU', 'PL'],
    'CA': ['CA'],
    'AU': ['AU'],
    'JP': ['JP'],
    'CN': ['CN'],
    'BR': ['BR'],
    'MX': ['MX'],
    'SG': ['SG'],
    'HK': ['HK'],
    'AE': ['AE'],
    'ZA': ['ZA'],
    'NZ': ['NZ'],
    'CH': ['CH'],
    'NO': ['NO'],
    'IL': ['IL'],
    'KR': ['KR'],
    'TW': ['TW'],
    'VN': ['VN'],
    'TH': ['TH'],
    'ID': ['ID'],
    'MY': ['MY'],
    'PH': ['PH'],
  };
  return mapping[countryCode.toUpperCase()] || [];
}

function mapLanguageToJurisdiction(lang: string): string[] {
  const mapping: Record<string, string[]> = {
    'en': ['US', 'UK', 'CA', 'AU', 'IN'],
    'en-US': ['US'],
    'en-GB': ['UK'],
    'en-CA': ['CA'],
    'en-AU': ['AU'],
    'en-IN': ['IN'],
    'de': ['EU', 'DE'],
    'de-DE': ['EU', 'DE'],
    'fr': ['EU', 'FR'],
    'fr-FR': ['EU', 'FR'],
    'es': ['EU', 'ES', 'MX'],
    'es-ES': ['EU', 'ES'],
    'es-MX': ['MX'],
    'fr-CA': ['CA'],
    'pt': ['EU', 'PT', 'BR'],
    'pt-BR': ['BR'],
    'it': ['EU', 'IT'],
    'nl': ['EU', 'NL'],
    'pl': ['EU', 'PL'],
    'ja': ['JP'],
    'zh': ['CN'],
    'zh-CN': ['CN'],
    'zh-TW': ['TW'],
    'ko': ['KR'],
    'hi': ['IN'],
    'bn': ['IN'],
    'ta': ['IN'],
    'te': ['IN'],
    'mr': ['IN'],
    'ar': ['AE', 'SA'],
    'ru': ['RU'],
    'tr': ['TR'],
    'vi': ['VN'],
    'th': ['TH'],
    'id': ['ID'],
    'ms': ['MY'],
    'tl': ['PH'],
  };
  return mapping[lang.toLowerCase()] || [];
}

export function getJurisdictionRequirements(jurisdiction: string): JurisdictionRequirements {
  return JURISDICTION_REQUIREMENTS[jurisdiction] || JURISDICTION_REQUIREMENTS.DEFAULT;
}