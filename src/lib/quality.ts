/**
 * Policy Quality Scoring Module
 * Evaluates policy content quality based on word count, required sections, and content depth
 */

export interface PolicyQualityResult {
  score: number; // 0-100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  wordCount: number;
  foundSections: string[];
  missingSections: string[];
  issues: QualityIssue[];
  recommendations: string[];
}

export interface QualityIssue {
  type: 'missing_section' | 'low_word_count' | 'thin_content' | 'missing_contact' | 'outdated';
  severity: 'critical' | 'important' | 'minor';
  message: string;
  section?: string;
}

export interface PolicyContent {
  url: string;
  html: string;
  text: string;
  title: string;
}

// Section detection patterns for common policy sections
const SECTION_PATTERNS: Record<string, RegExp[]> = {
  'Data Controller Details': [
    /data controller/i,
    /who we are/i,
    /company details/i,
    /organization details/i,
    /legal entity/i,
  ],
  'DPO Contact': [
    /data protection officer/i,
    /dpo/i,
    /privacy officer/i,
    /data protection contact/i,
  ],
  'Categories of Personal Data': [
    /categories of (personal )?data/i,
    /types of (personal )?data/i,
    /what (personal )?data/i,
    /data we collect/i,
  ],
  'Purpose of Processing': [
    /purpose of processing/i,
    /why we (process|use|collect)/i,
    /legal basis/i,
    /lawful basis/i,
  ],
  'Legal Basis': [
    /legal basis/i,
    /lawful basis/i,
    /grounds for processing/i,
  ],
  'Data Subject Rights': [
    /data subject rights/i,
    /your rights/i,
    /rights you have/i,
    /right to access/i,
    /right to rectif/i,
    /right to eras/i,
    /right to restrict/i,
    /right to portab/i,
    /right to object/i,
    /automated decision/i,
  ],
  'Data Retention': [
    /retention/i,
    /how long we keep/i,
    /data retention/i,
    /storage period/i,
    /deletion/i,
  ],
  'Third-Party Sharing': [
    /third (part|party) (ies| )/i,
    /service providers/i,
    /partners/i,
    /sharing (with|your) (data|information)/i,
    /disclose/i,
  ],
  'Grievance Officer Contact': [
    /grievance officer/i,
    /grievance redressal/i,
    /complaint officer/i,
    /data protection officer/i,
  ],
  'Data Transfer': [
    /international transfer/i,
    /cross.border transfer/i,
    /transfer outside/i,
    /adequacy decision/i,
    /standard contractual clauses/i,
  ],
  'Security Measures': [
    /security measures/i,
    /technical measures/i,
    /organizational measures/i,
    /encryption/i,
    /access control/i,
    /data security/i,
  ],
  'Cookie Categories': [
    /cookie categories/i,
    /types of cookies/i,
    /strictly necessary/i,
    /performance cookies/i,
    /functional cookies/i,
    /targeting cookies/i,
    /advertising cookies/i,
  ],
  'Consent Management': [
    /consent management/i,
    /cookie consent/i,
    /manage consent/i,
    /withdraw consent/i,
    /change consent/i,
  ],
  'Right to Withdraw Consent': [
    /withdraw consent/i,
    /revoke consent/i,
  ],
  'Lodging Complaints': [
    /lodge a complaint/i,
    /file a complaint/i,
    /supervisory authority/i,
    /data protection authority/i,
  ],
  'Automated Decision Making': [
    /automated decision/i,
    /profiling/i,
  ],
  'DPO Contact': [
    /data protection officer/i,
    /dpo/i,
    /privacy officer/i,
  ],
  'Records of Processing Activities': [
    /records of processing/i,
    /ropas?/i,
    /article 30/i,
  ],
  'Data Breach Notification': [
    /data breach/i,
    /breach notification/i,
    /72 hours/i,
  ],
  'Accessibility Statement': [
    /accessibility statement/i,
    /accessibility/i,
  ],
  'Modern Slavery Statement': [
    /modern slavery/i,
    /human trafficking/i,
  ],
  // Common sections
  'Acceptance of Terms': [
    /acceptance of terms/i,
    /by using/i,
    /by accessing/i,
    /agree to these terms/i,
  ],
  'User Obligations': [
    /user obligations/i,
    /your responsibilities/i,
    /user responsibilities/i,
  ],
  'Prohibited Activities': [
    /prohibited activities/i,
    /you may not/i,
    /restricted activities/i,
  ],
  'Intellectual Property': [
    /intellectual property/i,
    /copyright/i,
    /trademark/i,
    /ownership/i,
  ],
  'Limitation of Liability': [
    /limitation of liability/i,
    /liability/i,
    /not liable/i,
  ],
  'Termination': [
    /termination/i,
    /terminate/i,
    /suspend/i,
  ],
  'Governing Law': [
    /governing law/i,
    /applicable law/i,
    /jurisdiction/i,
  ],
  'Dispute Resolution': [
    /dispute resolution/i,
    /arbitration/i,
    /mediation/i,
  ],
  'Contract Formation': [
    /contract formation/i,
    /how (the )?contract is formed/i,
    /offer and acceptance/i,
  ],
  'Digital Content': [
    /digital content/i,
    /digital products/i,
  ],
  'Right of Withdrawal': [
    /right of withdrawal/i,
    /right to cancel/i,
    /cooling.off/i,
  ],
  'Warranties': [
    /warrant/i,
    /guarantee/i,
  ],
  'Consumer Guarantees': [
    /consumer guarantees/i,
    /statutory rights/i,
  ],
  'Cancellation': [
    /cancellation/i,
    /cancel/i,
  ],
  'Refunds': [
    /refund/i,
    /money.back/i,
  ],
  'Delivery': [
    /delivery/i,
    /shipping/i,
  ],
  'Accountability': [
    /accountability/i,
    /responsible for/i,
  ],
  'Identifying Purposes': [
    /identifying purposes/i,
    /purposes identified/i,
  ],
  'Consent': [
    /^consent$/i,
    /consent requirements/i,
  ],
  'Limiting Collection': [
    /limiting collection/i,
    /minimal collection/i,
  ],
  'Limiting Use Disclosure Retention': [
    /limiting (use|disclosure|retention)/i,
  ],
  'Accuracy': [
    /^accuracy$/i,
    /accurate and up.to.date/i,
  ],
  'Safeguards': [
    /safeguards/i,
    /protective measures/i,
  ],
  'Openness': [
    /openness/i,
    /transparency/i,
  ],
  'Individual Access': [
    /individual access/i,
    /right to access/i,
  ],
  'Challenging Compliance': [
    /challenging compliance/i,
    /complaint process/i,
  ],
};

function countWords(text: string): number {
  return text.trim().split(/\s+/).filter(w => w.length > 0).length;
}

function detectSections(text: string): string[] {
  const lowerText = text.toLowerCase();
  const found: string[] = [];
  
  for (const [section, patterns] of Object.entries(SECTION_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(lowerText)) {
        found.push(section);
        break;
      }
    }
  }
  
  return found;
}

export function scorePolicyQuality(
  content: PolicyContent,
  requiredSections: string[] = []
): PolicyQualityResult {
  const wordCount = countWords(content.text);
  const foundSections = detectSections(content.text);
  const missingSections = requiredSections.filter(s => !foundSections.includes(s));
  
  const issues: QualityIssue[] = [];
  const recommendations: string[] = [];
  
  // Word count scoring
  let wordScore = 0;
  if (wordCount >= 1500) wordScore = 30;
  else if (wordCount >= 1000) wordScore = 25;
  else if (wordCount >= 800) wordScore = 20;
  else if (wordCount >= 500) wordScore = 15;
  else if (wordCount >= 300) wordScore = 10;
  else wordScore = 5;
  
  if (wordCount < 500) {
    issues.push({
      type: 'low_word_count',
      severity: 'critical',
      message: `Policy has only ${wordCount} words. Minimum recommended is 500 words for substantive policies.`
    });
    recommendations.push('Expand policy content with more detailed explanations');
  } else if (wordCount < 800) {
    issues.push({
      type: 'low_word_count',
      severity: 'important',
      message: `Policy has ${wordCount} words. Recommended minimum is 800+ words for comprehensive coverage.`
    });
  }
  
  // Section coverage scoring
  const totalRequired = requiredSections.length;
  const foundRequired = requiredSections.filter(s => foundSections.includes(s)).length;
  const sectionCoverage = totalRequired > 0 ? foundRequired / totalRequired : 1;
  const sectionScore = Math.round(sectionCoverage * 50);
  
  for (const missing of missingSections) {
    issues.push({
      type: 'missing_section',
      severity: 'critical',
      message: `Missing required section: "${missing}"`,
      section: missing
    });
    recommendations.push(`Add "${missing}" section to comply with regulatory requirements`);
  }
  
  // Content depth - check for thin content patterns
  const sentences = content.text.split(/[.!?]+/).filter(s => s.trim().length > 10);
  if (sentences.length < 10 && wordCount > 300) {
    issues.push({
      type: 'thin_content',
      severity: 'important',
      message: 'Policy appears to have thin content - few substantive sentences'
    });
    recommendations.push('Expand content with more detailed explanations and examples');
  }
  
  // Check for contact information
  const hasContact = /contact/i.test(content.text) && 
    (/email|phone|address|@/.test(content.text));
  if (!hasContact) {
    issues.push({
      type: 'missing_contact',
      severity: 'important',
      message: 'No contact information found in policy'
    });
    recommendations.push('Add contact information (email, address, or contact form link)');
  }
  
  // Check for last updated date
  const hasDate = /\b(202[0-9]|202[4-9])\b/.test(content.text) ||
    /last updated|effective date|last modified/i.test(content.text);
  if (!hasDate) {
    issues.push({
      type: 'outdated',
      severity: 'minor',
      message: 'No effective date or last updated date found'
    });
    recommendations.push('Add "Last Updated" or "Effective Date" to the policy');
  }
  
  // Calculate final score
  let score = wordScore + sectionScore;
  
  // Deduct for issues
  for (const issue of issues) {
    if (issue.severity === 'critical') score -= 15;
    else if (issue.severity === 'important') score -= 8;
    else score -= 3;
  }
  
  score = Math.max(0, Math.min(100, score));
  
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
  
  return {
    score,
    grade,
    wordCount,
    foundSections,
    missingSections,
    issues,
    recommendations
  };
}

export function scoreMultiplePolicies(
  policies: Array<{ url: string; html: string; text: string; title: string; expectedType: string }>,
  jurisdiction: string
): Map<string, PolicyQualityResult> {
  // Import here to avoid circular dependency
  const { getJurisdictionRequirements } = require('./jurisdiction');
  const reqs = require('./jurisdiction').getJurisdictionRequirements(jurisdiction);
  
  const results = new Map<string, PolicyQualityResult>();
  
  for (const policy of policies) {
    const requiredSections = reqs.requiredPolicies
      .find(p => p.id === policy.expectedType.toLowerCase().replace(/\s+/g, '-'))?.requiredSections || [];
    
    const result = scorePolicyQuality({
      url: policy.url,
      html: policy.html,
      text: policy.text,
      title: policy.title
    }, requiredSections);
    
    results.set(policy.expectedType, result);
  }
  
  return results;
}

// Quick quality check for just word count (for quick scans)
export function quickQualityCheck(text: string): { wordCount: number; estimatedGrade: string } {
  const wordCount = countWords(text);
  let grade = 'F';
  if (wordCount >= 1500) grade = 'A';
  else if (wordCount >= 1000) grade = 'B';
  else if (wordCount >= 800) grade = 'B';
  else if (wordCount >= 500) grade = 'C';
  else if (wordCount >= 300) grade = 'D';
  return { wordCount, estimatedGrade: grade };
}