---
name: DTE Compliance Report
description: Structured compliance validation reports for SII/DTE requirements
---

When responding in this style, format responses as formal compliance reports:

## Report Structure

### Executive Summary
- **Status**: ✅ Compliant / ⚠️ Needs Attention / ❌ Non-Compliant
- **Date**: [Current date]
- **Scope**: [What was reviewed]
- **Key Findings**: [2-3 sentence summary]

### Compliance Assessment

#### Document Type Validation
| Requirement | Status | Evidence | Notes |
|-------------|--------|----------|-------|
| Schema conformance | ✅/⚠️/❌ | file:line | Details |
| Digital signature | ✅/⚠️/❌ | file:line | Details |
| Required fields | ✅/⚠️/❌ | file:line | Details |

#### SII Regulations
**Applicable Regulations**:
- Resolución Ex. SII N° [number]
- Circular N° [number]
- [Other relevant regulations]

**Compliance Status**:
1. **Regulation 1**: ✅ Compliant
   - Implementation: [details]
   - Location: file_path:line_number

2. **Regulation 2**: ⚠️ Partial
   - Issue: [description]
   - Impact: [Low/Medium/High]
   - Remediation: [action items]

### Technical Validation

#### XML Structure
```xml
<!-- Show validated/problematic XML snippets -->
<DTE version="1.0">
  <!-- ... -->
</DTE>
```

**Validation Results**:
- ✅ Schema: Valid against SII XSD
- ✅ Signature: XMLDSig verified
- ✅ TED: Timbre electrónico present and valid
- ⚠️ Amounts: Rounding differences detected

#### Security Assessment
**Certificate Validation**:
- Certificate status: Valid/Expired/Invalid
- Expiration date: YYYY-MM-DD
- Authority: [CA name]
- Algorithm: RSA-2048/SHA256

**CAF Validation**:
- Folio range: [start] - [end]
- Available folios: [count]
- Next renewal: [date]

### Findings

#### Critical Issues (🔴 Priority 1)
1. **[Issue Title]**
   - **Impact**: Legal/Financial risk
   - **Location**: file_path:line_number
   - **Description**: [detailed explanation]
   - **Required Action**: [specific steps]
   - **Deadline**: [date]

#### Warnings (🟡 Priority 2)
1. **[Issue Title]**
   - **Impact**: Compliance risk
   - **Location**: file_path:line_number
   - **Description**: [explanation]
   - **Recommended Action**: [steps]

#### Observations (🟢 Informational)
1. **[Issue Title]**
   - **Note**: [information]
   - **Best Practice**: [recommendation]

### Remediation Plan

| Issue | Priority | Action | Owner | Deadline | Status |
|-------|----------|--------|-------|----------|--------|
| [Issue 1] | P1 | [Action] | Dev Team | [Date] | Pending |
| [Issue 2] | P2 | [Action] | Dev Team | [Date] | Pending |

### Risk Assessment

**Risk Matrix**:
| Risk | Likelihood | Impact | Severity |
|------|------------|--------|----------|
| [Risk 1] | High/Medium/Low | High/Medium/Low | Critical/High/Medium/Low |

**Mitigation Strategies**:
1. [Strategy 1]
2. [Strategy 2]

### Code Review

#### Files Reviewed
- ✅ `addons/localization/l10n_cl_dte/models/account_move_dte.py`
- ✅ `addons/localization/l10n_cl_dte/libs/xml_generator.py`
- ⚠️ `addons/localization/l10n_cl_dte/tools/signature_helper.py`

#### Compliance Checklist
- [x] RUT validation algorithm correct (Mod 11)
- [x] Document type validation implemented
- [x] Folio sequence enforcement
- [ ] **PENDING**: Enhanced error handling for SII responses
- [ ] **PENDING**: Audit logging for all DTE operations

### Testing Requirements

#### Test Cases Required
1. **TC-001**: Validate RUT with invalid check digit
2. **TC-002**: Test CAF signature verification
3. **TC-003**: Validate DTE XML against SII schemas
4. **TC-004**: Test SII webservice error handling

#### Test Coverage
- Current: XX%
- Target: 90%
- Gap: XX%

### References

**SII Documentation**:
- Schema: https://palena.sii.cl/dte/schemas/[version]
- Technical Guide: [link]
- Regulations: [links]

**Internal Documentation**:
- Architecture: `.claude/project/02_architecture.md`
- SII Compliance: `.claude/project/08_sii_compliance.md`

### Recommendations

#### Immediate Actions (Within 1 week)
1. [Action 1]
2. [Action 2]

#### Short-term (Within 1 month)
1. [Action 1]
2. [Action 2]

#### Long-term (Within 3 months)
1. [Action 1]
2. [Action 2]

### Approval

**Reviewed By**: Claude DTE Compliance Agent
**Date**: [Date]
**Next Review**: [Date + 30 days]

---

## Severity Levels

- 🔴 **Critical**: Immediate legal/financial risk, blocks production
- 🟡 **Warning**: Compliance risk, should be addressed soon
- 🟢 **Info**: Best practice suggestion, no immediate risk

## Compliance Status Codes

- ✅ **Compliant**: Meets all requirements
- ⚠️ **Partial**: Meets some requirements, issues identified
- ❌ **Non-Compliant**: Does not meet requirements
- ⏳ **Pending**: Awaiting validation/implementation

## Example Usage

Use this output style when:
- Validating DTE implementations
- Auditing SII compliance
- Reviewing tax document workflows
- Assessing security measures
- Preparing for certification
- Documenting compliance status
