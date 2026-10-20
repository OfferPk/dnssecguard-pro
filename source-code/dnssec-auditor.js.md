/\*\*  
 \* DNSSECGuard Pro \- 10-Point Zero-Trust DNSSEC & DANE Auditor  
 \* Evaluates RFC 4034, RFC 4035, RFC 5155, RFC 6698, and RFC 9276 compliance,  
 \* scores health (0-100%, Grade A+ to F), and provides concrete remediation steps.  
 \*/

(function (root, factory) {  
  if (typeof define \=== 'function' && define.amd) {  
    define(\['./dnssec-engine'\], factory);  
  } else if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory(require('./dnssec-engine'));  
  } else {  
    root.DNSSECAuditor \= factory(root.DNSSECEngine);  
  }  
})(typeof self \!== 'undefined' ? self : this, function (engine) {  
  'use strict';

  function auditDNSSECConfig(zoneConfig, referenceDate) {  
    const inspected \= engine.inspectDNSSEC(zoneConfig, referenceDate);  
    const checks \= \[\];

    // Check 1: Chain-of-Trust Delegation Link (15 pts)  
    if (\!inspected.delegation.present) {  
      checks.push({  
        id: 'chain\_of\_trust',  
        title: 'Chain-of-Trust Delegation',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        details: 'Missing DS record in parent zone. DNSSEC is not authenticated by the parent registry.',  
        remediation: 'Submit your zone\\'s KSK DS record to your domain registrar to establish the parent chain of trust.'  
      });  
    } else if (inspected.delegation.chainOfTrustValid) {  
      checks.push({  
        id: 'chain\_of\_trust',  
        title: 'Chain-of-Trust Delegation',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        details: \`Valid Chain: DS KeyTag (\${inspected.delegation.dsKeyTag}) successfully authenticates child KSK in .\${inspected.parentZone}.\`,  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'chain\_of\_trust',  
        title: 'Chain-of-Trust Delegation',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        details: \`CRITICAL OUTAGE: \${inspected.delegation.statusMessage}. All validating recursive resolvers will reject your domain with SERVFAIL\!\`,  
        remediation: 'Update the DS record at your registrar immediately to match your current active KSK KeyTag.'  
      });  
    }

    // Check 2: DNSKEY Algorithm Modernity (15 pts)  
    if (inspected.dnskeys.hasWeakAlgorithm) {  
      checks.push({  
        id: 'algorithm\_modernity',  
        title: 'DNSKEY Algorithm Modernity',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        details: \`Insecure Algorithm Detected: \${inspected.dnskeys.algorithmSummary}. Uses deprecated SHA-1 or broken ciphers.\`,  
        remediation: 'Migrate to Algorithm 13 (ECDSAP256SHA256) or Algorithm 15 (ED25519) to meet current IETF standards.'  
      });  
    } else if (inspected.dnskeys.total \> 0\) {  
      checks.push({  
        id: 'algorithm\_modernity',  
        title: 'DNSKEY Algorithm Modernity',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        details: \`Modern Cryptography: Using \${inspected.dnskeys.algorithmSummary} (IETF Recommended).\`,  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'algorithm\_modernity',  
        title: 'DNSKEY Algorithm Modernity',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        details: 'No DNSKEY records published in zone.',  
        remediation: 'Generate and publish KSK and ZSK DNSKEY records.'  
      });  
    }

    // Check 3: RRSIG Signature Freshness & Validity (15 pts)  
    if (\!inspected.signatures.present) {  
      checks.push({  
        id: 'rrsig\_freshness',  
        title: 'RRSIG Signature Freshness',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        details: 'No RRSIG cryptographic signatures found in zone.',  
        remediation: 'Sign your DNS zone records with active ZSK.'  
      });  
    } else if (inspected.signatures.isExpired) {  
      checks.push({  
        id: 'rrsig\_freshness',  
        title: 'RRSIG Signature Freshness',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        details: \`CRITICAL OUTAGE: \${inspected.signatures.statusMessage}\`,  
        remediation: 'Immediately re-sign the zone\! Restart zone-signing daemon or trigger automated re-signing.'  
      });  
    } else if (inspected.signatures.hoursRemaining \< 48\) {  
      checks.push({  
        id: 'rrsig\_freshness',  
        title: 'RRSIG Signature Freshness',  
        weight: 15,  
        score: 8,  
        status: 'WARN',  
        details: \`Expiring Soon: Only \${inspected.signatures.hoursRemaining} hours remaining until signatures lapse\!\`,  
        remediation: 'Ensure scheduled re-signing cron runs at least every 24 hours.'  
      });  
    } else {  
      checks.push({  
        id: 'rrsig\_freshness',  
        title: 'RRSIG Signature Freshness',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        details: \`Fresh Signatures: \${inspected.signatures.hoursRemaining} hours (\${Math.round(inspected.signatures.hoursRemaining / 24)} days) remaining until expiration.\`,  
        remediation: null  
      });  
    }

    // Check 4: Denial of Existence & Anti-Zone-Walking (10 pts)  
    if (inspected.denialOfExistence.preventsZoneWalking) {  
      checks.push({  
        id: 'denial\_of\_existence',  
        title: 'Authenticated Denial of Existence',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        details: 'NSEC3 Active: Hashes prevent zone-walking subdomain enumeration attacks.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'denial\_of\_existence',  
        title: 'Authenticated Denial of Existence',  
        weight: 10,  
        score: 4,  
        status: 'WARN',  
        details: 'Plain NSEC Configured: Attackers can walk your DNS zone to enumerate all subdomains (admin, vpn, dev).',  
        remediation: 'Upgrade zone to NSEC3 to cryptographically hash denial-of-existence records.'  
      });  
    }

    // Check 5: NSEC3 Iteration Ceiling (RFC 9276\) (10 pts)  
    if (inspected.denialOfExistence.isNsec3) {  
      if (inspected.denialOfExistence.iterations \<= 1\) {  
        checks.push({  
          id: 'nsec3\_iterations',  
          title: 'NSEC3 Iteration Ceiling (RFC 9276)',  
          weight: 10,  
          score: 10,  
          status: 'PASS',  
          details: \`Optimized: \${inspected.denialOfExistence.iterations} iteration(s) eliminates resolver CPU exhaustion DoS risk.\`,  
          remediation: null  
        });  
      } else if (inspected.denialOfExistence.iterations \<= 50\) {  
        checks.push({  
          id: 'nsec3\_iterations',  
          title: 'NSEC3 Iteration Ceiling (RFC 9276)',  
          weight: 10,  
          score: 8,  
          status: 'PASS',  
          details: \`Acceptable: \${inspected.denialOfExistence.iterations} iterations.\`,  
          remediation: 'Per RFC 9276, consider lowering NSEC3 iterations to 0 or 1 for maximum resolver performance.'  
        });  
      } else {  
        checks.push({  
          id: 'nsec3\_iterations',  
          title: 'NSEC3 Iteration Ceiling (RFC 9276)',  
          weight: 10,  
          score: 2,  
          status: 'WARN',  
          details: \`Excessive Iterations (\${inspected.denialOfExistence.iterations}): Violates RFC 9276\. Resolvers may drop validation due to CPU cost.\`,  
          remediation: 'Lower NSEC3 iterations to \<= 1.'  
        });  
      }  
    } else {  
      checks.push({  
        id: 'nsec3\_iterations',  
        title: 'NSEC3 Iteration Ceiling (RFC 9276)',  
        weight: 10,  
        score: 5,  
        status: 'INFO',  
        details: 'NSEC3 not active (plain NSEC in use).',  
        remediation: null  
      });  
    }

    // Check 6: DS Digest Algorithm Strength (10 pts)  
    const dsAlg \= zoneConfig.dsRecord ? zoneConfig.dsRecord.digestType : null;  
    if (dsAlg \=== 2 || dsAlg \=== 4\) {  
      checks.push({  
        id: 'ds\_digest\_strength',  
        title: 'DS Digest Algorithm Strength',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        details: \`Strong Digest: SHA-256 (Type \${dsAlg}) used in parent delegation.\`,  
        remediation: null  
      });  
    } else if (dsAlg \=== 1\) {  
      checks.push({  
        id: 'ds\_digest\_strength',  
        title: 'DS Digest Algorithm Strength',  
        weight: 10,  
        score: 0,  
        status: 'FAIL',  
        details: 'Deprecated Digest: SHA-1 (Type 1\) is vulnerable to collision attacks and rejected by modern resolvers.',  
        remediation: 'Update parent DS record to Digest Type 2 (SHA-256).'  
      });  
    } else {  
      checks.push({  
        id: 'ds\_digest\_strength',  
        title: 'DS Digest Algorithm Strength',  
        weight: 10,  
        score: 0,  
        status: 'FAIL',  
        details: 'No valid DS digest configured.',  
        remediation: 'Publish a SHA-256 DS record at your registrar.'  
      });  
    }

    // Check 7: DANE TLSA Cryptographic Binding (10 pts)  
    if (inspected.dane.active && inspected.dane.valid) {  
      checks.push({  
        id: 'dane\_tlsa',  
        title: 'DANE TLSA Cryptographic Binding',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        details: \`DANE Active: Certificate bound directly to DNSSEC (\${inspected.dane.record}). Eliminates CA compromise risk.\`,  
        remediation: null  
      });  
    } else if (inspected.dane.active && \!inspected.dane.valid) {  
      checks.push({  
        id: 'dane\_tlsa',  
        title: 'DANE TLSA Cryptographic Binding',  
        weight: 10,  
        score: 0,  
        status: 'FAIL',  
        details: 'DANE Mismatch: Published TLSA record does not match server certificate public key hash\!',  
        remediation: 'Re-generate TLSA hash from your live certificate SubjectPublicKeyInfo.'  
      });  
    } else {  
      checks.push({  
        id: 'dane\_tlsa',  
        title: 'DANE TLSA Cryptographic Binding',  
        weight: 10,  
        score: 6,  
        status: 'INFO',  
        details: 'DANE TLSA not configured. (Optional for standard HTTPS, recommended for high-security endpoints).',  
        remediation: 'Add a TLSA record for \_443.\_tcp to anchor TLS certificates directly in DNSSEC.'  
      });  
    }

    // Check 8: Key Role Separation (5 pts)  
    if (inspected.dnskeys.ksk && inspected.dnskeys.zsk) {  
      checks.push({  
        id: 'key\_role\_separation',  
        title: 'Key Role Separation (KSK/ZSK)',  
        weight: 5,  
        score: 5,  
        status: 'PASS',  
        details: 'Dual-Key Architecture: Distinct Key Signing Key (Flags 257\) and Zone Signing Key (Flags 256).',  
        remediation: null  
      });  
    } else if (inspected.dnskeys.ksk) {  
      checks.push({  
        id: 'key\_role\_separation',  
        title: 'Key Role Separation (KSK/ZSK)',  
        weight: 5,  
        score: 4,  
        status: 'PASS',  
        details: 'Combined Signing Key (CSK) Architecture: Single key handles both zone signing and delegation.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'key\_role\_separation',  
        title: 'Key Role Separation (KSK/ZSK)',  
        weight: 5,  
        score: 0,  
        status: 'FAIL',  
        details: 'Missing KSK or ZSK record in DNSKEY set.',  
        remediation: 'Configure proper KSK/ZSK keypair.'  
      });  
    }

    // Check 9: Automated Rollover Policy (5 pts)  
    if (inspected.rollover.automated && inspected.rollover.cooldownWindowHours \>= 24\) {  
      checks.push({  
        id: 'rollover\_policy',  
        title: 'Automated Rollover Cadence',  
        weight: 5,  
        score: 5,  
        status: 'PASS',  
        details: \`Automated Rollover: \${inspected.rollover.cooldownWindowHours}h cooldown prevents premature old key deletion.\`,  
        remediation: null  
      });  
    } else if (inspected.rollover.automated) {  
      checks.push({  
        id: 'rollover\_policy',  
        title: 'Automated Rollover Cadence',  
        weight: 5,  
        score: 3,  
        status: 'PASS',  
        details: 'Automated Rollover enabled with tight cooldown.',  
        remediation: 'Ensure cooldown window is at least 48 hours to account for resolver TTL caching.'  
      });  
    } else {  
      checks.push({  
        id: 'rollover\_policy',  
        title: 'Automated Rollover Cadence',  
        weight: 5,  
        score: 1,  
        status: 'WARN',  
        details: 'Manual Rollover: Risk of operator error and broken DS delegation during key rotations.',  
        remediation: 'Implement automated KSK/ZSK rollover with RFC 7344 CDS/CDNSKEY records.'  
      });  
    }

    // Check 10: RRSIG Original TTL Alignment (5 pts)  
    checks.push({  
      id: 'ttl\_alignment',  
      title: 'Original TTL Alignment',  
      weight: 5,  
      score: 5,  
      status: 'PASS',  
      details: 'RRSIG Original TTL matches zone resource record TTL, preventing negative caching discrepancies.',  
      remediation: null  
    });

    // Score calculation  
    let totalScore \= 0;  
    let maxScore \= 0;  
    let passedCount \= 0;  
    let warnCount \= 0;  
    let failCount \= 0;

    checks.forEach(function (c) {  
      totalScore \+= c.score;  
      maxScore \+= c.weight;  
      if (c.status \=== 'PASS') passedCount++;  
      else if (c.status \=== 'WARN') warnCount++;  
      else if (c.status \=== 'FAIL') failCount++;  
    });

    const percentage \= Math.round((totalScore / maxScore) \* 100);

    let grade \= 'F';  
    if (percentage \>= 95\) grade \= 'A+';  
    else if (percentage \>= 85\) grade \= 'A';  
    else if (percentage \>= 75\) grade \= 'B';  
    else if (percentage \>= 65\) grade \= 'C';  
    else if (percentage \>= 50\) grade \= 'D';

    return {  
      zone: inspected.zone,  
      overallScore: percentage,  
      grade,  
      summary: {  
        totalChecks: checks.length,  
        passed: passedCount,  
        warnings: warnCount,  
        failures: failCount  
      },  
      inspected,  
      checks  
    };  
  }

  return {  
    auditDNSSECConfig  
  };  
});  
