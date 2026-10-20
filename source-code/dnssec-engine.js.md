/\*\*  
 \* DNSSECGuard Pro \- Core Engine  
 \* Standard DNSSEC Chain-of-Trust (RFC 4034, 4035\) & DANE TLSA (RFC 6698\) Analyzer  
 \*/

(function (root, factory) {  
  if (typeof define \=== 'function' && define.amd) {  
    define(\[\], factory);  
  } else if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.DNSSECEngine \= factory();  
  }  
})(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  // Standard IANA DNSSEC Algorithm Numbers  
  const DNSSEC\_ALGORITHMS \= {  
    1: { name: 'RSAMD5', status: 'DEPRECATED' },  
    3: { name: 'DSA', status: 'DEPRECATED' },  
    5: { name: 'RSASHA1', status: 'DEPRECATED' },  
    7: { name: 'RSASHA1-NSEC3-SHA1', status: 'DEPRECATED' },  
    8: { name: 'RSASHA256', status: 'ACCEPTABLE' },  
    10: { name: 'RSASHA512', status: 'ACCEPTABLE' },  
    13: { name: 'ECDSAP256SHA256', status: 'RECOMMENDED' },  
    14: { name: 'ECDSAP384SHA384', status: 'RECOMMENDED' },  
    15: { name: 'ED25519', status: 'RECOMMENDED' },  
    16: { name: 'ED448', status: 'RECOMMENDED' }  
  };

  // Standard DS Digest Types  
  const DS\_DIGEST\_TYPES \= {  
    1: 'SHA-1 (Deprecated)',  
    2: 'SHA-256 (Standard)',  
    3: 'GOST R 34.11-94',  
    4: 'SHA-384'  
  };

  /\*\*  
   \* Inspect and evaluate complete DNSSEC & DANE configuration  
   \* @param {Object} zoneConfig Configuration representing DNSKEY, DS, RRSIG, NSEC/NSEC3, and DANE  
   \* @param {Date} \[referenceDate\] Optional reference date for signature timing (defaults to now)  
   \*/  
  function inspectDNSSEC(zoneConfig, referenceDate) {  
    const now \= referenceDate ? new Date(referenceDate) : new Date();

    if (\!zoneConfig || typeof zoneConfig \!== 'object') {  
      throw new Error('Invalid input: zoneConfig must be an object');  
    }

    const zone \= zoneConfig.zone || 'unknown-zone';  
    const parentZone \= zoneConfig.parentZone || 'com';  
    const isEnabled \= Boolean(zoneConfig.dnssecEnabled);

    // 1\. DNSKEY Records Analysis  
    const dnskeys \= Array.isArray(zoneConfig.dnskey) ? zoneConfig.dnskey : \[\];  
    let kskRecord \= null;  
    let zskRecord \= null;  
    let hasWeakAlgorithm \= false;  
    let algorithmSummary \= \[\];

    dnskeys.forEach(function (k) {  
      const algInfo \= DNSSEC\_ALGORITHMS\[k.algorithm\] || { name: k.algorithmName || 'Unknown', status: 'UNKNOWN' };  
      if (algInfo.status \=== 'DEPRECATED') {  
        hasWeakAlgorithm \= true;  
      }  
      algorithmSummary.push(\`\${algInfo.name} (\${k.algorithm})\`);

      if (k.flags \=== 257 || k.keyType \=== 'KSK' || k.keyType \=== 'CSK') {  
        kskRecord \= k;  
      }  
      if (k.flags \=== 256 || k.keyType \=== 'ZSK') {  
        zskRecord \= k;  
      }  
    });

    // 2\. DS Record & Delegation Chain Check  
    const ds \= zoneConfig.dsRecord || null;  
    let chainOfTrustValid \= false;  
    let chainStatusMessage \= 'No DS record published in parent zone';

    if (ds && kskRecord) {  
      const keyTagMatch \= ds.keyTag \=== kskRecord.keyTag;  
      const algMatch \= ds.algorithm \=== kskRecord.algorithm;  
      const digestMatch \= ds.matchesKsk \!== false;

      if (keyTagMatch && algMatch && digestMatch) {  
        chainOfTrustValid \= true;  
        chainStatusMessage \= \`Valid & Unbroken: DS (KeyTag \${ds.keyTag}) authenticated by parent .\${parentZone}\`;  
      } else {  
        chainOfTrustValid \= false;  
        chainStatusMessage \= \`BROKEN CHAIN: Parent DS KeyTag (\${ds.keyTag}) does not match child KSK (\${kskRecord.keyTag})\! Causes SERVFAIL.\`;  
      }  
    }

    // 3\. RRSIG Signature Freshness  
    const rrsig \= zoneConfig.rrsig || null;  
    let sigExpired \= false;  
    let sigHoursRemaining \= 0;  
    let sigStatusMessage \= 'No RRSIG signature found';

    if (rrsig) {  
      const expDate \= rrsig.sigExpiration ? new Date(rrsig.sigExpiration) : null;  
      if (expDate) {  
        const msRemaining \= expDate.getTime() \- now.getTime();  
        sigHoursRemaining \= Math.round(msRemaining / (1000 \* 60 \* 60));  
        sigExpired \= msRemaining \<= 0;

        if (sigExpired) {  
          sigStatusMessage \= \`EXPIRED: Signature expired \${Math.abs(sigHoursRemaining)}h ago\! Resolvers will fail with SERVFAIL.\`;  
        } else if (sigHoursRemaining \< 48\) {  
          sigStatusMessage \= \`EXPIRING SOON: \${sigHoursRemaining}h remaining until signature expires.\`;  
        } else {  
          sigStatusMessage \= \`FRESH: Valid for \${Math.round(sigHoursRemaining / 24)} days.\`;  
        }  
      }  
    }

    // 4\. Denial of Existence (NSEC vs NSEC3)  
    const doe \= zoneConfig.denialOfExistence || { type: 'NSEC' };  
    const isNsec3 \= doe.type \=== 'NSEC3';  
    const preventsZoneWalking \= isNsec3 && doe.preventsZoneWalking \!== false;  
    const excessiveIterations \= isNsec3 && (doe.iterations || 0\) \> 50;

    // 5\. DANE TLSA Analysis  
    const dane \= zoneConfig.daneTlsa || { configured: false };  
    const daneActive \= Boolean(dane.configured);  
    const daneValid \= daneActive && dane.matchesCertSpki \!== false;

    // 6\. Rollover Policy  
    const rollover \= zoneConfig.rolloverPolicy || {};  
    const automatedRollover \= Boolean(rollover.automated);

    return {  
      zone,  
      parentZone,  
      isEnabled,  
      dnskeys: {  
        total: dnskeys.length,  
        ksk: kskRecord,  
        zsk: zskRecord,  
        hasWeakAlgorithm,  
        algorithmSummary: algorithmSummary.join(', ')  
      },  
      delegation: {  
        present: Boolean(ds),  
        dsKeyTag: ds ? ds.keyTag : null,  
        chainOfTrustValid,  
        statusMessage: chainStatusMessage  
      },  
      signatures: {  
        present: Boolean(rrsig),  
        isExpired: sigExpired,  
        hoursRemaining: sigHoursRemaining,  
        statusMessage: sigStatusMessage,  
        typeCovered: rrsig ? rrsig.typeCovered : null  
      },  
      denialOfExistence: {  
        type: doe.type,  
        isNsec3,  
        preventsZoneWalking,  
        excessiveIterations,  
        iterations: doe.iterations || 0,  
        salt: doe.salt || null  
      },  
      dane: {  
        active: daneActive,  
        valid: daneValid,  
        record: dane.record || null,  
        usage: dane.usage,  
        selector: dane.selector  
      },  
      rollover: {  
        automated: automatedRollover,  
        cooldownWindowHours: rollover.cooldownWindowHours || 0  
      }  
    };  
  }

  return {  
    DNSSEC\_ALGORITHMS,  
    DS\_DIGEST\_TYPES,  
    inspectDNSSEC  
  };  
});  
