/\*\*  
 \* DNSSECGuard Pro \- Web Application Orchestrator  
 \*/

(function () {  
  'use strict';

  // Embedded Presets for 100% Offline / Client-Side Execution  
  const PRESETS \= {  
    apex: {  
      name: "Apex FinBank (ECDSA P-256 & DANE TLSA \- Grade A+)",  
      zone: "apexfinbank.com",  
      dnssecEnabled: true,  
      parentZone: "com",  
      dnskey: \[  
        {  
          keyTag: 48210,  
          flags: 257,  
          protocol: 3,  
          algorithm: 13,  
          algorithmName: "ECDSAP256SHA256",  
          keyType: "KSK",  
          publicKey: "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0r3Ouz+v8CmbKwghw==",  
          bits: 256  
        },  
        {  
          keyTag: 19283,  
          flags: 256,  
          protocol: 3,  
          algorithm: 13,  
          algorithmName: "ECDSAP256SHA256",  
          keyType: "ZSK",  
          publicKey: "oJM1w95eH5KxF9q0YjM6A+6Z2Gk0Fz9F5XG4rD1P0Lw==",  
          bits: 256  
        }  
      \],  
      dsRecord: {  
        keyTag: 48210,  
        algorithm: 13,  
        digestType: 2,  
        digestTypeName: "SHA-256",  
        digest: "8F3B92A41D7E5C6B901A884EFC712894B5D6E7F8019A2B3C4D5E6F7A8B9C0D1E",  
        matchesKsk: true  
      },  
      denialOfExistence: {  
        type: "NSEC3",  
        hashAlgorithm: 1,  
        optOut: false,  
        iterations: 1,  
        salt: "a1b2c3d4e5f60718",  
        preventsZoneWalking: true  
      },  
      rrsig: {  
        typeCovered: "A",  
        algorithm: 13,  
        labels: 2,  
        originalTtl: 3600,  
        sigInception: "2026-09-28T00:00:00Z",  
        sigExpiration: "2026-10-12T00:00:00Z",  
        keyTag: 19283,  
        signerName: "apexfinbank.com",  
        isExpired: false,  
        hoursRemaining: 264  
      },  
      daneTlsa: {  
        configured: true,  
        record: "\_443.\_tcp.api.apexfinbank.com. IN TLSA 3 1 1 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  
        usage: 3,  
        usageName: "DANE-EE",  
        selector: 1,  
        matchingType: 1,  
        matchesCertSpki: true  
      },  
      rolloverPolicy: {  
        automated: true,  
        kskLifetimeDays: 365,  
        zskLifetimeDays: 90,  
        cooldownWindowHours: 72  
      }  
    },  
    cloudpulse: {  
      name: "CloudPulse SaaS (Cloudflare NSEC3 Optimized \- Grade A+)",  
      zone: "cloudpulse.io",  
      dnssecEnabled: true,  
      parentZone: "io",  
      dnskey: \[  
        {  
          keyTag: 2371,  
          flags: 257,  
          protocol: 3,  
          algorithm: 13,  
          algorithmName: "ECDSAP256SHA256",  
          keyType: "CSK",  
          publicKey: "K8vQW3gN9vC2XyZ4LmPo1QrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfG",  
          bits: 256  
        }  
      \],  
      dsRecord: {  
        keyTag: 2371,  
        algorithm: 13,  
        digestType: 2,  
        digestTypeName: "SHA-256",  
        digest: "3A4B5C6D7E8F901A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F901A2B3C4D5E6F",  
        matchesKsk: true  
      },  
      denialOfExistence: {  
        type: "NSEC3",  
        hashAlgorithm: 1,  
        optOut: false,  
        iterations: 0,  
        salt: "-",  
        preventsZoneWalking: true  
      },  
      rrsig: {  
        typeCovered: "A",  
        algorithm: 13,  
        labels: 2,  
        originalTtl: 300,  
        sigInception: "2026-09-25T00:00:00Z",  
        sigExpiration: "2026-10-06T00:00:00Z",  
        keyTag: 2371,  
        signerName: "cloudpulse.io",  
        isExpired: false,  
        hoursRemaining: 120  
      },  
      daneTlsa: {  
        configured: false,  
        record: null,  
        usage: null,  
        selector: null,  
        matchingType: null,  
        matchesCertSpki: false  
      },  
      rolloverPolicy: {  
        automated: true,  
        kskLifetimeDays: 730,  
        zskLifetimeDays: 180,  
        cooldownWindowHours: 48  
      }  
    },  
    legacy: {  
      name: "Legacy Corp Portal (Broken DS Chain & RSASHA1 \- Grade F)",  
      zone: "legacy-portal.internal-corp.net",  
      dnssecEnabled: true,  
      parentZone: "net",  
      dnskey: \[  
        {  
          keyTag: 59124,  
          flags: 257,  
          protocol: 3,  
          algorithm: 5,  
          algorithmName: "RSASHA1",  
          keyType: "KSK",  
          publicKey: "AQO8r1W8q2Z4tY6uI8oP0lK...",  
          bits: 1024  
        },  
        {  
          keyTag: 31415,  
          flags: 256,  
          protocol: 3,  
          algorithm: 5,  
          algorithmName: "RSASHA1",  
          keyType: "ZSK",  
          publicKey: "AQO3k2J1h0g9f8e7d6c5b4a...",  
          bits: 1024  
        }  
      \],  
      dsRecord: {  
        keyTag: 10045,  
        algorithm: 5,  
        digestType: 1,  
        digestTypeName: "SHA-1",  
        digest: "DEADBEEF1234567890ABCDEFDEADBEEF12345678",  
        matchesKsk: false  
      },  
      denialOfExistence: {  
        type: "NSEC",  
        preventsZoneWalking: false,  
        exposedNextDomain: "staging-admin.internal-corp.net"  
      },  
      rrsig: {  
        typeCovered: "A",  
        algorithm: 5,  
        labels: 2,  
        originalTtl: 86400,  
        sigInception: "2026-09-01T00:00:00Z",  
        sigExpiration: "2026-09-27T00:00:00Z",  
        keyTag: 31415,  
        signerName: "legacy-portal.internal-corp.net",  
        isExpired: true,  
        hoursRemaining: \-72  
      },  
      daneTlsa: {  
        configured: false,  
        record: null,  
        usage: null,  
        selector: null,  
        matchingType: null,  
        matchesCertSpki: false  
      },  
      rolloverPolicy: {  
        automated: false,  
        kskLifetimeDays: 1000,  
        zskLifetimeDays: 500,  
        cooldownWindowHours: 0  
      }  
    }  
  };

  let currentParsedConfig \= null;  
  let activeSynthTarget \= 'bind';  
  let activeSimScenario \= 'chain';

  // DOM Elements  
  const presetSelector \= document.getElementById('presetSelector');  
  const configInput \= document.getElementById('configInput');  
  const btnAudit \= document.getElementById('btnAudit');  
  const btnReset \= document.getElementById('btnReset');  
  const inspZone \= document.getElementById('inspZone');  
  const inspDs \= document.getElementById('inspDs');  
  const inspAlg \= document.getElementById('inspAlg');  
  const inspDoe \= document.getElementById('inspDoe');  
  const gradeBadge \= document.getElementById('gradeBadge');  
  const scoreText \= document.getElementById('scoreText');  
  const gradeSummary \= document.getElementById('gradeSummary');  
  const scoreSummaryTag \= document.getElementById('scoreSummaryTag');  
  const checksContainer \= document.getElementById('checksContainer');  
  const btnSimChain \= document.getElementById('btnSimChain');  
  const btnSimWalk \= document.getElementById('btnSimWalk');  
  const simUnhardenedSummary \= document.getElementById('simUnhardenedSummary');  
  const simHardenedSummary \= document.getElementById('simHardenedSummary');  
  const simUnhardenedTimeline \= document.getElementById('simUnhardenedTimeline');  
  const simHardenedTimeline \= document.getElementById('simHardenedTimeline');  
  const codeOutput \= document.getElementById('codeOutput');  
  const btnCopyCode \= document.getElementById('btnCopyCode');

  function loadPreset(key) {  
    const preset \= PRESETS\[key\] || PRESETS.apex;  
    configInput.value \= JSON.stringify(preset, null, 2);  
    runAnalysis();  
  }

  function runAnalysis() {  
    let parsed;  
    try {  
      parsed \= JSON.parse(configInput.value);  
      currentParsedConfig \= parsed;  
    } catch (e) {  
      alert('JSON Syntax Error: ' \+ e.message);  
      return;  
    }

    const refDate \= new Date('2026-09-30T12:00:00Z');  
    const result \= window.DNSSECAuditor.auditDNSSECConfig(parsed, refDate);  
    const inspected \= result.inspected;

    // Update Inspector Pills  
    inspZone.textContent \= \`\${inspected.zone} (.\${inspected.parentZone})\`;  
    inspDs.textContent \= inspected.delegation.chainOfTrustValid  
      ? \`Valid (KeyTag \${inspected.delegation.dsKeyTag})\`  
      : 'BROKEN CHAIN (SERVFAIL)';  
    inspDs.style.color \= inspected.delegation.chainOfTrustValid ? 'var(--accent-emerald)' : 'var(--accent-rose)';

    inspAlg.textContent \= inspected.dnskeys.algorithmSummary || 'None';  
    inspAlg.style.color \= inspected.dnskeys.hasWeakAlgorithm ? 'var(--accent-rose)' : 'var(--accent-cyan)';

    inspDoe.textContent \= \`\${inspected.denialOfExistence.type} (\${inspected.dane.active ? 'DANE Active' : 'No DANE'})\`;

    // Update Scorecard  
    scoreText.textContent \= \`\${result.overallScore} / 100 Points\`;  
    gradeBadge.textContent \= result.grade;  
    gradeBadge.className \= 'grade-circle';  
    if (result.grade \=== 'F' || result.grade \=== 'D') {  
      gradeBadge.classList.add('grade-f');  
    } else if (result.grade \=== 'A+' || result.grade \=== 'A') {  
      gradeBadge.classList.add('grade-a');  
    }

    scoreSummaryTag.textContent \= \`\${result.summary.passed} Passed • \${result.summary.warnings} Warnings • \${result.summary.failures} Failures\`;  
    gradeSummary.textContent \= \`\${result.grade \=== 'A+' ? 'Chain-of-Trust Authenticated' : 'Audit Complete'} • \${result.summary.failures} Outage Risks Identified\`;

    // Render Checks  
    checksContainer.innerHTML \= '';  
    result.checks.forEach(function (c) {  
      const item \= document.createElement('div');  
      item.className \= 'check-item';

      const badgeClass \=  
        c.status \=== 'PASS'  
          ? 'badge-pass'  
          : c.status \=== 'WARN'  
          ? 'badge-warn'  
          : c.status \=== 'FAIL'  
          ? 'badge-fail'  
          : 'badge-info';

      item.innerHTML \= \`  
        \<div class="check-header"\>  
          \<span class="check-name"\>\${c.title}\</span\>  
          \<span class="badge \${badgeClass}"\>\${c.status} (\${c.score}/\${c.weight})\</span\>  
        \</div\>  
        \<div class="check-desc"\>\${c.details}\</div\>  
        \${c.remediation ? \`\<div class="check-remediation"\>Remediation: \${c.remediation}\</div\>\` : ''}  
      \`;  
      checksContainer.appendChild(item);  
    });

    renderSimulation();  
    renderSynthesizer();  
  }

  function renderSimulation() {  
    if (activeSimScenario \=== 'chain') {  
      const unhardened \= window.DNSSECSimulator.simulateChainBreak({ gracefulRollover: false });  
      const hardened \= window.DNSSECSimulator.simulateChainBreak({ gracefulRollover: true });

      simUnhardenedSummary.textContent \= unhardened.verdict;  
      simHardenedSummary.textContent \= hardened.verdict;

      simUnhardenedTimeline.innerHTML \= unhardened.steps.map(s \=\> \`  
        \<div class="timeline-step \${s.isOutage ? 'step-outage' : ''}"\>  
          \<strong\>\${s.phase}\</strong\>: \${s.action}  
          \<div style="font-size: 11px; margin-top: 2px; color: \${s.isOutage ? 'var(--accent-rose)' : 'var(--accent-emerald)'};"\>  
            \${s.resolverStatus}  
          \</div\>  
        \</div\>  
      \`).join('');

      simHardenedTimeline.innerHTML \= hardened.steps.map(s \=\> \`  
        \<div class="timeline-step"\>  
          \<strong\>\${s.phase}\</strong\>: \${s.action}  
          \<div style="font-size: 11px; margin-top: 2px; color: var(--accent-emerald);"\>  
            \${s.resolverStatus}  
          \</div\>  
        \</div\>  
      \`).join('');  
    } else {  
      const unhardened \= window.DNSSECSimulator.simulateZoneWalking({ isNsec3: false });  
      const hardened \= window.DNSSECSimulator.simulateZoneWalking({ isNsec3: true });

      simUnhardenedSummary.textContent \= unhardened.verdict;  
      simHardenedSummary.textContent \= hardened.verdict;

      simUnhardenedTimeline.innerHTML \= unhardened.steps.map(s \=\> \`  
        \<div class="timeline-step \${s.compromised ? 'step-outage' : ''}"\>  
          \<strong\>\${s.phase}\</strong\>: \${s.attackerAction}  
          \<div style="font-size: 11px; margin-top: 2px; color: \${s.compromised ? 'var(--accent-rose)' : 'var(--text-muted)'};"\>  
            \${s.dnsResponse || s.outcome}  
          \</div\>  
        \</div\>  
      \`).join('');

      simHardenedTimeline.innerHTML \= hardened.steps.map(s \=\> \`  
        \<div class="timeline-step"\>  
          \<strong\>\${s.phase}\</strong\>: \${s.attackerAction}  
          \<div style="font-size: 11px; margin-top: 2px; color: var(--accent-emerald);"\>  
            \${s.dnsResponse || s.outcome}  
          \</div\>  
        \</div\>  
      \`).join('');  
    }  
  }

  function renderSynthesizer() {  
    if (\!currentParsedConfig) return;  
    const synth \= window.DNSSynthesizer;  
    let code \= '';  
    if (activeSynthTarget \=== 'bind') {  
      code \= synth.generateBindConfig(currentParsedConfig);  
    } else if (activeSynthTarget \=== 'ds') {  
      code \= synth.generateDsRecord(currentParsedConfig);  
    } else if (activeSynthTarget \=== 'dane') {  
      code \= synth.generateDaneTlsa(currentParsedConfig);  
    } else if (activeSynthTarget \=== 'python') {  
      code \= synth.generatePythonResolver(currentParsedConfig);  
    }  
    codeOutput.textContent \= code;  
  }

  // Event Listeners  
  presetSelector.addEventListener('change', function () {  
    loadPreset(this.value);  
  });

  btnAudit.addEventListener('click', runAnalysis);

  btnReset.addEventListener('click', function () {  
    loadPreset(presetSelector.value);  
  });

  btnSimChain.addEventListener('click', function () {  
    activeSimScenario \= 'chain';  
    btnSimChain.classList.add('active');  
    btnSimWalk.classList.remove('active');  
    renderSimulation();  
  });

  btnSimWalk.addEventListener('click', function () {  
    activeSimScenario \= 'walk';  
    btnSimWalk.classList.add('active');  
    btnSimChain.classList.remove('active');  
    renderSimulation();  
  });

  document.querySelectorAll('.synth-tabs button').forEach(function (btn) {  
    btn.addEventListener('click', function () {  
      document.querySelectorAll('.synth-tabs button').forEach(b \=\> b.classList.remove('active'));  
      btn.classList.add('active');  
      activeSynthTarget \= btn.getAttribute('data-target');  
      renderSynthesizer();  
    });  
  });

  btnCopyCode.addEventListener('click', function () {  
    navigator.clipboard.writeText(codeOutput.textContent).then(function () {  
      const originalText \= btnCopyCode.textContent;  
      btnCopyCode.textContent \= 'Copied\!';  
      setTimeout(function () {  
        btnCopyCode.textContent \= originalText;  
      }, 1800);  
    });  
  });

  // Initial Load  
  loadPreset('apex');  
})();  
