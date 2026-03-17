// Results rendering
function renderResults(scanResponse) {
    const container = document.getElementById('results');
    const explanationItems = buildProfessionalExplanationItems(scanResponse);
    const explanationList = explanationItems.map(item => `<li>${item}</li>`).join('');
    
    container.innerHTML = `
        <div class="verdict-badge">
            ${renderVerdictBadge(scanResponse.verdict)}
        </div>
        
        <div class="threat-meter">
            <div class="meter-label">
                <span>Threat Score</span>
                <span>${scanResponse.threat_score}/100</span>
            </div>
            ${renderThreatMeter(scanResponse.threat_score, scanResponse.verdict)}
        </div>
        
        
        <div class="channels">
            ${renderMergedClassifierCard(scanResponse)}
        </div>
      
        <div class="explanation">
            <h3>Analysis Explanation</h3>
            <ul>${explanationList}</ul>
        </div>
    `;
    
    container.classList.remove('hidden');
    
    // Animate meters
    animateCountUp(document.querySelector('.meter-label span:last-child'), scanResponse.threat_score);
    animateMeters();
}

function normalizeProbabilities(probabilities) {
    const benign = Number(probabilities?.Benign || 0);
    const phishing = Number(probabilities?.Phishing || 0);
    const malware = Number(probabilities?.Malware || 0);

    const total = benign + phishing + malware;
    if (total <= 0) {
        return { Benign: 0, Phishing: 0, Malware: 0 };
    }

    return {
        Benign: benign / total,
        Phishing: phishing / total,
        Malware: malware / total
    };
}

function renderVerdictBadge(verdict) {
    const classes = {
        'SAFE': 'safe',
        'SUSPICIOUS': 'suspicious', 
        'PHISHING': 'phishing',
        'MALWARE': 'malware'
    };
    
    return `<div class="badge ${classes[verdict] || 'safe'}">${verdict}</div>`;
}

function renderThreatMeter(score, verdict) {
    const classes = {
        'SAFE': 'safe',
        'SUSPICIOUS': 'suspicious',
        'PHISHING': 'phishing', 
        'MALWARE': 'malware'
    };
    
    return `
        <div class="meter-bar">
            <div class="meter-fill ${classes[verdict] || 'safe'}" style="width: 0%"></div>
        </div>
    `;
}

function renderMergedClassifierCard(scanResponse) {
    const aiResult = scanResponse.ai_result || {};
    const vtResult = scanResponse.vt_result || {};
    const gsbResult = scanResponse.gsb_result || {};
    const probs = normalizeProbabilities(aiResult?.probabilities);
    const benignPct = (probs.Benign * 100).toFixed(2);
    const phishingPct = (probs.Phishing * 100).toFixed(2);
    const malwarePct = (probs.Malware * 100).toFixed(2);
    const predictedLabel = aiResult?.prediction || 'Unknown';
    const predictedConfidence = probs[predictedLabel] !== undefined
        ? (probs[predictedLabel] * 100).toFixed(2)
        : (Math.max(probs.Benign, probs.Phishing, probs.Malware) * 100).toFixed(2);
    const malicious = vtResult.malicious || 0;
    const total = vtResult.total_engines || 0;
    const suspicious = vtResult.suspicious || 0;
    const vtStatus = humanizeStatus(vtResult.status || 'ok');
    const safeResult = gsbResult.is_safe === false ? 'Threat match detected' : 'No direct match';
    const safeStatus = humanizeStatus(gsbResult.status || 'ok');
    
    return `
        <div class="channel">
            <h3>URL Classifier Intelligence</h3>
            <div class="prob-bars">
                <div class="prob-bar">
                    <div class="prob-fill benign" data-percent="${benignPct}" style="width: 0%"></div>
                    <div class="prob-label">Benign<br>${benignPct}%</div>
                </div>
                <div class="prob-bar">
                    <div class="prob-fill phishing" data-percent="${phishingPct}" style="width: 0%"></div>
                    <div class="prob-label">Phishing<br>${phishingPct}%</div>
                </div>
                <div class="prob-bar">
                    <div class="prob-fill malware" data-percent="${malwarePct}" style="width: 0%"></div>
                    <div class="prob-label">Malware<br>${malwarePct}%</div>
                </div>
            </div>
            <p><strong>Prediction:</strong> ${predictedLabel}</p>
            <p><strong>Model Confidence:</strong> ${predictedConfidence}%</p>
            <p><strong>Detection Signals:</strong> ${malicious}/${total} malicious, ${suspicious} suspicious</p>
            <p><strong>Safety Screening:</strong> ${safeResult}</p>
            <p><strong>Signal Status:</strong> ${vtStatus} | ${safeStatus}</p>
        </div>
    `;
}

function humanizeStatus(status) {
    const value = String(status || 'ok').replace(/_/g, ' ');
    return value.charAt(0).toUpperCase() + value.slice(1);
}

function buildProfessionalExplanationItems(scanResponse) {
    const ai = scanResponse.ai_result || {};
    const vt = scanResponse.vt_result || {};
    const gsb = scanResponse.gsb_result || {};
    const probs = normalizeProbabilities(ai.probabilities || {});

    const prediction = ai.prediction || 'Unknown';
    const aiConfidence = probs[prediction] !== undefined
        ? (probs[prediction] * 100).toFixed(2)
        : ((ai.confidence || 0) * 100).toFixed(2);
    const malicious = vt.malicious || 0;
    const total = vt.total_engines || 0;
    const statusLine = gsb.is_safe
        ? 'Supplementary web safety validation did not identify direct threat matches'
        : 'Supplementary web safety validation identified threat indicators';

    return [
        `URL classifier prediction: ${prediction} (${aiConfidence}% confidence).`,
        `Independent detection checks: ${malicious}/${total} flagged as malicious.`,
        `${statusLine}.`,
        `Final decision: ${scanResponse.verdict} with threat score ${scanResponse.threat_score}/100.`
    ];
}

function animateMeters() {
    // Animate threat meter
    const threatFill = document.querySelector('.meter-fill');
    if (threatFill) {
        const score = parseInt(document.querySelector('.meter-label span:last-child').textContent);
        threatFill.style.width = `${score}%`;
    }
    
    // Animate probability bars
    document.querySelectorAll('.prob-fill').forEach(fill => {
        const percent = parseFloat(fill.dataset.percent || '0');
        if (!Number.isNaN(percent)) {
            fill.style.width = `${percent}%`;
        }
    });
}

function animateCountUp(element, target) {
    let current = 0;
    const increment = target / 50;
    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            current = target;
            clearInterval(timer);
        }
        element.textContent = Math.round(current) + '/100';
    }, 20);
}