// Email scan results renderer
function renderEmailResults(response) {
    const container = document.getElementById('results');

    container.innerHTML = `
        <div class="verdict-badge">
            ${renderEmailVerdictBadge(response.verdict, response.overall_score)}
        </div>
        <div class="email-breakdown">
            ${renderEmailThreatBreakdown(response.sender_analysis.risk_score, response.subject_analysis.risk_score, response.body_analysis.risk_score, response.url_results.length ? Math.max(...response.url_results.map(u => u.threat_score)) : 0)}
        </div>
        <div class="channels">
            ${renderSenderAnalysis(response.sender_analysis)}
            ${renderSubjectAnalysis(response.subject_analysis)}
            ${renderBodyAnalysis(response.body_analysis)}
        </div>
        <div class="email-urls">
            ${renderExtractedURLs(response.url_results)}
        </div>
        <div class="explanation">
            <h3>Email Threat Explanation</h3>
            <p>${response.explanation}</p>
        </div>
    `;

    container.classList.remove('hidden');
}

function renderEmailVerdictBadge(verdict, score) {
    const classes = {
        'SAFE': 'safe',
        'SUSPICIOUS': 'suspicious',
        'PHISHING': 'phishing',
        'MALWARE': 'malware'
    };

    return `<div class="badge ${classes[verdict] || 'safe'}">📧 ${verdict} (${score})</div>`;
}

function renderSenderAnalysis(senderAnalysis) {
    const spoofed = senderAnalysis.is_spoofed;
    return `
        <div class="channel">
            <h3>✉️ Sender Analysis</h3>
            <p><strong>Email:</strong> ${senderAnalysis.email}</p>
            <p><strong>Domain:</strong> ${senderAnalysis.domain}</p>
            <p><strong>Risk Score:</strong> ${senderAnalysis.risk_score}</p>
            <p><strong>Reason:</strong> ${senderAnalysis.reason}</p>
            ${spoofed ? `<p class="danger">⚠ Spoofed domain detected (${senderAnalysis.spoofed_brand})</p>` : ''}
        </div>
    `;
}

function renderSubjectAnalysis(subjectAnalysis) {
    const keywords = subjectAnalysis.triggered_keywords || [];
    const tags = keywords.map(k => `<span class="tag danger">${k}</span>`).join(' ');

    return `
        <div class="channel">
            <h3>📝 Subject Analysis</h3>
            <p><strong>Subject:</strong> ${subjectAnalysis.subject}</p>
            <p><strong>Category:</strong> ${subjectAnalysis.category}</p>
            <p><strong>Risk Score:</strong> ${subjectAnalysis.risk_score}</p>
            <p>${subjectAnalysis.reason}</p>
            <p>${tags}</p>
        </div>
    `;
}

function renderBodyAnalysis(bodyAnalysis) {
    const credentialTags = (bodyAnalysis.credential_phrases || []).map(p => `<span class="tag danger">${p}</span>`).join(' ');
    const patternTags = (bodyAnalysis.suspicious_patterns || []).map(p => `<span class="tag warning">${p}</span>`).join(' ');
    const manipTags = (bodyAnalysis.manipulation_tactics || []).map(p => `<span class="tag warning">${p}</span>`).join(' ');

    return `
        <div class="channel">
            <h3>📄 Body Analysis</h3>
            <p><strong>Risk Score:</strong> ${bodyAnalysis.risk_score}</p>
            <p>${bodyAnalysis.reason}</p>
            <p>${credentialTags}</p>
            <p>${patternTags}</p>
            <p>${manipTags}</p>
        </div>
    `;
}

function renderExtractedURLs(urlResults) {
    if (!urlResults || urlResults.length === 0) {
        return `
            <div class="channel">
                <h3>🔗 URLs found in email (0)</h3>
                <p>No URLs detected.</p>
            </div>
        `;
    }

    const items = urlResults.map(urlResult => {
        return `
            <div class="email-url-card">
                <div class="email-url-header">
                    <div class="email-url">${urlResult.url}</div>
                    <div class="history-verdict ${urlResult.verdict.toLowerCase()}">${urlResult.verdict}</div>
                </div>
                <div class="email-url-sub">Detections: ${urlResult.vt_result.malicious}/${urlResult.vt_result.total_engines} | Score: ${urlResult.threat_score}</div>
            </div>
        `;
    }).join('');

    return `
        <div class="channel">
            <h3>🔗 URLs found in this email (${urlResults.length})</h3>
            ${items}
        </div>
    `;
}

function renderEmailThreatBreakdown(senderScore, subjectScore, bodyScore, urlScore) {
    const bars = [
        { label: 'Sender', score: senderScore, color: 'var(--accent)' },
        { label: 'Subject', score: subjectScore, color: 'var(--info)' },
        { label: 'Body', score: bodyScore, color: 'var(--warning)' },
        { label: 'URLs', score: urlScore, color: 'var(--danger)' }
    ];

    const rows = bars.map(bar => `
        <div class="breakdown-row">
            <div class="breakdown-label">${bar.label}</div>
            <div class="breakdown-bar">
                <div class="breakdown-fill" style="width: ${bar.score}%; background: ${bar.color};"></div>
            </div>
            <div class="breakdown-value">${bar.score}%</div>
        </div>
    `).join('');

    return `
        <div class="email-breakdown-card">
            <h3>Threat Breakdown</h3>
            ${rows}
        </div>
    `;
}
