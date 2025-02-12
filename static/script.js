function updateStats(flows, blockedIPs) {
    const totalFlows = flows.length;
    const attackFlows = flows.filter(f => f.Prediction === 'Attack').length;

    $('#totalFlows').text(totalFlows);
    $('#attackFlows').text(attackFlows);
    $('#blockedIPs').text(blockedIPs.length);
}

function updateFlows() {
    $.get('/flows', function (data) {
        $('#flowData').empty();
        // Only show the 10 most recent flows
        const recentFlows = data.flows.slice(-10);
        recentFlows.forEach(function (flow) {
            const statusBadge = flow.Prediction === 'Attack'
                ? '<span class="badge bg-danger">Attack</span>'
                : '<span class="badge bg-success">Benign</span>';

            const row = `
                <tr>
                    <td>${flow.Timestamp}</td>
                    <td>${flow['Src IP']}</td>
                    <td>${flow['Src Country'] || 'Unknown'}</td>
                    <td>${flow['Dst IP']}</td>
                    <td>${flow['Dst Country'] || 'Unknown'}</td>
                    <td>${flow['Src Port']}</td>
                    <td>${flow['Dst Port']}</td>
                    <td>${flow['Protocol']}</td>
                    <td>${statusBadge}</td>
                    <td>${flow['Tot Fwd Pkts'] + flow['Tot Bwd Pkts']}</td>
                </tr>
            `;
            $('#flowData').append(row);
        });
        updateStats(data.flows, data.blocked_ips);
    });
}

function blockIP(ip) {
    $.ajax({
        url: '/block_ip',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ip: ip }),
        success: function (response) {
            updateFlows();
        }
    });
}

$('#startCapture').click(function () {
    $.get('/start_capture', function (data) {
        if (data.status === 'success') {
            $('#captureStatus').text('Running');
        }
    });
});

$('#stopCapture').click(function () {
    $.get('/stop_capture', function (data) {
        if (data.status === 'success') {
            $('#captureStatus').text('Stopped');
        }
    });
});

$('#downloadCSV').click(function () {
    window.location.href = '/download_csv';
});
// Page Navigation
$('.nav-item').click(function () {
    // Remove active class from all nav items
    $('.nav-item').removeClass('active');
    $(this).addClass('active');

    // Show/hide appropriate pages
    const page = $(this).data('page');
    if (page === 'dashboard') {
        $('#dashboardPage').show();
        $('#securityPage').hide();
    } else if (page === 'security') {
        $('#dashboardPage').hide();
        $('#securityPage').show();
        updateSecurityPage();
    }
});

// Function to update Security Page
function updateSecurityPage() {
    $.get('/detected_attacks', function (data) {
        // Update Attacks Table
        $('#attacksData').empty();
        data.attacks.forEach(function (attack) {
            const row = `
                <tr>
                    <td>${attack.Timestamp}</td>
                    <td>${attack['Src IP']}</td>
                    <td>${attack['Src Country'] || 'Unknown'}</td>
                    <td>${attack['Dst IP']}</td>
                    <td>${attack['Dst Country'] || 'Unknown'}</td>
                    <td>${attack['Src Port']}</td>
                    <td>${attack['Dst Port']}</td>
                    <td>${attack['Protocol']}</td>
                    <td><span class="badge bg-danger">${attack.Prediction}</span></td>
                    <td>${attack['Tot Fwd Pkts'] + attack['Tot Bwd Pkts']}</td>
                    <td>
                        <i class="fas fa-ban action-icon" onclick="blockIP('${attack['Src IP']}')"></i>
                        <i class="fas fa-info-circle action-icon" onclick="showAttackDetails('${attack.id}')"></i>
                    </td>
                </tr>
            `;
            $('#attacksData').append(row);
        });

        // Update Blocked IPs Table
        $('#blockedIPsData').empty();
        data.blocked_ips.forEach(function (ip) {
            const row = `
                        <tr>
                            <td>${ip.ip}</td>
                            <td>${ip.blocked_at}</td>
                            <td>
                                <i class="fas fa-unlock action-icon" onclick="unblockIP('${ip.ip}')"></i>
                            </td>
                        </tr>
                    `;
            $('#blockedIPsData').append(row);
        });
    });
}

// Clear Attacks functionality
$('#clearAttacks').click(function () {
    $.ajax({
        url: '/clear_attacks',
        method: 'POST',
        success: function (response) {
            updateSecurityPage();
        }
    });
});

// Show Attack Details (placeholder function)
function showAttackDetails(attackId) {
    alert('Detailed attack information for ID: ' + attackId);
    // You can expand this to show a modal with more details
}

// Unblock IP function
function unblockIP(ip) {
    $.ajax({
        url: '/unblock_ip',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ip: ip }),
        success: function (response) {
            updateSecurityPage();
        }
    });
}
// Page Navigation
$('.nav-item').click(function () {
    $('.nav-item').removeClass('active');
    $(this).addClass('active');

    const page = $(this).data('page');
    $('#dashboardPage, #securityPage, #statisticsPage').hide();

    if (page === 'dashboard') {
        $('#dashboardPage').show();
    } else if (page === 'security') {
        $('#securityPage').show();
        updateSecurityPage();
    } else if (page === 'statistics') {
        $('#statisticsPage').show();
        updateStatisticsPage();
    }
});

// Function to update Statistics Page
function updateStatisticsPage() {
    $.get('/network_statistics', function (data) {
        // Top Attacker IPs
        $('#topAttackerIPs').empty();
        data.top_attacker_ips.forEach(function (ip) {
            const statItem = `
                        <div class="stat-item">
                            <span class="stat-label">${ip.ip}</span>
                            <span class="stat-value">${ip.attack_count} attacks</span>
                        </div>
                    `;
            $('#topAttackerIPs').append(statItem);
        });

        // Top Victim IPs
        $('#topVictimIPs').empty();
        data.top_victim_ips.forEach(function (ip) {
            const statItem = `
                        <div class="stat-item">
                            <span class="stat-label">${ip.ip}</span>
                            <span class="stat-value">${ip.attack_count} attacks</span>
                        </div>
                    `;
            $('#topVictimIPs').append(statItem);
        });

        // Network Traffic Summary
        $('#totalPackets').text(data.total_packets);
        $('#avgPacketSize').text(data.avg_packet_size + ' bytes');
        $('#uniqueIPs').text(data.unique_ips);

        // Attack Statistics
        $('#totalAttacks').text(data.total_attacks);
        $('#attackRate').text(data.attack_rate.toFixed(2) + '%');
        $('#commonAttackType').text(data.common_attack_type);

        // Blocked & Quarantined
        $('#blockedIPCount').text(data.blocked_ip_count);
        $('#avgQuarantineDuration').text(data.avg_quarantine_duration.toFixed(1) + 'h');
        $('#unblockCount').text(data.unblocked_ip_count);
    });
}

// Update flows every 3 seconds
setInterval(updateFlows, 100);
updateFlows();  // Initial update