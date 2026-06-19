document.addEventListener("DOMContentLoaded", function() {
    // Shared chart styling config
    const textLightColor = '#8b9bb4';
    const gridLineColor = 'rgba(255, 255, 255, 0.05)';
    
    // Helper to fetch JSON from API
    async function fetchJson(url) {
        try {
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return await response.json();
        } catch (e) {
            console.error(`Failed to fetch data from ${url}:`, e);
            return null;
        }
    }

    // 1. Trust Distribution Chart (Doughnut)
    const trustCtx = document.getElementById('trustChart');
    if (trustCtx) {
        fetchJson('/api/trust-distribution').then(data => {
            if (!data) return;
            
            new Chart(trustCtx, {
                type: 'doughnut',
                data: {
                    labels: data.labels,
                    datasets: [{
                        data: data.data,
                        backgroundColor: [
                            'rgba(0, 230, 118, 0.7)',  // Trusted Green
                            'rgba(255, 179, 0, 0.7)',  // Warning Orange
                            'rgba(255, 23, 68, 0.7)'   // Danger Red
                        ],
                        borderColor: [
                            '#00e676',
                            '#ffb300',
                            '#ff1744'
                        ],
                        borderWidth: 1.5
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: textLightColor,
                                font: { family: 'Outfit' }
                            }
                        }
                    },
                    cutout: '70%'
                }
            });
        });
    }

    // 2. ML Threat Classification Engine (Bar Chart)
    const threatCtx = document.getElementById('threatChart');
    if (threatCtx) {
        fetchJson('/api/threat-classification-stats').then(data => {
            if (!data) return;
            
            new Chart(threatCtx, {
                type: 'bar',
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: 'Incidents Classified',
                        data: data.data,
                        backgroundColor: [
                            'rgba(0, 242, 254, 0.4)',  // Normal Blue
                            'rgba(255, 179, 0, 0.4)',  // Suspicious Orange
                            'rgba(255, 23, 68, 0.4)'   // High Risk Red
                        ],
                        borderColor: [
                            '#00f2fe',
                            '#ffb300',
                            '#ff1744'
                        ],
                        borderWidth: 1.5,
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: textLightColor, font: { family: 'Outfit' } }
                        },
                        y: {
                            grid: { color: gridLineColor },
                            ticks: { color: textLightColor, stepSize: 1 }
                        }
                    }
                }
            });
        });
    }

    // 3. Login Activity Trends (Line Chart)
    const trendsCtx = document.getElementById('trendsChart');
    if (trendsCtx) {
        fetchJson('/api/login-trends').then(data => {
            if (!data) return;
            
            new Chart(trendsCtx, {
                type: 'line',
                data: {
                    labels: data.labels,
                    datasets: [
                        {
                            label: 'Success Logins',
                            data: data.success,
                            borderColor: '#00e676',
                            backgroundColor: 'rgba(0, 230, 118, 0.05)',
                            tension: 0.3,
                            fill: true,
                            borderWidth: 2
                        },
                        {
                            label: 'Failed Logins',
                            data: data.failed,
                            borderColor: '#ff1744',
                            backgroundColor: 'rgba(255, 23, 68, 0.05)',
                            tension: 0.3,
                            fill: true,
                            borderWidth: 2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: textLightColor,
                                font: { family: 'Outfit' }
                            }
                        }
                    },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: textLightColor, font: { family: 'Outfit' } }
                        },
                        y: {
                            grid: { color: gridLineColor },
                            ticks: { color: textLightColor, stepSize: 1 }
                        }
                    }
                }
            });
        });
    }
});
