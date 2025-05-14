// Real-time updates
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Connect to Socket.IO
    const socket = io();
    
    // Handle real-time device updates
    socket.on('device_update', function(data) {
        console.log('Device update:', data);
        // Update UI as needed
    });
    
    // Handle alerts
    socket.on('new_alert', function(data) {
        showAlertNotification(data);
    });
    
    // Trust/Untrust device buttons
    document.querySelectorAll('.trust-btn').forEach(button => {
        button.addEventListener('click', function() {
            const deviceId = this.dataset.deviceId;
            const trusted = this.dataset.trusted === 'true';
            
            fetch('/api/trust_device', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    device_id: deviceId,
                    trusted: trusted
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    location.reload();
                }
            });
        });
    });
});

function showAlertNotification(alert) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `toast align-items-center text-white bg-${getAlertColor(alert.severity)} border-0`;
    notification.setAttribute('role', 'alert');
    notification.setAttribute('aria-live', 'assertive');
    notification.setAttribute('aria-atomic', 'true');
    
    notification.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <strong>${alert.alert_type}</strong><br>
                ${alert.message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    // Add to container
    const container = document.getElementById('toastContainer');
    if (!container) {
        const newContainer = document.createElement('div');
        newContainer.id = 'toastContainer';
        newContainer.className = 'position-fixed bottom-0 end-0 p-3';
        newContainer.style.zIndex = '11';
        document.body.appendChild(newContainer);
        newContainer.appendChild(notification);
    } else {
        container.appendChild(notification);
    }
    
    // Show toast
    const toast = new bootstrap.Toast(notification);
    toast.show();
    
    // Remove after hide
    notification.addEventListener('hidden.bs.toast', function() {
        notification.remove();
    });
}

function getAlertColor(severity) {
    switch (severity) {
        case 'High': return 'danger';
        case 'Medium': return 'warning';
        default: return 'primary';
    }
}