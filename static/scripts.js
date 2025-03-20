const apiUrl = 'http://localhost:5000';  // Adjust this to your backend URL

function clockIn() {
    fetch(`${apiUrl}/clock-in`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
    })
    .then(response => response.json())
    .then(data => showMessage(data.message));
}

function clockOut() {
    fetch(`${apiUrl}/clock-out`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
    })
    .then(response => response.json())
    .then(data => showMessage(data.message));
}

function startBreak() {
    fetch(`${apiUrl}/break`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ break_type: 'start' })
    })
    .then(response => response.json())
    .then(data => showMessage(data.message));
}

function endBreak() {
    fetch(`${apiUrl}/break`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ break_type: 'end' })
    })
    .then(response => response.json())
    .then(data => showMessage(data.message));
}

function showMessage(message) {
    document.getElementById('message').innerText = message;
}