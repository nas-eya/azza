function showSection(sectionId) {
    const sections = ['auth', 'dashboard', 'tasks', 'build', 'libraries'];
    sections.forEach(id => {
        document.getElementById(id).style.display = id === sectionId ? 'block' : 'none';
    });
}

async function register() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    if (!validateInput(username, password)) return;

    showLoading(true);

    try {
        const response = await fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const result = await response.json();
        alert(result.message);
    } catch (error) {
        alert('Registration failed: ' + error.message);
    } finally {
        showLoading(false);
    }
}

async function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    if (!validateInput(username, password)) return;

    showLoading(true);

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const result = await response.json();
        if (result.success) {
            showSection('dashboard');
            alert('Login successful!');
        } else {
            alert(result.message);
        }
    } catch (error) {
        alert('Login failed: ' + error.message);
    } finally {
        showLoading(false);
    }
}

function validateInput(username, password) {
    if (username.trim() === '' || password.trim() === '') {
        alert('Username and password cannot be empty.');
        return false;
    }
    if (username.length < 3 || password.length < 6) {
        alert('Username must be at least 3 characters and password at least 6 characters.');
        return false;
    }
    return true;
}

function showLoading(isLoading) {
    const loadingIndicator = document.getElementById('loading');
    loadingIndicator.style.display = isLoading ? 'block' : 'none';
}

// Add other necessary functions here
