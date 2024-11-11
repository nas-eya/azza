document.addEventListener("DOMContentLoaded", function() {
    // Initialize theme and color settings
    const themeSelect = document.getElementById('theme');
    const colorPicker = document.getElementById('color');
    colorPicker.addEventListener('change', (e) => changeColor(e.target.value));
    themeSelect.addEventListener('change', (e) => changeTheme(e.target.value));
});

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

function changeColor(color) {
    document.documentElement.style.setProperty('--primary-color', color);
}

function changeTheme(theme) {
    if (theme === 'dark') {
        document.body.classList.add('dark-mode');
        document.documentElement.style.setProperty('--background-color', 'var(--dark-background-color)');
        document.documentElement.style.setProperty('--text-color', 'var(--dark-text-color)');
        document.documentElement.style.setProperty('--card-bg-color', 'var(--dark-card-bg-color)');
    } else {
        document.body.classList.remove('dark-mode');
        document.documentElement.style.setProperty('--background-color', '#f4f4f4');
        document.documentElement.style.setProperty('--text-color', '#333');
        document.documentElement.style.setProperty('--card-bg-color', '#fff');
    }
}
