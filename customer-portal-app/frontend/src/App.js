import React, { useState } from 'react';
import './App.css';

function App() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [secret, setSecret] = useState('');
    const [qrCode, setQrCode] = useState('');
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');

    const validateInputs = () => {
        if (!username.match(/^[a-zA-Z0-9]+$/)) {
            setError('Username must be alphanumeric.');
            return false;
        }
        if (password.length < 8 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
            setError('Password must be at least 8 characters long and contain uppercase, lowercase, number, and special characters.');
            return false;
        }
        setError('');
        return true;
    };

    const handleRegister = async () => {
        if (!validateInputs()) return;

        const res = await fetch('https://localhost:5000/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        setMessage(data.message);
        if (data.message !== 'User registered successfully.') {
            setError(data.message);
        }
    };

    const handleLogin = async () => {
        if (!validateInputs()) return;

        const res = await fetch('https://localhost:5000/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        setMessage(data.message);
        if (data.message !== 'Login successful') {
            setError(data.message);
        }
    };

    const setup2FA = async () => {
        const res = await fetch('https://localhost:5000/2fa/setup', {
            method: 'POST',
        });
        const data = await res.json();
        setSecret(data.secret);
        setQrCode(data.qrCode);
    };

    return (
        <div className="App">
            <h1>Customer Portal</h1>
            <div>
                <input
                    type="text"
                    placeholder="Username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                />
                <input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                />
            </div>
            <button onClick={handleRegister}>Register</button>
            <button onClick={handleLogin}>Login</button>
            <button onClick={setup2FA}>Setup 2FA</button>
            {qrCode && <img src={qrCode} alt="QR Code for 2FA" />}
            <p>{message}</p>
            {error && <p style={{ color: 'red' }}>{error}</p>}
        </div>
    );
}

export default App;
