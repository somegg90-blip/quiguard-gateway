// 1. Load saved settings when popup opens
document.addEventListener('DOMContentLoaded', () => {
    const savedUrl = localStorage.getItem('ironlayer_url');
    if (savedUrl) {
        document.getElementById('serverUrl').value = savedUrl;
    } else {
        // Default for testing
        document.getElementById('serverUrl').value = 'http://127.0.0.1:8000';
    }
});

// 2. Save settings button
document.getElementById('saveBtn').addEventListener('click', () => {
    const url = document.getElementById('serverUrl').value;
    localStorage.setItem('ironlayer_url', url);
    alert('Settings Saved! Using: ' + url);
});

// 3. Send Request
document.getElementById('sendBtn').addEventListener('click', async () => {
    const prompt = document.getElementById('prompt').value;
    const statusDiv = document.getElementById('status');
    const responseDiv = document.getElementById('response');
    
    // GET THE URL FROM SETTINGS
    const serverUrl = localStorage.getItem('ironlayer_url') || 'http://127.0.0.1:8000';

    if (!prompt) return;

    statusDiv.innerText = "⏳ Sanitizing & Processing...";
    responseDiv.innerText = "";

    try {
        // USE THE DYNAMIC URL
        const response = await fetch(`${serverUrl}/v1/chat/completions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model: "gpt-4",
                messages: [{ role: "user", content: prompt }]
            })
        });

        const data = await response.json();

        if (data.choices && data.choices[0]) {
            statusDiv.innerText = "✅ Response received (Secrets Protected).";
            responseDiv.innerText = data.choices[0].message.content;
        } else {
            statusDiv.innerText = "❌ Error processing response.";
            responseDiv.innerText = JSON.stringify(data, null, 2);
        }
    } catch (error) {
        statusDiv.innerText = "❌ Connection Failed. Check URL in Settings.";
        responseDiv.innerText = error.message;
    }
});