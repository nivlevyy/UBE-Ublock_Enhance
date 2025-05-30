chrome.runtime.sendMessage({ type: 'getCheckResult' }, (response) => {
    const container = document.getElementById('result');

    if (!response || !response.result) {
        container.textContent = "No result available.";
        return;
    }

    const result = response.result;
    container.innerHTML = '';

    for (const key in result)
    {
        const item = document.createElement('div');
        item.className = 'item';
        item.innerHTML = `<span class="key">${key}:</span> ${result[key]}`;
        container.appendChild(item);
    }
});
