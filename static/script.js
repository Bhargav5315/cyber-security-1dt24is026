
const form = document.getElementById("scan-form");
const scanButton = document.getElementById("scan-button");

const HISTORY_KEY = "phishguard_scan_history";
const historyList = document.getElementById("history-list");
const scanCount = document.getElementById("scan-count");

function getHistory() {
    try {
        const data = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
        return Array.isArray(data) ? data : [];
    } catch {
        return [];
    }
}

function saveHistory(items) {
    try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
        return true;
    } catch {
        alert("History could not be saved in this browser.");
        return false;
    }
}

function makeElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.textContent = text;
    return element;
}

function renderHistory() {
    const items = getHistory();

    scanCount.textContent = String(items.length);
    historyList.replaceChildren();

    if (items.length === 0) {
        historyList.append(
            makeElement("p", "muted", "No scans recorded yet.")
        );
        return;
    }

    items.forEach((item) => {
        const row = makeElement("article", "history-row", "");
        const title = makeElement("strong", "", item.url);
        const details = makeElement(
            "p",
            "",
            `${item.status} · Score: ${item.score}/100 · ${item.time}`
        );
        const actions = makeElement("div", "history-actions", "");

        const rescanButton = makeElement(
            "button", "secondary-button", "Check again"
        );
        rescanButton.type = "button";

        rescanButton.addEventListener("click", () => {
            document.getElementById("url").value = item.url;
            document.getElementById("scanner").scrollIntoView();
            document.getElementById("url").focus();
        });

        const deleteButton = makeElement(
            "button", "secondary-button", "Delete"
        );
        deleteButton.type = "button";

        deleteButton.addEventListener("click", () => {
            const updated = getHistory().filter(
                entry => entry.id !== item.id
            );

            if (saveHistory(updated)) renderHistory();
        });

        actions.append(rescanButton, deleteButton);
        row.append(title, details, actions);
        historyList.append(row);
    });
}

// Save a completed scan shown by the server.
// The newest identical result is not added twice on refresh.
const resultCard = document.querySelector(".result-card");

if (resultCard && resultCard.dataset.url) {
    const record = {
        id: crypto.randomUUID(),
        url: resultCard.dataset.url,
        status: resultCard.dataset.status,
        score: Number(resultCard.dataset.score),
        time: new Date().toLocaleString()
    };

    const items = getHistory();

    const latest = items[0];
    const isDuplicate = latest &&
        latest.url === record.url &&
        latest.status === record.status &&
        latest.score === record.score;

    if (!isDuplicate) {
        items.unshift(record);
        saveHistory(items.slice(0, 100));
    }
}

if (form) {
    form.addEventListener("submit", () => {
        scanButton.textContent = "Analyzing...";
        scanButton.disabled = true;
    });
}

// Review the destination before opening it.
const reviewButton = document.getElementById("show-open-warning");
const warningBox = document.getElementById("open-warning");
const destinationText = document.getElementById("destination");
const openLink = document.getElementById("open-link");
const cancelButton = document.getElementById("cancel-open");

if (reviewButton) {
    reviewButton.addEventListener("click", () => {
        try {
            const destination = new URL(reviewButton.dataset.url);

            if (!["http:", "https:"].includes(destination.protocol)) {
                throw new Error("Unsupported protocol");
            }

            destinationText.textContent =
                `Hostname: ${destination.hostname}. Check the spelling carefully.`;

            openLink.href = destination.href;
            warningBox.hidden = false;
        } catch {
            alert("This URL is invalid and cannot be opened.");
        }
    });
}

if (cancelButton) {
    cancelButton.addEventListener("click", () => {
        warningBox.hidden = true;
        openLink.removeAttribute("href");
    });
}

document.getElementById("clear-history").addEventListener("click", () => {
    if (confirm("Delete all locally saved scan history?")) {
        if (saveHistory([])) renderHistory();
    }
});

renderHistory();
