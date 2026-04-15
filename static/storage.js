// Kontor Storage Node - Dashboard JavaScript

const ITEMS_PER_PAGE = 20;

let currentOffset = 0;
let totalFiles = 0;
let totalSize = 0;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadNodeInfo();
    loadFiles();
});

// Fetch node info from API
async function loadNodeInfo() {
    try {
        const response = await fetch('/api/info');
        if (response.ok) {
            const data = await response.json();
            document.getElementById('node-id').textContent = data.node_id;
        }
    } catch (error) {
        console.error('Failed to load node info:', error);
        document.getElementById('node-id').textContent = 'Unknown';
    }
}

// Fetch files from API
async function loadFiles() {
    showLoading();

    try {
        const response = await fetch(`/files?offset=${currentOffset}&limit=${ITEMS_PER_PAGE}`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        totalFiles = data.total;

        if (data.files.length === 0 && totalFiles === 0) {
            showEmpty();
        } else {
            renderFiles(data);
            updateStats(data);
            updatePagination(data);
            showTable();
        }
    } catch (error) {
        console.error('Failed to load files:', error);
        showError(error.message);
    }
}

// Render files table
function renderFiles(data) {
    const tbody = document.getElementById('files-tbody');
    tbody.innerHTML = '';

    // Calculate total size from current batch for display
    let batchSize = 0;

    data.files.forEach(file => {
        const row = document.createElement('tr');
        row.className = 'file-row';

        const size = file.original_size || 0;
        batchSize += size;

        row.innerHTML = `
            <td>
                <div class="flex items-center gap-3">
                    <div class="file-icon ${getFileIconClass(file.mime_type)}">
                        ${getFileIconSvg(file.mime_type)}
                    </div>
                    <div>
                        <p class="font-medium text-white truncate max-w-xs" title="${escapeHtml(file.filename)}">
                            ${escapeHtml(file.filename)}
                        </p>
                        <p class="text-xs text-gray-500 font-mono">${file.file_id}</p>
                    </div>
                </div>
            </td>
            <td class="text-gray-400 text-sm">${escapeHtml(file.mime_type)}</td>
            <td class="text-gray-300">${formatSize(size)}</td>
            <td>
                <span class="badge ${getStatusBadgeClass(file.status)}">
                    ${file.status}
                </span>
            </td>
            <td class="text-gray-400 text-sm">${formatDate(file.created_at)}</td>
            <td>
                <div class="flex justify-end">
                    <a href="${file.download_path}" class="btn-download" ${file.downloaded ? '' : 'disabled'} title="Download">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path>
                        </svg>
                    </a>
                </div>
            </td>
        `;

        tbody.appendChild(row);
    });

    // Store for stats
    totalSize = batchSize;
}

// Update dashboard stats
function updateStats(data) {
    document.getElementById('stat-total').textContent = data.total.toLocaleString();
    document.getElementById('stat-size').textContent = formatSize(totalSize);
}

// Update pagination controls
function updatePagination(data) {
    const start = data.total === 0 ? 0 : currentOffset + 1;
    const end = Math.min(currentOffset + data.limit, data.total);
    const totalPages = Math.ceil(data.total / ITEMS_PER_PAGE);
    const isSinglePage = totalPages <= 1;

    document.getElementById('showing-start').textContent = start;
    document.getElementById('showing-end').textContent = end;
    document.getElementById('showing-total').textContent = data.total;

    const btnPrev = document.getElementById('btn-prev');
    const btnNext = document.getElementById('btn-next');

    // Disable both buttons if only one page
    if (isSinglePage) {
        btnPrev.disabled = true;
        btnNext.disabled = true;
    } else {
        btnPrev.disabled = currentOffset === 0;
        btnNext.disabled = currentOffset + ITEMS_PER_PAGE >= data.total;
    }
}

// Pagination handlers
function prevPage() {
    if (currentOffset > 0) {
        currentOffset = Math.max(0, currentOffset - ITEMS_PER_PAGE);
        loadFiles();
    }
}

function nextPage() {
    if (currentOffset + ITEMS_PER_PAGE < totalFiles) {
        currentOffset += ITEMS_PER_PAGE;
        loadFiles();
    }
}

// UI State helpers
function showLoading() {
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('empty').classList.add('hidden');
    document.getElementById('table-container').classList.add('hidden');
    document.getElementById('pagination').classList.add('hidden');
}

function showError(message) {
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('error').classList.remove('hidden');
    document.getElementById('empty').classList.add('hidden');
    document.getElementById('table-container').classList.add('hidden');
    document.getElementById('pagination').classList.add('hidden');
    document.getElementById('error-message').textContent = message;
}

function showEmpty() {
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('empty').classList.remove('hidden');
    document.getElementById('table-container').classList.add('hidden');
    document.getElementById('pagination').classList.add('hidden');
}

function showTable() {
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('empty').classList.add('hidden');
    document.getElementById('table-container').classList.remove('hidden');
    document.getElementById('pagination').classList.remove('hidden');
}

// Format helpers
function formatSize(bytes) {
    if (bytes === 0 || bytes === null || bytes === undefined) return '0 B';
    
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const size = (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0);
    
    return `${size} ${units[i]}`;
}

function formatDate(isoString) {
    const date = new Date(isoString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// File type helpers
function getFileIconClass(mimeType) {
    if (!mimeType) return 'file-icon-default';
    
    if (mimeType.includes('pdf')) return 'file-icon-pdf';
    if (mimeType.startsWith('image/')) return 'file-icon-image';
    if (mimeType.startsWith('video/')) return 'file-icon-video';
    if (mimeType.startsWith('audio/')) return 'file-icon-audio';
    if (mimeType.includes('zip') || mimeType.includes('tar') || mimeType.includes('rar')) return 'file-icon-archive';
    if (mimeType.includes('document') || mimeType.includes('word') || mimeType.includes('text')) return 'file-icon-document';
    
    return 'file-icon-default';
}

function getFileIconSvg(mimeType) {
    // Document/PDF icon
    if (mimeType && (mimeType.includes('pdf') || mimeType.includes('document') || mimeType.includes('word') || mimeType.includes('text'))) {
        return `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
        </svg>`;
    }
    // Image icon
    if (mimeType && mimeType.startsWith('image/')) {
        return `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
        </svg>`;
    }
    // Video icon
    if (mimeType && mimeType.startsWith('video/')) {
        return `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
        </svg>`;
    }
    // Audio icon
    if (mimeType && mimeType.startsWith('audio/')) {
        return `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zm12-3c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zM9 10l12-3"></path>
        </svg>`;
    }
    // Archive icon
    if (mimeType && (mimeType.includes('zip') || mimeType.includes('tar') || mimeType.includes('rar'))) {
        return `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"></path>
        </svg>`;
    }
    // Default file icon
    return `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"></path>
    </svg>`;
}

function getStatusBadgeClass(status) {
    switch (status?.toLowerCase()) {
        case 'ready':
            return 'badge-ready';
        case 'pending':
        case 'processing':
            return 'badge-pending';
        case 'error':
        case 'failed':
            return 'badge-error';
        default:
            return 'badge-ready';
    }
}
