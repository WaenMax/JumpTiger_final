// 辅助函数：格式化字节数为可读单位 (Bytes, KB, MB, GB, TB)
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024; // 1KB = 1024 Bytes
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

let connectionsChart; // 用于连接数图表的 Chart.js 实例
let trafficChart;     // 用于流量图表的 Chart.js 实例

// 从后端 API 获取数据并更新页面
function fetchData() {
    // 使用 jQuery 的 getJSON 方法发起 AJAX 请求，获取 /api/connections 的数据
    $.getJSON('/api/connections', function(data) {
        // 更新概览卡片数据
        $('#active-connections-count').text(data.active_connections);
        $('#total-upload-bytes').text(formatBytes(data.total_upload_bytes));
        $('#total-download-bytes').text(formatBytes(data.total_download_bytes));

        // 更新最新连接记录表格
        const tableBody = $('#connections-table-body');
        tableBody.empty(); // 清空之前的表格内容

        // 显示最新的 10 条连接记录 (倒序排列，最新的在上面)
        // 使用 slice(-10) 获取数组的最后 10 个元素，然后 reverse() 进行倒序
        data.connections.slice(-10).reverse().forEach(conn => {
            const row = `<tr>
                <td>${conn.timestamp}</td>
                <td>${conn.client_address ? conn.client_address[0] : 'N/A'}</td>
                <td>${conn.target_address || 'N/A'}</td>
                <td>${conn.duration_seconds !== undefined ? conn.duration_seconds.toFixed(2) : 'N/A'}</td>
                <td>${conn.bytes_received_from_client !== undefined ? formatBytes(conn.bytes_received_from_client) : 'N/A'}</td>
                <td>${conn.bytes_sent_to_client !== undefined ? formatBytes(conn.bytes_sent_to_client) : 'N/A'}</td>
            </tr>`;
            tableBody.append(row); // 将拼接好的行 HTML 添加到表格中
        });

        // 更新图表数据
        updateCharts(data.chart_data);
    });
}

// 更新 Chart.js 图表
function updateCharts(chart_data) {
    const labels = chart_data.labels; // 时间标签 (例如：'2025-06-11 01:30')
    const activeConnectionsData = chart_data.active_connections; // 每分钟连接数数据
    const trafficData = chart_data.traffic; // 每分钟总流量数据

    // 更新连接数图表
    if (connectionsChart) { // 如果图表实例已存在，则更新数据
        connectionsChart.data.labels = labels;
        connectionsChart.data.datasets[0].data = activeConnectionsData;
        connectionsChart.update(); // 告诉 Chart.js 更新图表
    } else { // 否则，创建一个新的图表实例
        const ctxConnections = document.getElementById('connectionsChart').getContext('2d');
        connectionsChart = new Chart(ctxConnections, {
            type: 'line', // 折线图类型
            data: {
                labels: labels,
                datasets: [{
                    label: '每分钟连接数', // 数据集的标签
                    data: activeConnectionsData, // 数据点
                    borderColor: 'rgb(75, 192, 192)', // 线条颜色
                    tension: 0.1, // 曲线张力，控制线条平滑度
                    fill: false // 不填充曲线下方区域
                }]
            },
            options: {
                responsive: true, // 响应式布局，图表会根据容器大小自动调整
                maintainAspectRatio: false, // 不保持宽高比，可以自由调整 Canvas 元素的大小
                scales: {
                    y: { beginAtZero: true } // Y 轴从 0 开始
                }
            }
        });
    }

    // 更新流量图表 (逻辑与连接数图表类似)
    if (trafficChart) {
        trafficChart.data.labels = labels;
        trafficChart.data.datasets[0].data = trafficData;
        trafficChart.update();
    } else {
        const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
        trafficChart = new Chart(ctxTraffic, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: '每分钟总流量 (字节)',
                    data: trafficData,
                    borderColor: 'rgb(255, 99, 132)',
                    tension: 0.1,
                    fill: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    }
}

// 当文档 (HTML 页面) 完全加载并解析完成后执行此函数
$(document).ready(function() {
    fetchData(); // 页面加载时立即获取并显示数据
    setInterval(fetchData, 5000); // 每 5 秒钟调用 fetchData 函数刷新数据
});