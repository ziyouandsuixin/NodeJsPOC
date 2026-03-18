// ========== Node.js分析功能 ==========

let currentResult = null;

// 初始化分析器
export function initAnalyzer() {
  const analyzeBtn = document.getElementById('analyzeBtn');
  const fileInput = document.getElementById('fileInput');
  const uploadCard = document.querySelector('.upload-card');
  
  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', handleAnalyze);
  }
  
  if (uploadCard) {
    uploadCard.addEventListener('click', () => {
      fileInput.click();
    });
  }
  
  if (fileInput) {
    fileInput.addEventListener('change', handleFileSelect);
  }
}

// 处理文件选择
function handleFileSelect(event) {
  const file = event.target.files[0];
  if (file) {
    console.log('已选择文件:', file.name);
    // 可以在这里显示文件名
  }
}

// 处理分析
async function handleAnalyze() {
  const fileInput = document.getElementById('fileInput');
  if (!fileInput.files || fileInput.files.length === 0) {
    showNotification('请先选择文件', 'error');
    return;
  }
  
  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  
  // 显示进度
  document.getElementById('progressContainer').style.display = 'block';
  document.getElementById('resultContainer').style.display = 'none';
  
  try {
    // 模拟分析过程（实际应该调用后端API）
    await simulateAnalysis();
    
    // 模拟结果数据
    const mockResult = {
      success: true,
      nodejs_analysis: {
        retriever_NodeJs: [
          { name: 'express', version: '4.18.2', vulnerability: '高危' },
          { name: 'body-parser', version: '1.20.1', vulnerability: '中危' }
        ]
      },
      rootcause_analysis: {
        final_vulnerability: {
          vulnerability_name: '原型污染',
          severity: '高危',
          description: '通过__proto__属性污染对象原型'
        }
      },
      graph_data: {
        nodes: [
          { id: 'root', name: '入口', type: 'root' },
          { id: 'express', name: 'Express', type: 'component' },
          { id: 'vuln', name: '原型污染', type: 'rootcause' }
        ],
        links: [
          { source: 'root', target: 'express' },
          { source: 'express', target: 'vuln' }
        ]
      }
    };
    
    document.getElementById('progressContainer').style.display = 'none';
    displayResults(mockResult);
  } catch (error) {
    document.getElementById('progressContainer').style.display = 'none';
    showNotification('错误: ' + error.message, 'error');
  }
}

// 模拟分析过程
async function simulateAnalysis() {
  return new Promise((resolve) => {
    let progress = 0;
    const interval = setInterval(() => {
      progress += 10;
      const progressBar = document.querySelector('.progress-bar');
      if (progressBar) {
        progressBar.style.width = progress + '%';
      }
      
      if (progress >= 100) {
        clearInterval(interval);
        setTimeout(resolve, 500);
      }
    }, 200);
  });
}

// 显示分析结果
function displayResults(result) {
  currentResult = result;
  document.getElementById('resultContainer').style.display = 'block';
  
  // 更新Node.js组件分析
  const nodejsCount = result.nodejs_analysis?.retriever_NodeJs?.length || 0;
  document.getElementById('nodejsBadge').textContent = nodejsCount;
  
  if (nodejsCount > 0) {
    let nodejsHtml = '<table class="table table-sm"><thead><tr><th>组件</th><th>版本</th><th>风险</th></tr></thead><tbody>';
    result.nodejs_analysis.retriever_NodeJs.forEach(comp => {
      nodejsHtml += `<tr>
        <td>${comp.name}</td>
        <td>${comp.version}</td>
        <td><span class="badge bg-${comp.vulnerability === '高危' ? 'danger' : 'warning'}">${comp.vulnerability}</span></td>
      </tr>`;
    });
    nodejsHtml += '</tbody></table>';
    document.getElementById('nodejsContent').innerHTML = nodejsHtml;
  }
  
  // 更新漏洞根因分析
  const vuln = result.rootcause_analysis?.final_vulnerability;
  if (vuln && vuln.vulnerability_name) {
    document.getElementById('rootcauseBadge').textContent = '1';
    document.getElementById('rootcauseContent').innerHTML = `
      <div class="alert alert-${vuln.severity === '高危' ? 'danger' : 'warning'}">
        <h5>${vuln.vulnerability_name}</h5>
        <p>${vuln.description || '暂无描述'}</p>
        <p><strong>严重程度:</strong> <span class="badge bg-${vuln.severity === '高危' ? 'danger' : 'warning'}">${vuln.severity}</span></p>
      </div>
    `;
  }
  
  // 更新漏洞利用分析
  document.getElementById('exploitContent').innerHTML = `
    <pre><code>// 漏洞利用示例
const payload = '{"__proto__":{"admin":true}}';
const obj = JSON.parse(payload);
console.log(obj.admin); // true</code></pre>
  `;
  
  // 更新POC验证
  document.getElementById('pocContent').innerHTML = `
    <div class="alert alert-success">
      <i class="bi bi-check-circle-fill me-2"></i>
      POC可达性验证通过，漏洞可被利用
    </div>
  `;
  
  // 更新图数据
  document.getElementById('graphBadge').textContent = '已加载';
  
  // 如果有图数据，渲染图
  if (result.graph_data) {
    renderGraph(result.graph_data);
  }
}

// 渲染图结构
function renderGraph(graphData) {
  const container = document.getElementById('graphSvgContainer');
  if (!container) return;
  
  // 清空容器
  container.innerHTML = '';
  
  const width = container.clientWidth;
  const height = 500;
  
  const svg = d3.select("#graphSvgContainer")
    .append("svg")
    .attr("width", width)
    .attr("height", height);
  
  // 添加缩放功能
  const g = svg.append("g");
  
  const zoom = d3.zoom()
    .scaleExtent([0.1, 4])
    .on("zoom", (event) => {
      g.attr("transform", event.transform);
    });
  
  svg.call(zoom);
  
  // 创建力导向图
  const simulation = d3.forceSimulation(graphData.nodes)
    .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(100))
    .force("charge", d3.forceManyBody().strength(-300))
    .force("center", d3.forceCenter(width / 2, height / 2));
  
  // 绘制连线
  const link = g.append("g")
    .selectAll("line")
    .data(graphData.links)
    .join("line")
    .attr("class", "link")
    .attr("stroke", "#999")
    .attr("stroke-opacity", 0.6)
    .attr("stroke-width", 1.5);
  
  // 定义节点颜色
  const colorMap = {
    root: "#4c78a8",
    component: "#54a24b",
    rootcause: "#e45756",
    exploit: "#f58518"
  };
  
  // 绘制节点
  const node = g.append("g")
    .selectAll("circle")
    .data(graphData.nodes)
    .join("circle")
    .attr("r", 8)
    .attr("fill", d => colorMap[d.type] || "#6c757d")
    .attr("stroke", "#2d3748")
    .attr("stroke-width", 1.5)
    .call(d3.drag()
      .on("start", dragstarted)
      .on("drag", dragged)
      .on("end", dragended));
  
  // 添加节点标签
  const label = g.append("g")
    .selectAll("text")
    .data(graphData.nodes)
    .join("text")
    .attr("dy", -10)
    .attr("text-anchor", "middle")
    .text(d => d.name)
    .attr("font-size", "10px")
    .attr("font-weight", "500")
    .attr("fill", "#374151");
  
  // 更新位置
  simulation.on("tick", () => {
    link
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);
    
    node
      .attr("cx", d => d.x)
      .attr("cy", d => d.y);
    
    label
      .attr("x", d => d.x)
      .attr("y", d => d.y);
  });
  
  // 拖拽函数
  function dragstarted(event) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    event.subject.fx = event.subject.x;
    event.subject.fy = event.subject.y;
  }
  
  function dragged(event) {
    event.subject.fx = event.x;
    event.subject.fy = event.y;
  }
  
  function dragended(event) {
    if (!event.active) simulation.alphaTarget(0);
    event.subject.fx = null;
    event.subject.fy = null;
  }
  
  // 保存到全局变量
  window.graphSimulation = simulation;
  window.graphSvg = svg;
  window.graphG = g;
  window.graphZoom = zoom;
}

// 缩放控制
window.zoomIn = function() {
  if (window.graphSvg && window.graphZoom) {
    window.graphSvg.transition().call(window.graphZoom.scaleBy, 1.2);
  }
};

window.zoomOut = function() {
  if (window.graphSvg && window.graphZoom) {
    window.graphSvg.transition().call(window.graphZoom.scaleBy, 0.8);
  }
};

window.resetZoom = function() {
  if (window.graphSvg && window.graphZoom) {
    window.graphSvg.transition().call(window.graphZoom.transform, d3.zoomIdentity);
  }
};

// 显示通知
function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.className = `notification-toast notification-${type}`;
  notification.innerHTML = `
    <i class="bi bi-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
    <span>${message}</span>
  `;
  
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: white;
    border-left: 4px solid ${type === 'success' ? '#198754' : type === 'error' ? '#dc3545' : '#0d6efd'};
    border-radius: 8px;
    padding: 12px 20px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    z-index: 9999;
    display: flex;
    align-items: center;
    gap: 12px;
    animation: slideIn 0.3s ease;
  `;
  
  document.body.appendChild(notification);
  
  setTimeout(() => {
    notification.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => {
      document.body.removeChild(notification);
    }, 300);
  }, 3000);
}