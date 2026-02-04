# app.py
from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import uuid
from pathlib import Path
import json
from datetime import datetime
import logging

from main import AnalysisCoordinator, save_results_to_file, KnowledgeCoordinator
from config import UPLOAD_FOLDER, OUTPUT_DIR

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nodejs-security-analysis-system'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# 确保上传目录存在
Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    """显示单页面应用"""
    return render_template('single_page.html')

@app.route('/knowledge_base')
def knowledge_base():
    return render_template('knowledge_base.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """处理JavaScript文件上传并返回分析结果"""
    if 'file' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
    
    if file and file.filename.endswith('.js'):
        try:
            # 生成唯一ID，避免文件名冲突
            unique_id = str(uuid.uuid4())[:8]
            original_filename = file.filename
            safe_filename = f"{unique_id}_{original_filename}"
            
            # 保存上传的文件
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
            file.save(file_path)
            
            # 读取文件内容
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 创建JavaScript源字典
            js_sources = {original_filename: content}  # 改为js_sources
            module_name = os.path.splitext(original_filename)[0]
            
            # 运行分析
            coord = AnalysisCoordinator()
            result = coord.full_analysis(js_sources)  # 改为js_sources
            
            # 保存结果
            output_dir = save_results_to_file(result, module_name)
            
            # 删除上传的文件
            os.remove(file_path)
            
            # 准备返回的详细结果
            response_data = {
                'success': True,
                'module_name': module_name,  # 改为module_name
                'result_dir': output_dir.name,
                'nodejs_analysis': result['nodejs_analysis'],  # 改为nodejs_analysis
                'rootcause_analysis': result['rootcause_analysis'],
                'exploit_analysis': result['exploit_analysis'],
                'poc_reachability_report': result['poc_reachability_report'],
                'graph_data': result['graph_data']
            }
            
            return jsonify(response_data)
            
        except Exception as e:
            # 如果发生错误，删除上传的文件
            if 'file_path' in locals() and os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({'error': f'分析过程中出现错误: {str(e)}'}), 500
    
    return jsonify({'error': '只支持 .js 格式的文件'}), 400  # 改为.js

@app.route('/knowledge_base/analyze', methods=['POST'])
def knowledge_base_analyze():
    """处理知识库分析（JavaScript文件 + POC文件）"""
    try:
        # 检查文件上传
        if 'js_file' not in request.files or 'poc_file' not in request.files:
            return jsonify({'error': '请同时上传JavaScript文件和POC文件'}), 400
        
        js_file = request.files['js_file']
        poc_file = request.files['poc_file']
        
        if js_file.filename == '' or poc_file.filename == '':
            return jsonify({'error': '请选择文件'}), 400
        
        # 检查文件格式
        if not (js_file.filename.endswith('.js') and poc_file.filename.endswith('.js')):
            return jsonify({'error': 'JavaScript文件必须是.js格式，POC文件也必须是.js格式'}), 400
        
        # 保存上传的文件
        js_content = js_file.read().decode('utf-8')
        poc_content = poc_file.read().decode('utf-8')
        
        # 调用知识库分析
        coordinator = KnowledgeCoordinator()
        result = coordinator.full_analysis(
            js_sources={js_file.filename: js_content},  # 改为js_sources
            poc_code=poc_content
        )
        
        # 构建新的响应数据结构
        response_data = {
            'success': True,
            'js_file_name': js_file.filename,  # 改为js_file_name
            'poc_name': poc_file.filename,
            'analysis_result': {
                'poc_validation': {
                    'matched': result.get('poc_validation', {}).get('original_matched', False),
                    'reasoning': result.get('poc_validation', {}).get('reasoning', ''),
                    'exploited_vulnerability': result.get('poc_validation', {}).get('exploited_vulnerability')
                },
                'nodejs_analysis': result.get('nodejs_analysis', {}),  # 改为nodejs_analysis
                'rootcause_analysis': result.get('rootcause_analysis', {}),
                'knowledge_base_expansion': {
                    'expanded': not result.get('poc_validation', {}).get('original_matched', True),
                    'new_nodejs_type': result.get('new_nodejs_type', {}),  # 改为new_nodejs_type
                    'new_rootcause': result.get('new_rootcause', {}),
                    'update_status': result.get('update_status', {})
                }
            }
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"知识库分析错误: {str(e)}")
        return jsonify({'error': f'分析过程中出现错误: {str(e)}'}), 500

@app.route('/analyze_text', methods=['POST'])
def analyze_text():
    """直接分析文本输入的JavaScript代码"""
    try:
        data = request.json
        if not data or 'code' not in data:
            return jsonify({'error': '请输入JavaScript代码'}), 400
        
        code = data['code']
        filename = data.get('filename', 'input.js')
        
        # 直接调用main.py中的函数
        from main import analyze_js_from_content
        result = analyze_js_from_content(code, filename)
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"文本分析错误: {str(e)}")
        return jsonify({'error': f'分析过程中出现错误: {str(e)}'}), 500

@app.route('/batch_analyze', methods=['POST'])
def batch_analyze():
    """批量分析多个JavaScript文件"""
    try:
        if 'files' not in request.files:
            return jsonify({'error': '没有选择文件'}), 400
        
        files = request.files.getlist('files')
        if not files:
            return jsonify({'error': '没有选择文件'}), 400
        
        # 收集所有JavaScript文件
        js_sources = {}
        temp_files = []
        
        for file in files:
            if file.filename == '' or not file.filename.endswith('.js'):
                continue
                
            # 保存临时文件
            unique_id = str(uuid.uuid4())[:8]
            safe_filename = f"{unique_id}_{file.filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
            file.save(file_path)
            temp_files.append(file_path)
            
            # 读取内容
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            js_sources[file.filename] = content
        
        if not js_sources:
            return jsonify({'error': '没有有效的JavaScript文件'}), 400
        
        # 运行分析
        coord = AnalysisCoordinator()
        result = coord.full_analysis(js_sources)
        
        # 清理临时文件
        for file_path in temp_files:
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # 保存结果
        output_dir = save_results_to_file(result, "batch_analysis")
        
        return jsonify({
            'success': True,
            'file_count': len(js_sources),
            'result_dir': output_dir.name,
            'analysis_result': result
        })
        
    except Exception as e:
        # 清理临时文件
        for file_path in temp_files:
            if os.path.exists(file_path):
                os.remove(file_path)
        return jsonify({'error': f'批量分析过程中出现错误: {str(e)}'}), 500

@app.route('/results/<result_dir>/<filename>')
def download_result_file(result_dir, filename):
    """下载结果文件"""
    result_path = os.path.join(OUTPUT_DIR, result_dir)
    
    if not os.path.exists(result_path):
        return jsonify({'error': '找不到分析结果'}), 404
    
    return send_from_directory(result_path, filename, as_attachment=True)

@app.route('/api/status')
def api_status():
    """API状态检查"""
    return jsonify({
        'status': 'online',
        'service': 'Node.js Security Analysis System',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

@app.errorhandler(413)
def too_large(e):
    """处理文件过大错误"""
    return jsonify({'error': '文件太大，请上传小于16MB的文件'}), 413

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)