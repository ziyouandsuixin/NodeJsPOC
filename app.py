# app.py
from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import uuid
from pathlib import Path
import json
from datetime import datetime
import logging
import traceback

from main import AnalysisCoordinator, save_results_to_file, KnowledgeCoordinator, analyze_js_from_content
from config import UPLOAD_FOLDER, OUTPUT_DIR

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nodejs-security-analysis-system'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# 确保上传目录存在
Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)
Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    """显示单页面应用"""
    return render_template('nodejs_pro.html')

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
        temp_file_path = None
        try:
            # 生成唯一ID，避免文件名冲突
            unique_id = str(uuid.uuid4())[:8]
            original_filename = file.filename
            safe_filename = f"{unique_id}_{original_filename}"
            
            # 保存上传的文件
            temp_file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
            file.save(temp_file_path)
            
            # 读取文件内容
            with open(temp_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 创建JavaScript源字典
            js_sources = {original_filename: content}
            module_name = os.path.splitext(original_filename)[0]
            
            # 运行分析
            logger.info(f"开始分析文件: {original_filename}")
            coord = AnalysisCoordinator()
            result = coord.full_analysis(js_sources)
            
            # 保存结果
            output_dir = save_results_to_file(result, module_name)
            
            # 构建前端响应数据 - 完全匹配main.py返回字段
            response_data = {
                'success': True,
                'module_name': module_name,
                'result_dir': output_dir.name,
                'nodejs_analysis': result.get('nodejs_analysis', {}),
                'rootcause_analysis': result.get('rootcause_analysis', {}),
                'exploit_analysis': result.get('exploit_analysis', {}),
                'poc_reachability_report': result.get('poc_reachability_report', {}),
                'graph_data': result.get('graph_data', {})
            }
            
            return jsonify(response_data)
            
        except Exception as e:
            logger.error(f"分析过程中出现错误: {str(e)}\n{traceback.format_exc()}")
            return jsonify({'error': f'分析过程中出现错误: {str(e)}'}), 500
        finally:
            # 删除上传的临时文件
            if temp_file_path and os.path.exists(temp_file_path):
                os.remove(temp_file_path)
    
    return jsonify({'error': '只支持 .js 格式的文件'}), 400

@app.route('/knowledge_base/analyze', methods=['POST'])
def knowledge_base_analyze():
    """处理知识库分析（JavaScript文件 + POC文件）"""
    temp_files = []
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
            return jsonify({'error': 'JavaScript文件和POC文件必须是.js格式'}), 400
        
        # 保存上传的文件内容
        js_content = js_file.read().decode('utf-8')
        poc_content = poc_file.read().decode('utf-8')
        
        # 调用知识库分析
        logger.info(f"开始知识库分析: JS文件={js_file.filename}, POC文件={poc_file.filename}")
        coordinator = KnowledgeCoordinator()
        result = coordinator.full_analysis(
            js_sources={js_file.filename: js_content},
            poc_code=poc_content
        )
        
        # 构建响应数据 - 完全兼容原前端期望的格式
        response_data = {
            'success': True,
            'js_file_name': js_file.filename,
            'poc_name': poc_file.filename,
            'analysis_result': {
                'poc_validation': {
                    'matched': result.get('poc_validation', {}).get('original_matched', False),
                    'reasoning': result.get('poc_validation', {}).get('reasoning', ''),
                    'exploited_vulnerability': result.get('poc_validation', {}).get('exploited_vulnerability')
                },
                'nodejs_analysis': result.get('nodejs_analysis', {}),
                'rootcause_analysis': result.get('rootcause_analysis', {}),
                'knowledge_base_expansion': {
                    'expanded': not result.get('poc_validation', {}).get('original_matched', True),
                    'new_nodejs_type': result.get('new_nodejs_type', {}),
                    'new_rootcause': result.get('new_rootcause', {}),
                    'update_status': result.get('update_status', {})
                }
            }
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"知识库分析错误: {str(e)}\n{traceback.format_exc()}")
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
        logger.info(f"开始文本分析: {filename}")
        result = analyze_js_from_content(code, filename)
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"文本分析错误: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': f'分析过程中出现错误: {str(e)}'}), 500

@app.route('/batch_analyze', methods=['POST'])
def batch_analyze():
    """批量分析多个JavaScript文件"""
    temp_files = []
    try:
        if 'files' not in request.files:
            return jsonify({'error': '没有选择文件'}), 400
        
        files = request.files.getlist('files')
        if not files:
            return jsonify({'error': '没有选择文件'}), 400
        
        # 收集所有JavaScript文件
        js_sources = {}
        
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
        logger.info(f"开始批量分析: {len(js_sources)} 个文件")
        coord = AnalysisCoordinator()
        result = coord.full_analysis(js_sources)
        
        # 保存结果
        output_dir = save_results_to_file(result, "batch_analysis")
        
        return jsonify({
            'success': True,
            'file_count': len(js_sources),
            'result_dir': output_dir.name,
            'analysis_result': result
        })
        
    except Exception as e:
        logger.error(f"批量分析错误: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': f'批量分析过程中出现错误: {str(e)}'}), 500
    finally:
        # 清理临时文件
        for file_path in temp_files:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass

@app.route('/api/analysis/<result_dir>', methods=['GET'])
def get_analysis_result(result_dir):
    """获取已保存的分析结果"""
    try:
        result_path = os.path.join(OUTPUT_DIR, result_dir, 'full_analysis.json')
        
        if not os.path.exists(result_path):
            return jsonify({'error': '找不到分析结果'}), 404
        
        with open(result_path, 'r', encoding='utf-8') as f:
            result = json.load(f)
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"获取分析结果错误: {str(e)}")
        return jsonify({'error': f'获取分析结果失败: {str(e)}'}), 500

@app.route('/results/<result_dir>/<filename>')
def download_result_file(result_dir, filename):
    """下载结果文件"""
    try:
        result_path = os.path.join(OUTPUT_DIR, result_dir)
        
        if not os.path.exists(result_path):
            return jsonify({'error': '找不到分析结果'}), 404
        
        # 处理前端请求.sol但实际文件是.js的情况
        if filename == 'exploit_poc.sol':
            actual_file = 'exploit_poc.js'
            file_path = os.path.join(result_path, actual_file)
            if os.path.exists(file_path):
                return send_from_directory(result_path, actual_file, as_attachment=True, download_name='exploit_poc.js')
        
        return send_from_directory(result_path, filename, as_attachment=True)
        
    except Exception as e:
        logger.error(f"下载文件错误: {str(e)}")
        return jsonify({'error': f'下载文件失败: {str(e)}'}), 500

@app.route('/api/status')
def api_status():
    """API状态检查"""
    return jsonify({
        'status': 'online',
        'service': 'Node.js Security Analysis System',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/health')
def health_check():
    """健康检查接口"""
    try:
        # 简单测试RAG是否可用
        from rag.rag_manager import RAGManager
        rag = RAGManager()
        return jsonify({
            'status': 'healthy',
            'rag_initialized': rag.retriever_NodeJs is not None,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/results', methods=['GET'])
def list_results():
    """列出所有分析结果目录"""
    try:
        results_dir = Path(OUTPUT_DIR)
        if not results_dir.exists():
            return jsonify({'success': True, 'results': []})
        
        result_dirs = []
        for item in results_dir.iterdir():
            if item.is_dir():
                # 检查是否有完整的分析结果文件
                result_file = item / 'full_analysis.json'
                report_file = item / 'security_report.md'
                poc_file = item / 'exploit_poc.js'
                
                stats = item.stat()
                result_dirs.append({
                    'name': item.name,
                    'path': str(item),
                    'created_time': datetime.fromtimestamp(stats.st_ctime).isoformat(),
                    'modified_time': datetime.fromtimestamp(stats.st_mtime).isoformat(),
                    'has_full_analysis': result_file.exists(),
                    'has_report': report_file.exists(),
                    'has_poc': poc_file.exists()
                })
        
        # 按修改时间倒序排序
        result_dirs.sort(key=lambda x: x['modified_time'], reverse=True)
        
        return jsonify({
            'success': True,
            'results': result_dirs
        })
        
    except Exception as e:
        logger.error(f"列出结果错误: {str(e)}")
        return jsonify({'error': f'列出结果失败: {str(e)}'}), 500

@app.errorhandler(413)
def too_large(e):
    """处理文件过大错误"""
    return jsonify({'error': '文件太大，请上传小于16MB的文件'}), 413

@app.errorhandler(404)
def not_found(e):
    """处理404错误"""
    return jsonify({'error': '请求的资源不存在'}), 404

@app.errorhandler(500)
def internal_error(e):
    """处理500错误"""
    return jsonify({'error': '服务器内部错误'}), 500

if __name__ == '__main__':
    # 启动前验证配置
    logger.info(f"上传目录: {UPLOAD_FOLDER}")
    logger.info(f"输出目录: {OUTPUT_DIR}")
    logger.info("启动 Node.js 安全分析系统...")
    
    app.run(debug=True, host='0.0.0.0', port=5000)