"""
Flask Application Module - Node.js Security Analysis System

Provides web interface and API endpoints for:
- Uploading JavaScript files for security analysis
- Displaying analysis results in dashboard and analyzer views
- Managing knowledge base
- Downloading analysis reports and POC files

Date: 2025
Version: 1.0.0
"""

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
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure directories exist
Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)
Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ========== Page Routes ==========

@app.route('/')
def index():
    """Home page - redirect to analyzer"""
    return render_template('analyzer.html')

@app.route('/analyzer')
def analyzer():
    """Node.js security analysis page"""
    return render_template('analyzer.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html')

@app.route('/knowledge_base')
def knowledge_base():
    """Knowledge base page"""
    return render_template('knowledge_base.html')

# ========== API Routes ==========

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle JavaScript file upload and return analysis results"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and file.filename.endswith('.js'):
        temp_file_path = None
        try:
            # Generate unique ID for the file
            unique_id = str(uuid.uuid4())[:8]
            original_filename = file.filename
            safe_filename = f"{unique_id}_{original_filename}"
            
            # Save uploaded file temporarily
            temp_file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
            file.save(temp_file_path)
            
            # Read file content
            with open(temp_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Prepare for analysis
            js_sources = {original_filename: content}
            module_name = os.path.splitext(original_filename)[0]
            
            logger.info(f"Starting analysis for file: {original_filename}")
            
            # Perform analysis
            coord = AnalysisCoordinator()
            result = coord.full_analysis(js_sources)
            
            # Save results to file
            output_dir = save_results_to_file(result, module_name)
            
            # Prepare response
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
            logger.error(f"Error during analysis: {str(e)}\n{traceback.format_exc()}")
            return jsonify({'error': f'Analysis error: {str(e)}'}), 500
        finally:
            # Clean up temporary file
            if temp_file_path and os.path.exists(temp_file_path):
                os.remove(temp_file_path)
    
    return jsonify({'error': 'Only .js files are supported'}), 400


@app.route('/results/<result_dir>/<filename>')
def download_result_file(result_dir, filename):
    """Download result files"""
    try:
        result_path = os.path.join(OUTPUT_DIR, result_dir)
        
        if not os.path.exists(result_path):
            return jsonify({'error': 'Analysis result not found'}), 404
        
        return send_from_directory(result_path, filename, as_attachment=True)
        
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({'error': f'Download failed: {str(e)}'}), 500


@app.route('/api/analysis/<result_dir>', methods=['GET'])
def get_analysis_result(result_dir):
    """Get saved analysis result"""
    try:
        result_path = os.path.join(OUTPUT_DIR, result_dir, 'full_analysis.json')
        
        if not os.path.exists(result_path):
            return jsonify({'error': 'Analysis result not found'}), 404
        
        with open(result_path, 'r', encoding='utf-8') as f:
            result = json.load(f)
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Error retrieving analysis result: {str(e)}")
        return jsonify({'error': f'Failed to retrieve analysis result: {str(e)}'}), 500


@app.route('/api/results', methods=['GET'])
def list_results():
    """List all analysis result directories"""
    try:
        results_dir = Path(OUTPUT_DIR)
        if not results_dir.exists():
            return jsonify({'success': True, 'results': []})
        
        result_dirs = []
        for item in results_dir.iterdir():
            if item.is_dir():
                result_file = item / 'full_analysis.json'
                stats = item.stat()
                result_dirs.append({
                    'name': item.name,
                    'created_time': datetime.fromtimestamp(stats.st_ctime).isoformat(),
                    'has_full_analysis': result_file.exists()
                })
        
        # Sort by creation time (newest first)
        result_dirs.sort(key=lambda x: x['created_time'], reverse=True)
        
        return jsonify({'success': True, 'results': result_dirs})
        
    except Exception as e:
        logger.error(f"Error listing results: {str(e)}")
        return jsonify({'error': f'Failed to list results: {str(e)}'}), 500


# ========== Static File Serving ==========

@app.route('/static/css/<path:filename>')
def serve_css(filename):
    """Serve CSS files"""
    return send_from_directory('static/css', filename)


@app.route('/static/js/<path:filename>')
def serve_js(filename):
    """Serve JavaScript files"""
    return send_from_directory('static/js', filename)


# ========== Error Handlers ==========

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    return jsonify({'error': 'File too large. Maximum size is 16MB.'}), 413


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({'error': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 internal server errors"""
    return jsonify({'error': 'Internal server error'}), 500


# ========== Application Startup ==========

if __name__ == '__main__':
    logger.info(f"Upload directory: {UPLOAD_FOLDER}")
    logger.info(f"Output directory: {OUTPUT_DIR}")
    logger.info("Starting Node.js Security Analysis System...")
    logger.info("Access URL: http://localhost:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)