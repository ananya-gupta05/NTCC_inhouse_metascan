#!/usr/bin/env python3
"""
MetaScan v2.1 - Enhanced Metadata Analysis Tool with Download Functionality
Complete bug-free version with cleaned image download capability
"""

import os
import hashlib
import json
import mimetypes
import threading
import time
import re
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, send_file
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try importing optional packages with better error handling
try:
    import cv2
    OPENCV_AVAILABLE = True
    logger.info("OpenCV available - QR code detection enabled")
except ImportError:
    OPENCV_AVAILABLE = False
    logger.info("OpenCV not available - QR code detection disabled")

try:
    from PIL import Image, ExifTags
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
    logger.info("PIL available - EXIF extraction enabled")
except ImportError:
    PIL_AVAILABLE = False
    logger.warning("PIL not available - EXIF extraction disabled")

try:
    import numpy as np
    NUMPY_AVAILABLE = True
    logger.info("NumPy available - steganography detection enabled")
except ImportError:
    NUMPY_AVAILABLE = False
    logger.info("NumPy not available - steganography detection disabled")

try:
    from geopy.geocoders import Nominatim
    GEOPY_AVAILABLE = True
    logger.info("Geopy available - GPS geocoding enabled")
except ImportError:
    GEOPY_AVAILABLE = False
    logger.info("Geopy not available - GPS geocoding disabled")

# Improved magic library handling
MAGIC_AVAILABLE = False
try:
    import magic
    MAGIC_AVAILABLE = True
    logger.info("python-magic available - enhanced file type detection enabled")
except ImportError:
    try:
        import python_magic as magic
        MAGIC_AVAILABLE = True
        logger.info("python-magic (alternative) available - file type detection enabled")
    except ImportError:
        logger.info("python-magic not available - using basic file type detection")

app = Flask(__name__)
app.config.update(
    SECRET_KEY='metascan-security-key-2025',
    UPLOAD_FOLDER='uploads',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
    TEMPLATES_AUTO_RELOAD=True
)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'tiff', 'bmp', 'webp'}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def cleanup_old_files():
    """Clean up old files in uploads directory"""
    try:
        upload_dir = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_dir):
            return

        current_time = time.time()
        for filename in os.listdir(upload_dir):
            file_path = os.path.join(upload_dir, filename)
            if os.path.isfile(file_path):
                # Remove files older than 3 minutes (180 seconds)
                if current_time - os.path.getmtime(file_path) > 180:
                    try:
                        os.remove(file_path)
                        logger.info(f"Cleaned up old file: {file_path}")
                    except Exception as e:
                        logger.error(f"Error removing file {file_path}: {e}")
    except Exception as e:
        logger.error(f"Cleanup error: {e}")

def schedule_cleanup():
    """Schedule periodic cleanup"""
    cleanup_old_files()
    # Schedule next cleanup in 60 seconds
    threading.Timer(60, schedule_cleanup).start()

class MetaScanAnalyzer:
    """Main analysis class with all functionality"""

    def __init__(self):
        self.results = {}
        self.privacy_score = 100
        self.risk_factors = []

    def analyze_file(self, file_path):
        """Perform comprehensive file analysis"""
        logger.info(f"Starting analysis of: {file_path}")
        try:
            # Reset for each analysis
            self.privacy_score = 100
            self.risk_factors = []

            # Initialize results
            self.results = {
                'file_info': self._get_file_info(file_path),
                'hashes': self._calculate_hashes(file_path),
                'magic_bytes': self._check_magic_bytes(file_path),
                'exif_data': self._extract_exif_metadata(file_path),
                'qr_codes': self._detect_qr_codes(file_path),
                'steganography': self._detect_steganography(file_path),
                'script_injection': self._check_script_injection(file_path),
                'privacy_score': 100,
                'risks': [],
                'analysis_time': datetime.now().isoformat()
            }

            # Calculate privacy score
            self._calculate_privacy_score()
            self.results['privacy_score'] = self.privacy_score
            self.results['risks'] = self.risk_factors

            logger.info("Analysis completed successfully")
            return self.results

        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")
            return {
                'error': f"Analysis failed: {str(e)}",
                'privacy_score': 0,
                'risks': ['Analysis failed - file may be corrupted or unsupported'],
                'hashes': {},
                'exif_data': {},
                'qr_codes': {'found': False},
                'steganography': {'suspicious': False},
                'script_injection': {'suspicious': False},
                'magic_bytes': {'is_valid': False}
            }

    def _get_file_info(self, file_path):
        """Get basic file information"""
        try:
            stat = os.stat(file_path)
            return {
                'name': os.path.basename(file_path),
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'extension': os.path.splitext(file_path)[1].lower()
            }
        except Exception as e:
            logger.error(f"File info error: {e}")
            return {'error': str(e)}

    def _calculate_hashes(self, file_path):
        """Calculate MD5, SHA1, and SHA256 hashes"""
        try:
            hashes = {}
            with open(file_path, 'rb') as f:
                content = f.read()

            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
            hashes['file_size'] = len(content)

            logger.info(f"Calculated hashes for {len(content)} byte file")
            return hashes
        except Exception as e:
            logger.error(f"Hash calculation error: {e}")
            return {'error': str(e)}

    def _check_magic_bytes(self, file_path):
        """Check file magic bytes and validate extension"""
        try:
            result = {
                'file_extension': os.path.splitext(file_path)[1].lower(),
                'detected_mime': 'unknown',
                'expected_mime': 'unknown',
                'is_valid': True
            }

            # Try to detect MIME type with improved error handling
            if MAGIC_AVAILABLE:
                try:
                    result['detected_mime'] = magic.from_file(file_path, mime=True)
                except Exception as e:
                    logger.debug(f"Magic library error: {e}")
                    # Fallback to mimetypes
                    mime_type, _ = mimetypes.guess_type(file_path)
                    result['detected_mime'] = mime_type or 'unknown'
            else:
                # Use mimetypes as fallback
                mime_type, _ = mimetypes.guess_type(file_path)
                result['detected_mime'] = mime_type or 'unknown'

            # Expected MIME types for extensions
            expected_mimes = {
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg', 
                '.png': 'image/png',
                '.gif': 'image/gif',
                '.bmp': 'image/bmp',
                '.tiff': 'image/tiff',
                '.webp': 'image/webp'
            }

            result['expected_mime'] = expected_mimes.get(result['file_extension'], 'unknown')

            # Validate if detected matches expected
            if result['detected_mime'] != 'unknown' and result['expected_mime'] != 'unknown':
                result['is_valid'] = result['detected_mime'] == result['expected_mime']
                if not result['is_valid']:
                    self.risk_factors.append('File extension mismatch detected')

            return result
        except Exception as e:
            logger.error(f"Magic bytes check error: {e}")
            return {'error': str(e), 'is_valid': False}

    def _extract_exif_metadata(self, file_path):
        """Extract EXIF metadata from image"""
        if not PIL_AVAILABLE:
            return {'metadata': {}, 'gps_data': None, 'has_sensitive_data': False}

        try:
            image = Image.open(file_path)
            exifdata = image.getexif()
            metadata = {}
            gps_data = None

            if exifdata:
                for tag_id in exifdata:
                    tag = TAGS.get(tag_id, tag_id)
                    data = exifdata.get(tag_id)

                    # Handle different data types
                    if isinstance(data, bytes):
                        try:
                            data = data.decode('utf-8')
                        except:
                            data = str(data)
                    elif isinstance(data, (tuple, list)):
                        data = str(data)

                    metadata[str(tag)] = str(data)

                    # Extract GPS data - FIXED: Check if data is dict-like before calling keys()
                    if tag == 'GPSInfo' and data:
                        gps_data = self._extract_gps_data(data)

            # Check for sensitive data
            sensitive_tags = ['DateTime', 'Make', 'Model', 'Software', 'GPS', 'GPSInfo']
            has_sensitive_data = any(tag in metadata for tag in sensitive_tags) or gps_data is not None

            if has_sensitive_data:
                self.risk_factors.append('Sensitive EXIF metadata found')
            if gps_data:
                self.risk_factors.append('GPS location data embedded in image')

            return {
                'metadata': metadata,
                'gps_data': gps_data,
                'has_sensitive_data': has_sensitive_data
            }

        except Exception as e:
            logger.error(f"EXIF extraction error: {e}")
            return {'error': str(e), 'metadata': {}, 'gps_data': None}

    def _extract_gps_data(self, gps_info):
        """Extract GPS coordinates from EXIF data - FIXED GPS extraction error"""
        try:
            # FIXED: Check if gps_info is actually a dictionary or dict-like object
            if not hasattr(gps_info, 'keys') or not callable(getattr(gps_info, 'keys')):
                logger.debug(f"GPS info is not dict-like: {type(gps_info)} - {gps_info}")
                return None

            if not GEOPY_AVAILABLE:
                logger.debug("Geopy not available for GPS processing")
                return {'raw_data': str(gps_info), 'processed': False}

            gps_data = {}

            # Convert GPS info to readable format
            for key in gps_info.keys():
                name = GPSTAGS.get(key, key)
                gps_data[name] = gps_info[key]

            # Extract latitude and longitude if available
            if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                try:
                    lat = self._convert_to_degrees(gps_data['GPSLatitude'])
                    lon = self._convert_to_degrees(gps_data['GPSLongitude'])

                    # Handle hemisphere
                    if 'GPSLatitudeRef' in gps_data and gps_data['GPSLatitudeRef'] == 'S':
                        lat = -lat
                    if 'GPSLongitudeRef' in gps_data and gps_data['GPSLongitudeRef'] == 'W':
                        lon = -lon

                    # Get address if possible
                    address = self._get_address(lat, lon)

                    return {
                        'latitude': lat,
                        'longitude': lon,
                        'location': address,
                        'raw_data': gps_data,
                        'processed': True
                    }
                except Exception as e:
                    logger.error(f"GPS coordinate conversion error: {e}")
                    return {'raw_data': gps_data, 'error': str(e), 'processed': False}
            else:
                return {'raw_data': gps_data, 'processed': False}

        except Exception as e:
            logger.error(f"GPS extraction error: {e}")
            return None

    def _convert_to_degrees(self, value):
        """Convert GPS coordinates to decimal degrees"""
        try:
            if isinstance(value, (list, tuple)) and len(value) >= 3:
                d, m, s = value[:3]
                return float(d) + (float(m) / 60.0) + (float(s) / 3600.0)
            else:
                return float(value)
        except:
            return 0.0

    def _get_address(self, lat, lon):
        """Get address from coordinates using reverse geocoding"""
        try:
            geolocator = Nominatim(user_agent="metascan-analyzer")
            location = geolocator.reverse(f"{lat}, {lon}", timeout=5)
            return location.address if location else None
        except Exception as e:
            logger.debug(f"Geocoding error: {e}")
            return None

    def _detect_qr_codes(self, file_path):
        """Detect QR codes in image"""
        if not OPENCV_AVAILABLE:
            return {'found': False, 'message': 'OpenCV not available'}

        try:
            image = cv2.imread(file_path)
            if image is None:
                return {'found': False, 'error': 'Could not load image'}

            # Initialize QR code detector
            detector = cv2.QRCodeDetector()

            # Detect and decode QR codes
            data, vertices_array, binary_qrcode = detector.detectAndDecode(image)

            if vertices_array is not None and len(data) > 0:
                self.risk_factors.append('QR code detected in image')
                return {
                    'found': True,
                    'data': data,
                    'count': 1,
                    'vertices': vertices_array.tolist() if hasattr(vertices_array, 'tolist') else str(vertices_array)
                }
            else:
                return {'found': False, 'message': 'No QR codes detected'}

        except Exception as e:
            logger.error(f"QR code detection error: {e}")
            return {'found': False, 'error': str(e)}

    def _detect_steganography(self, file_path):
        """Basic steganography detection"""
        if not PIL_AVAILABLE or not NUMPY_AVAILABLE:
            return {'suspicious': False, 'message': 'Required libraries not available'}

        try:
            image = Image.open(file_path)

            # Get file size and image dimensions
            width, height = image.size
            file_size = os.path.getsize(file_path)

            # Calculate expected size for uncompressed RGB
            expected_size = width * height * 3
            size_ratio = file_size / expected_size if expected_size > 0 else 0

            # Convert image to array for LSB analysis
            if image.mode in ['RGB', 'RGBA']:
                img_array = np.array(image)

                # Check LSB variance (simplified steganography detection)
                lsb_data = img_array & 1  # Get least significant bits
                lsb_variance = float(np.var(lsb_data))

                # Determine if suspicious (more conservative thresholds)
                suspicious = size_ratio > 5.0 or lsb_variance > 0.3

                if suspicious:
                    self.risk_factors.append('Potential steganography detected')

                return {
                    'suspicious': suspicious,
                    'size_ratio': round(size_ratio, 3),
                    'lsb_variance': round(lsb_variance, 6),
                    'analysis': 'Statistical analysis completed',
                    'details': {
                        'file_size': file_size,
                        'expected_size': expected_size,
                        'dimensions': f"{width}x{height}"
                    }
                }
            else:
                return {
                    'suspicious': False,
                    'analysis': 'Image format not suitable for LSB analysis'
                }

        except Exception as e:
            logger.error(f"Steganography detection error: {e}")
            return {'suspicious': False, 'error': str(e)}

    def _check_script_injection(self, file_path):
        """Check for potential script injection in file - IMPROVED to avoid false positives"""
        try:
            # Read file in binary mode
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB only to avoid memory issues

            # More specific malicious patterns (reduced false positives)
            dangerous_patterns = [
                rb'<script[^>]*>',
                rb'javascript:',
                rb'vbscript:',
                rb'onload\s*=',
                rb'onerror\s*=',
                rb'<?php',
                rb'<%.*%>',
                rb'#!/bin/sh',
                rb'#!/bin/bash',
                rb'cmd.exe',
                rb'powershell',
                rb'eval\s*\(',
                rb'exec\s*\(',
                rb'system\s*\(',
                rb'shell_exec',
                rb'base64_decode',
                rb'gzinflate'
            ]

            detected_patterns = []

            # Convert to lowercase for case-insensitive matching
            content_lower = content.lower()

            for pattern in dangerous_patterns:
                if re.search(pattern, content_lower):
                    pattern_str = pattern.decode('utf-8', errors='ignore')
                    detected_patterns.append(pattern_str)

            # Only flag as suspicious if multiple patterns or high-confidence patterns found
            suspicious = len(detected_patterns) > 1 or any(
                high_risk in str(detected_patterns).lower() 
                for high_risk in ['script', 'php', 'eval', 'exec', 'shell']
            )

            if suspicious:
                self.risk_factors.append('Potential script injection detected')

            return {
                'suspicious': suspicious,
                'patterns_found': detected_patterns[:5],  # Limit to 5 patterns
                'pattern_count': len(detected_patterns),
                'analysis': 'Pattern matching completed'
            }

        except Exception as e:
            logger.error(f"Script injection check error: {e}")
            return {'suspicious': False, 'error': str(e)}

    def _calculate_privacy_score(self):
        """Calculate privacy score based on detected risks"""
        penalties = {
            'GPS location data embedded in image': 30,
            'Sensitive EXIF metadata found': 20,
            'QR code detected in image': 15,
            'Potential steganography detected': 25,
            'Potential script injection detected': 40,
            'File extension mismatch detected': 20
        }

        total_penalty = 0
        for risk in self.risk_factors:
            penalty = penalties.get(risk, 10)  # Default penalty of 10
            total_penalty += penalty

        self.privacy_score = max(0, 100 - total_penalty)

    def remove_metadata(self, file_path, output_path):
        """Remove metadata from image file"""
        if not PIL_AVAILABLE:
            raise Exception("PIL not available - cannot remove metadata")

        try:
            # Open the image
            with Image.open(file_path) as image:
                # Create a new image without EXIF data
                clean_image = Image.new(image.mode, image.size)
                clean_image.putdata(list(image.getdata()))

                # Save the clean image
                if image.format:
                    clean_image.save(output_path, format=image.format)
                else:
                    # Default to JPEG if format unknown
                    clean_image.save(output_path, format='JPEG')

            return True
        except Exception as e:
            logger.error(f"Metadata removal error: {e}")
            raise Exception(f"Failed to remove metadata: {str(e)}")
import shutil

def remove_all_metadata(input_path, output_path):
    from PIL import Image
    ext = input_path.lower().split('.')[-1]
    with Image.open(input_path) as img:
        data = list(img.getdata())
        img_no_metadata = Image.new(img.mode, img.size)
        img_no_metadata.putdata(data)
        if ext in ['jpg', 'jpeg']:
            img_no_metadata.save(output_path, format='JPEG', quality=95)
        elif ext == 'png':
            img_no_metadata.save(output_path, format='PNG')
            # Remove ancillary PNG chunks
            try:
                with open(output_path, 'rb') as f:
                    raw = f.read()
                pngsig = b'\211PNG\r\n\032\n'
                header = raw[:8]
                chunks = []
                i = 8
                while i < len(raw):
                    length = int.from_bytes(raw[i:i+4], 'big')
                    chunk_type = raw[i+4:i+8]
                    # Skip metadata chunks
                    if chunk_type not in [b'tEXt', b'zTXt', b'iTXt', b'tIME']:
                        chunks.append(raw[i:i+length+12])
                    i += length + 12
                with open(output_path, 'wb') as f:
                    f.write(header)
                    for c in chunks:
                        f.write(c)
            except Exception:
                pass
        elif ext == 'webp':
            img_no_metadata.save(output_path, format='WEBP')
        else:
            img_no_metadata.save(output_path)

def remove_qr_code(input_path, output_path):
    # Requires OpenCV and NumPy
    try:
        import cv2
        import numpy as np
        img = cv2.imread(input_path)
        qr_decoder = cv2.QRCodeDetector()
        data, points, _ = qr_decoder.detectAndDecode(img)
        if points is not None and len(points) > 0:
            points = points[0].astype(np.int32)
            cv2.fillPoly(img, [points], (0,0,0))
        cv2.imwrite(output_path, img)
    except Exception:
        # On error, just copy over as-is
        shutil.copyfile(input_path, output_path)

def remove_steganography(input_path, output_path):
    from PIL import Image
    with Image.open(input_path) as img:
        img = img.convert("RGB")
        img.save(output_path, format='JPEG', quality=95)

def clean_image(input_path, output_path):
    ext = input_path.lower().split('.')[-1]
    temp_path = output_path + '.tmp'
    remove_all_metadata(input_path, temp_path)
    if ext in ['jpg', 'jpeg', 'png']:
        remove_steganography(temp_path, output_path)
    else:
        shutil.move(temp_path, output_path)
    # Remove QR codes last
    remove_qr_code(output_path, output_path)
    if os.path.exists(temp_path):
        os.remove(temp_path)

# Flask routes
@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400

        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Analyze file
        analyzer = MetaScanAnalyzer()
        results = analyzer.analyze_file(filepath)

        # Clean up original file after analysis
        try:
            os.remove(filepath)
        except:
            pass

        return jsonify(results)

    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/remove_metadata', methods=['POST'])
def remove_metadata():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)
        cleaned_path = input_path.rsplit('.', 1)[0] + '_clean.' + filename.rsplit('.',1)[-1]
        clean_image(input_path, cleaned_path)
        size_reduction = os.path.getsize(input_path) - os.path.getsize(cleaned_path)
        return jsonify({
            'success': True,
            'download_url': '/download/' + os.path.basename(cleaned_path),
            'download_filename': os.path.basename(cleaned_path),
            'size_reduction': size_reduction
        })
    return jsonify({'error': 'Invalid file format'}), 400


from flask import send_from_directory

@app.route('/download/<filename>')
def download_file(filename):
    uploads = app.config['UPLOAD_FOLDER']
    return send_from_directory(uploads, filename, as_attachment=True)


@app.route('/health')
def health_check():
    """Enhanced health check"""
    try:
        features = {
            'pil_available': PIL_AVAILABLE,
            'opencv_available': OPENCV_AVAILABLE,
            'numpy_available': NUMPY_AVAILABLE,
            'geopy_available': GEOPY_AVAILABLE,
            'magic_available': MAGIC_AVAILABLE
        }

        enhancements = {
            'metadata_removal_download': PIL_AVAILABLE,
            'auto_cleanup_system': True,
            'secure_file_handling': True
        }

        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '2.1.0 Enhanced',
            'features': features,
            'enhancements': enhancements,
            'upload_folder_exists': os.path.exists(app.config['UPLOAD_FOLDER'])
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/api/info')
def api_info():
    """Get cybersecurity information"""
    info = {
        'concepts': {
            'exif_metadata': {
                'description': 'Exchangeable Image File Format data embedded in photos',
                'risks': 'Can reveal camera settings, timestamps, GPS location, and device information',
                'mitigation': 'Remove EXIF data before sharing images publicly',
                'calculation': 'Detected if sensitive EXIF tags are present'
            },
            'gps_location': {
                'description': 'Geographic coordinates embedded in image metadata',
                'risks': 'Reveals exact location where photo was taken',
                'mitigation': 'Disable GPS on camera or remove location data before sharing',
                'calculation': 'High privacy risk if GPS coordinates found'
            },
            'steganography': {
                'description': 'Hidden data concealed within image files',
                'risks': 'May contain secret messages or malicious payloads',
                'mitigation': 'Use steganography detection tools and analyze file integrity',
                'calculation': 'Statistical analysis of file size ratios and bit patterns'
            },
            'qr_codes': {
                'description': 'Quick Response codes that can contain URLs or data',
                'risks': 'May link to malicious websites or contain suspicious data',
                'mitigation': 'Scan QR codes with caution and verify destinations',
                'calculation': 'Computer vision detection using OpenCV'
            },
            'script_injection': {
                'description': 'Embedded scripts or executable code within files',
                'risks': 'Could execute malicious code when file is processed',
                'mitigation': 'Scan files for script patterns and validate file integrity',
                'calculation': 'Pattern matching for suspicious code signatures'
            }
        },
        'tools_used': {
            'PIL (Python Imaging Library)': 'Image processing and EXIF metadata extraction',
            'OpenCV': 'Computer vision for QR code detection',
            'NumPy': 'Numerical analysis for steganography detection',
            'Geopy': 'Reverse geocoding for GPS coordinates',
            'Magic': 'File type detection and validation',
            'Flask': 'Web framework for user interface'
        }
    }
    return jsonify(info)

@app.route('/info')
def info_page():
    """Information page"""
    return render_template('info.html')

if __name__ == '__main__':
    logger.info("Starting MetaScan v2.1 Enhanced...")

    # Start cleanup scheduler
    schedule_cleanup()

    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)
