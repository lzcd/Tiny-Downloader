#!/usr/bin/env python3
"""
USENET NNTP client script to connect over SSL and retrieve available groups.
Uses only Python standard library modules.
"""

import socket
import ssl
import sys
import configparser
import os
import xml.etree.ElementTree as ET
import shutil
import glob
import base64
import re
import subprocess
import zipfile
import tarfile
import time
import threading
import time
import threading


class ProgressDisplay:
    """ASCII progress display for downloads."""
    
    def __init__(self, total_items=0, description="Processing"):
        self.total_items = total_items
        self.completed_items = 0
        self.failed_items = 0
        self.description = description
        self.start_time = time.time()
        self.last_update = 0
        self.lock = threading.Lock()
        self.header_printed = False
        
        # Print static header once
        self._print_header()
        
    def _print_header(self):
        """Print static information that doesn't change during progress."""
        print(f"\n{self.description}")
        print(f"Total segments: {self.total_items}")
        print("-" * 60)
        self.header_printed = True
        
    def update(self, completed=0, failed=0, force=False):
        """Update progress display."""
        with self.lock:
            self.completed_items += completed
            self.failed_items += failed
            
            current_time = time.time()
            # Update display every 0.5 seconds or if forced
            if force or current_time - self.last_update >= 0.5:
                self._display_progress()
                self.last_update = current_time
    
    def _display_progress(self):
        """Display the progress bar."""
        if self.total_items == 0:
            return
            
        # Calculate progress
        processed = self.completed_items + self.failed_items
        progress_percent = (processed / self.total_items) * 100
        
        # Calculate elapsed time and ETA
        elapsed = time.time() - self.start_time
        if processed > 0:
            avg_time_per_item = elapsed / processed
            remaining_items = self.total_items - processed
            eta = avg_time_per_item * remaining_items
            eta_str = f"{int(eta//60):02d}:{int(eta%60):02d}"
        else:
            eta_str = "--:--"
        
        elapsed_str = f"{int(elapsed//60):02d}:{int(elapsed%60):02d}"
        
        # Create progress bar
        bar_width = 40
        filled = int((progress_percent / 100) * bar_width)
        bar = "█" * filled + "░" * (bar_width - filled)
        
        try:
            # Move cursor to beginning of line and clear
            sys.stdout.write('\r')
            sys.stdout.write(' ' * 80)  # Clear entire line
            sys.stdout.write('\r')
            sys.stdout.write(f"[{bar}] {progress_percent:5.1f}% ")
            sys.stdout.write(f"({processed}/{self.total_items}) ")
            sys.stdout.write(f"✓{self.completed_items} ✗{self.failed_items} ")
            sys.stdout.write(f"Elapsed:{elapsed_str} ETA:{eta_str}")
            sys.stdout.flush()
        except (BrokenPipeError, IOError):
            # Handle case where stdout is closed or corrupted
            pass
    
    def finish(self):
        """Display final completion message."""
        self.update(force=True)
        sys.stdout.write('\n')
        total = self.completed_items + self.failed_items
        success_rate = (self.completed_items / total * 100) if total > 0 else 100
        elapsed = time.time() - self.start_time
        elapsed_str = f"{int(elapsed//60):02d}:{int(elapsed%60):02d}"
        
        print(f"\n✓ {self.description} completed!")
        print(f"  Total: {total} | Success: {self.completed_items} | Failed: {self.failed_items} | Success Rate: {success_rate:.1f}% | Time: {elapsed_str}")


class NNTPClient:
    """Simple NNTP client for connecting to USENET servers over SSL."""
    
    def __init__(self, server_hostname, port=563):
        self.server_hostname = server_hostname
        self.port = port
        self.socket = None
        self.ssl_socket = None
    
    def get_category_folder(self, category_string):
        """Map category string to folder name."""
        if not category_string:
            return "Other"
        
        # Clean up category string and convert to lowercase
        category_clean = category_string.lower().strip()
        
        # Handle HTML entities and special characters
        category_clean = category_clean.replace('&gt;', '>').replace('&amp;', '&').replace('&lt;', '<')
        
        # Category mapping
        category_map = {
            'movies': 'Movies',
            'movie': 'Movies',
            'tv': 'TV',
            'television': 'TV',
            'anime': 'Anime',
            'music': 'Music',
            'audio': 'Music',
            'games': 'Games',
            'game': 'Games',
            'apps': 'Applications',
            'applications': 'Applications',
            'app': 'Applications',
            'books': 'Books',
            'book': 'Books',
            'documentaries': 'Documentaries',
            'documentary': 'Documentaries',
            'sports': 'Sports',
            'sport': 'Sports',
            'other': 'Other',
            'misc': 'Other'
        }
        
        # Check for exact matches first
        if category_clean in category_map:
            return category_map[category_clean]
        
        # Check for partial matches (handles "TV & Anime" style categories)
        for key, folder in category_map.items():
            if key in category_clean:
                return folder
        
        # Default for unknown categories
        return "Other"
        
    def connect(self):
        """Establish SSL connection to the NNTP server."""
        try:
            # Create a TCP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(30)
            
            # Wrap the socket with SSL
            context = ssl.create_default_context()
            self.ssl_socket = context.wrap_socket(
                self.socket, 
                server_hostname=self.server_hostname
            )
            
            # Connect to the server
            self.ssl_socket.connect((self.server_hostname, self.port))
            
            # Read the welcome message
            welcome_message = self._read_response()
            if not welcome_message.startswith('200'):
                raise ConnectionError(f"Server rejected connection: {welcome_message}")
                

            
        except Exception as error:
            self.disconnect()
            raise ConnectionError(f"Failed to connect to {self.server_hostname}:{self.port} - {error}")
    
    def authenticate(self, username, password):
        """Authenticate with the NNTP server using username and password."""
        try:
            # Send AUTHINFO USER command
            self._send_command(f"AUTHINFO USER {username}")
            response = self._read_response()
            
            # Check if server accepts username and asks for password
            if response.startswith('381'):
                # Send AUTHINFO PASS command
                self._send_command(f"AUTHINFO PASS {password}")
                response = self._read_response()
                
                if response.startswith('281'):
                    print("Authentication successful")
                    return True
                else:
                    raise PermissionError(f"Authentication failed: {response}")
            else:
                raise PermissionError(f"Unexpected response to AUTHINFO USER: {response}")
                
        except Exception as error:
            raise PermissionError(f"Authentication error: {error}")
    
    def _send_command(self, command):
        """Send a command to the NNTP server."""
        if not self.ssl_socket:
            raise ConnectionError("Not connected to server")
        
        try:
            full_command = f"{command}\r\n"
            self.ssl_socket.sendall(full_command.encode('utf-8'))
        except Exception as error:
            raise ConnectionError(f"Failed to send command '{command}': {error}")
    
    def _read_response(self):
        """Read a response line from the NNTP server."""
        if not self.ssl_socket:
            raise ConnectionError("Not connected to server")
        
        try:
            response = self.ssl_socket.recv(1024)
            if not response:
                raise ConnectionError("Connection closed by server")
            
            # Try to decode as UTF-8 for status responses, fallback to latin-1 for binary data
            try:
                decoded = response.decode('utf-8').strip()
                # Check if response looks like a valid NNTP status code (3-digit number)
                if len(decoded) >= 3 and decoded[:3].isdigit():
                    return decoded
                else:
                    # Fallback to latin-1 if response doesn't look like NNTP status
                    return response.decode('latin-1', errors='ignore').strip()
            except UnicodeDecodeError:
                return response.decode('latin-1', errors='ignore').strip()
        except Exception as error:
            raise ConnectionError(f"Failed to read response: {error}")
    
    def _read_line(self):
        """Read a single line from the NNTP server."""
        if not self.ssl_socket:
            raise ConnectionError("Not connected to server")
        
        try:
            # Read byte by byte for status lines to avoid corruption
            line = b''
            while True:
                char = self.ssl_socket.recv(1)
                if not char:
                    break
                if char == b'\n':
                    break
                if char != b'\r':
                    line += char
            
            # Try to decode as UTF-8 for status lines, fallback to latin-1 for binary data
            try:
                decoded = line.decode('utf-8').strip()
                # Check if this looks like a valid NNTP response
                if len(decoded) >= 3 and decoded[:3].isdigit():
                    return decoded
                else:
                    return line.decode('latin-1', errors='ignore').strip()
            except UnicodeDecodeError:
                return line.decode('latin-1', errors='ignore').strip()
            
        except Exception as error:
            raise ConnectionError(f"Failed to read line: {error}")
    
    def _read_raw_line(self):
        """Read a single line as raw bytes from the NNTP server."""
        if not self.ssl_socket:
            raise ConnectionError("Not connected to server")
        
        try:
            # Read byte by byte to avoid mixing responses
            line = b''
            while True:
                char = self.ssl_socket.recv(1)
                if not char:
                    break
                if char == b'\n':
                    break
                if char != b'\r':
                    line += char
            return line
        except Exception as error:
            raise ConnectionError(f"Failed to read raw line: {error}")
    
    def extract_yenc_from_response(self, response_data):
        """Extract yEnc data from a mixed NNTP response."""
        try:
            # Convert to string for analysis
            if isinstance(response_data, bytes):
                response_str = response_data.decode('latin-1', errors='ignore')
            else:
                response_str = response_data
            
            # Look for yEnc begin marker - extract everything after name= until end of line
            ybegin_match = re.search(r'=ybegin.*?name=(.+)$', response_str, re.MULTILINE)
            if not ybegin_match:
                return None
            
            filename = ybegin_match.group(1).strip()
            
            # Look for yEnc end marker (optional for incomplete responses)
            yend_match = re.search(r'=yend.*?size=(\d+)', response_str)
            if yend_match:
                expected_size = int(yend_match.group(1))
            else:
                # Handle incomplete yEnc data (server "feature")
                expected_size = None
            
            # Extract the yEnc payload between =ybegin and =yend (or end of response)
            ybegin_pos = response_str.find('=ybegin')
            yend_pos = response_str.find('=yend')
            
            if ybegin_pos == -1:
                return None
            
            if yend_pos != -1 and yend_pos > ybegin_pos:
                # Complete yEnc data with =yend marker
                yenc_payload = response_str[ybegin_pos:yend_pos + len('=yend')]
            else:
                # Incomplete yEnc data - take everything after =ybegin
                yenc_payload = response_str[ybegin_pos:]
            
            # Find the actual encoded data (after =ybegin line, before =yend line)
            lines = yenc_payload.split('\n')
            encoded_lines = []
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('=ybegin') and not line.startswith('=yend') and not line.startswith('=ypart'):
                    encoded_lines.append(line)
            
            encoded_data = '\n'.join(encoded_lines)
            
            return {
                'filename': filename,
                'size': expected_size,
                'encoded_data': encoded_data
            }
            
        except Exception as error:
            print(f"    ⚠ Error extracting yEnc from response: {error}")
            return None
    
    def _extract_yenc_from_binary(self, binary_data):
        """Extract yEnc data from binary response data."""
        try:
            # Convert to string for pattern matching
            response_str = binary_data.decode('latin-1', errors='ignore')
            
            # Look for yEnc begin marker - be more flexible with pattern matching
            ybegin_match = re.search(r'=ybegin.*?name=([^\r\n]+)', response_str, re.MULTILINE | re.IGNORECASE)
            if not ybegin_match:
                # Try even more flexible pattern - just look for =ybegin anywhere
                if '=ybegin' not in response_str.lower():
                    return None
                else:
                    # Found =ybegin but couldn't parse name - still try to extract
                    ybegin_pos = response_str.lower().find('=ybegin')
                    if ybegin_pos == -1:
                        return None
            else:
                ybegin_pos = response_str.find('=ybegin')
            
            # Look for yEnc end marker
            yend_match = re.search(r'=yend.*?size=(\d+)', response_str, re.MULTILINE | re.IGNORECASE)
            if yend_match:
                expected_size = int(yend_match.group(1))
                yend_pos = response_str.lower().find('=yend')
            else:
                expected_size = None
                yend_pos = -1
            
            # Extract the yEnc payload
            if ybegin_pos == -1:
                return None
            
            if yend_pos != -1 and yend_pos > ybegin_pos:
                # Complete yEnc data
                yenc_payload = response_str[ybegin_pos:yend_pos + len('=yend')]
            else:
                # Incomplete yEnc data - take everything after =ybegin
                yenc_payload = response_str[ybegin_pos:]
            
            # Extract encoded data lines - be more permissive
            lines = yenc_payload.split('\n')
            encoded_lines = []
            
            for line in lines:
                line = line.strip()
                # Skip yEnc control lines but keep everything else
                if (line and 
                    not line.lower().startswith('=ybegin') and 
                    not line.lower().startswith('=yend') and 
                    not line.lower().startswith('=ypart')):
                    encoded_lines.append(line)
            
            encoded_data = '\n'.join(encoded_lines)
            
            # Return the raw yEnc data as bytes for saving
            if encoded_data.strip():
                return encoded_data.encode('latin-1')
            else:
                return None
            
        except Exception as error:
            print(f"    ⚠ Error extracting yEnc from binary: {error}")
            return None
    
    def disconnect(self):
        """Close the connection to the NNTP server."""
        try:
            if self.ssl_socket:
                self.ssl_socket.close()
                self.ssl_socket = None
            if self.socket:
                self.socket.close()
                self.socket = None
            print("Disconnected from server")
        except Exception as error:
            print(f"Error during disconnect: {error}")
    
    def list_groups(self, pattern=None):
        """Retrieve list of available USENET groups."""
        try:
            # Send LIST command with optional pattern
            if pattern:
                command = f"LIST ACTIVE {pattern}"
            else:
                command = "LIST"
                
            self._send_command(command)
            response = self._read_response()
            
            if not response.startswith('215'):
                raise RuntimeError(f"Failed to list groups: {response}")
            
            print(f"Retrieving group list... {response}")
            
            groups = []
            while True:
                line = self._read_line()
                if line == '.':  # End of list marker
                    break
                    
                # Parse group line: group.name high low status
                parts = line.split()
                if len(parts) >= 4:
                    group_name = parts[0]
                    high_article = int(parts[1])
                    low_article = int(parts[2])
                    status = parts[3]
                    
                    groups.append({
                        'name': group_name,
                        'high_article': high_article,
                        'low_article': low_article,
                        'status': status
                    })
            
            return groups
            
        except Exception as error:
            raise RuntimeError(f"Error listing groups: {error}")
    
    def move_segments_to_pending(self, nzb_file_path, segments_folder, pending_folder):
        """Move segments for a specific NZB to the pending combining folder."""
        try:
            # Parse the NZB file to get segment list
            tree = ET.parse(nzb_file_path)
            root = tree.getroot()
            namespace = {'nzb': 'http://www.newzbin.com/DTD/2003/nzb'}
            
            moved_count = 0
            for file_elem in root.findall('.//nzb:file', namespace):
                for segment in file_elem.findall('.//nzb:segment', namespace):
                    segment_id = segment.text
                    segment_filename = f"{segment_id}.seg"
                    source_path = os.path.join(segments_folder, segment_filename)
                    target_path = os.path.join(pending_folder, segment_filename)
                    
                    if os.path.exists(source_path):
                        shutil.move(source_path, target_path)
                        moved_count += 1
            
            return moved_count
            
        except Exception as error:
            raise RuntimeError(f"Error moving segments to pending: {error}")
    
    def decode_yenc_segment(self, segment_data):
        """Decode a single yEnc segment with proper format handling."""
        try:
            # Process as bytes directly to avoid encoding issues
            lines = segment_data.split(b'\n')
            decoded_data = bytearray()
            
            for line in lines:
                # Skip yEnc header lines
                if (line.startswith(b'=ybegin') or 
                    line.startswith(b'=ypart') or 
                    line.startswith(b'=yend') or
                    not line):  # Skip empty lines
                    continue
                
                # Remove carriage return if present
                line = line.rstrip(b'\r')
                
                # Decode this line byte by byte with proper escape handling
                i = 0
                while i < len(line):
                    byte = line[i]
                    
                    if byte == ord('='):
                        # Escape sequence (=X) - skip escape char and decode next byte
                        i += 1
                        if i < len(line):
                            escaped_byte = line[i]
                            # yEnc escape: decoded = (escaped - 42 - 64) % 256
                            decoded_byte = (escaped_byte - 42 - 64) & 0xFF
                            decoded_data.append(decoded_byte)
                    else:
                        # Regular yEnc character: decoded = (encoded - 42) % 256
                        decoded_byte = (byte - 42) & 0xFF
                        decoded_data.append(decoded_byte)
                    
                    i += 1
            
            # If no decoded data, return original
            if not decoded_data:
                return segment_data
            
            return bytes(decoded_data)
            
        except Exception as error:
            print(f"    ⚠ Segment decode error: {error}")
            return segment_data
    
    def _decode_yenc_data(self, encoded_data):
        """Decode yEnc encoded data using simple, reliable approach."""
        try:
            # Convert to bytes for processing
            if isinstance(encoded_data, str):
                yenc_bytes = encoded_data.encode('latin1')
            else:
                yenc_bytes = encoded_data
            
            # Simple yEnc decode without complex corruption fixing
            decoded = bytearray()
            i = 0
            while i < len(yenc_bytes):
                byte = yenc_bytes[i]
                
                if byte == ord('='):
                    # Escape sequence (=X)
                    i += 1
                    if i < len(yenc_bytes):
                        escaped_byte = yenc_bytes[i]
                        # yEnc escape: escaped = (escaped - 42 - 64) % 256
                        decoded_byte = (escaped_byte - 42 - 64) & 0xFF
                        decoded.append(decoded_byte)
                elif byte == ord('*'):
                    # Alternative escape sequence (*X) - some implementations use this
                    i += 1
                    if i < len(yenc_bytes):
                        escaped_byte = yenc_bytes[i]
                        # Similar to = escape but different offset
                        decoded_byte = (escaped_byte - 42 - 64) & 0xFF
                        decoded.append(decoded_byte)
                else:
                    # Regular yEnc character: decoded = (encoded - 42) % 256
                    decoded_byte = (byte - 42) & 0xFF
                    decoded.append(decoded_byte)
                
                i += 1
            
            return bytes(decoded)
            
        except Exception as error:
            print(f"    ⚠ yEnc decode error: {error}")
            return encoded_data if isinstance(encoded_data, bytes) else encoded_data.encode('latin1')

    def _fix_utf8_corruption(self, data):
        """Fix UTF-8 encoding corruption in binary data."""
        try:
            # Comprehensive UTF-8 corruption fix based on observed patterns
            # The issue is that binary data with high bytes is being encoded as UTF-8
            fixed = bytearray()
            i = 0
            while i < len(data):
                byte = data[i]
                
                # Pattern 1: 0xC2 followed by any byte -> original byte (0x80-0xFF range)
                if byte == 0xC2 and i + 1 < len(data):
                    next_byte = data[i + 1]
                    fixed.append(next_byte)
                    i += 2
                    continue
                
                # Pattern 2: 0xC3 followed by 0x80-0x9F -> original byte (0xA0-0xFF range)  
                elif byte == 0xC3 and i + 1 < len(data):
                    next_byte = data[i + 1]
                    if 0x80 <= next_byte <= 0x9F:
                        original_byte = next_byte + 0x20
                        fixed.append(original_byte)
                        i += 2
                        continue
                    elif 0xA0 <= next_byte <= 0xBF:
                        # Handle extended range
                        original_byte = next_byte + 0x20  
                        if original_byte > 255:
                            original_byte -= 256
                        fixed.append(original_byte)
                        i += 2
                        continue
                
                # Pattern 3: 0xE0-0xEF followed by valid UTF-8 continuation
                elif 0xE0 <= byte <= 0xEF and i + 2 < len(data):
                    next_byte = data[i + 1]
                    third_byte = data[i + 2]
                    if (next_byte & 0xC0) == 0x80 and (third_byte & 0xC0) == 0x80:
                        # 3-byte UTF-8 sequence - this is definitely corruption for yEnc data
                        # Extract the original byte that was corrupted
                        # Most likely the third byte is the original one
                        original_candidate = third_byte & 0x3F  # Remove UTF-8 continuation bits
                        
                        # Try different recovery methods
                        # Method 1: Use third byte directly
                        if 32 <= original_candidate <= 126:  # Valid yEnc range
                            fixed.append(original_candidate)
                            i += 3
                            continue
                        
                        # Method 2: Use second byte
                        original_candidate = next_byte & 0x3F
                        if 32 <= original_candidate <= 126:
                            fixed.append(original_candidate)
                            i += 3
                            continue
                        
                        # Method 3: Reconstruct from full UTF-8 value
                        utf8_value = ((byte & 0x0F) << 12) | ((next_byte & 0x3F) << 6) | (third_byte & 0x3F)
                        if utf8_value <= 255:
                            fixed.append(utf8_value & 0xFF)
                            i += 3
                            continue
                
                # Pass through ASCII and other bytes as-is
                fixed.append(byte)
                i += 1
                
            return bytes(fixed)
        except Exception:
            return data  # Return original if fixing fails

    def decode_yenc(self, data):
        """Decode yEnc encoded data using proper implementation."""
        try:
            # Convert to string for analysis if it's bytes
            if isinstance(data, bytes):
                # Use latin1 to preserve binary data during analysis
                data_str = data.decode('latin1', errors='ignore')
            else:
                data_str = data
                data = data.encode('latin1')
            
            # Look for yEnc header first
            yenc_match = re.search(r'=ybegin.*line=(\d+).*size=(\d+)', data_str)
            
            # Check for yEnd marker (indicates already-decoded data)
            yend_match = re.search(r'=yend.*', data_str)
            
            if yend_match and not yenc_match:
                # This is already-decoded binary data with yEnd marker
                # Extract only binary data before yEnd marker
                yend_pos = data_str.find('=yend')
                if yend_pos != -1:
                    # Return binary data before yEnd marker
                    return data[:yend_pos]
                else:
                    return data  # No yEnd found, return as-is
            
            elif yenc_match:
                # Traditional yEnc encoded data - extract encoded payload
                lines = data_str.split('\n')
                yenc_data_lines = []
                
                for line in lines:
                    if line.startswith('=ybegin') or line.startswith('=ypart') or line.startswith('=yend'):
                        continue
                    if line.strip():
                        yenc_data_lines.append(line.strip())
                
                yenc_data = ''.join(yenc_data_lines)
                
                # Convert to bytes for processing
                if isinstance(yenc_data, str):
                    yenc_bytes = yenc_data.encode('latin1')  # Use latin1 for binary data
                else:
                    yenc_bytes = yenc_data
                
                # Proper yEnc decoding according to specification
                decoded = bytearray()
                i = 0
                while i < len(yenc_bytes):
                    byte = yenc_bytes[i]
                    if isinstance(byte, str):
                        byte = ord(byte)
                    
                    if byte == ord('='):
                        # Escape sequence - next byte is escaped
                        i += 1  # Skip the escape character
                        if i < len(yenc_bytes):
                            escaped_byte = yenc_bytes[i]
                            if isinstance(escaped_byte, str):
                                escaped_byte = ord(escaped_byte)
                            # yEnc: escaped = (escaped - 42 - 64) % 256
                            decoded_byte = (escaped_byte - 42 - 64) & 0xFF
                            decoded.append(decoded_byte)
                    else:
                        # yEnc: decoded = (encoded - 42) % 256
                        decoded_byte = (byte - 42) & 0xFF
                        decoded.append(decoded_byte)
                    
                    i += 1
                
                decoded_bytes = bytes(decoded)
                
                # Look for common file headers and clean up any leading garbage
                common_headers = [
                    b'ftyp',          # MP4/MOV (check first due to header issues)
                    b'\x00\x00\x00\x18ftyp',  # MP4 with size prefix
                    b'\x00\x00\x00\x20ftyp',  # MP4 variant
                    b'Rar!\x1a\x07',  # RAR
                    b'PK\x03\x04',     # ZIP
                    b'\x1f\x8b\x08',   # GZIP
                    b'BZh',           # BZIP2
                    b'\x89PNG',       # PNG
                    b'\xff\xd8\xff',  # JPEG
                    b'\x1a\x45\xdf\xa3', # MKV
                ]
                
                for header in common_headers:
                    pos = decoded_bytes.find(header)
                    if pos != -1 and pos > 0:
                        # Found header after some garbage, return clean data
                        clean_data = decoded_bytes[pos:]
                        
                        # Special handling for MP4 files - fix missing size field
                        if header in [b'ftyp', b'\x00\x00\x00\x18ftyp', b'\x00\x00\x00\x20ftyp'] and len(clean_data) >= 16:
                            # Check if this is a malformed MP4 header (missing size field)
                            ftyp_data = clean_data[:16]
                            major_brand = ftyp_data[4:8]
                            
                            if major_brand == b'mp42':
                                # Fix MP4 header by adding correct size field (24 bytes for ftyp box)
                                ftyp_size = (24).to_bytes(4, 'big')
                                fixed_header = ftyp_size + ftyp_data[:12]  # size + ftyp + major_brand + minor_version
                                clean_data = fixed_header + clean_data[12:]  # Skip the duplicated ftyp part
                                print(f"  Fixed malformed MP4 header")
                        
                        return clean_data
                
                return decoded_bytes
            
            else:
                # No yEnc markers found, but check for common file headers to clean up garbage
                if isinstance(data, str):
                    data_bytes = data.encode('utf-8')
                else:
                    data_bytes = data
                
                # Look for common file headers and clean up any leading garbage
                # Check MP4 first since it's most likely to have header issues
                common_headers = [
                    b'ftyp',          # MP4/MOV (check first due to header issues)
                    b'\x00\x00\x00\x18ftyp',  # MP4 with size prefix
                    b'\x00\x00\x00\x20ftyp',  # MP4 variant
                    b'Rar!\x1a\x07',  # RAR
                    b'PK\x03\x04',     # ZIP
                    b'\x1f\x8b\x08',   # GZIP
                    b'BZh',           # BZIP2
                    b'\x89PNG',       # PNG
                    b'\xff\xd8\xff',  # JPEG
                    b'\x1a\x45\xdf\xa3', # MKV
                ]
                
                for header in common_headers:
                    pos = data_bytes.find(header)
                    if pos != -1 and pos > 0:
                        # Found header after some garbage, return clean data
                        clean_data = data_bytes[pos:]
                        
                        # Special handling for MP4 files - fix missing size field
                        if header in [b'ftyp', b'\x00\x00\x00\x18ftyp', b'\x00\x00\x00\x20ftyp'] and len(clean_data) >= 16:
                            # Check if this is a malformed MP4 header (missing size field)
                            ftyp_data = clean_data[:16]
                            major_brand = ftyp_data[4:8]
                            
                            if major_brand == b'mp42':
                                # Fix MP4 header by adding correct size field (24 bytes for ftyp box)
                                ftyp_size = (24).to_bytes(4, 'big')
                                fixed_header = ftyp_size + ftyp_data[:12]  # size + ftyp + major_brand + minor_version
                                clean_data = fixed_header + clean_data[12:]  # Skip the duplicated ftyp part
                                print(f"  Fixed malformed MP4 header")
                        
                        return clean_data
                
                return data_bytes
            
        except Exception as e:
            print(f"Warning: yEnc decoding failed: {e}")
            return data  # Return original data if decoding fails
    
    def decode_files(self, downloaded_encoded_folder, file_decode_folder, downloaded_folder):
        """Decode and process files from downloaded_encoded folder to final destination."""
        try:
            os.makedirs(file_decode_folder, exist_ok=True)
            os.makedirs(downloaded_folder, exist_ok=True)
            
            # Get all files in downloaded_encoded folder (excluding metadata files)
            files_to_process = []
            for file_path in glob.glob(os.path.join(downloaded_encoded_folder, '*')):
                filename = os.path.basename(file_path)
                if not filename.startswith('.category_') and os.path.isfile(file_path):
                    files_to_process.append(file_path)
            
            if not files_to_process:
                print("No files to decode in downloaded_encoded folder.")
                return 0
            
            print(f"Found {len(files_to_process)} files to decode")
            
            successful_decodes = 0
            failed_decodes = 0
            
            for file_path in files_to_process:
                filename = os.path.basename(file_path)
                base_name = os.path.splitext(filename)[0]
                
                print(f"\nProcessing file: {filename}")
                
                # Read category from metadata file
                category = "Other"  # Default category
                metadata_file = os.path.join(downloaded_encoded_folder, f".category_{base_name}")
                if os.path.exists(metadata_file):
                    try:
                        with open(metadata_file, 'r') as f:
                            category = f.read().strip()
                    except:
                        category = "Other"
                
                # Create category folder
                category_folder = os.path.join(downloaded_folder, category)
                os.makedirs(category_folder, exist_ok=True)
                
                final_output_path = os.path.join(category_folder, filename)
                temp_decode_path = os.path.join(file_decode_folder, filename)
                
                # Copy file to temp location for processing
                shutil.copy2(file_path, temp_decode_path)
                
                # Check if this is a PAR2 file first (before yEnc detection)
                is_par2_file = filename.lower().endswith('.par2') or 'par2' in filename.lower()
                
                # Try to decode yEnc if present (skip PAR2 files)
                try:
                    with open(temp_decode_path, 'rb') as f:
                        file_data = f.read()
                    
                    if is_par2_file:
                        print(f"  Detected PAR2 file: {filename}")
                        # Move PAR2 files to file_decode for processing
                        par2_folder = os.path.join(file_decode_folder, 'par2_files')
                        os.makedirs(par2_folder, exist_ok=True)
                        
                        par2_dst = os.path.join(par2_folder, filename)
                        shutil.move(temp_decode_path, par2_dst)
                        os.remove(file_path)
                        
                        # Clean up metadata file
                        if os.path.exists(metadata_file):
                            os.remove(metadata_file)
                        
                        print(f"  ✓ Moved PAR2 file for processing")
                        successful_decodes += 1
                        continue  # Skip to next file
                    
                    # Check if file appears to be yEnc encoded
                    data_str = file_data.decode('utf-8', errors='ignore')
                    
                    # NEW STRATEGY: Only attempt yEnc decoding if we're confident it's yEnc
                    # If file has valid binary headers, assume it's already decoded
                    has_file_header = False
                    common_headers = [
                        b'\xff\xd8\xff',  # JPEG
                        b'ftyp',          # MP4/MOV
                        b'\x1a\x45\xdf\xa3', # MKV
                        b'RIFF',          # AVI/WAV
                        b'PK\x03\x04',     # ZIP
                        b'Rar!\x1a\x07',  # RAR
                    ]
                    
                    for header in common_headers:
                        if file_data.startswith(header):
                            has_file_header = True
                            break
                    
                    # Only decode yEnc if it has markers AND no valid file header
                    if '=ybegin' in data_str and '=yend' in data_str and not has_file_header:
                            print(f"  Detected yEnc encoding, attempting to decode...")
                            decoded_data = self.decode_yenc(data_str)
                            
                            # Write decoded data to final location
                            with open(final_output_path, 'wb') as f:
                                if isinstance(decoded_data, str):
                                    f.write(decoded_data.encode('utf-8'))
                                else:
                                    f.write(decoded_data)
                            
                            print(f"  ✓ Successfully decoded and saved to: {filename}")
                            successful_decodes += 1
                            
                            # Remove original encoded file and temp decode file
                            os.remove(file_path)
                            os.remove(temp_decode_path)
                            
                            # Clean up metadata file
                            if os.path.exists(metadata_file):
                                os.remove(metadata_file)
                            
                    elif filename.lower().endswith(('.rar', '.zip', '.tar', '.tar.gz', '.tgz')):
                        print(f"  Detected archive file: {filename}")
                        
                        # For multi-volume RAR archives, copy all parts to file_decode folder
                        if filename.lower().endswith('.rar') and '.part' in filename.lower():
                            base_match = re.match(r'(.+?)\.\.part\d+\.rar$', filename, re.IGNORECASE)
                            if base_match:
                                base_name = base_match.group(1)
                                # Find all RAR files in downloaded_encoded and copy matching ones
                                all_rar_files = glob.glob(os.path.join(downloaded_encoded_folder, '*.rar'))
                                for part_file in all_rar_files:
                                    part_filename = os.path.basename(part_file)
                                    # Check if this file matches our archive pattern
                                    if re.match(re.escape(base_name) + r'\.\.part\d+\.rar$', part_filename, re.IGNORECASE):
                                        part_dest = os.path.join(file_decode_folder, part_filename)
                                        if not os.path.exists(part_dest):
                                            shutil.copy2(part_file, part_dest)
                                            print(f"    Copied additional part: {part_filename}")
                        
                        # Extract archive to a subfolder in file_decode
                        archive_name = os.path.splitext(filename)[0]
                        extract_folder = os.path.join(file_decode_folder, f"{archive_name}_extracted")
                        
                        if self.extract_archive(temp_decode_path, extract_folder):
                            # Process PAR2 files if they exist
                            self.process_par2_files(extract_folder)
                            
                            # Move extracted files to final location
                            extracted_files = []
                            for root, dirs, files in os.walk(extract_folder):
                                for file in files:
                                    src_path = os.path.join(root, file)
                                    # Calculate relative path
                                    rel_path = os.path.relpath(src_path, extract_folder)
                                    dst_path = os.path.join(category_folder, rel_path)
                                    
                                    # Create subdirectories if needed
                                    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                                    
                                    # Move file
                                    shutil.move(src_path, dst_path)
                                    extracted_files.append(dst_path)
                            
                            print(f"  ✓ Extracted {len(extracted_files)} files from archive")
                            
                            # Clean up extraction folder
                            shutil.rmtree(extract_folder, ignore_errors=True)
                            
                            # Remove original archive and temp file
                            os.remove(file_path)
                            os.remove(temp_decode_path)
                            
                            # Clean up metadata file
                            if os.path.exists(metadata_file):
                                os.remove(metadata_file)
                            
                            successful_decodes += 1
                        else:
                            print(f"  ✗ Failed to extract archive: {filename}")
                            failed_decodes += 1
                            # Clean up temp file
                            if os.path.exists(temp_decode_path):
                                os.remove(temp_decode_path)
                            
                    elif filename.lower().endswith('.par2'):
                        print(f"  Detected PAR2 file: {filename}")
                        # Move PAR2 files to file_decode for processing
                        par2_folder = os.path.join(file_decode_folder, 'par2_files')
                        os.makedirs(par2_folder, exist_ok=True)
                        
                        par2_dst = os.path.join(par2_folder, filename)
                        shutil.move(temp_decode_path, par2_dst)
                        os.remove(file_path)
                        
                        # Clean up metadata file
                        if os.path.exists(metadata_file):
                            os.remove(metadata_file)
                        
                        print(f"  ✓ Moved PAR2 file for processing")
                        successful_decodes += 1
                        
                    else:
                        print(f"  File does not appear to be yEnc encoded or archive, moving as-is")
                        # Move file directly to downloaded folder
                        shutil.move(temp_decode_path, final_output_path)
                        os.remove(file_path)
                        
                        # Clean up metadata file
                        if os.path.exists(metadata_file):
                            os.remove(metadata_file)
                        
                        successful_decodes += 1
                        
                except Exception as error:
                    print(f"  ✗ Failed to decode {filename}: {error}")
                    failed_decodes += 1
                    # Clean up temp file if it exists
                    if os.path.exists(temp_decode_path):
                        try:
                            os.remove(temp_decode_path)
                        except:
                            pass
                    continue
            
            print(f"\nDecoding summary:")
            print(f"  Successful: {successful_decodes}")
            print(f"  Failed: {failed_decodes}")
            
            return successful_decodes
            
        except Exception as error:
            raise RuntimeError(f"Error decoding files: {error}")
    
    def _fix_media_headers(self, file_path):
        """Fix common media file header issues after yEnc decoding."""
        try:
            with open(file_path, 'r+b') as f:
                header = f.read(32)
                
                # Fix MP4 header size issue
                if len(header) >= 8 and header[4:8] == b'ftyp':
                    # Check if size is wrong (common yEnc decoding issue)
                    size = int.from_bytes(header[0:4], 'big')
                    if size == 24:  # Wrong size (0x18)
                        # Fix to correct size (0x20 for ftyp header)
                        f.seek(0)
                        f.write(b'\x00\x00\x00\x20' + header[4:])
                        print(f"    ✓ Fixed MP4 header size")
                
                # Fix MKV header if needed
                elif len(header) >= 4 and header.startswith(b'\x1aE'):
                    # MKV header looks correct, no fix needed
                    pass
                    
        except Exception as error:
            # Don't fail the whole process if header fix fails
            pass
    
    def verify_combined_file(self, file_path):
        """Verify that a combined file is valid and not corrupted."""
        try:
            if not os.path.exists(file_path):
                return False
            
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return False
            
            # Check for common file headers
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            # Valid file headers
            valid_headers = [
                b'\xff\xd8\xff',  # JPEG
                b'ftyp',          # MP4/MOV
                b'\x1a\x45\xdf\xa3', # MKV
                b'RIFF',          # AVI/WAV
                b'PK\x03\x04',     # ZIP
                b'Rar!\x1a\x07',  # RAR
            ]
            
            for valid_header in valid_headers:
                if header.startswith(valid_header):
                    return True
            
            # If no valid header found, check if it might be a valid text file
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    f.read(100)  # Try to read as text
                return True  # If readable as text, consider it valid
            except:
                return False  # Binary file without recognized header
                
        except Exception:
            return False
    
    def combine_segments_from_nzb(self, nzb_file_path, pending_segments_folder, output_folder):
        """Combine segments from NZB file into complete files."""
        try:
            # Parse the NZB file
            tree = ET.parse(nzb_file_path)
            root = tree.getroot()
            namespace = {'nzb': 'http://www.newzbin.com/DTD/2003/nzb'}
            
            os.makedirs(output_folder, exist_ok=True)
            
            combined_files = []
            
            # Process each file in the NZB
            for file_elem in root.findall('.//nzb:file', namespace):
                subject = file_elem.get('subject', '')
                
                # Extract filename from subject
                # First try HTML-encoded quotes
                filename_match = re.search(r'&quot;([^&]+)&quot;', subject)
                if not filename_match:
                    # Try regular quotes
                    filename_match = re.search(r'"([^"]+)"', subject)
                
                if filename_match:
                    filename = filename_match.group(1)
                else:
                    # Fallback: extract filename before yEnc metadata
                    # Look for pattern: [hash].extension before yEnc
                    yenc_pos = subject.find(' yEnc')
                    if yenc_pos != -1:
                        filename_part = subject[:yenc_pos].strip().rstrip('"')
                        # Find the last [hash].extension pattern
                        filename_match = re.search(r'.*\[([0-9a-fA-F]+)\]\.(\w+)', filename_part)
                        if filename_match:
                            filename = f"[{filename_match.group(1)}].{filename_match.group(2)}"
                        else:
                            # Final fallback: clean up the filename part
                            filename = re.sub(r'[^\w\-_\.]', '_', filename_part)
                    else:
                        # No yEnc found, use fallback
                        filename = re.sub(r'[^\w\-_\.]', '_', subject)
                
                output_path = os.path.join(output_folder, filename)
                
                # Get all segments for this file, sorted by number
                segments = []
                for segment in file_elem.findall('.//nzb:segment', namespace):
                    segment_id = segment.text
                    segment_number = int(segment.get('number', 1))
                    segment_filename = f"{segment_id}.seg"
                    segment_path = os.path.join(pending_segments_folder, segment_filename)
                    
                    if os.path.exists(segment_path):
                        segments.append((segment_number, segment_path))
                
                if not segments:
                    print(f"Warning: No segments found for file: {filename}")
                    continue
                
                # Sort segments by number
                segments.sort(key=lambda x: x[0])
                
                # Decode and combine segments
                print(f"Decoding and combining {len(segments)} segments for: {filename}")
                
                # First, decode each segment individually
                decoded_segments = []
                for segment_number, segment_path in segments:
                    try:
                        with open(segment_path, 'rb') as seg_file:
                            segment_data = seg_file.read()
                        
                        # Decode this segment's yEnc content
                        decoded_segment = self.decode_yenc_segment(segment_data)
                        decoded_segments.append((segment_number, decoded_segment))
                        print(f"  ✓ Decoded segment {segment_number}")
                        
                    except Exception as error:
                        print(f"    ✗ Failed to decode segment {segment_number}: {error}")
                        continue
                
                if not decoded_segments:
                    print(f"Warning: No successfully decoded segments for {filename}")
                    continue
                
                # Sort decoded segments by number and combine
                decoded_segments.sort(key=lambda x: x[0])
                
                with open(output_path, 'wb') as output_file:
                    for segment_number, decoded_data in decoded_segments:
                        try:
                            output_file.write(decoded_data)
                        except Exception as error:
                            print(f"    ✗ Failed to write decoded segment {segment_number}: {error}")
                            continue
                
                # Fix common MP4/MKV header issues if detected
                try:
                    self._fix_media_headers(output_path)
                except Exception as error:
                    print(f"    ⚠ Header fix attempt failed: {error}")
                            
                print(f"  ✓ Combined segments for: {filename}")
                combined_files.append(output_path)
            
            print(f"\nCombining summary:")
            print(f"  Combined {len(combined_files)} files")
            
            return combined_files
            
        except Exception as error:
            raise RuntimeError(f"Error combining segments: {error}")
    
    def cleanup_file_decode_folder(self, file_decode_folder):
        """Clean up any remaining files in the file_decode folder."""
        try:
            # Find all files and directories in file_decode folder
            remaining_items = []
            for item_path in glob.glob(os.path.join(file_decode_folder, '*')):
                remaining_items.append(item_path)
            
            if not remaining_items:
                print("No files to clean up in file_decode folder.")
                return 0
            
            print(f"Cleaning up {len(remaining_items)} items from file_decode folder:")
            
            cleaned_count = 0
            for item_path in remaining_items:
                try:
                    item_name = os.path.basename(item_path)
                    
                    if os.path.isfile(item_path):
                        print(f"  Removing file: {item_name}")
                        os.remove(item_path)
                        cleaned_count += 1
                    elif os.path.isdir(item_path):
                        print(f"  Removing directory: {item_name}")
                        shutil.rmtree(item_path, ignore_errors=True)
                        cleaned_count += 1
                        
                except Exception as error:
                    print(f"  Warning: Failed to remove {os.path.basename(item_path)}: {error}")
                    continue
            
            print(f"Cleaned up {cleaned_count} items from file_decode folder")
            return cleaned_count
            
        except Exception as error:
            raise RuntimeError(f"Error cleaning up file_decode folder: {error}")
    
    def cleanup_completed_segments(self, completed_folder, pending_segments_folder):
        """Clean up segment files for completed NZB files."""
        try:
            # Get all completed NZB files
            completed_nzbs = glob.glob(os.path.join(completed_folder, '*.nzb'))
            
            if not completed_nzbs:
                print("No completed NZB files to clean up segments for.")
                return 0
            
            print(f"Cleaning up segments for {len(completed_nzbs)} completed NZB files...")
            
            cleaned_count = 0
            
            for nzb_file in completed_nzbs:
                try:
                    # Parse the NZB file to get segment IDs
                    tree = ET.parse(nzb_file)
                    root = tree.getroot()
                    namespace = {'nzb': 'http://www.newzbin.com/DTD/2003/nzb'}
                    
                    # Get all segment IDs from this NZB
                    segment_ids = set()
                    for segment in root.findall('.//nzb:segment', namespace):
                        segment_id = segment.text
                        if segment_id:
                            segment_ids.add(segment_id)
                    
                    # Remove corresponding segment files
                    for segment_id in segment_ids:
                        segment_filename = f"{segment_id}.seg"
                        segment_path = os.path.join(pending_segments_folder, segment_filename)
                        
                        if os.path.exists(segment_path):
                            os.remove(segment_path)
                            cleaned_count += 1
                    
                    print(f"  Cleaned up {len(segment_ids)} segments for {os.path.basename(nzb_file)}")
                    
                except Exception as error:
                    print(f"  Warning: Failed to clean up segments for {os.path.basename(nzb_file)}: {error}")
                    continue
            
            print(f"Total segments cleaned up: {cleaned_count}")
            return cleaned_count
            
        except Exception as error:
            raise RuntimeError(f"Error cleaning up completed segments: {error}")
    
    def extract_archive(self, archive_path, extract_to_folder):
        """Extract archive files (RAR, ZIP, TAR) to specified folder."""
        try:
            os.makedirs(extract_to_folder, exist_ok=True)
            archive_name = os.path.basename(archive_path)
            
            print(f"  Extracting archive: {archive_name}")
            
            # Try ZIP extraction first
            if archive_name.lower().endswith('.zip'):
                try:
                    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                        zip_ref.extractall(extract_to_folder)
                    print(f"  ✓ Successfully extracted ZIP archive")
                    return True
                except Exception as e:
                    print(f"  ⚠ ZIP extraction failed: {e}")
            
            # Try TAR extraction
            elif archive_name.lower().endswith(('.tar', '.tar.gz', '.tgz')):
                try:
                    with tarfile.open(archive_path, 'r:*') as tar_ref:
                        tar_ref.extractall(extract_to_folder)
                    print(f"  ✓ Successfully extracted TAR archive")
                    return True
                except Exception as e:
                    print(f"  ⚠ TAR extraction failed: {e}")
            
            # Try RAR extraction (requires unrar command)
            elif archive_name.lower().endswith('.rar'):
                try:
                    # Try using unrar command
                    result = subprocess.run(
                        ['unrar', 'x', '-y', archive_path, extract_to_folder],
                        capture_output=True, text=True, timeout=300
                    )
                    if result.returncode == 0:
                        print(f"  ✓ Successfully extracted RAR archive")
                        return True
                    else:
                        print(f"  ⚠ RAR extraction failed: {result.stderr}")
                except FileNotFoundError:
                    print(f"  ⚠ unrar command not found, trying python-rarfile")
                except subprocess.TimeoutExpired:
                    print(f"  ⚠ RAR extraction timed out")
                except Exception as e:
                    print(f"  ⚠ RAR extraction failed: {e}")
                
                # Try using rarfile library if available
                try:
                    import rarfile
                    with rarfile.RarFile(archive_path, 'r') as rar_ref:
                        rar_ref.extractall(extract_to_folder)
                    print(f"  ✓ Successfully extracted RAR archive using python-rarfile")
                    return True
                except ImportError:
                    print(f"  ⚠ rarfile library not available")
                except Exception as e:
                    print(f"  ⚠ python-rarfile extraction failed: {e}")
            
            else:
                print(f"  ⚠ Unsupported archive format: {archive_name}")
            
            return False
            
        except Exception as error:
            print(f"  ✗ Archive extraction failed: {error}")
            return False
    
    def process_par2_files(self, file_decode_folder):
        """Process PAR2 files to verify and repair archives."""
        try:
            # Find PAR2 files
            par2_files = glob.glob(os.path.join(file_decode_folder, '*.par2'))
            if not par2_files:
                return True  # No PAR2 files to process
            
            print(f"  Found {len(par2_files)} PAR2 files")
            
            # Try to use par2 command line tool
            try:
                main_par2 = None
                for par2_file in par2_files:
                    if 'vol' not in os.path.basename(par2_file).lower():
                        main_par2 = par2_file
                        break
                
                if main_par2:
                    print(f"  Verifying with PAR2: {os.path.basename(main_par2)}")
                    result = subprocess.run(
                        ['par2', 'r', main_par2],
                        cwd=file_decode_folder,
                        capture_output=True, text=True, timeout=600
                    )
                    
                    if result.returncode == 0:
                        print(f"  ✓ PAR2 verification completed successfully")
                        return True
                    else:
                        print(f"  ⚠ PAR2 verification issues: {result.stderr}")
                        return False
                else:
                    print(f"  ⚠ No main PAR2 file found")
                    return False
                    
            except FileNotFoundError:
                print(f"  ⚠ par2 command not found, skipping verification")
                return True  # Continue without PAR2 verification
            except subprocess.TimeoutExpired:
                print(f"  ⚠ PAR2 verification timed out")
                return False
            except Exception as e:
                print(f"  ⚠ PAR2 verification failed: {e}")
                return False
                
        except Exception as error:
            print(f"  ✗ PAR2 processing failed: {error}")
            return False
    
    def process_pending_combining(self, pending_folder, segments_folder, pending_segments_folder, output_folder, completed_folder, delete_segments=True):
        """Process all NZB files in the pending combining folder."""
        try:
            # Find all NZB files in the pending combining folder
            nzb_pattern = os.path.join(pending_folder, '*.nzb')
            nzb_files = glob.glob(nzb_pattern)
            
            if not nzb_files:
                print("No NZB files found in pending combining folder.")
                return 0
            
            print(f"Found {len(nzb_files)} NZB files to combine:")
            for nzb_file in nzb_files:
                print(f"  - {os.path.basename(nzb_file)}")
            
            print("\nStarting combining process...")
            
            successful_count = 0
            for nzb_file in nzb_files:
                try:
                    print(f"\nProcessing: {os.path.basename(nzb_file)}")
                    
                    # Move segments to pending combining folder
                    moved_segments = self.move_segments_to_pending(nzb_file, segments_folder, pending_segments_folder)
                    print(f"Moved {moved_segments} segments to pending combining folder")
                    
                    # Extract category from NZB metadata
                    try:
                        tree = ET.parse(nzb_file)
                        root = tree.getroot()
                        namespace = {'nzb': 'http://www.newzbin.com/DTD/2003/nzb'}
                        
                        category = "Other"
                        category_meta = root.find('.//nzb:meta[@type="category"]', namespace)
                        if category_meta is not None and category_meta.text:
                            category = self.get_category_folder(category_meta.text)
                            print(f"  Category: {category}")
                    except Exception as error:
                        print(f"  Warning: Could not extract category: {error}")
                        category = "Other"
                    
                    # Combine segments
                    combined_files = self.combine_segments_from_nzb(nzb_file, pending_segments_folder, output_folder)
                    
                    if combined_files:
                        print(f"Successfully combined {len(combined_files)} files")
                        
                        # Verify combined files are valid before marking as successful
                        valid_files = 0
                        for combined_file in combined_files:
                            if self.verify_combined_file(combined_file):
                                print(f"  ✓ Verified combined file: {os.path.basename(combined_file)}")
                                valid_files += 1
                            else:
                                print(f"  ⚠ Combined file appears invalid: {os.path.basename(combined_file)}")
                        
                        if valid_files > 0:
                            # Move NZB to completed folder only if files are valid
                            nzb_filename = os.path.basename(nzb_file)
                            completed_path = os.path.join(completed_folder, nzb_filename)
                            shutil.move(nzb_file, completed_path)
                            print(f"Moved NZB to completed folder: {completed_path}")
                            
                            successful_count += 1
                        else:
                            print(f"Warning: No valid combined files for {os.path.basename(nzb_file)}")
                    else:
                        print(f"No files were combined for {os.path.basename(nzb_file)}")
                        
                except Exception as error:
                    print(f"Failed to process {os.path.basename(nzb_file)}: {error}")
                    continue
            
            # Clean up segments for completed NZBs (only if delete_segments is True)
            if successful_count > 0 and delete_segments:
                self.cleanup_completed_segments(completed_folder, pending_segments_folder)
                print("Segments deleted after successful combining")
            elif successful_count > 0:
                print("Segments retained after successful combining")
            
            print(f"\nCombining complete!")
            print(f"Successfully processed: {successful_count}/{len(nzb_files)} files")
            
            return successful_count
            
        except Exception as error:
            raise RuntimeError(f"Error in pending combining process: {error}")
    
    def process_nzb_file(self, nzb_file_path, segments_folder, completed_folder, pending_combining_folder=None):
        """Process a single NZB file by downloading its segments."""
        try:
            print(f"\nProcessing NZB file: {os.path.basename(nzb_file_path)}")
            
            # Parse NZB file to get segments
            tree = ET.parse(nzb_file_path)
            root = tree.getroot()
            namespace = {'nzb': 'http://www.newzbin.com/DTD/2003/nzb'}
            
            # Extract category from NZB metadata
            category = "Other"
            category_meta = root.find('.//nzb:meta[@type="category"]', namespace)
            if category_meta is not None and category_meta.text:
                category = self.get_category_folder(category_meta.text)
                print(f"  Category: {category}")
            
            # Count total segments first for progress tracking
            total_segments = 0
            for file_elem in root.findall('.//nzb:file', namespace):
                for segment in file_elem.findall('.//nzb:segment', namespace):
                    total_segments += 1
            
            successful_downloads = 0
            failed_downloads = 0
            
            # Initialize progress display
            progress = ProgressDisplay(total_segments, f"Downloading {os.path.basename(nzb_file_path)}")
            
            # Process each file in the NZB
            for file_elem in root.findall('.//nzb:file', namespace):
                filename = file_elem.get('subject', 'unknown')
                print(f"  Processing file: {filename}")
                
                # Process each segment
                for segment in file_elem.findall('.//nzb:segment', namespace):
                    segment_id = segment.text
                    
                    # Extract message ID from segment ID
                    if segment_id:
                        # Convert to proper message-ID format if needed
                        if not segment_id.startswith('<'):
                            message_id = f"<{segment_id}>"
                        else:
                            message_id = segment_id
                        segment_filename = f"{segment_id}.seg"
                        segment_path = os.path.join(segments_folder, segment_filename)
                        
                        # Check if segment already exists
                        if os.path.exists(segment_path):
                            successful_downloads += 1
                            progress.update(completed=1)
                            continue
                        
                        # Download the segment
                        try:
                            # Join the group first
                            group_elem = file_elem.find('.//nzb:groups/nzb:group', namespace)
                            if group_elem is None or group_elem.text is None:
                                print(f"    ⚠ No group found for segment {segment_filename}")
                                failed_downloads += 1
                                continue
                            
                            group_name = group_elem.text
                            self._send_command(f"GROUP {group_name}")
                            group_response = self._read_response()
                            
                            if not group_response.startswith('211'):
                                # Check if response contains yEnc data (server "feature")
                                if '=ybegin' in group_response:
                                    print(f"    ✓ Server sent yEnc data instead of group response for {group_name}")
                                    print(f"    ✓ Extracting article data from response...")
                                    
                                    # Try to extract yEnc data from the response
                                    yenc_data = self.extract_yenc_from_response(group_response)
                                    if yenc_data:
                                        # Save the extracted data as a segment
                                        try:
                                            # Decode the yEnc data
                                            decoded_data = self.decode_yenc(yenc_data['encoded_data'])
                                            
                                            # Create segment filename based on message ID
                                            segment_filename = f"{segment_id}.seg"
                                            segment_path = os.path.join(segments_folder, segment_filename)
                                            
                                            # Save the decoded data
                                            os.makedirs(segments_folder, exist_ok=True)
                                            with open(segment_path, 'wb') as f:
                                                f.write(decoded_data)
                                            
                                            print(f"    ✓ Successfully extracted and saved {yenc_data['filename']}")
                                            successful_downloads += 1
                                            progress.update(completed=1)
                                            continue  # Skip to next segment
                                            
                                        except Exception as error:
                                            print(f"    ⚠ Failed to process yEnc data: {error}")
                                    
                                    # If we couldn't extract the data, treat as failure
                                    print(f"    ⚠ Could not extract usable data from yEnc response")
                                    failed_downloads += 1
                                    progress.update(failed=1)
                                else:
                                    # Check if response contains binary data (yEnc extraction opportunity)
                                    has_binary = any(ord(c) < 32 or ord(c) > 126 for c in group_response[:100] if c not in '\r\n\t')
                                    if has_binary:
                                        print(f"    ⚠ Server sent binary data instead of NNTP response - attempting yEnc extraction")
                                        
                                        # Try to extract yEnc data from the binary response
                                        try:
                                            # Convert to bytes for yEnc processing
                                            if isinstance(group_response, str):
                                                binary_data = group_response.encode('latin-1', errors='ignore')
                                            else:
                                                binary_data = group_response
                                            
                                            # Look for yEnc pattern in the binary data
                                            yenc_data = self._extract_yenc_from_binary(binary_data)
                                            
                                            if yenc_data:
                                                # Save the extracted yEnc data as segment
                                                try:
                                                    with open(segment_path, 'wb') as f:
                                                        f.write(yenc_data)
                                                    
                                                    print(f"    ✓ Extracted and saved yEnc data to {segment_filename}")
                                                    successful_downloads += 1
                                                    progress.update(completed=1)
                                                    
                                                    continue  # Success, move to next segment
                                                    
                                                except IOError as save_error:
                                                    print(f"    ⚠ Failed to save extracted yEnc data: {save_error}")
                                            else:
                                                # Debug: Save the binary response for analysis
                                                debug_filename = f"debug_binary_response_{segment_id.replace('@', '_').replace('$', '_')}.bin"
                                                debug_path = os.path.join(segments_folder, debug_filename)
                                                try:
                                                    with open(debug_path, 'wb') as f:
                                                        f.write(binary_data)
                                                    print(f"    ⚠ No valid yEnc data found in binary response")
                                                    print(f"    💾 Saved binary data to {debug_filename} for analysis")
                                                    
                                                    # Show first 200 characters as hex dump for analysis
                                                    sample_size = min(200, len(binary_data))
                                                    sample_data = binary_data[:sample_size]
                                                    hex_dump = ' '.join(f'{b:02x}' for b in sample_data)
                                                    ascii_dump = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in sample_data)
                                                    print(f"    🔍 Sample data (hex): {hex_dump[:80]}...")
                                                    print(f"    🔍 Sample data (ascii): {ascii_dump[:80]}...")
                                                    
                                                except Exception as debug_error:
                                                    print(f"    ⚠ No valid yEnc data found in binary response")
                                                    print(f"    ⚠ Failed to save debug data: {debug_error}")
                                                
                                        except Exception as extract_error:
                                            print(f"    ⚠ Failed to extract yEnc from binary response: {extract_error}")
                                    else:
                                        # Show first 100 chars of text response
                                        safe_response = group_response[:100].replace('\r', '\\r').replace('\n', '\\n')
                                        print(f"    ⚠ Failed to join group {group_name}: {safe_response}...")
                                    
                                    failed_downloads += 1
                                    progress.update(completed=1)
                                    continue
                            
                            # Download the article
                            self._send_command(f"BODY {message_id}")
                            response = self._read_line()
                            
                            if response.startswith('222'):
                                # Read article data line by line to preserve yEnc headers
                                article_data = b''
                                
                                try:
                                    while True:
                                        line = self._read_raw_line()
                                        if not line:
                                            print(f"    ⚠ Connection closed while reading article data")
                                            break
                                        
                                        # Check for end marker (single dot on a line)
                                        if line == b'.':
                                            break
                                        
                                        # Handle escaped dots (.. -> .)
                                        if line.startswith(b'..'):
                                            line = line[1:]
                                        
                                        article_data += line + b'\r\n'
                                        
                                        # Safety limit to prevent infinite reading
                                        if len(article_data) > 800000:  # 800KB limit
                                            print(f"    ⚠ Article size limit reached, truncating")
                                            break
                                
                                except ConnectionError as error:
                                    print(f"    ⚠ Connection error reading article data: {error}")
                                    article_data = b''
                                except Exception as error:
                                    print(f"    ⚠ Error reading article data: {error}")
                                    article_data = b''
                                
                                # Save the segment
                                os.makedirs(segments_folder, exist_ok=True)
                                with open(segment_path, 'wb') as f:
                                    f.write(article_data)
                                
                                successful_downloads += 1
                                progress.update(completed=1)
                            else:
                                # Check if we got yEnc data instead of proper response
                                if '=ybegin' in response:
                                    print(f"    ✓ Server sent yEnc data instead of BODY response for {message_id}")
                                    print(f"    ✓ Extracting article data from response...")
                                    
                                    # Try to extract yEnc data from the response
                                    yenc_data = self.extract_yenc_from_response(response)
                                    if yenc_data:
                                        try:
                                            # Decode the yEnc data
                                            decoded_data = self.decode_yenc(yenc_data['encoded_data'])
                                            
                                            # Save the decoded data directly as segment
                                            os.makedirs(segments_folder, exist_ok=True)
                                            with open(segment_path, 'wb') as f:
                                                f.write(decoded_data)
                                            
                                            print(f"    ✓ Successfully extracted and saved {yenc_data['filename']}")
                                            successful_downloads += 1
                                            progress.update(completed=1)
                                            continue  # Skip to next segment
                                            
                                        except Exception as error:
                                            print(f"    ⚠ Failed to process yEnc data: {error}")
                                    
                                    # If we couldn't extract the data, treat as failure
                                    print(f"    ⚠ Could not extract usable data from yEnc response")
                                    failed_downloads += 1
                                    progress.update(failed=1)
                                else:
                                    # Enhanced error handling for different NNTP response codes
                                    if response.startswith('430'):
                                        print(f"    ⚠ Article not found on server: {message_id}")
                                        print(f"      Error: Article expired or not available (430)")
                                    elif response.startswith('423'):
                                        print(f"    ⚠ Article not selected: {message_id}")
                                        print(f"      Error: Bad article number (423)")
                                    elif response.startswith('480'):
                                        print(f"    ⚠ Authentication required for: {message_id}")
                                        print(f"      Error: Permission denied (480)")
                                    else:
                                        print(f"    ⚠ Failed to retrieve article {message_id}: {response}")
                                    
                                    failed_downloads += 1
                                    progress.update(failed=1)
                            
                        except Exception as error:
                            failed_downloads += 1
                            progress.update(failed=1)
                    else:
                        failed_downloads += 1
                        progress.update(failed=1)
            
            # Finish progress display
            progress.finish()
            
            # Move NZB to appropriate folder based on success
            nzb_filename = os.path.basename(nzb_file_path)
            
            if failed_downloads == 0:
                # All segments downloaded successfully
                os.makedirs(completed_folder, exist_ok=True)
                completed_path = os.path.join(completed_folder, nzb_filename)
                shutil.move(nzb_file_path, completed_path)
                print(f"✓ Moved NZB to completed folder: {completed_path}")
                
                # Automatically copy NZB to pending combining folder for next step
                if pending_combining_folder:
                    os.makedirs(pending_combining_folder, exist_ok=True)
                    pending_path = os.path.join(pending_combining_folder, nzb_filename)
                    shutil.copy2(completed_path, pending_path)
                    print(f"✓ Copied NZB to pending combining folder: {pending_path}")
                
                return True
            else:
                # Some segments failed - provide detailed analysis
                total_segments = successful_downloads + failed_downloads
                success_rate = (successful_downloads / total_segments * 100) if total_segments > 0 else 0
                
                print(f"\n📊 DOWNLOAD SUMMARY:")
                print(f"   Total segments: {total_segments}")
                print(f"   Successful: {successful_downloads}")
                print(f"   Failed: {failed_downloads}")
                print(f"   Success rate: {success_rate:.1f}%")
                
                if failed_downloads > 0:
                    print(f"\n⚠️  COMMON CAUSES OF 430 ERRORS:")
                    print(f"   • Article retention expired (most common)")
                    print(f"   • Server doesn't carry the newsgroup")
                    print(f"   • Article was removed (DMCA/takedown)")
                    print(f"   • Incomplete server coverage")
                    
                failed_folder = completed_folder.replace('completed', 'failed')
                os.makedirs(failed_folder, exist_ok=True)
                failed_path = os.path.join(failed_folder, nzb_filename)
                
                if success_rate < 25:
                        print(f"\n❌ VERY LOW SUCCESS RATE ({success_rate:.1f}%)")
                        print(f"   This content is likely no longer available")
                        print(f"   Try searching for a newer post or different source")
                        
                        # Check if this might be a retention issue
                        try:
                            import datetime
                            nzb_date = None
                            with open(nzb_file_path, 'r') as f:
                                content = f.read()
                                # Look for date attribute in NZB
                                date_match = re.search(r'date="(\d+)"', content)
                                if date_match:
                                    nzb_date = datetime.datetime.fromtimestamp(int(date_match.group(1)))
                                    days_old = (datetime.datetime.now() - nzb_date).days
                                    print(f"\n📅 CONTENT AGE ANALYSIS:")
                                    print(f"   Post date: {nzb_date.strftime('%Y-%m-%d %H:%M:%S')}")
                                    print(f"   Days old: {days_old}")
                                    
                                    if days_old > 1000:
                                        print(f"   ⚠️  Very old post - likely beyond server retention")
                                        print(f"   Most Usenet servers retain articles 30-2000 days")
                                    elif days_old > 500:
                                        print(f"   ⚠️  Old post - may be beyond some server retention")
                                    else:
                                        print(f"   ✅ Recent post - retention should not be an issue")
                        except Exception:
                            pass  # Skip date analysis if it fails
                
                shutil.move(nzb_file_path, failed_path)
                print(f"\n✗ Moved NZB to failed folder: {failed_path}")
                return False
                
        except Exception as error:
            print(f"Error processing NZB file: {error}")
            return False


def load_config():
    """Load configuration from config.ini file."""
    config_file = 'config.ini'
    
    if not os.path.exists(config_file):
        print(f"Error: Configuration file '{config_file}' not found.")
        print(f"Please copy 'config.example.ini' to '{config_file}' and configure your server details.")
        sys.exit(1)
    
    config = configparser.ConfigParser()
    try:
        config.read(config_file)
        
        # Validate required fields
        required_fields = ['server_hostname', 'username', 'password']
        for field in required_fields:
            if not config.get('nntp', field, fallback=''):
                print(f"Error: Required field '{field}' missing from configuration file.")
                sys.exit(1)
        
        return config
        
    except Exception as error:
        print(f"Error reading configuration file: {error}")
        sys.exit(1)


def process_nzb_files():
    """Process all NZB files in the indicies folder."""
    print("USENET NNTP Client - NZB File Processor")
    print("=" * 50)
    
    # Load configuration
    config = load_config()
    
    # Get server details from config
    server_hostname = config.get('nntp', 'server_hostname')
    port = config.getint('nntp', 'port', fallback=563)
    username = config.get('nntp', 'username')
    password = config.get('nntp', 'password')
    
    # Get folder paths from config
    indicies_folder = config.get('downloads', 'download_folder', fallback='indicies')
    segments_folder = config.get('segments', 'segments_folder', fallback='segments')
    completed_folder = config.get('completed', 'completed_indicies_folder', fallback='completed_indicies')
    pending_combining_folder = config.get('pending_combining', 'pending_combining_indicies_folder', fallback='pending_combining_indicies')
    
    # Create and connect client
    client = NNTPClient(server_hostname, port)
    
    try:
        # Connect to server
        client.connect()
        
        # Authenticate
        client.authenticate(username, password)
        
        # Find all NZB files in indicies folder
        nzb_pattern = os.path.join(indicies_folder, '*.nzb')
        nzb_files = glob.glob(nzb_pattern)
        
        if not nzb_files:
            print(f"No NZB files found in '{indicies_folder}' folder.")
            return
        
        print(f"Found {len(nzb_files)} NZB files to process:")
        for nzb_file in nzb_files:
            print(f"  - {os.path.basename(nzb_file)}")
        
        print("\nStarting processing...")
        
        # Process each NZB file
        successful_count = 0
        for nzb_file in nzb_files:
            try:
                if client.process_nzb_file(nzb_file, segments_folder, completed_folder, pending_combining_folder):
                    successful_count += 1
            except Exception as error:
                print(f"Failed to process {os.path.basename(nzb_file)}: {error}")
                continue
        
        print(f"\nProcessing complete!")
        print(f"Successfully processed: {successful_count}/{len(nzb_files)} files")
        
    except Exception as error:
        print(f"Error: {error}")
        sys.exit(1)
    
    finally:
        client.disconnect()


def process_pending_combining(delete_segments=True):
    """Process all NZB files in the pending combining folder."""
    print("USENET NNTP Client - Pending Combining Processor")
    print("=" * 50)
    
    # Load configuration
    config = load_config()
    
    # Get folder paths from config
    pending_folder = config.get('pending_combining', 'pending_combining_indicies_folder', fallback='pending_combining_indicies')
    segments_folder = config.get('segments', 'segments_folder', fallback='segments')
    pending_segments_folder = config.get('pending_combining', 'segments_pending_combining_folder', fallback='segments_pending_combining')
    output_folder = config.get('downloaded_encoded', 'downloaded_encoded_folder', fallback='downloaded_encoded')
    completed_folder = config.get('completed', 'completed_indicies_folder', fallback='completed_indicies')
    
    # Create folders if they don't exist
    for folder in [pending_folder, segments_folder, pending_segments_folder, output_folder, completed_folder]:
        os.makedirs(folder, exist_ok=True)
    
    # Process combining (no server connection needed for this operation)
    try:
        # Create a dummy client just to access the methods
        client = NNTPClient("dummy")
        
        # Process pending combining
        successful_count = client.process_pending_combining(
            pending_folder, segments_folder, pending_segments_folder, 
            output_folder, completed_folder
        )
        
        print(f"\nPending combining process completed!")
        print(f"Successfully processed: {successful_count} NZB files")
        
    except Exception as error:
        print(f"Error: {error}")
        sys.exit(1)


def process_file_decoding():
    """Process all files in the downloaded_encoded folder through decoding."""
    print("USENET NNTP Client - File Decoder")
    print("=" * 50)
    
    # Load configuration
    config = load_config()
    
    # Get folder paths from config
    downloaded_encoded_folder = config.get('downloaded_encoded', 'downloaded_encoded_folder', fallback='downloaded_encoded')
    file_decode_folder = config.get('file_decode', 'file_decode_folder', fallback='file_decode')
    downloaded_folder = config.get('downloaded', 'downloaded_folder', fallback='downloaded')
    
    # Create folders if they don't exist
    for folder in [downloaded_encoded_folder, file_decode_folder, downloaded_folder]:
        os.makedirs(folder, exist_ok=True)
    
    # Process file decoding (no server connection needed for this operation)
    try:
        # Create a dummy client just to access the methods
        client = NNTPClient("dummy")
        
        # Decode files
        successful_count = client.decode_files(
            downloaded_encoded_folder, file_decode_folder, downloaded_folder
        )
        
        # Clean up file_decode folder
        client.cleanup_file_decode_folder(file_decode_folder)
        
        print(f"\nFile decoding process completed!")
        print(f"Successfully processed: {successful_count} files")
        
    except Exception as error:
        print(f"Error: {error}")
        sys.exit(1)


def show_status():
    """Show current status of all folders and files."""
    print("USENET NNTP Client - System Status")
    print("=" * 50)
    
    # Load configuration
    config = load_config()
    
    # Get folder paths from config
    folders = {
        'Indicies (NZB files)': config.get('downloads', 'download_folder', fallback='indicies'),
        'Completed indicies': config.get('completed', 'completed_indicies_folder', fallback='completed_indicies'),
        'Failed indicies': config.get('failed', 'failed_indicies_folder', fallback='failed_indicies'),
        'Segments': config.get('segments', 'segments_folder', fallback='segments'),
        'Pending combining indicies': config.get('pending_combining', 'pending_combining_indicies_folder', fallback='pending_combining_indicies'),
        'Segments pending combining': config.get('pending_combining', 'segments_pending_combining_folder', fallback='segments_pending_combining'),
        'Downloaded (final files)': config.get('downloaded', 'downloaded_folder', fallback='downloaded'),
        'Downloaded encoded': config.get('downloaded_encoded', 'downloaded_encoded_folder', fallback='downloaded_encoded'),
        'File decode (temp)': config.get('file_decode', 'file_decode_folder', fallback='file_decode')
    }
    
    for folder_name, folder_path in folders.items():
        if os.path.exists(folder_path):
            nzb_count = len(glob.glob(os.path.join(folder_path, '*.nzb')))
            seg_count = len(glob.glob(os.path.join(folder_path, '*.seg')))
            file_count = len([f for f in glob.glob(os.path.join(folder_path, '*')) 
                           if os.path.isfile(f) and not f.endswith(('.nzb', '.seg'))])
            
            total_files = nzb_count + seg_count + file_count
            status = "Exists" if total_files > 0 else "Empty"
            
            print(f"{folder_name:<30} {folder_path:<25} {total_files:>3} files ({status})")
            if nzb_count > 0:
                print(f"{'':30} {'- NZB files:':<25} {nzb_count}")
            if seg_count > 0:
                print(f"{'':30} {'- Segment files:':<25} {seg_count}")
            if file_count > 0:
                print(f"{'':30} {'- Other files:':<25} {file_count}")
        else:
            print(f"{folder_name:<30} {folder_path:<25} {'Not created':>15}")
        
        print()


def show_help():
    """Show comprehensive help for NZB processing workflow."""
    print("USENET NNTP Client - Complete NZB Processing Guide")
    print("=" * 60)
    print()
    print("OVERVIEW:")
    print("Process NZB files downloaded by the NZB indexer script through")
    print("a complete 3-step workflow from segments to final files.")
    print()
    print("FEATURES:")
    print("  • Complete workflow documentation and troubleshooting guide")
    print("  • Real-time ASCII progress display with detailed statistics")
    print("  • Fully automated --full-workflow mode")
    print("  • Archive support: ZIP, TAR, RAR (with unrar), PAR2 processing")
    print("  • Thread-safe progress tracking for concurrent operations")
    print("  • Live progress bars, success rates, ETA calculations")
    print("  • Handles incomplete segments gracefully")
    print()
    print("REQUIRED WORKFLOW STEPS:")
    print("-" * 40)
    print()
    print("Step 1: DOWNLOAD SEGMENTS")
    print("  Command: python3 nntp_client.py --process-nzb")
    print("  Purpose: Download Usenet segments for NZB files in 'indicies/' folder")
    print("  Input:  NZB files in indicies/ folder")
    print("  Output: Segment files (.seg) in segments/ folder")
    print("  Result: NZB files moved to completed_indicies/ folder")
    print("  Progress: Real-time ASCII progress bar with statistics")
    print()
    print("Step 2: COMBINE SEGMENTS")
    print("  Command: python3 nntp_client.py --combine-pending")
    print("  Purpose: Combine segments into complete files")
    print("  Input:  Segments from segments/ folder")
    print("  Output: Combined files in downloaded_encoded/ folder")
    print("  Result: Archives (RAR/ZIP), PAR2 files, and other content")
    print()
    print("Step 3: DECODE & EXTRACT")
    print("  Command: python3 nntp_client.py --decode-files")
    print("  Purpose: Extract archives and process final files")
    print("  Input:  Files from downloaded_encoded/ folder")
    print("  Output: Final extracted files in downloaded/ folder")
    print("  Result: Ready-to-use files with archives extracted")
    print()
    print("COMPLETE WORKFLOW EXAMPLES:")
    print("-" * 40)
    print("# 1. Use NZB indexer to find and download content")
    print("python3 nzb_indexer.py --download \"search terms\"")
    print()
    print("# 2. Run full automated workflow (recommended)")
    print("python3 nntp_client.py --full-workflow")
    print()
    print("# OR run steps manually:")
    print("python3 nntp_client.py --process-nzb      # Step 1")
    print("python3 nntp_client.py --combine-pending   # Step 2")
    print("python3 nntp_client.py --decode-files     # Step 3")
    print()
    print("# 3. Check final results")
    print("python3 nntp_client.py --status")
    print()
    print("FOLDER STRUCTURE:")
    print("-" * 40)
    print("indicies/              ← NZB files (from indexer script)")
    print("segments/              ← Downloaded Usenet segments")
    print("completed_indicies/     ← Processed NZB files")
    print("downloaded_encoded/     ← Combined but encoded files")
    print("file_decode/           ← Temporary extraction folder")
    print("downloaded/            ← Final extracted files (READY TO USE)")
    print()
    print("COMMAND REFERENCE:")
    print("-" * 40)
    print("python3 nntp_client.py --process-nzb     # Step 1: Download segments")
    print("python3 nntp_client.py --combine-pending  # Step 2: Combine files")
    print("python3 nntp_client.py --decode-files     # Step 3: Extract archives")
    print("python3 nntp_client.py --full-workflow   # Run all steps automatically")
    print("python3 nntp_client.py --status          # Check system state")
    print("python3 nntp_client.py --help           # Show this help")
    print("python3 nntp_client.py                 # List Usenet groups")
    print()
    print("PROGRESS DISPLAY FEATURES:")
    print("-" * 40)
    print("When downloading segments, displays real-time progress:")
    print("  • ASCII progress bar: [████████░░░░░░░░░░] visual representation")
    print("  • Real-time statistics: Percentage, current/total, success/failure counts")
    print("  • Performance metrics: Success rate, elapsed time, ETA calculations")
    print("  • Automatic updates: Progress updates every 0.5 seconds")
    print("  • Completion summary: Final statistics with total processing time")
    print()
    print("ARCHIVE EXTRACTION SUPPORT:")
    print("-" * 40)
    print("• ZIP files: Extracted automatically (built-in Python support)")
    print("• TAR files: Extracted automatically (built-in Python support)")
    print("• TAR.GZ files: Extracted automatically (built-in Python support)")
    print("• RAR files: Requires 'unrar' command or 'rarfile' Python library")
    print("• PAR2 files: Processed for verification if 'par2' command available")
    print("• Extraction workflow: Archives extracted to subfolders, then moved")
    print("• Cleanup: Temporary extraction folders cleaned up after success")
    print()
    print("TROUBLESHOOTING GUIDE:")
    print("-" * 40)
    print("• No NZB files found: Run nzb_indexer.py to download content first")
    print("• Download fails: Check NNTP server credentials in config.ini")
    print("• Combine fails: Ensure segments were successfully downloaded in Step 1")
    print("• Extract fails: Install unrar utility for RAR files")
    print("• Partial downloads: System works with incomplete segments, continue workflow")
    print("• Progress not updating: Check if segments already exist (counted as completed)")
    print("• Slow downloads: Progress display shows success rate and ETA to monitor")
    print()
    print("CONFIGURATION REQUIREMENTS:")
    print("-" * 40)
    print("Edit config.ini with your service credentials:")
    print("• server_hostname: Your Usenet server (e.g., news.easynews.com)")
    print("• username: Your Usenet username")
    print("• password: Your Usenet password")
    print("• port: Usually 563 for SSL connections")
    print()
    print("INSTALLATION REQUIREMENTS:")
    print("-" * 40)
    print("• Python 3.6+ with standard library only")
    print("• Optional: sudo apt-get install unrar (Ubuntu/Debian) for RAR support")
    print("• Optional: brew install unrar (macOS) for RAR support")
    print("• Optional: par2 command for archive verification")
    print()
    print("For complete end-to-end workflow examples, see AGENTS.md.")
    print()


def process_full_workflow():
    """Run the complete automated workflow from NZB to final files."""
    print("USENET NNTP Client - Full Automated Workflow")
    print("=" * 50)
    print("This will run all steps: Download segments → Combine → Extract")
    print()
    
    try:
        # Step 1: Download segments
        print("STEP 1: Downloading segments from Usenet server...")
        process_nzb_files()
        print()
        
        # Step 2: Combine segments
        print("STEP 2: Combining segments into complete files...")
        # Default to deleting segments unless --keep-segments is specified
        delete_segments = '--keep-segments' not in sys.argv
        if not delete_segments:
            print("NOTE: --keep-segments flag detected - segments will be retained")
        process_pending_combining(delete_segments=delete_segments)
        print()
        
        # Step 3: Decode and extract files
        print("STEP 3: Extracting archives and processing final files...")
        process_file_decoding()
        print()
        
        print("✅ Full workflow completed successfully!")
        print("Check your downloaded/ folder for final files.")
        
    except Exception as error:
        print(f"❌ Workflow failed: {error}")
        sys.exit(1)


def main():
    """Main function to run NNTP client."""
    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] in ['--help', '-h']:
            show_help()
            return
        elif sys.argv[1] == '--process-nzb':
            print("ACTION: Processing NZB files - downloading segments from Usenet server")
            process_nzb_files()
            return
        elif sys.argv[1] == '--combine-pending':
            print("ACTION: Combining pending files - combining segments into complete files")
            process_pending_combining()
            return
        elif sys.argv[1] == '--decode-files':
            print("ACTION: Decoding files - processing encoded files to final format")
            process_file_decoding()
            return
        elif sys.argv[1] == '--status':
            print("ACTION: Status check - showing current system state")
            show_status()
            return
        elif sys.argv[1] == '--full-workflow':
            print("ACTION: Running full automated workflow")
            process_full_workflow()
            return
        elif sys.argv[1] == '--process-nzb':
            print("ACTION: Processing NZB files - downloading segments from Usenet server")
            process_nzb_files()
            return
        elif sys.argv[1] == '--combine-pending':
            print("ACTION: Combining pending files - combining segments into complete files")
            process_pending_combining()
            return
        elif sys.argv[1] == '--decode-files':
            print("ACTION: Decoding files - processing encoded files to final format")
            process_file_decoding()
            return
        elif sys.argv[1] == '--status':
            print("ACTION: Status check - showing current system state")
            show_status()
            return
    
    print("USENET NNTP Client - Group List Retrieval")
    print("=" * 50)
    print("ACTION: Listing available Usenet groups")
    
    # Load configuration
    config = load_config()
    
    # Get server details from config
    server_hostname = config.get('nntp', 'server_hostname')
    port = config.getint('nntp', 'port', fallback=563)
    username = config.get('nntp', 'username')
    password = config.get('nntp', 'password')
    
    # Get optional settings
    pattern = config.get('options', 'group_pattern', fallback=None)
    if pattern == '':
        pattern = None
    
    max_groups = config.getint('options', 'max_groups', fallback=100)
    
    # Create and connect client
    client = NNTPClient(server_hostname, port)
    
    try:
        # Connect to server
        client.connect()
        
        # Authenticate
        client.authenticate(username, password)
        
        # Get group list
        groups = client.list_groups(pattern)
        
        # Display results
        print(f"\nFound {len(groups)} groups:")
        print("-" * 80)
        print(f"{'Group Name':<50} {'Articles':<15} {'Status':<10}")
        print("-" * 80)
        
        for group in groups[:max_groups]:  # Show configured number of groups
            article_count = group['high_article'] - group['low_article']
            print(f"{group['name']:<50} {article_count:<15} {group['status']:<10}")
        
        if len(groups) > max_groups:
            print(f"... and {len(groups) - max_groups} more groups")
        
        print(f"\nTotal groups available: {len(groups)}")
        
    except Exception as error:
        print(f"Error: {error}")
        sys.exit(1)
    
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()