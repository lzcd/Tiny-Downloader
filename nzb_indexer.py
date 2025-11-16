#!/usr/bin/env python3
"""
NZB Indexer client script to search for content on NZB indexers like NZBGeek.
Uses only Python standard library modules.
"""

import urllib.parse
import urllib.request
import urllib.error
import json
import sys
import os
import configparser
import xml.etree.ElementTree as ET
from datetime import datetime
import re


class NZBIndexerClient:
    """Simple NZB indexer client for searching content on NZB indexers."""
    
    def __init__(self, base_url, api_key):
        self.base_hostname = base_url.rstrip('/')
        self.api_key = api_key
    
    def _preprocess_query(self, query):
        """Preprocess search query to improve results."""
        if not query:
            return query
        
        processed = query.strip()
        
        # Handle search operators
        # Convert explicit AND to spaces (implicit AND)
        processed = re.sub(r'\bAND\b', ' ', processed, flags=re.IGNORECASE)
        
        # Handle NOT operator (exclusion) - remove for now since NZBGeek doesn't support it
        not_terms = re.findall(r'-(\w+)', processed)
        if not_terms:
            print(f"Note: Exclusion terms ({not_terms}) not supported by indexer")
            processed = re.sub(r'-\w+', '', processed)
        
        # Clean up extra spaces
        processed = ' '.join(processed.split())
        
        # Generate alternative query suggestions for better matching
        words = processed.split()
        if len(words) >= 2:
            # For multi-word queries, try exact phrase first
            return processed
        elif len(words) == 1 and len(words[0]) > 3:
            # For single long words, try wildcard
            return f"{words[0]}*"
        
        return processed
        
    def search(self, keywords=None, category=None, max_results=25, sort_by='date_desc'):
        """Search for content using keywords and optional category filtering."""
        try:
            # Enhanced query processing
            processed_keywords = self._preprocess_query(keywords) if keywords else keywords
            
            # Build API URL for search
            search_url = f"{self.base_hostname}/api"
            
            # Parameters for API call
            parameters = {
                't': 'search',
                'o': 'json',
                'apikey': self.api_key,
                'limit': max_results
            }
            
            # Add search query if provided
            if processed_keywords:
                parameters['q'] = processed_keywords
                if processed_keywords != keywords:
                    print(f"Enhanced query: '{processed_keywords}' (from: '{keywords}')")
            
            # Add category filter if provided
            if category:
                # Map common category names to NZBGeek category IDs
                category_map = {
                    'movies': '2000',
                    'tv': '5000',
                    'music': '3000',
                    'games': '1000',
                    'apps': '4000',
                    'books': '7000',
                    'anime': '5070',
                    'documentaries': '2030',
                    'sports': '6000'
                }
                
                # Use category ID if it's numeric, otherwise map it
                if category.isdigit():
                    parameters['cat'] = category
                else:
                    cat_lower = category.lower()
                    if cat_lower in category_map:
                        parameters['cat'] = category_map[cat_lower]
                    else:
                        print(f"Warning: Unknown category '{category}', searching all categories")
            
            # Add sorting
            if sort_by == 'date_desc':
                parameters['sort'] = 'postdate_desc'
            elif sort_by == 'date_asc':
                parameters['sort'] = 'postdate_asc'
            elif sort_by == 'size_desc':
                parameters['sort'] = 'size_desc'
            elif sort_by == 'size_asc':
                parameters['sort'] = 'size_asc'
            
            # Create the full URL with parameters
            url_with_params = f"{search_url}?{urllib.parse.urlencode(parameters)}"
            
            # Make the API request
            request = urllib.request.Request(url_with_params)
            request.add_header('User-Agent', 'NZB-Indexer-Client/1.0')
            
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status == 200:
                    response_data = response.read().decode('utf-8')
                    results = self._parse_search_response(response_data)
                    
                    # Enhanced result processing
                    results = self._enhance_results(results, keywords)
                    
                    # Sort results by date if requested
                    if sort_by.startswith('date'):
                        results = self._sort_results_by_date(results, sort_by)
                    elif sort_by.startswith('size'):
                        results = self._sort_results_by_size(results, sort_by)
                    else:
                        # Default: sort by relevance then date
                        results = self._sort_results_by_relevance(results)
                    
                    return results
                else:
                    raise RuntimeError(f"API request failed with status {response.status}")
                    
        except urllib.error.URLError as error:
            raise ConnectionError(f"Failed to connect to indexer: {error}")
        except Exception as error:
            raise RuntimeError(f"Search error: {error}")
    
    def download_nzb(self, nzb_link, title, download_folder):
        """Download NZB file from the provided link."""
        try:
            # Create download folder if it doesn't exist
            os.makedirs(download_folder, exist_ok=True)
            
            # Sanitize filename
            safe_title = self._sanitize_filename(title)
            filename = f"{safe_title}.nzb"
            filepath = os.path.join(download_folder, filename)
            
            # Download the NZB file
            print(f"Downloading NZB: {filename}")
            request = urllib.request.Request(nzb_link)
            request.add_header('User-Agent', 'NZB-Indexer-Client/1.0')
            
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status == 200:
                    nzb_content = response.read().decode('utf-8')
                    
                    # Save to file
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(nzb_content)
                    
                    print(f"✓ Saved to: {filepath}")
                    return filepath
                else:
                    raise RuntimeError(f"Failed to download NZB: HTTP {response.status}")
                    
        except urllib.error.URLError as error:
            raise ConnectionError(f"Failed to download NZB: {error}")
        except Exception as error:
            raise RuntimeError(f"Download error: {error}")
    
    def _sanitize_filename(self, filename):
        """Sanitize filename for safe file system storage."""
        # Remove or replace unsafe characters
        safe_name = re.sub(r'[<>:"/\\|?*]', '_', filename)
        safe_name = re.sub(r'\s+', '_', safe_name)  # Replace spaces with underscores
        safe_name = safe_name.strip('._')  # Remove leading/trailing dots and underscores
        
        # Limit length
        if len(safe_name) > 100:
            safe_name = safe_name[:100]
        
        return safe_name
    
    def _parse_search_response(self, response_data):
        """Parse the JSON response from the indexer API."""
        try:
            data = json.loads(response_data)
            
            
            
            # Handle different response formats
            items = []
            
            # Try NZBGeek format (RSS-style)
            if 'channel' in data and 'item' in data['channel']:
                items = data['channel']['item']
            # Try direct format
            elif 'item' in data:
                items = data['item']
            # Try results format
            elif 'results' in data:
                items = data['results']
            # Try if data itself is a list
            elif isinstance(data, list):
                items = data
            else:
                return []
            
            if not isinstance(items, list):
                items = [items] if items else []
            
            results = []
            for i, item in enumerate(items):
                # Safely parse numeric fields
                size = 0
                try:
                    # Try to get size from enclosure attributes first
                    enclosure = item.get('enclosure', {})
                    if isinstance(enclosure, dict) and '@attributes' in enclosure:
                        size_val = enclosure['@attributes'].get('length', '0')
                        if size_val and size_val != '0':
                            size = int(float(size_val))
                    
                    # If not found, try from attr array
                    if size == 0:
                        attrs = item.get('attr', [])
                        if isinstance(attrs, list):
                            for attr in attrs:
                                if isinstance(attr, dict) and '@attributes' in attr:
                                    attr_info = attr['@attributes']
                                    if attr_info.get('name') == 'size':
                                        size_val = attr_info.get('value', '0')
                                        if size_val and size_val != '0':
                                            size = int(float(size_val))
                                            break
                except (ValueError, TypeError):
                    size = 0
                
                grabs = 0
                try:
                    grabs = int(item.get('grabs', 0))
                except (ValueError, TypeError):
                    grabs = 0
                
                comments = 0
                try:
                    comments = int(item.get('comments', 0))
                except (ValueError, TypeError):
                    comments = 0
                
                result = {
                    'title': item.get('title', 'Unknown Title'),
                    'guid': item.get('guid', ''),
                    'link': item.get('link', ''),
                    'size': size,
                    'posted_date': item.get('postdate', item.get('pubDate', '')),
                    'category': item.get('category', ''),
                    'description': item.get('description', ''),
                    'grabs': grabs,
                    'comments': comments,
                    'password': item.get('password', ''),
                    'group': item.get('group', ''),
                    'nzb_id': item.get('id', '')
                }
                results.append(result)
            
            return results
            
        except json.JSONDecodeError as error:
            raise RuntimeError(f"Failed to parse JSON response: {error}")
        except Exception as error:
            raise RuntimeError(f"Error parsing response: {error}")
    
    def _sort_results_by_date(self, results, sort_order='date_desc'):
        """Sort results by posted date."""
        def parse_date(date_str):
            try:
                # Try different date formats
                formats = [
                    '%a, %d %b %Y %H:%M:%S %Z',
                    '%a, %d %b %Y %H:%M:%S %z',
                    '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%d'
                ]
                
                for fmt in formats:
                    try:
                        return datetime.strptime(date_str, fmt)
                    except ValueError:
                        continue
                
                # If all formats fail, return a very old date
                return datetime(1970, 1, 1)
                
            except Exception:
                return datetime(1970, 1, 1)
        
        # Sort by date
        results.sort(key=lambda x: parse_date(x['posted_date']), 
                    reverse=(sort_order == 'date_desc'))
        
        return results
    
    def _enhance_results(self, results, original_query):
        """Enhance results with relevance scoring."""
        if not results or not original_query:
            return results
        
        query_words = set(original_query.lower().split())
        
        for result in results:
            title = result.get('title', '').lower()
            title_words = set(title.split())
            
            # Calculate relevance score
            score = 0
            
            # Exact query match
            if original_query.lower() in title:
                score += 100
            
            # Word matches
            matching_words = query_words.intersection(title_words)
            score += len(matching_words) * 10
            
            # All words match
            if query_words.issubset(title_words):
                score += 50
            
            # Recent posts get bonus
            posted_date = result.get('posted_date', '')
            if posted_date:
                try:
                    # Parse date and calculate age
                    if 'T' in posted_date:
                        post_date = datetime.fromisoformat(posted_date.replace('Z', '+00:00'))
                    else:
                        post_date = datetime.strptime(posted_date, '%a, %d %b %Y %H:%M:%S %z')
                    
                    age_days = (datetime.now(post_date.tzinfo) - post_date).days
                    
                    if age_days < 7:  # Less than a week old
                        score += 20
                    elif age_days < 30:  # Less than a month old
                        score += 10
                except:
                    pass
            
            # Popular posts get bonus
            grabs = result.get('grabs', 0)
            if grabs > 100:
                score += 15
            elif grabs > 50:
                score += 10
            elif grabs > 10:
                score += 5
            
            result['relevance_score'] = score
        
        return results
    
    def _sort_results_by_size(self, results, sort_order):
        """Sort results by size."""
        return sorted(results, 
                  key=lambda x: x.get('size', 0), 
                  reverse=(sort_order == 'size_desc'))
    
    def _sort_results_by_relevance(self, results):
        """Sort results by relevance score, then by date."""
        # First sort by date (newest first)
        dated_results = self._sort_results_by_date(results, 'date_desc')
        
        # Then sort by relevance (highest first)
        return sorted(dated_results, 
                    key=lambda x: x.get('relevance_score', 0), 
                    reverse=True)


def load_config():
    """Load configuration from config.ini file."""
    config_file = 'config.ini'
    
    if not os.path.exists(config_file):
        print(f"Error: Configuration file '{config_file}' not found.")
        print(f"Please copy 'config.example.ini' to '{config_file}' and configure your indexer details.")
        sys.exit(1)
    
    config = configparser.ConfigParser()
    try:
        config.read(config_file)
        
        # Validate required fields
        required_fields = ['base_url', 'api_key']
        for field in required_fields:
            if not config.get('indexer', field, fallback=''):
                print(f"Error: Required field '{field}' missing from configuration file.")
                sys.exit(1)
        
        return config
        
    except Exception as error:
        print(f"Error reading configuration file: {error}")
        sys.exit(1)


def format_size(size_bytes):
    """Format file size in human readable format."""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"


def format_date_display(date_str):
    """Format date for display with year."""
    if not date_str:
        return 'Unknown'
    
    try:
        # Try different date formats to parse
        formats = [
            '%a, %d %b %Y %H:%M:%S %Z',
            '%a, %d %b %Y %H:%M:%S %z',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d',
            '%d %b %Y',
            '%b %d, %Y'
        ]
        
        for fmt in formats:
            try:
                parsed_date = datetime.strptime(date_str, fmt)
                # Format as "MMM DD, YYYY" for display
                return parsed_date.strftime('%b %d, %Y')
            except ValueError:
                continue
        
        # If all formats fail, try to extract year from the string
        if any(char.isdigit() for char in date_str):
            # Look for 4-digit year pattern
            import re
            year_match = re.search(r'\b(19|20)\d{2}\b', date_str)
            if year_match:
                year = year_match.group()
                # Return first 10 chars to show date part with year
                return date_str[:10] + f" {year}" if len(date_str) < 15 else date_str[:15]
        
        # Return first 12 chars as fallback
        return date_str[:12]
        
    except Exception:
        return date_str[:12] if date_str else 'Unknown'


def show_help():
    """Show comprehensive usage help."""
    print("NZB Indexer Client - Complete Usage Guide")
    print("=" * 60)
    print()
    print("OVERVIEW:")
    print("Search and download NZB files from Usenet indexers with enhanced")
    print("selection options, configurable limits, and multiple sorting modes.")
    print()
    print("DEFAULT BEHAVIOR:")
    print("When run without arguments, prompts for search terms and enters")
    print("interactive mode for browsing and selecting results.")
    print()
    print("FEATURES:")
    print("  • Enhanced search with configurable result limits (1-200)")
    print("  • Interactive selection mode for browsing results")
    print("  • Download with selection (shows all results and asks which to download)")
    print("  • Download by specific result number for automatic downloads")
    print("  • Multiple sorting options (date, size, ascending/descending)")
    print("  • Category filtering for targeted searches")
    print("  • Real-time file size display with proper formatting")
    print()
    print("BASIC SEARCH:")
    print("  python3 nzb_indexer.py                    # Prompt for search terms (interactive)")
    print("  python3 nzb_indexer.py \"movie title 2024\"")
    print("  python3 nzb_indexer.py \"1984 George Orwell\"")
    print()
    print("WITH CATEGORY FILTER:")
    print("  python3 nzb_indexer.py --category movies \"action movie\"")
    print("  python3 nzb_indexer.py --category tv \"drama series\"")
    print("  python3 nzb_indexer.py --category books \"epub novel\"")
    print()
    print("WITH SORTING:")
    print("  python3 nzb_indexer.py --sort date_desc \"keywords\"  # Newest first (default)")
    print("  python3 nzb_indexer.py --sort date_asc \"keywords\"   # Oldest first")
    print("  python3 nzb_indexer.py --sort size_desc \"keywords\"  # Largest first")
    print("  python3 nzb_indexer.py --sort size_asc \"keywords\"   # Smallest first")
    print()
    print("WITH RESULT LIMIT:")
    print("  python3 nzb_indexer.py --limit 50 \"keywords\"      # Show up to 50 results")
    print("  python3 nzb_indexer.py --limit 100 \"keywords\"     # Show up to 100 results")
    print("  python3 nzb_indexer.py --limit 200 \"keywords\"     # Show up to 200 results (max)")
    print()
    print("DOWNLOAD OPTIONS:")
    print("  python3 nzb_indexer.py --download \"movie title\"           # Download with selection")
    print("  python3 nzb_indexer.py --interactive \"movie title\"        # Interactive selection")
    print("  python3 nzb_indexer.py --download --number 5 \"keywords\"  # Download 5th result")
    print()
    print("ADVANCED COMBINED EXAMPLES:")
    print("  # Show 50 movie trailers, newest first, interactive selection")
    print("  python3 nzb_indexer.py --category movies --sort date_desc --limit 50 --interactive \"trailer\"")
    print()
    print("  # Download with selection from TV shows")
    print("  python3 nzb_indexer.py --category tv --download \"drama series\"")
    print()
    print("  # Download specific result automatically")
    print("  python3 nzb_indexer.py --category movies --download --number 3 \"action 2024\"")
    print()
    print("  # Find largest books first, show 30 results (new default)")
    print("  python3 nzb_indexer.py --category books --sort size_desc --limit 30 \"epub\"")
    print()
    print("AVAILABLE CATEGORIES:")
    print("  movies, tv, books, music, games, apps, anime, documentaries, sports")
    print("  (Or use numeric category IDs from your indexer)")
    print()
    print("NEW OPTIONS:")
    print("  --limit N        - Show up to N results (1-200, default: 30)")
    print("  --interactive    - Browse and select from results")
    print("  --download       - Download with selection (shows all results)")
    print("  --number N       - Download specific result number")
    print("  --sort MODE      - Sort by date_desc (newest first), date_asc, size_desc, size_asc")
    print("  --category CAT   - Filter by category")
    print()
    print("For more information, see AGENTS.md for complete workflow guide.")


def main():
    """Main function to run the NZB indexer client."""
    # Show help if requested
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h']:
        show_help()
        return
    
    print("NZB Indexer Client - Search Tool")
    print("=" * 50)
    
    # Load configuration
    config = load_config()
    
    # Get indexer details from config
    base_url = config.get('indexer', 'base_url')
    api_key = config.get('indexer', 'api_key')
    max_results = config.getint('indexer', 'max_results', fallback=30)
    
    # Get download folder from config
    download_folder = config.get('downloads', 'download_folder', fallback='downloads')
    
    # Parse command line arguments
    keywords = None
    category = None
    sort_order = 'date_desc'  # Default: most recent first
    download_first = False
    interactive_mode = False
    download_number = None
    
    # Expected format: python3 nzb_indexer.py [--category CAT] [--sort SORT] [--limit NUM] [--download|--interactive|--number NUM] [keywords...]
    args = sys.argv[1:]
    i = 0
    keyword_parts = []
    
    while i < len(args):
        if args[i] == '--category' and i + 1 < len(args):
            category = args[i + 1]
            i += 2
        elif args[i] == '--sort' and i + 1 < len(args):
            sort_order = args[i + 1]
            if sort_order not in ['date_desc', 'date_asc', 'size_desc', 'size_asc']:
                print(f"Warning: Invalid sort order '{sort_order}', using 'date_desc'")
                sort_order = 'date_desc'
            i += 2
        elif args[i] == '--limit' and i + 1 < len(args):
            try:
                max_results = int(args[i + 1])
                if max_results < 1:
                    print("Warning: Limit must be at least 1, using 30")
                    max_results = 30
                elif max_results > 200:
                    print("Warning: Limit capped at 200 for performance")
                    max_results = 200
            except ValueError:
                print("Warning: Invalid limit value, using default 30")
                max_results = 30
            i += 2
        elif args[i] == '--download':
            download_first = True
            i += 1
        elif args[i] == '--interactive':
            interactive_mode = True
            i += 1
        elif args[i] == '--number' and i + 1 < len(args):
            try:
                download_number = int(args[i + 1])
                download_first = True
            except ValueError:
                print("Warning: Invalid number for --number, using first result")
                download_number = 1
            i += 2
        else:
            # Collect keyword parts
            keyword_parts.append(args[i])
            i += 1
    
    # Join keyword parts if any
    if keyword_parts:
        keywords = ' '.join(keyword_parts)
    
    # If no keywords provided, prompt user and set interactive mode
    if not keywords:
        print("No search terms provided.")
        try:
            keywords = input("Enter search terms: ").strip()
            if not keywords:
                print("No search terms entered. Exiting.")
                return
            # Set interactive mode when no command line args provided
            if not download_first and not interactive_mode:
                interactive_mode = True
        except KeyboardInterrupt:
            print("\nExiting...")
            return
    
    # Create indexer client
    client = NZBIndexerClient(base_url, api_key)
    
    try:
# Show search parameters
        print(f"Searching for: {keywords}")
        if category:
            print(f"Category: {category}")
        print(f"Sort order: {sort_order.replace('_', ' ').title()}")
        print(f"Max results: {max_results}")
        if download_first and download_number is not None:
            print(f"Download mode: Will download result #{download_number}")
        elif download_first:
            print(f"Download mode: Interactive selection")
        elif interactive_mode:
            print(f"Mode: Interactive selection")
        print("-" * 50)
        
        results = client.search(keywords, category, max_results, sort_order)
        
        if not results:
            print("No results found.")
            return
        
        # If download mode with specific number, download immediately
        if download_first and download_number is not None:
            # Download the specified result number
            result_index = download_number - 1
            if result_index < 0 or result_index >= len(results):
                print(f"Error: Result number {download_number} not found (only {len(results)} results available)")
                return
                
            selected_result = results[result_index]
            print(f"\nDownloading result #{download_number}:")
            print(f"Title: {selected_result['title']}")
            print(f"Size: {format_size(selected_result['size'])}")
            print(f"Category: {selected_result['category']}")
            print(f"Posted: {format_date_display(selected_result['posted_date'])}")
            print("-" * 50)
            
            try:
                downloaded_file = client.download_nzb(
                    selected_result['link'], 
                    selected_result['title'], 
                    download_folder
                )
                print(f"\n✓ Successfully downloaded NZB file!")
                print(f"File saved as: {downloaded_file}")
                print(f"You can now use this file with your Usenet downloader.")
            except Exception as error:
                print(f"✗ Failed to download NZB: {error}")
            return
        
        # Display results for normal search mode
        print(f"Found {len(results)} results:")
        print("-" * 110)
        print(f"{'#':<3} {'Title':<65} {'Size':<10} {'Category':<15} {'Posted':<12}")
        print("-" * 110)
        
        for index, result in enumerate(results, 1):
            title = result['title'][:62] + "..." if len(result['title']) > 65 else result['title']
            size = format_size(result['size'])
            category_display = result['category'][:12] + "..." if len(result['category']) > 15 else result['category']
            posted = format_date_display(result['posted_date'])
            
            print(f"{index:<3} {title:<65} {size:<10} {category_display:<15} {posted:<12}")
        
        print("-" * 110)
        
        # Interactive mode or download mode without specific number
        if interactive_mode or (download_first and download_number is None):
            if interactive_mode:
                print("\nInteractive selection mode:")
            else:
                print("\nDownload selection mode:")
            print("Enter a number to download, or 'q' to quit")
            try:
                while True:
                    choice = input(f"\nSelect result (1-{len(results)}) or 'q': ").strip().lower()
                    if choice in ['q', 'quit', 'exit']:
                        print("Exiting...")
                        break
                    try:
                        result_num = int(choice)
                        if 1 <= result_num <= len(results):
                            selected_result = results[result_num - 1]
                            print(f"\nDownloading result #{result_num}:")
                            print(f"Title: {selected_result['title']}")
                            print(f"Size: {format_size(selected_result['size'])}")
                            print(f"Category: {selected_result['category']}")
                            print(f"Posted: {format_date_display(selected_result['posted_date'])}")
                            print("-" * 50)
                            
                            try:
                                downloaded_file = client.download_nzb(
                                    selected_result['link'], 
                                    selected_result['title'], 
                                    download_folder
                                )
                                print(f"\n✓ Successfully downloaded NZB file!")
                                print(f"File saved as: {downloaded_file}")
                                print(f"You can now use this file with your Usenet downloader.")
                                break
                            except Exception as error:
                                print(f"✗ Failed to download NZB: {error}")
                                continue
                        else:
                            print(f"Please enter a number between 1 and {len(results)}")
                    except ValueError:
                        print("Please enter a valid number or 'q' to quit")
            except KeyboardInterrupt:
                print("\nExiting...")
        else:
            # Download mode - show all results and ask which to download
            if results:
                print(f"\nSelect which file to download:")
                print("Enter a number to download, or 'q' to quit")
                try:
                    while True:
                        choice = input(f"\nSelect result (1-{len(results)}) or 'q': ").strip().lower()
                        if choice in ['q', 'quit', 'exit']:
                            print("Exiting...")
                            break
                        
                        try:
                            selected_index = int(choice) - 1
                            if 0 <= selected_index < len(results):
                                selected_result = results[selected_index]
                                print(f"\nDownloading: {selected_result['title']}")
                                print(f"Size: {format_size(selected_result['size'])}")
                                print(f"Category: {selected_result['category']}")
                                
                                downloaded_file = client.download_nzb(
                                    selected_result['link'], 
                                    selected_result['title'], 
                                    download_folder
                                )
                                print(f"\n✓ Successfully downloaded NZB file!")
                                print(f"File saved as: {downloaded_file}")
                                print(f"You can now use this file with your Usenet downloader.")
                                break
                            else:
                                print(f"Please enter a number between 1 and {len(results)}")
                        except ValueError:
                            print("Please enter a valid number or 'q' to quit")
                except KeyboardInterrupt:
                    print("\nExiting...")
                except Exception as error:
                    print(f"✗ Failed to download NZB: {error}")
        
    except Exception as error:
        print(f"Error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()