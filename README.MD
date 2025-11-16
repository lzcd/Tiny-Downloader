A vibe coded set of python scripts to search and download files from USENET (via NNTP).

There's a popular suite of apps for doing this... but the only way to configure them is via endless hours of web interface silliness with no alternative.
I don't have a need for such services but the idea of not being able to easily configure stuff via a config file annoyed me enough on principle that I asked a machine to write me a better service.
Enjoy.

## Overview
This project contains two main scripts that work together for complete Usenet content management:
- **nzb_indexer.py**: Search and download NZB files from indexers
- **nntp_client.py**: Process NZB files through download, combine, and extract workflow

## NZB Indexer Commands (nzb_indexer.py)

### Enhanced Search System
The NZB indexer now features an **enhanced search system** that significantly improves search accuracy and user experience:

**🔍 Smart Query Processing**:
- Automatically optimizes search queries for better matching
- Converts explicit operators to indexer-compatible formats
- Provides feedback on query enhancements and limitations
- Supports relevance-based result ranking

**📊 Result Quality Improvements**:
- **Relevance scoring**: Results ranked by query match quality
- **Age bonus**: Recent posts receive higher relevance scores
- **Popularity bonus**: Frequently downloaded content prioritized
- **Smart sorting**: Relevance first, then chronological order

**⚡ Search Operators**:
- `AND`: Implicit AND between terms (explicit AND converted to spaces)
- `-term`: Exclusion operator with informative messages
- Wildcards: Automatic for single long terms
- Multi-word: Phrase matching prioritized

### Basic Search and Download
- **Default behavior**: `python3 nzb_indexer.py` (prompts for search terms, shows 30 results, enters interactive mode)
- **Search**: `python3 nzb_indexer.py "search terms"` (shows 30 results by default)
- **With category**: `python3 nzb_indexer.py --category movies "movie title"`
- **Download with selection**: `python3 nzb_indexer.py --download "search terms"` (shows all results and asks which to download)
- **Download specific result**: `python3 nzb_indexer.py --download --number 5 "keywords"` (downloads 5th result immediately)
- **Combined options**: `python3 nzb_indexer.py --category tv --download "show name"` (shows TV results and asks which to download)
- **Show help**: `python3 nzb_indexer.py --help`

### Enhanced Search Features
- **Smart query processing**: Automatically optimizes search queries for better results
- **Search operator support**: Handles AND, NOT operators with user feedback
- **Relevance ranking**: Results ranked by match quality, recency, and popularity
- **Query enhancement feedback**: Shows optimized queries and explains limitations

### Search Operators
- **AND operator**: `python3 nzb_indexer.py "movie AND trailer AND 2024"` (converts to implicit AND)
- **NOT operator**: `python3 nzb_indexer.py "jurassic world -park"` (exclusion with informative message)
- **Wildcard support**: Automatic wildcard addition for single long search terms
- **Query optimization**: Multi-word queries prioritized for exact phrase matching

### Advanced Search Options
- **Result limits**: `python3 nzb_indexer.py --limit 50 "search terms"` (show up to 50 results, default: 30, max: 200)
- **Sort options**: 
  - `python3 nzb_indexer.py --sort date_desc "keywords"` (most recent first - default)
  - `python3 nzb_indexer.py --sort size_desc "keywords"` (largest first)
  - `python3 nzb_indexer.py --sort date_asc "keywords"` (oldest first)
  - `python3 nzb_indexer.py --sort size_asc "keywords"` (smallest first)
  - `python3 nzb_indexer.py --sort relevance_desc "keywords"` (by relevance score - new default for complex queries)

### Interactive Selection
- **Interactive mode**: `python3 nzb_indexer.py --interactive "search terms"` (browse and select from results)
- **Download with selection**: `python3 nzb_indexer.py --download "search terms"` (shows all results and asks which to download)
- **Download specific result**: `python3 nzb_indexer.py --download --number 5 "keywords"` (downloads 5th result immediately)

### Display Features
- **Enhanced title display**: 65-character wide title column (was 45) for better readability
- **Default result count**: 30 results shown by default (was 10)
- **Configurable limits**: Show 1-200 results using `--limit N`
- **Formatted table**: Clear display with #, Title, Size, Category, and Posted columns
- **Query feedback**: Shows enhanced queries and search optimization info
- **Relevance scoring**: Results ranked by match quality, age, and popularity

### Enhanced Search Examples
```bash
# Basic search with automatic query optimization
python3 nzb_indexer.py "jurassic world trailer"
# Output: Enhanced query: 'jurassic world trailer' (from: 'jurassic world trailer')

# Search with AND operator (converted to implicit AND)
python3 nzb_indexer.py "movie AND trailer AND 2024"
# Output: Enhanced query: 'movie trailer 2024' (from: 'movie AND trailer AND 2024')

# Search with exclusion (shows limitation message)
python3 nzb_indexer.py "jurassic world -park"
# Output: Note: Exclusion terms (['park']) not supported by indexer
# Output: Enhanced query: 'jurassic world' (from: 'jurassic world -park')

# Category-filtered search with relevance ranking
python3 nzb_indexer.py --category movies "action thriller"
# Results ranked by relevance to query terms

### Combined Advanced Examples
```bash
# Show 50 movie trailers, newest first, interactive selection
python3 nzb_indexer.py --category movies --sort date_desc --limit 50 --interactive "trailer"

# Download with selection from TV shows (shows results and asks which to download)
python3 nzb_indexer.py --category tv --download "drama series"

# Download the 3rd result for TV shows automatically
python3 nzb_indexer.py --category tv --download --number 3 "drama series"

# Find largest books first, show 30 results (new default)
python3 nzb_indexer.py --category books --sort size_desc "epub"

# Show 100 results with newest first, wide title display
python3 nzb_indexer.py --sort date_desc --limit 100 "movie trailer 2024"
```

## NNTP Client Commands (nntp_client.py)

### Category-Based Organization
The NNTP client automatically organizes downloaded files into category-based subfolders:

**Supported Categories:**
- **Movies** - All movie content (trailers, films, etc.)
- **TV** - Television shows and series
- **Books** - Ebooks, audiobooks, and publications
- **Music** - Audio files, albums, and playlists
- **Games** - PC, console, and mobile games
- **Applications** - Software and utilities
- **Anime** - Animated content and series
- **Documentaries** - Documentary films and series
- **Sports** - Sports events and content
- **Other** - Uncategorized content

**Folder Structure:**
```
downloaded/
├── Movies/
├── TV/
├── Books/
├── Music/
├── Games/
├── Applications/
├── Anime/
├── Documentaries/
├── Sports/
└── Other/
```

**How it works:**
1. Category is extracted from NZB metadata (`<meta type="category">`)
2. Category information is stored in metadata files during the combine step
3. Files are organized into appropriate subfolders only during the final decode step
4. Missing or unknown categories default to "Other"
5. Metadata files are automatically cleaned up after processing

### Individual Workflow Steps
- **Run script**: `python3 nntp_client.py`
- **Show help**: `python3 nntp_client.py --help` or `python3 nntp_client.py -h`
- **Process NZB files**: `python3 nntp_client.py --process-nzb`
- **Combine pending files**: `python3 nntp_client.py --combine-pending`
- **Keep segments after combining**: `python3 nntp_client.py --combine-pending --keep-segments`
- **Decode files**: `python3 nntp_client.py --decode-files`
- **Show status**: `python3 nntp_client.py --status`
- **Syntax check**: `python3 -m py_compile nntp_client.py`
- **Lint**: `python3 -m flake8 nntp_client.py` (if flake8 available)
- **Type check**: `python3 -m mypy nntp_client.py` (if mypy available)

### Automated Workflow
- **Full automated workflow**: `python3 nntp_client.py --full-workflow`
  - Automatically runs: Download segments → Combine → Extract
  - Shows real-time progress with ASCII progress bars
  - Handles all NZB files in indicies/ folder

### Progress Display Features
When downloading segments, the NNTP client now displays:
- **ASCII progress bar**: `[████████░░░░░░░░░]` visual representation
- **Real-time statistics**: Percentage, current/total, success/failure counts
- **Performance metrics**: Success rate, elapsed time, ETA calculations
- **Automatic updates**: Progress updates every 0.5 seconds
- **Completion summary**: Final statistics with total processing time

## Code Style Guidelines
- **Python version**: Python 3.6+ compatible
- **Imports**: Use standard library only, group imports at top
- **Formatting**: Follow PEP 8, 4-space indentation, 88-char line limit
- **Naming**: Use descriptive names, no abbreviations or single-letter variables
- **Types**: Use type hints where appropriate, but maintain compatibility
- **Error handling**: Use specific exceptions, include context in error messages
- **Documentation**: Docstrings for all classes and public methods
- **Security**: Never log or expose credentials, use getpass for password input
- **Network**: Always use SSL/TLS, implement proper connection cleanup
- **Testing**: Validate inputs, handle connection timeouts gracefully

## Archive Extraction Features
- **Supported formats**: ZIP, TAR, TAR.GZ, TGZ (built-in), RAR (requires unrar or rarfile library)
- **PAR2 support**: Automatic verification and repair if par2 command is available
- **Extraction workflow**: Archives are extracted to subfolders in file_decode, then moved to downloaded folder
- **Cleanup**: Temporary extraction folders are cleaned up after successful extraction

## Troubleshooting Guide

### NZB Indexer Issues
- **No results found**: Try different search terms, broader categories, or increase `--limit`
- **Download fails**: Check API key in config.ini and indexer service status
- **Invalid category**: Use supported categories (movies, tv, books, music, games, apps, anime, documentaries, sports)
- **Too many results**: Use `--limit` to control number of results shown (default: 30, max: 200)
- **Want specific result**: Use `--interactive` mode or `--number N` to download specific items
- **Title display**: Long titles are truncated at 65 characters with enhanced readability

### Enhanced Search Troubleshooting
- **Query not finding known content**: 
  - Try different keyword combinations
  - Use category filters: `--category movies`
  - Increase result limit: `--limit 100`
  - Check query feedback for optimization suggestions
- **Exclusion terms not working**: Most indexers don't support `-term` syntax
  - Use more specific positive terms instead
  - Filter by category when possible
- **Results not in relevant order**: 
  - Use `--sort relevance_desc` for query-specific ranking
  - Try `--sort size_desc` for largest first
  - Use `--sort date_desc` for newest first
- **Too many unrelated results**:
  - Add more specific keywords
  - Use category filtering
  - Try exact phrase matching with quotes

### NNTP Client Issues
- **No NZB files found**: Run nzb_indexer.py first to download NZB files
- **Download fails**: Check NNTP server credentials in config.ini (server_hostname, username, password, port)
- **Combine fails**: Ensure segments were successfully downloaded in Step 2
- **Extract fails**: Install unrar utility for RAR files or check file integrity
- **Partial downloads**: System works with incomplete segments, continue workflow
- **Progress not updating**: Check if segments already exist (they're counted as completed)
- **Slow downloads**: Progress display shows real-time ETA and success rate to monitor performance
- **Need to keep segments**: Use `--combine-pending --keep-segments` to retain segments for debugging

### Common Solutions
- **Install unrar**: `sudo apt-get install unrar` (Ubuntu/Debian) or `brew install unrar` (macOS)
- **Check credentials**: Verify config.ini has correct NNTP server details
- **Verify API key**: Ensure nzb_indexer.py has valid indexer API key
- **Monitor progress**: Use `--status` command to check system state
- **Better search results**: Use `--limit 50` or `--limit 100` to see more options
- **Selective downloading**: Use `--interactive` mode to browse before downloading
- **Automated processing**: Use `--full-workflow` for complete hands-free operation
- **Segment retention**: Use `--combine-pending --keep-segments` to retain segments after combining

## Configuration Requirements

### config.ini Setup
Edit config.ini with your service credentials:

```ini
[nntp]
server_hostname = news.easynews.com  # Your Usenet server
port = 563                      # Usually 563 for SSL
username = your_username           # Your Usenet username  
password = your_password           # Your Usenet password

[indexer]
base_url = https://api.nzbgeek.info  # NZB indexer URL
api_key = your_api_key_here          # Your indexer API key
```

### Folder Configuration
All folders are automatically created and configurable in config.ini:
- **indicies/**: NZB files downloaded by indexer
- **segments/**: Usenet segment files
- **downloaded/**: Final extracted files organized by category (READY TO USE)
  - **downloaded/Movies/**: Movie content
  - **downloaded/TV/**: Television content
  - **downloaded/Books/**: Books and publications
  - **downloaded/Music/**: Audio content
  - **downloaded/Games/**: Game content
  - **downloaded/Applications/**: Software and utilities
  - **downloaded/Anime/**: Animated content
  - **downloaded/Documentaries/**: Documentary content
  - **downloaded/Sports/**: Sports content
  - **downloaded/Other/**: Uncategorized content
- **downloaded_encoded/**: Combined files (flat structure, category info stored in metadata files)
- **file_decode/**: Temporary extraction folder
- **completed_indicies/**: Processed NZB files

## Code Style Guidelines
- **Python version**: Python 3.6+ compatible
- **Imports**: Use standard library only, group imports at top
- **Formatting**: Follow PEP 8, 4-space indentation, 88-char line limit
- **Naming**: Use descriptive names, no abbreviations or single-letter variables
- **Types**: Use type hints where appropriate, but maintain compatibility
- **Error handling**: Use specific exceptions, include context in error messages
- **Documentation**: Docstrings for all classes and public methods
- **Security**: Never log or expose credentials, use getpass for password input
- **Network**: Always use SSL/TLS, implement proper connection cleanup
- **Testing**: Validate inputs, handle connection timeouts gracefully

## Enhanced Search System Details

### 🔍 Search Query Processing
The enhanced search system automatically improves your queries:

**Query Optimization Examples:**
```
Input: "movie AND trailer AND 2024"
Output: Enhanced query: 'movie trailer 2024' (from: 'movie AND trailer AND 2024')

Input: "jurassic world -park"  
Output: Note: Exclusion terms (['park']) not supported by indexer
Output: Enhanced query: 'jurassic world' (from: 'jurassic world -park')

Input: "singlelongword"
Output: Enhanced query: 'singlelongword*' (automatic wildcard)
```

**Relevance Scoring System:**
- **Exact match**: +100 points
- **Word matches**: +10 points per matching word
- **All words match**: +50 points
- **Recent posts**: +20 points (< 7 days), +10 points (< 30 days)
- **Popular posts**: +15 points (>100 grabs), +10 points (>50 grabs), +5 points (>10 grabs)

### 📊 Search Result Ranking
Results are ranked using a multi-factor algorithm:
1. **Relevance score** (primary): Query match quality
2. **Post date** (secondary): Most recent first
3. **Popularity** (bonus): Download frequency

**Sorting Options:**
- `--sort relevance_desc`: By relevance score (new default for complex queries)
- `--sort date_desc`: Most recent first (default)
- `--sort size_desc`: Largest first
- `--sort size_asc`: Smallest first

### 🎯 Search Best Practices

**For Better Results:**
1. **Use specific keywords**: `4K movie trailer 2024` vs `movie`
2. **Multiple terms**: `jurassic world trailer hd` vs `jurassic`
3. **Category filtering**: `--category movies` for targeted searches
4. **Increase limits**: `--limit 100` for more options
5. **Check feedback**: Review enhanced query messages

**Query Examples:**
```bash
# Good: Specific and multi-keyword
python3 nzb_indexer.py "4K movie trailer 2024" --category movies --limit 50

# Good: Category filtering with keywords
python3 nzb_indexer.py "action thriller series" --category tv

# Good: Multiple specific terms
python3 nzb_indexer.py "documentary nature wildlife 2023" --category documentaries
```

## Complete End-to-End Workflow Guide

### Step 1: Search and Download NZB Files
Use the NZB indexer to find content and download NZB files:

```bash
# Default behavior (prompts for search terms, shows 30 results, interactive mode)
python3 nzb_indexer.py

# Basic search (shows 30 results by default)
python3 nzb_indexer.py "1984 George Orwell"

# Search with category filter
python3 nzb_indexer.py --category books "George Orwell 1984"

# Download with selection (shows results and asks which to download)
python3 nzb_indexer.py --download "1984 George Orwell"

# Show more results (up to 200)
python3 nzb_indexer.py --limit 50 "movie trailer"

# Interactive selection mode
python3 nzb_indexer.py --interactive "movie title"

# Download specific result number
python3 nzb_indexer.py --download --number 3 "movie title"

# Combined advanced search with selection
python3 nzb_indexer.py --category movies --sort size_desc --limit 30 --download "action movie 2024"
```

### Step 2: Download Usenet Segments
Process NZB files to download segments from Usenet server:

```bash
# Manual step-by-step processing
python3 nntp_client.py --process-nzb

# OR use fully automated workflow
python3 nntp_client.py --full-workflow
```

**What happens**: Downloads .seg files from Usenet server to segments/ folder
**Input**: NZB files in indicies/ folder (from Step 1)
**Output**: Segment files in segments/ folder
**Result**: NZB files moved to completed_indicies/ folder
**Progress Display**: Real-time ASCII progress bar with:
- Percentage completion and current/total count
- Success/failure counters with success rate
- Elapsed time and estimated time remaining (ETA)
- Updates every 0.5 seconds for smooth display

### Step 3: Combine Segments into Files
Combine downloaded segments into complete archives and files:

```bash
python3 nntp_client.py --combine-pending
```

**What happens**: Combines segments into complete files (RAR, ZIP, PAR2)
**Input**: Segment files from segments/ folder
**Output**: Combined files in downloaded_encoded/ folder
**Result**: Archives and content ready for extraction
**Default**: Segments are deleted after successful combining

**Optional: Keep segments after combining**:
```bash
python3 nntp_client.py --combine-pending --keep-segments
```
**Result**: Segments are retained in segments/ folder for debugging or reprocessing

### Step 4: Extract Archives to Final Files
Extract archives and process final files:

```bash
python3 nntp_client.py --decode-files
```

**What happens**: Extracts RAR/ZIP archives, processes PAR2 files
**Input**: Files from downloaded_encoded/ folder
**Output**: Final extracted files in downloaded/ folder
**Result**: Ready-to-use files with archives extracted

### Step 5: Check Results
Monitor system status and verify results:

```bash
python3 nntp_client.py --status
```

**What happens**: Shows current state of all folders and file counts, including category breakdown
**Result**: Complete visibility into processing status with category organization
**Example Output**:
```
Downloaded (final files)       downloaded                  15 files (Exists)
                               - Movies files:           8
                               - TV files:               4
                               - Other files:            3
```

## Complete Example Workflows

### Manual Step-by-Step Workflow
```bash
# 1. Enhanced search for George Orwell 1984 (show 50 results, newest first)
python3 nzb_indexer.py --category books --sort date_desc --limit 50 "1984 George Orwell"
# Output: Enhanced query: '1984 George Orwell' (from: '1984 George Orwell')

# 2. Search with automatic query optimization
python3 nzb_indexer.py "graphic novel 1984 Orwell" --category books
# Output: Enhanced query: 'graphic novel 1984 Orwell' (from: 'graphic novel 1984 Orwell')

# OR use default behavior (prompts for search terms, shows 30 results, interactive mode)
python3 nzb_indexer.py

# 2. Download segments from Usenet (with progress display)
python3 nntp_client.py --process-nzb

# 3. Combine segments into complete files
python3 nntp_client.py --combine-pending

# OR keep segments after combining (for debugging/reprocessing)
python3 nntp_client.py --combine-pending --keep-segments

# 4. Extract archives to final location
python3 nntp_client.py --decode-files

# 5. Check final results
python3 nntp_client.py --status
```

### Fully Automated Workflow
```bash
# 1. Enhanced interactive search with relevance ranking
python3 nzb_indexer.py --interactive --category movies "4K trailer 2024"
# Output: Enhanced query: '4K trailer 2024' (from: '4K trailer 2024')

# 2. Search with operator handling and feedback
python3 nzb_indexer.py --interactive "movie AND trailer AND -cam"
# Output: Note: Exclusion terms (['cam']) not supported by indexer
# Output: Enhanced query: 'movie trailer' (from: 'movie AND trailer AND -cam')

# 3. Complete automated processing (one command!)
python3 nntp_client.py --full-workflow
```

### Advanced Search and Download Example
```bash
# Find specific content with selection (shows results and asks which to download)
python3 nzb_indexer.py \
  --category movies \
  --sort size_desc \
  --limit 100 \
  --download \
  "4K movie trailer 2024"

# Download specific result number automatically
python3 nzb_indexer.py \
  --category movies \
  --sort size_desc \
  --limit 100 \
  --download \
  --number 5 \
  "4K movie trailer 2024"

# Process with full automation and progress tracking
python3 nntp_client.py --full-workflow

# OR process manually with segment retention option
python3 nntp_client.py --combine-pending --keep-segments
```

## Folder Structure Workflow

```
indicies/                 ← NZB files (downloaded from indexer)
segments/                 ← Usenet segments (downloaded in Step 2)
completed_indicies/        ← Processed NZB files (from Step 2)
downloaded_encoded/         ← Combined files (from Step 3)
file_decode/              ← Temporary extraction folder (Step 4)
downloaded/               ← Final extracted files (READY TO USE)
```

## Help Systems

### NZB Indexer Help
- **Command**: `python3 nzb_indexer.py --help`
- **Enhanced Search Features**:
  - Smart query processing with automatic optimization
  - Search operator support (AND, NOT) with user feedback
  - Relevance-based result ranking by match quality, age, and popularity
  - Query enhancement feedback showing optimized searches
  - Configurable result limits (1-200, default: 30)
  - Interactive selection mode for browsing results
  - Download with selection (shows all results and asks which to download)
  - Download by specific result number for automatic downloads
  - Multiple sorting options (relevance, date, size, ascending/descending)
  - Category filtering for targeted searches
  - Enhanced display with 65-character wide title column
- **Categories**: movies, tv, books, music, games, apps, anime, documentaries, sports
- **Options**: `--limit N` (1-200 results, default: 30), `--interactive`, `--download` (with selection), `--number N`, `--sort MODE`, `--category CAT`
- **Search Operators**: `AND` (implicit), `-term` (exclusion with feedback), automatic wildcards

### NNTP Client Help  
- **Command**: `python3 nntp_client.py --help` or `python3 nntp_client.py -h`
- **Features**: 
  - Complete workflow documentation and troubleshooting guide
  - Real-time ASCII progress display with detailed statistics
  - Fully automated `--full-workflow` mode
  - Archive support: ZIP, TAR, RAR (with unrar), PAR2 processing
  - Thread-safe progress tracking for concurrent operations
  - Segment retention control with `--keep-segments` option
- **Progress Display**: Live progress bars, success rates, ETA calculations