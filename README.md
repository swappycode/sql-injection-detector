# SQL Injection Detector — BULLETPROOF Parser Edition (FIXED)

A Python-based SQL Injection Detection Tool featuring a bulletproof multi-strategy query parser, advanced DFA injection pattern detection, and formal SQL grammar validation using a Lark-based CFG parser.

This version includes full .SQL file support, improved detection accuracy, fixed verdict logic, optimized parsing, and a polished graphical interface.

---

## Features

### 1. BULLETPROOF Multi-Strategy Query Extraction
The tool extracts SQL queries from any text file using three parallel strategies:

- Semicolon-based splitting  
- Regex-based SQL keyword splitting  
- Smart line-by-line reconstruction  

The system automatically selects the strategy that detects the highest number of queries.

---

### 2. Enhanced DFA Injection Detection
The DFA engine detects all major SQL injection techniques, including:

- Tautology conditions  
- UNION-based injections  
- Stacked queries  
- Comment injections  
- Error-based injections (extractvalue, updatexml, exp, floor(rand()), convert, etc.)  
- Time-based injections (sleep, benchmark, waitfor delay, pg_sleep)  
- Blind injections (substring, ascii, ord, length-based probing)  
- Encoding bypasses (hex payloads, CHAR(), concat with hex)  
- Dangerous functions (load_file, outfile, xp_cmdshell, sp_executesql)  
- Unbalanced quotes and structural anomalies  
- Excessive special character density  

Patterns are classified into **LOW**, **MEDIUM**, **HIGH**, and **CRITICAL** severities.

---

### 3. CFG Grammar Validation (Lark)
A complete SQL grammar is implemented to validate:

- SELECT  
- INSERT  
- UPDATE  
- DELETE  

The grammar validator checks:

- Clause ordering  
- Statement structure  
- Balanced parentheses  
- Multiple-statement detection  
- Syntax correctness  
- Missing FROM clause and other structural faults  

---

### 4. Modern Tkinter GUI
The application provides:

- Dark-themed interface  
- Loading dialog with progress indication  
- Scrollable input and result windows  
- Status bar for system messages  
- File load and reload controls  
- Export results functionality  

---

### 5. .SQL File Support
The tool supports:

- .txt files  
- .sql files  
- Any file containing SQL commands  

The parser extracts all valid queries regardless of formatting, comments, or inconsistencies.

---

### 6. Context-Aware Mode Switching
The system automatically switches between modes:

#### Single Query Mode
Activated when the user types or edits text manually.

#### File Analysis Mode
Activated when a file is loaded and remains unedited.

#### Batch Mode
Available only in File Analysis Mode.  
Displays individual results for each query in the loaded file.

---

### 7. Comprehensive File Analysis Report
The tool generates an aggregated report including:

- Total number of queries  
- Safe, suspicious, and malicious counts  
- Overall verdict  
- Risk level assessment  
- Critical, high, and medium issues  
- Recommended actions  

---

## Installation

Python 3.7+ is required.

Install Lark:

```bash
pip install lark-parser
```

Tkinter is included with standard Python installations.

---

## How to Use

### Running the Application
```bash
python bulletproof-sql-detector-FIXED.py
```

---

### Single Query Analysis
- Type or paste a SQL query into the input box.  
- Click "Analyze".  
- View DFA pattern results, grammar issues, and the final verdict.

---

### File Analysis
- Click "Load File".  
- Select a `.txt` or `.sql` file containing SQL statements.  
- Click "Analyze" for a comprehensive analysis report.  

The BULLETPROOF parser automatically extracts all valid queries.

---

### Batch Mode
Available only when in File Analysis Mode.

- Displays detailed results for every extracted query.  
- Includes individual verdicts and detected patterns.

---

### Reloading File
If you edit the loaded text, batch mode is disabled.  
Use "Reload File" to restore the original file content and re-enable file mode.

---

### Exporting Results
Click "Export Results" to save the displayed analysis into a text report.

The exported report includes:

- Verdict  
- DFA patterns  
- Grammar issues  
- Recommendations  
- Timestamp  
- File metadata  

---

## Changes in the FIXED Version

### Major Fixes
- Completely rebuilt DFA detector  
- Added seven new injection pattern categories  
- Removed early termination in pattern scanning  
- Corrected verdict escalation logic  
- Improved error reporting  
- Enhanced detection of complex blind, error-based, and time-based injections  

### Parser Improvements
- Handles multi-line and irregular queries  
- Detects queries without semicolons  
- Correctly removes all comment types  
- Uses multi-pass parsing to ensure maximum coverage  

### GUI Enhancements
- Updated layout and styling  
- Added mode indicator and status messages  
- Integrated loading dialog for long file operations  
- Better text formatting for richer report display  

---

## Limitations

This project is intended for educational and demonstration purposes.  
For production-level security:

- Use parameterized queries  
- Validate and sanitize user inputs  
- Implement server-side query controls  
- Deploy WAF or IDS systems  
- Follow OWASP security guidelines  

---

## Concepts Demonstrated

- Deterministic Finite Automata (DFA) for pattern detection  
- Context-Free Grammars (CFG) for SQL validation  
- Query parsing strategies and normalization  
- GUI application development using Tkinter  
- Multi-threaded operations for non-blocking UI  
- Security auditing and SQL injection detection methods  
