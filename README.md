# Payment Information Scanner

A PyQt6-based GUI application for scanning files and detecting payment-related information such as credit card numbers, names, email addresses, and phone numbers.

## Features

- **Multi-format Detection**: Scans for credit cards, names, emails, and phone numbers
- **Credit Card Validation**: Uses Luhn algorithm to validate credit card numbers
- **Batch Processing**: Scan multiple files or entire folders
- **Real-time Progress**: Progress bar and status updates during scanning
- **Export Results**: Save scan results to text files
- **Configurable Options**: Choose what types of information to scan for
- **File Type Filtering**: Specify which file extensions to include

## Installation

1. Install Python 3.7 or higher
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python payment_scanner.py
   ```

2. **Select Files**: Use "Select Files" for individual files or "Select Folder" for batch scanning

3. **Configure Scan Options**: Choose which types of information to detect:
   - Credit Cards (with Luhn validation)
   - Names (capitalized word patterns)
   - Email Addresses
   - Phone Numbers

4. **Start Scan**: Click "Start Scan" to begin the process

5. **View Results**: Check the "Results" tab to see detected information

6. **Export**: Save results to a text file for further analysis

## Supported Credit Card Types

- Visa (4xxx-xxxx-xxxx-xxxx)
- MasterCard (5xxx-xxxx-xxxx-xxxx)
- American Express (3xxx-xxxxxx-xxxxx)
- Discover (6xxx-xxxx-xxxx-xxxx)
- Generic 16-digit patterns

## File Types Supported

By default scans: `.txt`, `.log`, `.csv`, `.json`, `.xml`, `.html`

You can customize file extensions in the Settings tab.

## Security Note

This tool is designed for legitimate security auditing and compliance purposes. Always ensure you have proper authorization before scanning files that may contain sensitive information.

## License

This project is provided as-is for educational and security auditing purposes.

