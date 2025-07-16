# Discadia Auto Voter


Yeah claude made readme, what else?

https://oguser.com/Thread-failure-to-proceed-with-deal?page=1 unpaid script, so opensourcing to make it patched

Automated Discord server voting system for Discadia.com with captcha solving capabilities.

## Features

- Automated Discord OAuth authentication
- Image-based captcha solving using OpenCV
- Multi-threaded token processing
- Proxy support with session management
- Vote status tracking and logging
- Retry mechanisms for failed attempts

## Requirements

```
python3
curl_cffi
opencv-python
numpy
cryptography
structlog
```

## Installation

```bash
pip install curl_cffi opencv-python numpy cryptography structlog
```

## File Structure

```
├── main.py              # Main voting automation script
├── utils/
│   └── solver.py        # Captcha solver module
├── tokens.txt           # Discord tokens (one per line)
├── server.txt           # Server names to vote for (one per line)
├── successful.txt       # Successfully voted tokens
├── failed.txt           # Failed voting attempts
├── banned_token.txt     # Banned/invalid tokens
└── already_voted.txt    # Already voted tokens
```

## Configuration

### tokens.txt
```
discord_token_1
discord_token_2
discord_token_3
```

### server.txt
```
server-name-1
server-name-2
server-name-3
```

## Usage

```bash
python main.py
```

## Components

### PuzzleSolver
- Processes captcha images using OpenCV
- Detects puzzle pieces and calculates positioning
- Returns coordinate values for captcha completion

### DiscordAuth
- Handles Discord OAuth flow
- Manages session cookies and CSRF tokens
- Processes vote submissions with captcha solving

### Solver
- Coordinates captcha solving attempts
- Supports both general and guild-specific captchas
- Implements retry logic for failed solves

## Threading

- Default: 50 concurrent threads
- Processes tokens in batches
- Includes rate limiting delays

## Proxy Support

- iProyal proxy integration
- Session-based proxy rotation
- Geolocation support (default: Germany)

## Output Files

- `successful.txt` - Tokens that voted successfully
- `failed.txt` - Tokens that failed to vote
- `banned_token.txt` - Invalid or banned tokens
- `already_voted.txt` - Tokens that already voted

## Debug Mode

Enable debug mode in PuzzleSolver for visual captcha analysis:
- Creates debug folder with processed images
- Shows detection boundaries and coordinates
- Useful for captcha solving optimization

## Notes

- Uses Chrome 136 user agent impersonation
- Implements AES cookie decryption
- Supports Discord API v9 OAuth flow
- Handles rate limiting and cooldown periods
