# Quick Reference Guide

## Common Issues

### Port Already in Use: `Address already in use`
```bash
pkill -9 -f python && python3 app.py
```

### Seeing Old Chat Messages
**Quick fix**: Click the "Clear All Cache" button on the page

**Alternative**: Open in incognito/private mode at `http://127.0.0.1:8080`
- Chrome: `⌘ + Shift + N`
- Safari: `⌘ + Shift + N`

### Message Send Failure
1. Refresh page (`⌘ + R`)
2. Log in again
3. Confirm chat recipient is selected

### Verify Encryption is Working
1. Press `F12` to open developer tools
2. Click `Network` tab
3. Send a message
4. Check `/send_message` request
5. Should see `"message": "5L2g5aW9"` (Base64 encoded, not plaintext)

## Startup Checklist

**Normal startup log**:
```
ALL DATA CLEARED - FRESH START!
 * Running on http://127.0.0.1:8080
```

**Access URL**: `http://127.0.0.1:8080`

**Expected**: Login page (not chat page)

## Security Verification

| Check | Expected Result | 
|-------|-----------------|
| Network transmission | Base64 encoded `"5L2g5aW9"` |
| UI display | Normal text `"Hello"` |
| Server logs | `Message encryption successful` |
| Data storage | Fully encrypted |

## System Reset (Last Resort)

```bash
# 1. Kill all processes
pkill -9 -f python

# 2. Clear cache
find . -name "*.pyc" -delete

# 3. Restart
python3 app.py
```

Then access system in incognito mode.

## Troubleshooting Steps

If none of the above work:

1. Screenshot error messages
2. Copy browser console errors (F12 → Console)  
3. Record server error logs
4. Try restarting computer 