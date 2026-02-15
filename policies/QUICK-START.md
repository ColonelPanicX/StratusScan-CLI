# StratusScan IAM Permissions - Quick Start Guide

## 1. Check Your Current Permissions

```bash
python configure.py --perms
```

This will:
- Test your AWS credentials
- Check which permissions you have
- Show which permissions are missing
- Provide recommendations

## 2. Apply Required Permissions

### Option A: Custom Policy (Recommended - Least Privilege)

1. **Copy the policy file**:
   ```bash
   cat policies/stratusscan-required-permissions.json
   ```

2. **Create IAM policy**:
   - Go to [IAM Policies Console](https://console.aws.amazon.com/iam/home#/policies)
   - Click "Create policy" > "JSON" tab
   - Paste the JSON content
   - Name it: `StratusScanRequiredPermissions`
   - Click "Create policy"

3. **Attach to your user/role**:
   - Go to your IAM user or role
   - Click "Add permissions" > "Attach policies directly"
   - Search for `StratusScanRequiredPermissions`
   - Click "Add permissions"

### Option B: AWS Managed Policy (Simpler but broader)

Attach the `ReadOnlyAccess` managed policy to your user/role.

## 3. (Optional) Add Advanced Features

If you need Security Hub, Cost Optimization, or Trusted Advisor:

1. Copy `policies/stratusscan-optional-permissions.json`
2. Create policy named `StratusScanOptionalPermissions`
3. Attach to your user/role

## 4. Verify Permissions

```bash
python configure.py --perms
```

Should show: `[SUCCESS] All required permissions are available!`

## 5. Start Using StratusScan

```bash
python stratusscan.py
```

## Troubleshooting

### "No AWS credentials found"
```bash
# Configure credentials
aws configure

# Or for IAM Identity Center
aws configure sso
aws sso login
```

### "Access Denied" errors
- Make sure the policy is attached to your user/role
- Check if SCPs are blocking access at organization level
- Verify you're using the correct AWS profile

### Still having issues?
See the complete documentation in `policies/README.md`
