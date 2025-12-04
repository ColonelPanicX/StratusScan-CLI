#!/bin/bash
# Region Selection Pattern Detection Script
# Identifies scripts that need partition-aware region selection fixes

echo "========================================="
echo "Region Selection Pattern Detection"
echo "========================================="
echo ""

SCRIPTS_DIR="scripts"
OUTPUT_FILE=".collab/reference/region-selection-audit-$(date +%Y%m%d).txt"

# Create output file with header
cat > "$OUTPUT_FILE" << EOF
Region Selection Pattern Detection Report
Generated: $(date)
Scripts Directory: $SCRIPTS_DIR
Total Scripts: $(ls -1 $SCRIPTS_DIR/*.py 2>/dev/null | wc -l)

========================================
PATTERN ANALYSIS
========================================

EOF

echo "Analyzing scripts in $SCRIPTS_DIR..."
echo ""

# Pattern 1: Custom get_aws_regions functions
echo "1. Scripts with custom get_aws_regions() functions:"
echo "   (These likely need to be updated to use utils.get_partition_regions())"
echo ""
echo "========================================" >> "$OUTPUT_FILE"
echo "1. CUSTOM get_aws_regions() FUNCTIONS" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"
grep -l "def get_aws_regions" $SCRIPTS_DIR/*.py | while read file; do
    echo "   - $(basename $file)"
    echo "   - $(basename $file)" >> "$OUTPUT_FILE"
done
echo "" >> "$OUTPUT_FILE"
echo ""

# Pattern 2: Hardcoded region lists
echo "2. Scripts with potential hardcoded region lists:"
echo "   (Look for 'us-east-1' and 'us-west-2' together)"
echo ""
echo "========================================" >> "$OUTPUT_FILE"
echo "2. HARDCODED REGION LISTS" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"
grep -l "us-east-1.*us-west-2\|us-west-2.*us-east-1" $SCRIPTS_DIR/*.py | while read file; do
    base=$(basename $file)
    # Count occurrences
    count=$(grep -c "us-east-1\|us-west-2" "$file")
    echo "   - $base ($count occurrences)"
    echo "   - $base ($count occurrences)" >> "$OUTPUT_FILE"
done
echo "" >> "$OUTPUT_FILE"
echo ""

# Pattern 3: Scripts using utils.get_available_aws_regions()
echo "3. Scripts using utils.get_available_aws_regions():"
echo "   (Should now work correctly after utils.py fix)"
echo ""
echo "========================================" >> "$OUTPUT_FILE"
echo "3. USING utils.get_available_aws_regions()" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"
grep -l "utils.get_available_aws_regions" $SCRIPTS_DIR/*.py | while read file; do
    echo "   - $(basename $file)"
    echo "   - $(basename $file)" >> "$OUTPUT_FILE"
done
echo "" >> "$OUTPUT_FILE"
echo ""

# Pattern 4: EC2 describe_regions calls
echo "4. Scripts with EC2 describe_regions calls:"
echo "   (May need partition-aware region filtering)"
echo ""
echo "========================================" >> "$OUTPUT_FILE"
echo "4. EC2 describe_regions() CALLS" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"
grep -l "describe_regions" $SCRIPTS_DIR/*.py | while read file; do
    echo "   - $(basename $file)"
    echo "   - $(basename $file)" >> "$OUTPUT_FILE"
done
echo "" >> "$OUTPUT_FILE"
echo ""

# Pattern 5: User input for regions
echo "5. Scripts with region user input:"
echo "   (May need partition-aware examples in prompts)"
echo ""
echo "========================================" >> "$OUTPUT_FILE"
echo "5. REGION USER INPUT" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"
grep -l "input.*region\|region.*input" $SCRIPTS_DIR/*.py | while read file; do
    echo "   - $(basename $file)"
    echo "   - $(basename $file)" >> "$OUTPUT_FILE"
done
echo "" >> "$OUTPUT_FILE"
echo ""

# Pattern 6: DEFAULT_REGIONS usage
echo "6. Scripts using DEFAULT_REGIONS:"
echo "   (Should use partition-aware alternatives)"
echo ""
echo "========================================" >> "$OUTPUT_FILE"
echo "6. DEFAULT_REGIONS USAGE" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"
grep -l "DEFAULT_REGIONS" $SCRIPTS_DIR/*.py | while read file; do
    echo "   - $(basename $file)"
    echo "   - $(basename $file)" >> "$OUTPUT_FILE"
done
echo "" >> "$OUTPUT_FILE"
echo ""

# Summary statistics
echo "========================================" >> "$OUTPUT_FILE"
echo "SUMMARY STATISTICS" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"

total_scripts=$(ls -1 $SCRIPTS_DIR/*.py 2>/dev/null | wc -l)
custom_funcs=$(grep -l "def get_aws_regions" $SCRIPTS_DIR/*.py 2>/dev/null | wc -l)
hardcoded=$(grep -l "us-east-1.*us-west-2\|us-west-2.*us-east-1" $SCRIPTS_DIR/*.py 2>/dev/null | wc -l)
using_utils=$(grep -l "utils.get_available_aws_regions" $SCRIPTS_DIR/*.py 2>/dev/null | wc -l)
describe_regions=$(grep -l "describe_regions" $SCRIPTS_DIR/*.py 2>/dev/null | wc -l)
user_input=$(grep -l "input.*region\|region.*input" $SCRIPTS_DIR/*.py 2>/dev/null | wc -l)
default_regions=$(grep -l "DEFAULT_REGIONS" $SCRIPTS_DIR/*.py 2>/dev/null | wc -l)

echo "Total scripts analyzed: $total_scripts" >> "$OUTPUT_FILE"
echo "Scripts with custom get_aws_regions(): $custom_funcs" >> "$OUTPUT_FILE"
echo "Scripts with hardcoded regions: $hardcoded" >> "$OUTPUT_FILE"
echo "Scripts using utils.get_available_aws_regions(): $using_utils" >> "$OUTPUT_FILE"
echo "Scripts with describe_regions calls: $describe_regions" >> "$OUTPUT_FILE"
echo "Scripts with region user input: $user_input" >> "$OUTPUT_FILE"
echo "Scripts using DEFAULT_REGIONS: $default_regions" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Calculate unique scripts needing review
unique_scripts=$(cat <(grep -l "def get_aws_regions" $SCRIPTS_DIR/*.py 2>/dev/null) \
                      <(grep -l "us-east-1.*us-west-2\|us-west-2.*us-east-1" $SCRIPTS_DIR/*.py 2>/dev/null) \
                      <(grep -l "utils.get_available_aws_regions" $SCRIPTS_DIR/*.py 2>/dev/null) \
                      <(grep -l "describe_regions" $SCRIPTS_DIR/*.py 2>/dev/null) \
                      <(grep -l "input.*region\|region.*input" $SCRIPTS_DIR/*.py 2>/dev/null) \
                      <(grep -l "DEFAULT_REGIONS" $SCRIPTS_DIR/*.py 2>/dev/null) | sort -u | wc -l)

echo "Unique scripts needing review: $unique_scripts" >> "$OUTPUT_FILE"

echo "========================================="
echo "Summary:"
echo "  Total scripts: $total_scripts"
echo "  Custom get_aws_regions(): $custom_funcs"
echo "  Hardcoded regions: $hardcoded"
echo "  Using utils functions: $using_utils"
echo "  EC2 describe_regions: $describe_regions"
echo "  Region user input: $user_input"
echo "  DEFAULT_REGIONS usage: $default_regions"
echo "  ---"
echo "  Unique scripts needing review: $unique_scripts"
echo ""
echo "Full report saved to: $OUTPUT_FILE"
echo "========================================="
