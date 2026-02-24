#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: StratusScan Output Archive Script
Date: FEB-22-2026

Description:
Creates a dated zip archive of all files in the output/ directory.
Follows the gold-standard 2-step flow: confirm → archive.
"""

import sys
import zipfile
import datetime
from pathlib import Path

try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    try:
        import utils
    except ImportError:
        print("ERROR: Could not import the utils module. Make sure utils.py is in the StratusScan directory.")
        sys.exit(1)

utils.setup_logging("output-archive")


def _create_archive(account_name: str) -> bool:
    """
    Create a dated zip archive of the output/ directory.

    Args:
        account_name: AWS account name used in the archive filename.

    Returns:
        True if the archive was created successfully, False otherwise.
    """
    output_dir = Path(__file__).parent.parent / "output"

    if not output_dir.exists():
        print("Output directory not found. Run an export first.")
        return False

    files = list(output_dir.glob("*.*"))
    if not files:
        print("No files found in the output directory. Nothing to archive.")
        return False

    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    zip_filename = f"{account_name}-export-{current_date}.zip"
    zip_path = Path(__file__).parent.parent / zip_filename

    print(f"\nFound {len(files)} file(s) to archive.")
    print(f"Creating: {zip_filename}\n")

    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in files:
                zipf.write(file, arcname=file.name)
                print(f"  Added: {file.name}")

        print(f"\nArchive created successfully: {zip_path}")
        utils.log_success(f"Output archive created: {zip_path}")
        return True

    except Exception as e:
        utils.log_error("Failed to create archive", e)
        return False


def main():
    """Main function — 2-step state machine: confirm → archive."""
    try:
        utils.setup_logging("output-archive")
        account_id, account_name = utils.print_script_banner("OUTPUT ARCHIVE")

        step = 1
        while True:
            if step == 1:
                result = utils.prompt_confirmation(
                    f"Create a zip archive of all files in output/ "
                    f"({account_name}-export-<date>.zip)?"
                )
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                step = 2

            elif step == 2:
                _create_archive(account_name)
                print("\nScript execution completed.")
                break

    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
