"""
Interactive Script Selector

Provides interactive CLI interface for selecting export scripts to run.
Uses questionary library for rich checkbox/menu navigation.
"""

import sys
from typing import Any, Dict, List, Optional, Set
from pathlib import Path

try:
    import utils
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent))
    import utils

# Try to import questionary, provide helpful message if not available
try:
    import questionary
    from questionary import Style

    QUESTIONARY_AVAILABLE = True

    # Custom style for questionary prompts
    CUSTOM_STYLE = Style(
        [
            ("qmark", "fg:#5f87ff bold"),  # Question mark
            ("question", "bold"),  # Question text
            ("answer", "fg:#00d787 bold"),  # Selected answer
            ("pointer", "fg:#00d787 bold"),  # Pointer (>)
            ("highlighted", "fg:#00d787 bold"),  # Highlighted choice
            ("selected", "fg:#00d787"),  # Selected item in checkbox
            ("separator", "fg:#6c6c6c"),  # Separator
            ("instruction", "fg:#858585"),  # Instructions
            ("text", ""),  # Regular text
            ("disabled", "fg:#858585 italic"),  # Disabled choice
        ]
    )

except ImportError:
    QUESTIONARY_AVAILABLE = False
    CUSTOM_STYLE = None  # Will not be used when questionary unavailable
    # Silently handle - warning shown when attempting to use interactive features

from .mapping import SCRIPT_CATEGORIES, ALWAYS_RUN_SCRIPTS


class SmartScanSelector:
    """Interactive selector for Smart Scan script recommendations."""

    def __init__(self, recommendations: Dict[str, Any]):
        """
        Initialize the selector with recommendations.

        Args:
            recommendations: Recommendations dict from analyzer.generate_recommendations()
        """
        if not QUESTIONARY_AVAILABLE:
            raise ImportError(
                "questionary library is required for interactive selection. "
                "Install it with: pip install questionary>=2.0.0"
            )

        self.recommendations = recommendations
        self.selected_scripts: Set[str] = set()

    def show_welcome(self) -> None:
        """Display welcome message with Smart Scan stats."""
        stats = self.recommendations.get("coverage_stats", {})

        print()
        print("=" * 80)
        print(" " * 28 + "SMART SCAN ANALYZER")
        print("=" * 80)
        print()
        print(f"  Services Discovered:      {stats.get('total_services_found', 0)}")
        print(f"  Services with Scripts:    {stats.get('services_with_scripts', 0)}")
        print(f"  Scripts Recommended:      {stats.get('total_scripts_recommended', 0)}")
        print(f"  Coverage:                 {stats.get('coverage_percentage', 0)}%")
        print()
        print("=" * 80)
        print()

    def show_main_menu(self) -> str:
        """
        Show main menu and return user's choice.

        Returns:
            User's menu choice: 'quick', 'custom', 'view', 'save', or 'exit'
        """
        choices = [
            {
                "name": "Quick Scan - Run all recommended scripts (recommended)",
                "value": "quick",
            },
            {
                "name": "Custom Selection - Choose specific scripts to run",
                "value": "custom",
            },
            {
                "name": "View Checklist - See all recommendations without running",
                "value": "view",
            },
            {
                "name": "Save Checklist - Export recommendations to file",
                "value": "save",
            },
            {"name": "Exit - Return without running scripts", "value": "exit"},
        ]

        answer = questionary.select(
            "What would you like to do?",
            choices=choices,
            style=CUSTOM_STYLE,
            instruction="(Use arrow keys to navigate, Enter to select)",
        ).ask()

        return answer if answer else "exit"

    def quick_scan_confirm(self) -> bool:
        """
        Show Quick Scan summary and get confirmation.

        Returns:
            True if user confirms, False otherwise
        """
        stats = self.recommendations.get("coverage_stats", {})
        total_scripts = stats.get("total_scripts_recommended", 0)
        always_run = stats.get("always_run_count", 0)
        service_based = stats.get("service_based_count", 0)

        print()
        print("=" * 80)
        print(" " * 32 + "QUICK SCAN")
        print("=" * 80)
        print()
        print("Quick Scan will run ALL recommended scripts:")
        print()
        print(f"  • {always_run} security/compliance scripts (always recommended)")
        print(f"  • {service_based} service-specific scripts (based on discovery)")
        print(f"  • {total_scripts} total scripts")
        print()
        print("This is the most comprehensive scan option.")
        print()
        print("=" * 80)
        print()

        confirm = questionary.confirm(
            "Proceed with Quick Scan?", default=True, style=CUSTOM_STYLE
        ).ask()

        return confirm if confirm is not None else False

    def custom_selection_by_category(self) -> Set[str]:
        """
        Interactive category-based script selection.

        Returns:
            Set of selected script filenames
        """
        selected = set()

        # Get categories with scripts
        by_category = self.recommendations.get("by_category", {})

        if not by_category:
            utils.log_warning("No categories available for selection")
            return selected

        # First, select categories
        print()
        print("=" * 80)
        print(" " * 28 + "SELECT CATEGORIES")
        print("=" * 80)
        print()

        category_choices = []
        for category, scripts in sorted(by_category.items()):
            count = len(scripts)
            category_choices.append(
                {"name": f"{category} ({count} scripts)", "value": category}
            )

        selected_categories = questionary.checkbox(
            "Select categories to explore:",
            choices=category_choices,
            style=CUSTOM_STYLE,
            instruction="(Use arrow keys, Space to select, Enter to confirm)",
        ).ask()

        if not selected_categories:
            return selected

        # For each selected category, select specific scripts
        for category in selected_categories:
            scripts = by_category.get(category, [])
            if not scripts:
                continue

            print()
            print(f"Category: {category}")
            print("-" * 80)

            script_choices = [{"name": script, "value": script} for script in sorted(scripts)]

            # Pre-select "always run" scripts
            preselected = [s for s in scripts if s in ALWAYS_RUN_SCRIPTS]

            category_selected = questionary.checkbox(
                f"Select scripts from {category}:",
                choices=script_choices,
                style=CUSTOM_STYLE,
                instruction="(Space to toggle, Enter to confirm)",
                default=preselected,
            ).ask()

            if category_selected:
                selected.update(category_selected)

        return selected

    def custom_selection_by_service(self) -> Set[str]:
        """
        Interactive service-based script selection.

        Returns:
            Set of selected script filenames
        """
        selected = set()

        service_based = self.recommendations.get("service_based", {})

        if not service_based:
            utils.log_warning("No service-based recommendations available")
            return selected

        print()
        print("=" * 80)
        print(" " * 25 + "SELECT BY SERVICE")
        print("=" * 80)
        print()

        # Create choices for each service
        service_choices = []
        for service, scripts in sorted(service_based.items()):
            count = len(scripts)
            service_choices.append(
                {"name": f"{service} ({count} script{'s' if count > 1 else ''})", "value": service}
            )

        selected_services = questionary.checkbox(
            "Select services to export:",
            choices=service_choices,
            style=CUSTOM_STYLE,
            instruction="(Use arrow keys, Space to select, Enter to confirm)",
        ).ask()

        if not selected_services:
            return selected

        # Collect scripts from selected services
        for service in selected_services:
            scripts = service_based.get(service, [])
            selected.update(scripts)

        return selected

    def custom_selection_menu(self) -> Set[str]:
        """
        Show custom selection menu and handle selection flow.

        Returns:
            Set of selected script filenames
        """
        print()
        print("=" * 80)
        print(" " * 28 + "CUSTOM SELECTION")
        print("=" * 80)
        print()

        selection_method = questionary.select(
            "How would you like to select scripts?",
            choices=[
                {"name": "By Category (Security, Compute, Storage, etc.)", "value": "category"},
                {"name": "By Service (EC2, S3, RDS, etc.)", "value": "service"},
                {"name": "Back to Main Menu", "value": "back"},
            ],
            style=CUSTOM_STYLE,
        ).ask()

        if selection_method == "category":
            return self.custom_selection_by_category()
        elif selection_method == "service":
            return self.custom_selection_by_service()
        else:
            return set()

    def view_checklist(self) -> None:
        """Display complete checklist of recommendations."""
        print()
        print("=" * 80)
        print(" " * 30 + "RECOMMENDATION CHECKLIST")
        print("=" * 80)
        print()

        # Always-run scripts
        always_run = self.recommendations.get("always_run", [])
        if always_run:
            print("SECURITY & COMPLIANCE (Always Recommended):")
            print("-" * 80)
            for i, script in enumerate(sorted(always_run), 1):
                print(f"  {i:2}. {script}")
            print()

        # Service-based recommendations by category
        by_category = self.recommendations.get("by_category", {})

        # Remove "Other" category items from always_run display
        for category, scripts in sorted(by_category.items()):
            # Skip if category only has always-run scripts we've already shown
            category_scripts = [s for s in scripts if s not in always_run]
            if not category_scripts:
                continue

            print(f"{category.upper()}:")
            print("-" * 80)
            for i, script in enumerate(sorted(category_scripts), 1):
                print(f"  {i:2}. {script}")
            print()

        # Summary
        stats = self.recommendations.get("coverage_stats", {})
        print("=" * 80)
        print(f"Total Scripts Recommended: {stats.get('total_scripts_recommended', 0)}")
        print(f"Coverage: {stats.get('coverage_percentage', 0)}%")
        print("=" * 80)
        print()

    def save_checklist(self, filename: Optional[str] = None) -> bool:
        """
        Save checklist to a text file.

        Args:
            filename: Output filename (auto-generated if None)

        Returns:
            True if saved successfully, False otherwise
        """
        from datetime import datetime

        if filename is None:
            timestamp = datetime.now().strftime("%m.%d.%Y-%H%M")
            filename = f"smart-scan-checklist-{timestamp}.txt"

        try:
            with open(filename, "w", encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write(" " * 28 + "SMART SCAN CHECKLIST\n")
                f.write("=" * 80 + "\n\n")

                # Stats
                stats = self.recommendations.get("coverage_stats", {})
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Services Discovered: {stats.get('total_services_found', 0)}\n")
                f.write(f"Scripts Recommended: {stats.get('total_scripts_recommended', 0)}\n")
                f.write(f"Coverage: {stats.get('coverage_percentage', 0)}%\n\n")
                f.write("=" * 80 + "\n\n")

                # Always-run scripts
                always_run = self.recommendations.get("always_run", [])
                if always_run:
                    f.write("SECURITY & COMPLIANCE (Always Recommended):\n")
                    f.write("-" * 80 + "\n")
                    for script in sorted(always_run):
                        f.write(f"  [ ] {script}\n")
                    f.write("\n")

                # By category
                by_category = self.recommendations.get("by_category", {})
                for category, scripts in sorted(by_category.items()):
                    category_scripts = [s for s in scripts if s not in always_run]
                    if not category_scripts:
                        continue

                    f.write(f"{category.upper()}:\n")
                    f.write("-" * 80 + "\n")
                    for script in sorted(category_scripts):
                        f.write(f"  [ ] {script}\n")
                    f.write("\n")

                f.write("=" * 80 + "\n")
                f.write(f"Total Scripts: {stats.get('total_scripts_recommended', 0)}\n")
                f.write("=" * 80 + "\n")

            print()
            print(f"✓ Checklist saved to: {filename}")
            print()
            return True

        except Exception as e:
            utils.log_error(f"Error saving checklist to {filename}", e)
            return False

    def run_interactive(self) -> Optional[Set[str]]:
        """
        Run the complete interactive selection workflow.

        Returns:
            Set of selected scripts to run, or None if user cancelled
        """
        self.show_welcome()

        while True:
            choice = self.show_main_menu()

            if choice == "quick":
                if self.quick_scan_confirm():
                    # Return all recommended scripts
                    return self.recommendations.get("all_scripts", set())
                # If not confirmed, show menu again
                continue

            elif choice == "custom":
                selected = self.custom_selection_menu()
                if selected:
                    # Show confirmation
                    print()
                    print(f"✓ Selected {len(selected)} script(s)")
                    print()
                    confirm = questionary.confirm(
                        "Proceed with these scripts?", default=True, style=CUSTOM_STYLE
                    ).ask()
                    if confirm:
                        return selected
                # If no selection or not confirmed, show menu again
                continue

            elif choice == "view":
                self.view_checklist()
                # Return to main menu
                continue

            elif choice == "save":
                self.save_checklist()
                # Return to main menu
                continue

            elif choice == "exit":
                print()
                print("Exiting Smart Scan without running scripts.")
                print()
                return None

            else:
                # Unknown choice, exit
                return None


def interactive_select(recommendations: Dict[str, Any]) -> Optional[Set[str]]:
    """
    Run interactive script selection.

    Args:
        recommendations: Recommendations dict from analyzer

    Returns:
        Set of selected scripts, or None if cancelled
    """
    if not QUESTIONARY_AVAILABLE:
        utils.log_error(
            "Interactive selection requires questionary library. "
            "Install it with: pip install questionary>=2.0.0"
        )
        return None

    selector = SmartScanSelector(recommendations)
    return selector.run_interactive()
