# tf_plan_analyzer_enhanced.py

import json
import os
import sys
import argparse
import yaml
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any, Optional, DefaultDict, Tuple, Set

# --- Constants ---

# JSON Plan Keys
KEY_RESOURCE_CHANGES = 'resource_changes'
KEY_CHANGE = 'change'
KEY_ACTIONS = 'actions'
KEY_BEFORE = 'before'
KEY_AFTER = 'after'
KEY_AFTER_UNKNOWN = 'after_unknown'
KEY_ADDRESS = 'address'
KEY_TYPE = 'type'
KEY_NAME = 'name'
KEY_PROVIDER_NAME = 'provider_name'
KEY_DEPENDS_ON = 'depends_on'
KEY_TERRAFORM_VERSION = 'terraform_version'
KEY_FORMAT_VERSION = 'format_version'
KEY_VARIABLES = 'variables'
KEY_VALUE = 'value'

# Change Actions
ACTION_CREATE = 'create'
ACTION_UPDATE = 'update'
ACTION_DELETE = 'delete'
ACTION_READ = 'read'
ACTION_NOOP = 'no-op'

# Change Categories
CAT_CREATED = 'created'
CAT_UPDATED = 'updated'
CAT_DESTROYED = 'destroyed'
CAT_REPLACED = 'replaced'
CAT_READ = 'read' # For data sources read
CAT_NO_CHANGES = 'no_changes'

# --- Color Definitions ---

class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

# --- Helper Functions ---

def load_config(config_path: str = 'config.yaml') -> Dict[str, Any]:
    """Loads configuration from a YAML file."""
    default_config = {
        'critical_delete_types': ['aws_instance', 'aws_db_instance'],
        'sensitive_update_types': ['security_group', 'iam'], # Can use partial matches
        'impact_scores': {
            CAT_CREATED: 1,
            CAT_UPDATED: 2,
            CAT_DESTROYED: 3,
            CAT_REPLACED: 4,
            CAT_READ: 0,
            CAT_NO_CHANGES: 0
        },
        'tagging_analysis': {
            'enabled': False,
            'required_tags': ['Environment', 'Owner']
        }
    }
    try:
        with open(config_path, 'r') as f:
            loaded_config = yaml.safe_load(f)
            # Simple merge strategy (loaded overrides default)
            default_config.update(loaded_config or {})
            return default_config
    except FileNotFoundError:
        print(f"{Colors.YELLOW}Warning: Config file '{config_path}' not found. Using default settings.{Colors.RESET}")
        return default_config
    except yaml.YAMLError as e:
        print(f"{Colors.RED}Error loading config file '{config_path}': {e}{Colors.RESET}")
        print("Using default settings.")
        return default_config

# --- Main Analyzer Class ---

class TerraformPlanAnalyzer:
    """
    Analyzes a Terraform plan JSON file, identifies changes, assesses risks,
    and generates a detailed report.
    """

    def __init__(self, plan_file_path: str, config: Dict[str, Any], use_color: bool = True):
        """
        Initializes the analyzer.

        Args:
            plan_file_path: Path to the Terraform plan JSON file.
            config: Configuration dictionary.
            use_color: Whether to use colored output.
        """
        self.plan_file_path: str = plan_file_path
        self.config: Dict[str, Any] = config
        self.use_color: bool = use_color and sys.stdout.isatty() # Only colorize if TTY

        self.plan_data: Optional[Dict[str, Any]] = None
        self.report: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.dependencies: DefaultDict[str, List[str]] = defaultdict(list)
        self.risk_factors: List[str] = []
        self.tagging_issues: List[str] = []
        self.metadata: Dict[str, Any] = {}
        self.advanced_stats: Dict[str, Any] = {
            'resource_types': defaultdict(int),
            'providers': defaultdict(int),
            'impact_score': 0
        }

    def _colorize(self, text: str, color: str = "", bold: bool = False, underline: bool = False) -> str:
        """Applies ANSI color and formatting if enabled."""
        if self.use_color:
            formatting = color
            if bold: formatting += Colors.BOLD
            if underline: formatting += Colors.UNDERLINE
            return f"{formatting}{text}{Colors.RESET}"
        return text

    def load_plan(self) -> bool:
        """Loads and validates the Terraform plan JSON file."""
        try:
            with open(self.plan_file_path, 'r') as file:
                self.plan_data = json.load(file)
            if not isinstance(self.plan_data, dict):
                 print(self._colorize(f"Error: Plan file '{self.plan_file_path}' does not contain a valid JSON object.", Colors.RED))
                 return False
            return True
        except FileNotFoundError:
            print(self._colorize(f"Error: File '{self.plan_file_path}' not found.", Colors.RED))
            return False
        except json.JSONDecodeError as e:
            print(self._colorize(f"Error: Invalid JSON format in plan file '{self.plan_file_path}': {e}", Colors.RED))
            return False
        except Exception as e:
            print(self._colorize(f"An unexpected error occurred while loading the plan: {e}", Colors.RED))
            return False

    def _extract_metadata(self) -> None:
        """Extracts metadata from the loaded plan data."""
        if not self.plan_data: return

        self.metadata['terraform_version'] = self.plan_data.get(KEY_TERRAFORM_VERSION, 'N/A')
        self.metadata['format_version'] = self.plan_data.get(KEY_FORMAT_VERSION, 'N/A')
        self.metadata['variables'] = self.plan_data.get(KEY_VARIABLES, {})
        self.metadata['resource_changes_count'] = len(self.plan_data.get(KEY_RESOURCE_CHANGES, []))

    def _extract_dependencies(self, resource_change: Dict[str, Any]) -> List[str]:
        """Safely extracts dependencies from a resource change."""
        change = resource_change.get(KEY_CHANGE, {})
        before = change.get(KEY_BEFORE) if isinstance(change, dict) else None
        if isinstance(before, dict):
            depends_on = before.get(KEY_DEPENDS_ON)
            if isinstance(depends_on, list):
                return depends_on
        return []

    def _determine_change_category(self, actions: List[str]) -> str:
        """Determines the primary category of change based on actions."""
        if ACTION_DELETE in actions and ACTION_CREATE in actions:
            return CAT_REPLACED
        elif ACTION_CREATE in actions:
            return CAT_CREATED
        elif ACTION_DELETE in actions:
            return CAT_DESTROYED
        elif ACTION_UPDATE in actions:
            return CAT_UPDATED
        elif ACTION_READ in actions:
             return CAT_READ # Explicitly handle read actions (data sources)
        elif actions == [ACTION_NOOP]:
             return CAT_NO_CHANGES
        else:
            # Default or unexpected combination, treat as no-change for safety
             return CAT_NO_CHANGES


    def _assess_risk(self, resource_info: Dict[str, Any], category: str) -> None:
        """Assesses potential risks based on the resource type and change category."""
        addr = resource_info[KEY_ADDRESS]
        rtype = resource_info[KEY_TYPE]

        if category == CAT_DESTROYED and rtype in self.config.get('critical_delete_types', []):
            self.risk_factors.append(f"Critical resource deletion: {addr} ({rtype})")

        if category in [CAT_UPDATED, CAT_REPLACED]:
            sensitive_patterns = self.config.get('sensitive_update_types', [])
            for pattern in sensitive_patterns:
                if pattern in rtype:
                    self.risk_factors.append(f"Sensitive resource modification: {addr} ({rtype})")
                    break # Only add one risk factor per sensitive type match

    def _analyze_tagging(self, resource_info: Dict[str, Any], category: str) -> None:
        """Analyzes resource tags if enabled in config."""
        if not self.config.get('tagging_analysis', {}).get('enabled', False):
            return
        if category not in [CAT_CREATED, CAT_UPDATED, CAT_REPLACED]:
            return

        required_tags = set(self.config.get('tagging_analysis', {}).get('required_tags', []))
        if not required_tags:
            return

        # Check 'after' state for tags
        after_state = resource_info.get('change_details', {}).get(KEY_AFTER, {})
        tags = after_state.get('tags', {}) if isinstance(after_state, dict) else {}
        if not isinstance(tags, dict): # Handle cases where tags might not be a dict
            tags = {}

        present_tags = set(tags.keys())
        missing_tags = required_tags - present_tags

        if missing_tags:
            self.tagging_issues.append(
                f"Resource {resource_info[KEY_ADDRESS]} missing required tags: {', '.join(sorted(list(missing_tags)))}"
            )


    def analyze_changes(self) -> None:
        """Analyzes resource changes in the plan."""
        if not self.plan_data or KEY_RESOURCE_CHANGES not in self.plan_data:
            print(self._colorize("Warning: No 'resource_changes' found in the plan file.", Colors.YELLOW))
            return

        for resource in self.plan_data.get(KEY_RESOURCE_CHANGES, []):
            change = resource.get(KEY_CHANGE, {})
            actions = change.get(KEY_ACTIONS, [ACTION_NOOP]) if isinstance(change, dict) else [ACTION_NOOP]

            # Ensure actions is a list
            if not isinstance(actions, list):
                 actions = [ACTION_NOOP] # Default to no-op if actions format is unexpected


            dependencies = self._extract_dependencies(resource)

            resource_info = {
                KEY_ADDRESS: resource.get(KEY_ADDRESS, 'N/A'),
                KEY_TYPE: resource.get(KEY_TYPE, 'N/A'),
                KEY_NAME: resource.get(KEY_NAME, 'N/A'),
                KEY_PROVIDER_NAME: resource.get(KEY_PROVIDER_NAME, 'N/A'),
                'change_details': {},
                'dependencies': dependencies
            }

            # Populate change details only if there's an actual change state
            if isinstance(change, dict) and any(a in actions for a in [ACTION_CREATE, ACTION_UPDATE, ACTION_DELETE]):
                 resource_info['change_details'] = {
                     KEY_BEFORE: change.get(KEY_BEFORE), # Can be None
                     KEY_AFTER: change.get(KEY_AFTER),   # Can be None
                     KEY_AFTER_UNKNOWN: change.get(KEY_AFTER_UNKNOWN) or {} # Default to empty dict
                 }


            # Determine category
            category = self._determine_change_category(actions)
            self.report[category].append(resource_info)

            # Update dependencies map (resource X depends on items listed in its 'dependencies' list)
            # So, if resource Y lists X in depends_on, then X affects Y.
            # We map: affected_resource -> [list_of_dependencies]
            # And want: dependency -> [list_of_affected_resources]
            for dep in dependencies:
                self.dependencies[dep].append(resource_info[KEY_ADDRESS])

            # Update stats
            self.advanced_stats['resource_types'][resource_info[KEY_TYPE]] += 1
            self.advanced_stats['providers'][resource_info[KEY_PROVIDER_NAME]] += 1
            self.advanced_stats['impact_score'] += self.config.get('impact_scores', {}).get(category, 0)

            # Assess risks and tagging
            self._assess_risk(resource_info, category)
            self._analyze_tagging(resource_info, category)


    def _format_change_details(self, details: Dict[str, Any], indent: int = 4) -> List[str]:
        """Formats the before/after/unknown details for console output."""
        output = []
        before = details.get(KEY_BEFORE) or {}
        after = details.get(KEY_AFTER) or {}
        unknown = details.get(KEY_AFTER_UNKNOWN) or {}

        # Ensure 'before' and 'after' are dicts for comparison
        if not isinstance(before, dict): before = {}
        if not isinstance(after, dict): after = {}

        all_keys = set(before.keys()) | set(after.keys())
        changed_attrs: Dict[str, Dict[str, Any]] = {}

        for key in sorted(list(all_keys)):
             # Ignore 'tags_all' if 'tags' exists and is the same (often redundant)
             if key == 'tags_all' and 'tags' in all_keys and before.get('tags') == after.get('tags'):
                 continue

             val_before = before.get(key)
             val_after = after.get(key)

             if val_before is None and val_after is not None:
                 changed_attrs[key] = {'new': val_after}
             elif val_before is not None and val_after is None:
                 changed_attrs[key] = {'removed': val_before}
             elif val_before != val_after:
                 # Add special handling for potentially large strings or lists? (Optional)
                 changed_attrs[key] = {'before': val_before, 'after': val_after}


        if changed_attrs:
            output.append(self._colorize("✦ Changes:", Colors.CYAN, bold=True))
            for attr, change in changed_attrs.items():
                attr_colored = self._colorize(attr, Colors.WHITE) # Keep attribute name neutral
                if 'new' in change:
                    val = json.dumps(change['new'], indent=2) if isinstance(change['new'], (dict, list)) else json.dumps(change['new'])
                    line = f"  {self._colorize('+', Colors.GREEN)} {attr_colored}: {val}"
                    output.append(self._colorize(line, Colors.GREEN))
                elif 'removed' in change:
                    val = json.dumps(change['removed'], indent=2) if isinstance(change['removed'], (dict, list)) else json.dumps(change['removed'])
                    line = f"  {self._colorize('-', Colors.RED)} {attr_colored}: {val}"
                    output.append(self._colorize(line, Colors.RED))
                else:
                    val_b = json.dumps(change['before'], indent=2) if isinstance(change['before'], (dict, list)) else json.dumps(change['before'])
                    val_a = json.dumps(change['after'], indent=2) if isinstance(change['after'], (dict, list)) else json.dumps(change['after'])
                    line = (f"  {self._colorize('~', Colors.YELLOW)} {attr_colored}: {val_b} → {val_a}")
                    output.append(self._colorize(line, Colors.YELLOW))

        # Only show unknown section if there are actually unknown values
        if isinstance(unknown, dict) and any(v for k, v in unknown.items() if k not in after): # Check if key truly unknown or just shadowed
            output.append(self._colorize("✦ Unknown After Apply:", Colors.MAGENTA, bold=True))
            for key, value in unknown.items():
                if value and key not in after: # Show only truly computed/unknown values
                     line = f"  {self._colorize('?', Colors.MAGENTA)} {key}: (known after apply)"
                     output.append(self._colorize(line, Colors.MAGENTA))

        return [" " * indent + line for line in output]


    def _generate_console_report(self) -> str:
        """Generates the human-readable console report."""
        report_output = []
        hr = self._colorize("═" * 80, Colors.BLUE)

        report_output.append(hr)
        report_output.append(self._colorize(
            f"Terraform Plan Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            Colors.WHITE, bold=True, underline=True
        ))
        report_output.append(f"Plan File: {self.plan_file_path}")
        report_output.append(hr)

        # --- Metadata ---
        report_output.append("")
        report_output.append(self._colorize("✸ Plan Metadata", Colors.BLUE, bold=True))
        report_output.append(f"  Terraform Version: {self.metadata.get('terraform_version', 'N/A')}")
        report_output.append(f"  Plan Format Version: {self.metadata.get('format_version', 'N/A')}")
        report_output.append(f"  Total Resources in Plan: {self.metadata.get('resource_changes_count', 0)}")

        if self.metadata.get('variables'):
            report_output.append("")
            report_output.append(self._colorize("✸ Input Variables:", Colors.CYAN))
            for var_name, var_data in self.metadata['variables'].items():
                 # Handle potential lack of 'value' key
                 value = var_data.get('value', '(sensitive)') if isinstance(var_data, dict) else '(unknown format)'
                 report_output.append(f"    {var_name}: {value}")


        # --- Summary ---
        report_output.append("")
        report_output.append(self._colorize("✸ Changes Summary", Colors.BLUE, bold=True))
        report_output.append(self._colorize(f"  Resources to be Created:  {len(self.report[CAT_CREATED])}", Colors.GREEN))
        report_output.append(self._colorize(f"  Resources to be Updated:  {len(self.report[CAT_UPDATED])}", Colors.YELLOW))
        report_output.append(self._colorize(f"  Resources to be Replaced: {len(self.report[CAT_REPLACED])}", Colors.MAGENTA)) # Changed color
        report_output.append(self._colorize(f"  Resources to be Destroyed:{len(self.report[CAT_DESTROYED])}", Colors.RED))
        report_output.append(self._colorize(f"  Data Sources Read:      {len(self.report[CAT_READ])}", Colors.CYAN)) # Added Read
        report_output.append(f"  Resources with No Changes:{len(self.report[CAT_NO_CHANGES] + self.report.get('no-op',[]))}") # Combine no-op


        # --- Advanced Analysis ---
        report_output.append("")
        report_output.append(self._colorize("✸ Advanced Analysis", Colors.BLUE, bold=True))
        impact = self.advanced_stats['impact_score']
        impact_color = Colors.RED if impact > 10 else Colors.YELLOW if impact > 5 else Colors.GREEN
        report_output.append(f"  Change Impact Score: {self._colorize(str(impact), impact_color)}")
        report_output.append(self._colorize("  Resource Type Distribution:", Colors.CYAN))
        for rtype, count in sorted(self.advanced_stats['resource_types'].items()):
            report_output.append(f"    {rtype}: {count}")
        report_output.append(self._colorize("  Provider Distribution:", Colors.CYAN))
        for provider, count in sorted(self.advanced_stats['providers'].items()):
            report_output.append(f"    {provider}: {count}")

        # --- Risks ---
        if self.risk_factors:
            report_output.append("")
            report_output.append(self._colorize("✸ Risk Assessment", Colors.RED, bold=True))
            for risk in self.risk_factors:
                report_output.append(self._colorize(f"  ⚠ {risk}", Colors.RED))

        # --- Tagging Issues ---
        if self.tagging_issues:
             report_output.append("")
             report_output.append(self._colorize("✸ Tagging Issues", Colors.YELLOW, bold=True))
             for issue in self.tagging_issues:
                 report_output.append(self._colorize(f"   T {issue}", Colors.YELLOW)) # T for Tag

        # --- Dependencies ---
        if self.dependencies:
            report_output.append("")
            report_output.append(self._colorize("✸ Dependency Graph (Resource -> Affected By)", Colors.BLUE, bold=True))
            # Displaying as: Dependency -> Affects Resource
            for dep, affected_list in sorted(self.dependencies.items()):
                report_output.append(self._colorize(f"  {dep} affects:", Colors.CYAN))
                for aff in sorted(affected_list):
                    report_output.append(f"    ↳ {aff}")
            # --- Placeholder for Graphviz output ---
            # report_output.append(self._colorize("  (Consider adding --graphviz for visual output)", Colors.WHITE))

        # --- Detailed Changes ---
        def print_resource_list(title: str, resources: List[Dict[str, Any]], color: str, symbol: str):
            if resources:
                report_output.append("")
                report_output.append(self._colorize(f"{symbol} {title}", color, bold=True))
                report_output.append(self._colorize("-" * (len(title) + 2), color)) # Adjust line length
                for resource in sorted(resources, key=lambda x: x[KEY_ADDRESS]): # Sort resources by address
                    report_output.append(self._colorize(f"  ✷ {resource[KEY_ADDRESS]} ({resource[KEY_TYPE]})", color))
                    report_output.append(f"      Provider: {resource[KEY_PROVIDER_NAME]}")
                    if resource.get('change_details'):
                        report_output.extend(self._format_change_details(resource['change_details']))
                    if resource['dependencies']:
                        report_output.append(self._colorize("    Dependencies:", Colors.CYAN))
                        for dep in sorted(resource['dependencies']):
                            report_output.append(f"      ↳ {dep}")

        print_resource_list("Resources to be Created", self.report[CAT_CREATED], Colors.GREEN, "⊕") # Changed symbol
        print_resource_list("Resources to be Updated", self.report[CAT_UPDATED], Colors.YELLOW, "↻") # Changed symbol
        print_resource_list("Resources to be Replaced", self.report[CAT_REPLACED], Colors.MAGENTA, "⇄") # Changed symbol
        print_resource_list("Resources to be Destroyed", self.report[CAT_DESTROYED], Colors.RED, "⊖") # Changed symbol
        print_resource_list("Data Sources Read", self.report[CAT_READ], Colors.CYAN, "ℹ") # Added Read section

        # --- Footer ---
        report_output.append("")
        report_output.append(hr)

        return "\n".join(report_output)

    def _generate_json_report(self) -> str:
        """Generates the report in JSON format."""
        json_report = {
            'metadata': self.metadata,
            'summary': {cat: len(res_list) for cat, res_list in self.report.items()},
             'analysis': {
                 'impact_score': self.advanced_stats['impact_score'],
                 'resource_type_distribution': dict(self.advanced_stats['resource_types']),
                 'provider_distribution': dict(self.advanced_stats['providers']),
                 'dependencies_on': dict(self.dependencies), # dependency -> affects list
                 'risk_assessment': self.risk_factors,
                 'tagging_issues': self.tagging_issues,
             },
            'resource_details': self.report, # Contains the full details per category
            'report_timestamp': datetime.now().isoformat()
        }
        try:
             return json.dumps(json_report, indent=2, default=str) # Use default=str for non-serializable items if any
        except TypeError as e:
             print(self._colorize(f"Error generating JSON report: {e}. Check data structures.", Colors.RED))
             # Fallback: try to serialize problematic parts individually or return error structure
             return json.dumps({"error": "Failed to serialize report to JSON", "details": str(e)}, indent=2)


    def run_analysis(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Loads the plan, runs all analysis steps, and generates reports.

        Returns:
            A tuple containing (console_report_string, json_report_string)
        """
        if not self.load_plan():
            return None, None # Indicate failure

        self._extract_metadata()
        self.analyze_changes()

        console_report = self._generate_console_report()
        json_report = self._generate_json_report()

        return console_report, json_report

# --- Main Execution ---

def main():
    """Main function to parse arguments and run the analyzer."""
    parser = argparse.ArgumentParser(
        description='Enhanced Terraform Plan Analyzer. Analyzes Terraform plan JSON output.',
        formatter_class=argparse.RawTextHelpFormatter # Preserve formatting in help
    )
    parser.add_argument('plan_file', help='Path to Terraform plan JSON file (generated with terraform show -json plan.out)')
    parser.add_argument('--config', default='config.yaml', help='Path to configuration YAML file (default: config.yaml)')
    parser.add_argument('--no-color', action='store_true', help='Disable ANSI color output')
    parser.add_argument('--json', action='store_true', help='Output report ONLY in JSON format to stdout')
    # Example for future extension:
    # parser.add_argument('--graphviz', help='Output dependency graph to a DOT file')

    args = parser.parse_args()

    # Determine color usage
    use_color = not args.no_color
    if os.environ.get('NO_COLOR') or os.environ.get('TF_PLAN_NO_COLOR'): # Check common env vars
        use_color = False

    # Load configuration
    config = load_config(args.config)

    # Initialize and run analyzer
    analyzer = TerraformPlanAnalyzer(args.plan_file, config, use_color)
    console_report, json_report = analyzer.run_analysis()

    # Output results
    if console_report is None and json_report is None:
         sys.exit(1) # Exit with error if analysis failed early

    if args.json:
        if json_report: print(json_report)
    else:
        if console_report: print(console_report)
        # Optionally print JSON report to a file if not args.json?
        # with open('tf_plan_report.json', 'w') as f:
        #     f.write(json_report)

if __name__ == "__main__":
    main()
