import json
import os
import sys
from datetime import datetime
import argparse
from collections import defaultdict

class Colors:
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

class TerraformPlanAnalyzer:
    def __init__(self, plan_file_path, use_color=True):
        self.plan_file_path = plan_file_path
        self.plan_data = None
        self.use_color = use_color
        self.report = {
            'created': [],
            'updated': [],
            'destroyed': [],
            'replaced': [],
            'no_changes': []
        }
        self.dependencies = defaultdict(list)
        self.risk_factors = []

    def load_plan(self):
        try:
            with open(self.plan_file_path, 'r') as file:
                self.plan_data = json.load(file)
            return True
        except FileNotFoundError:
            print(f"Error: File {self.plan_file_path} not found")
            return False
        except json.JSONDecodeError:
            print("Error: Invalid JSON format in plan file")
            return False

    def analyze_changes(self):
        if not self.plan_data or 'resource_changes' not in self.plan_data:
            return

        for resource in self.plan_data['resource_changes']:
            change = resource.get('change') or {}
            
            # Safely extract dependencies
            before = change.get('before') if change else None
            dependencies = []
            if isinstance(before, dict):
                depends_on = before.get('depends_on')
                if isinstance(depends_on, list):
                    dependencies = depends_on

            resource_info = {
                'address': resource['address'],
                'type': resource['type'],
                'name': resource['name'],
                'provider': resource['provider_name'],
                'change_details': {},
                'dependencies': dependencies
            }

            change_actions = change.get('actions', [])

            if 'create' in change_actions or 'update' in change_actions:
                resource_info['change_details'] = {
                    'before': change.get('before') or {},
                    'after': change.get('after') or {},
                    'after_unknown': change.get('after_unknown') or {}
                }

            for dep in resource_info['dependencies']:
                self.dependencies[dep].append(resource['address'])

            if 'delete' in change_actions and resource['type'] in ['aws_instance', 'aws_db_instance']:
                self.risk_factors.append(f"Critical resource deletion: {resource['address']}")
            if 'update' in change_actions and 'security_group' in resource['type']:
                self.risk_factors.append(f"Security group modification: {resource['address']}")

            if 'create' in change_actions and 'delete' in change_actions:
                self.report['replaced'].append(resource_info)
            elif 'create' in change_actions:
                self.report['created'].append(resource_info)
            elif 'delete' in change_actions:
                self.report['destroyed'].append(resource_info)
            elif 'update' in change_actions:
                self.report['updated'].append(resource_info)
            else:
                self.report['no_changes'].append(resource_info)

    def get_plan_metadata(self):
        metadata = {}
        if not self.plan_data:
            return metadata

        metadata['terraform_version'] = self.plan_data.get('terraform_version', 'N/A')
        metadata['format_version'] = self.plan_data.get('format_version', 'N/A')
        metadata['planned_resources'] = len(self.plan_data.get('resource_changes', []))
        metadata['variables'] = self.plan_data.get('variables', {})
        return metadata

    def colorize(self, text, color="", bold=False, underline=False):
        if self.use_color and sys.stdout.isatty():
            formatting = color
            if bold:
                formatting += Colors.BOLD
            if underline:
                formatting += Colors.UNDERLINE
            return f"{formatting}{text}{Colors.RESET}"
        return text

    def format_change_details(self, details, indent=4):
        if not details or not details.get('after'):
            return []
        
        output = []
        before = details['before'] or {}
        after = details['after'] or {}
        unknown = details['after_unknown'] or {}

        changed_attrs = {}
        for key in set(before.keys()) | set(after.keys()):
            if key not in before:
                changed_attrs[key] = {'new': after[key]}
            elif key not in after:
                changed_attrs[key] = {'removed': before[key]}
            elif before[key] != after[key]:
                changed_attrs[key] = {'before': before[key], 'after': after[key]}

        if changed_attrs:
            output.append(self.colorize("✦ Changes:", Colors.CYAN, bold=True))
            for attr, change in changed_attrs.items():
                if 'new' in change:
                    line = f"  {self.colorize('➕', Colors.GREEN)} {attr}: {json.dumps(change['new'])}"
                    output.append(self.colorize(line, Colors.GREEN))
                elif 'removed' in change:
                    line = f"  {self.colorize('➖', Colors.RED)} {attr}: {json.dumps(change['removed'])}"
                    output.append(self.colorize(line, Colors.RED))
                else:
                    line = (f"  {self.colorize('↳', Colors.YELLOW)} {attr}: "
                           f"{json.dumps(change['before'])} → {json.dumps(change['after'])}")
                    output.append(self.colorize(line, Colors.YELLOW))

        if unknown and any(val for val in unknown.values()):
            output.append(self.colorize("✦ Unknown After Apply:", Colors.MAGENTA, bold=True))
            for key, value in unknown.items():
                if value:
                    line = f"  {self.colorize('?', Colors.MAGENTA)} {key}: <computed>"
                    output.append(self.colorize(line, Colors.MAGENTA))
        
        return [" " * indent + line for line in output]

    def generate_advanced_report(self):
        stats = {
            'resource_types': defaultdict(int),
            'providers': defaultdict(int),
            'impact_score': 0
        }

        for category in self.report:
            for resource in self.report[category]:
                stats['resource_types'][resource['type']] += 1
                stats['providers'][resource['provider']] += 1
                
                if category == 'destroyed':
                    stats['impact_score'] += 3
                elif category == 'updated':
                    stats['impact_score'] += 2
                elif category == 'created':
                    stats['impact_score'] += 1
                elif category == 'replaced':
                    stats['impact_score'] += 4

        return stats

    def generate_report(self, json_output=False):
        if not self.load_plan():
            return None

        self.analyze_changes()
        metadata = self.get_plan_metadata()
        advanced_stats = self.generate_advanced_report()

        report_output = []
        
        if not json_output:
            report_output.append(self.colorize("═" * 80, Colors.BLUE))
            report_output.append(self.colorize(
                f"Terraform Plan Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                Colors.WHITE, bold=True, underline=True
            ))
            report_output.append(self.colorize("═" * 80, Colors.BLUE))

            report_output.append("")
            report_output.append(self.colorize("✸ Plan Metadata", Colors.BLUE, bold=True))
            report_output.append(self.colorize(f"Terraform Version: {metadata['terraform_version']}", Colors.WHITE))
            report_output.append(self.colorize(f"Plan Format Version: {metadata['format_version']}", Colors.WHITE))
            report_output.append(self.colorize(f"Total Resources Planned: {metadata['planned_resources']}", Colors.WHITE))

            if metadata['variables']:
                report_output.append("")
                report_output.append(self.colorize("✸ Input Variables", Colors.BLUE, bold=True))
                for var_name, var_data in metadata['variables'].items():
                    report_output.append(self.colorize(f"  {var_name}: {var_data.get('value', 'N/A')}", Colors.WHITE))

            report_output.append("")
            report_output.append(self.colorize("✸ Changes Summary", Colors.BLUE, bold=True))
            report_output.append(self.colorize(f"Resources to be Created: {len(self.report['created'])}", Colors.GREEN))
            report_output.append(self.colorize(f"Resources to be Updated: {len(self.report['updated'])}", Colors.YELLOW))
            report_output.append(self.colorize(f"Resources to be Destroyed: {len(self.report['destroyed'])}", Colors.RED))
            report_output.append(self.colorize(f"Resources to be Replaced: {len(self.report['replaced'])}", Colors.BLUE))
            report_output.append(self.colorize(f"Resources with No Changes: {len(self.report['no_changes'])}", Colors.WHITE))

            report_output.append("")
            report_output.append(self.colorize("✸ Advanced Analysis", Colors.BLUE, bold=True))
            report_output.append(self.colorize(f"Change Impact Score: {advanced_stats['impact_score']}", 
                                            Colors.YELLOW if advanced_stats['impact_score'] > 10 else Colors.GREEN))
            report_output.append(self.colorize("Resource Type Distribution:", Colors.CYAN))
            for rtype, count in advanced_stats['resource_types'].items():
                report_output.append(self.colorize(f"  {rtype}: {count}", Colors.WHITE))
            report_output.append(self.colorize("Provider Distribution:", Colors.CYAN))
            for provider, count in advanced_stats['providers'].items():
                report_output.append(self.colorize(f"  {provider}: {count}", Colors.WHITE))

            if self.dependencies:
                report_output.append("")
                report_output.append(self.colorize("✸ Dependency Graph", Colors.BLUE, bold=True))
                for dep, affected in self.dependencies.items():
                    report_output.append(self.colorize(f"  {dep} affects:", Colors.CYAN))
                    for aff in affected:
                        report_output.append(self.colorize(f"    ↳ {aff}", Colors.WHITE))

            if self.risk_factors:
                report_output.append("")
                report_output.append(self.colorize("✸ Risk Assessment", Colors.BLUE, bold=True))
                for risk in self.risk_factors:
                    report_output.append(self.colorize(f"  ⚠ {risk}", Colors.RED))

            def print_resource_list(title, resources, color, symbol):
                if resources:
                    report_output.append("")
                    report_output.append(self.colorize(f"{symbol} {title}", color, bold=True))
                    report_output.append(self.colorize("-" * 60, color))
                    for resource in resources:
                        report_output.append(self.colorize(f"  ✷ {resource['address']} ({resource['type']})", color))
                        report_output.append(self.colorize(f"    Provider: {resource['provider']}", Colors.WHITE))
                        if resource.get('change_details'):
                            report_output.extend(self.format_change_details(resource['change_details']))
                        if resource['dependencies']:
                            report_output.append(self.colorize("    Dependencies:", Colors.CYAN))
                            for dep in resource['dependencies']:
                                report_output.append(self.colorize(f"      ↳ {dep}", Colors.WHITE))

            print_resource_list("Resources to be Created", self.report['created'], Colors.GREEN, "➕")
            print_resource_list("Resources to be Updated", self.report['updated'], Colors.YELLOW, "↳")
            print_resource_list("Resources to be Destroyed", self.report['destroyed'], Colors.RED, "➖")
            print_resource_list("Resources to be Replaced", self.report['replaced'], Colors.BLUE, "↻")
            print_resource_list("Resources with No Changes", self.report['no_changes'], Colors.WHITE, "═")

            report_output.append("")
            report_output.append(self.colorize("═" * 80, Colors.BLUE))
            print("\n".join(report_output))

        json_report = {
            'metadata': metadata,
            'summary': {
                'created': len(self.report['created']),
                'updated': len(self.report['updated']),
                'destroyed': len(self.report['destroyed']),
                'replaced': len(self.report['replaced']),
                'no_changes': len(self.report['no_changes'])
            },
            'details': self.report,
            'advanced_analysis': {
                'impact_score': advanced_stats['impact_score'],
                'resource_types': dict(advanced_stats['resource_types']),
                'providers': dict(advanced_stats['providers']),
                'dependencies': dict(self.dependencies),
                'risk_factors': self.risk_factors
            },
            'timestamp': datetime.now().isoformat()
        }

        if json_output:
            return json.dumps(json_report, indent=2)
        return None

def main():
    parser = argparse.ArgumentParser(description='Terraform Plan Analyzer')
    parser.add_argument('plan_file', help='Path to Terraform plan JSON file')
    parser.add_argument('--no-color', action='store_true', help='Disable color output')
    parser.add_argument('--json', action='store_true', help='Output report in JSON format')
    args = parser.parse_args()

    use_color = not args.no_color
    if os.environ.get('NO_COLOR') or os.environ.get('TF_PLAN_ANALYZER_NO_COLOR'):
        use_color = False

    analyzer = TerraformPlanAnalyzer(args.plan_file, use_color)
    json_report = analyzer.generate_report(json_output=args.json)

    if json_report:
        print(json_report)

if __name__ == "__main__":
    main()
