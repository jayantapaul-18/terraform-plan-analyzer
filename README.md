## Terraform Plan Analyzer

Terraform Plan Analyzer . Python script that analyzes a Terraform plan JSON file and generates a detailed report of changes, including resources to be created, modified, destroyed, and other useful information.

### Generate a Terraform plan in JSON format using:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > terraform_plan.json
```

## Basic usage with colors
```bash
python3 tf_plan_analyzer.py terraform_plan.json
```
## Disable colors
```bash
python3 tf_plan_analyzer.py terraform_plan.json --no-color
```
## JSON output
```bash
python3 tf_plan_analyzer.py terraform_plan.json --json
```
## Using environment variable
```bash
export NO_COLOR=1
python3 tf_plan_analyzer.py terraform_plan.json
```

## Beautified Report Structure:
- Header with bold, underlined title in white
- Blue section headers with star symbol (✸)
- Resource listings with bullet symbol (✷)
- Change details with specific symbols:
- ➕ Green for new attributes
- ➖ Red for removed attributes
- ↳ Yellow for modified attributes
- ? Magenta for unknown values

## Sample Output (visualized with color descriptions):

<img width="885" alt="tf-report" src="https://github.com/user-attachments/assets/ce0924a8-212d-47a4-9ab2-73414c92f28e" />

=> Enhance the Terraform Plan Analyzer with advanced reporting features. Here are some sophisticated additions we can implement:

- `Change Impact Analysis`: Assess the potential impact of changes
- `Dependency Graph`: Show resource dependencies
- `Cost Estimation`: Basic cost impact analysis (if cost-related data is available)
- `Risk Assessment`: Flag potentially risky changes
- `Summary Statistics`: Detailed metrics about the plan
  
