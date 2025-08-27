#!/bin/bash

# Script to generate metrics for a Java project from a GitHub repository
# Input: GitHub repository URL (e.g., https://github.com/eclipse-openj9/openj9)
# Output: CSV file with metrics for each Java class, including bug count from Git log

# Check if repository URL is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <GitHub repository URL>"
  exit 1
fi

REPO_URL="$1"
REPO_NAME=$(basename "$REPO_URL" .git)
OUTPUT_DIR="metrics_output"
CSV_FILE="$OUTPUT_DIR/${REPO_NAME}_metrics.csv"
TEMP_DIR="temp_repo"
VENV_DIR="venv"

# Ensure required tools are installed
if ! command -v git &> /dev/null; then
  echo "Git is required but not installed. Please install git."
  exit 1
fi

if ! command -v python3 &> /dev/null; then
  echo "Python3 is required but not installed. Please install python3."
  exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Set up virtual environment
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment..."
  python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"

# Install javalang if not present
if ! python3 -c "import javalang" &> /dev/null; then
  echo "Installing javalang in virtual environment..."
  pip install javalang
  if [ $? -ne 0 ]; then
    echo "Failed to install javalang."
    deactivate
    exit 1
  fi
fi

# Clone the repository
echo "Cloning repository from $REPO_URL..."
if [ -d "$TEMP_DIR" ]; then
  rm -rf "$TEMP_DIR"
fi
git clone "$REPO_URL" "$TEMP_DIR"
if [ $? -ne 0 ]; then
  echo "Failed to clone repository."
  deactivate
  exit 1
fi

# Get project version (from pom.xml, build.gradle, or fallback to 'unknown')
VERSION="unknown"
if [ -f "$TEMP_DIR/pom.xml" ]; then
  VERSION=$(grep -m1 "<version>" "$TEMP_DIR/pom.xml" | sed -E 's/.*<version>([^<]+)<\/version>.*/\1/')
elif [ -f "$TEMP_DIR/build.gradle" ]; then
  VERSION=$(grep -m1 "version =" "$TEMP_DIR/build.gradle" | sed -E "s/.*version = ['\"]([^'\"]+)['\"].*/\1/")
fi

# Create Python script for parsing and computing metrics
PYTHON_SCRIPT=$(mktemp)
cat << 'EOF' > "$PYTHON_SCRIPT"
import javalang
import sys
import os
import subprocess
from collections import defaultdict
import csv
import re

def get_cyclomatic_complexity(method):
    complexity = 1
    for _, node in method.filter(javalang.tree.IfStatement):
        complexity += 1
    for _, node in method.filter(javalang.tree.ForStatement):
        complexity += 1
    for _, node in method.filter(javalang.tree.WhileStatement):
        complexity += 1
    for _, node in method.filter(javalang.tree.DoStatement):
        complexity += 1
    for _, node in method.filter(javalang.tree.SwitchStatement):
        complexity += len([s for s in node.cases if s.statements])
    for _, node in method.filter(javalang.tree.CatchClause):
        complexity += 1
    return complexity

def get_bug_count(file_path, repo_dir):
    try:
        relative_path = os.path.relpath(file_path, repo_dir)
        result = subprocess.run(
            ['git', '-C', repo_dir, 'log', '--follow', '--', relative_path],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return 0
        bug_count = len([line for line in result.stdout.splitlines() if re.search(r'\b(fix|hotfix|bugfix|chore|refactor|test-fix)\b', line, re.IGNORECASE)])
        return bug_count
    except:
        return 0

def build_dependency_graph(repo_dir, class_metrics):
    imports = defaultdict(set)
    class_names = set()
    for file_path, metrics in class_metrics.items():
        class_names.add(metrics['class_name'])
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            tree = javalang.parse.parse(code)
            for _, imp in tree.filter(javalang.tree.Import):
                if imp.path in class_names:
                    imports[metrics['class_name']].add(imp.path)
            for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
                for method in class_node.methods:
                    for _, node in method.filter(javalang.tree.ClassCreator):
                        if node.type.name in class_names:
                            imports[metrics['class_name']].add(node.type.name)
        except:
            continue
    return imports

def get_subclasses(repo_dir, class_metrics):
    subclasses = defaultdict(list)
    for file_path, metrics in class_metrics.items():
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            tree = javalang.parse.parse(code)
            for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
                if class_node.extends:
                    parent = class_node.extends.name
                    subclasses[parent].append(metrics['class_name'])
        except:
            continue
    return subclasses

def get_inherited_methods(class_node, class_metrics, repo_dir):
    inherited_methods = set()
    if class_node.extends:
        parent_name = class_node.extends.name
        for file_path, metrics in class_metrics.items():
            if metrics['class_name'].endswith(parent_name):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                    parent_tree = javalang.parse.parse(code)
                    for _, parent_class in parent_tree.filter(javalang.tree.ClassDeclaration):
                        inherited_methods.update(m.name for m in parent_class.methods if 'public' in m.modifiers or 'protected' in m.modifiers)
                except:
                    continue
    return inherited_methods

def get_method_parameters(method):
    return [param.type.name for param in method.parameters] if method.parameters else []

def calculate_cam(methods):
    if not methods or len(methods) < 2:
        return 0
    param_sets = [frozenset(get_method_parameters(m)) for m in methods]
    shared_params = 0
    total_comparisons = 0
    for i, p1 in enumerate(param_sets):
        for p2 in param_sets[i+1:]:
            if p1 and p2:
                shared_params += len(p1 & p2)
                total_comparisons += len(p1 | p2)
    return shared_params / total_comparisons if total_comparisons > 0 else 0

def analyze_file(file_path, project_name, version, repo_dir, class_metrics):
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()
    try:
        tree = javalang.parse.parse(code)
    except:
        return None

    for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
        fully_qualified_name = f"{tree.package.name}.{class_node.name}" if tree.package else class_node.name

        metrics = {
            'project_name': project_name,
            'version': version,
            'class_name': fully_qualified_name,
            'wmc': 0,
            'rfc': 0,
            'loc': len(code.splitlines()),
            'max_cc': 0,
            'avg_cc': 0,
            'cbo': 0,
            'ca': 0,
            'ce': 0,
            'ic': 0,
            'cbm': 0,
            'lcom': 0,
            'lcom3': 0,
            'dit': 0,
            'noc': 0,
            'mfa': 0,
            'npm': 0,
            'dam': 0,
            'moa': 0,
            'cam': 0,
            'amc': 0,
            'bug': get_bug_count(file_path, repo_dir)
        }

        # Methods and complexity
        methods = class_node.methods
        metrics['wmc'] = len(methods)
        cc_values = []
        method_names = set()
        for method in methods:
            cc = get_cyclomatic_complexity(method)
            cc_values.append(cc)
            method_names.add(method.name)
            if isinstance(method, javalang.tree.MethodDeclaration):
                metrics['npm'] += 1 if method.modifiers and 'public' in method.modifiers else 0

        metrics['max_cc'] = max(cc_values) if cc_values else 0
        metrics['avg_cc'] = sum(cc_values) / len(cc_values) if cc_values else 0
        metrics['amc'] = metrics['loc'] / metrics['wmc'] if metrics['wmc'] > 0 else 0

        # Inheritance metrics
        metrics['dit'] = 1 if class_node.extends else 0
        metrics['ic'] = metrics['dit']

        # Coupling and cohesion
        fields = [f for f in class_node.fields if isinstance(f, javalang.tree.FieldDeclaration)]
        metrics['moa'] = sum(1 for f in fields if f.type and isinstance(f.type, javalang.tree.ReferenceType))
        total_fields = len(fields)
        private_fields = sum(1 for f in fields if f.modifiers and ('private' in f.modifiers or 'protected' in f.modifiers))
        metrics['dam'] = private_fields / total_fields if total_fields > 0 else 0

        # LCOM calculation
        field_usage = defaultdict(set)
        for method in methods:
            for _, node in method.filter(javalang.tree.MemberReference):
                if node.qualifier in [f.declarators[0].name for f in fields]:
                    field_usage[method.name].add(node.qualifier)
        lcom = 0
        for i, m1 in enumerate(methods):
            for m2 in methods[i+1:]:
                if not (field_usage[m1.name] & field_usage[m2.name]):
                    lcom += 1
        metrics['lcom'] = lcom
        metrics['lcom3'] = 2 * lcom / (len(methods) * (len(methods) - 1)) if len(methods) > 1 else 0

        # RFC and CBO
        called_methods = set()
        for method in methods:
            for _, node in method.filter(javalang.tree.MethodInvocation):
                called_methods.add(node.member)
        metrics['rfc'] = len(methods) + len(called_methods)
        metrics['cbo'] = len(called_methods)

        # CBM: Count intra-class method calls
        intra_class_calls = 0
        for method in methods:
            for _, node in method.filter(javalang.tree.MethodInvocation):
                if node.member in method_names:
                    intra_class_calls += 1
        metrics['cbm'] = intra_class_calls

        # CAM: Cohesion among methods
        metrics['cam'] = calculate_cam(methods)

        # MFA: Measure of functional abstraction
        inherited_methods = get_inherited_methods(class_node, class_metrics, repo_dir)
        total_methods = len(methods) + len(inherited_methods)
        metrics['mfa'] = len(inherited_methods) / total_methods if total_methods > 0 else 0

        class_metrics[file_path] = metrics
        return metrics
    return None

def main(repo_dir, project_name, version, output_csv):
    class_metrics = {}
    metrics_list = []
    for root, _, files in os.walk(repo_dir):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                metrics = analyze_file(file_path, project_name, version, repo_dir, class_metrics)
                if metrics:
                    metrics_list.append(metrics)

    # Calculate ca, ce, and noc
    imports = build_dependency_graph(repo_dir, class_metrics)
    subclasses = get_subclasses(repo_dir, class_metrics)
    for metrics in metrics_list:
        class_name = metrics['class_name']
        metrics['ca'] = sum(1 for c, deps in imports.items() if class_name in deps)
        metrics['ce'] = len(imports[class_name])
        metrics['noc'] = len(subclasses.get(class_name, []))

    # Write to CSV
    with open(output_csv, 'w', newline='') as f:
        fieldnames = ['project_name', 'version', 'class_name', 'wmc', 'rfc', 'loc', 'max_cc', 'avg_cc',
                      'cbo', 'ca', 'ce', 'ic', 'cbm', 'lcom', 'lcom3', 'dit', 'noc', 'mfa',
                      'npm', 'dam', 'moa', 'cam', 'amc', 'bug']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(metrics_list)
    return len(metrics_list)

if __name__ == '__main__':
    metrics_count = main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    print(f"Processed {metrics_count} classes")
EOF

# Create CSV header
echo "Generating metrics for $REPO_NAME..."
echo "project_name,version,class_name,wmc,rfc,loc,max_cc,avg_cc,cbo,ca,ce,ic,cbm,lcom,lcom3,dit,noc,mfa,npm,dam,moa,cam,amc,bug" > "$CSV_FILE"

# Run Python script to analyze Java files
python3 "$PYTHON_SCRIPT" "$TEMP_DIR" "$REPO_NAME" "$VERSION" "$CSV_FILE"
EXIT_CODE=$?

# Check if CSV was generated successfully and contains data
if [ $EXIT_CODE -eq 0 ] && [ -f "$CSV_FILE" ]; then
  LINE_COUNT=$(wc -l < "$CSV_FILE")
  if [ "$LINE_COUNT" -gt 1 ]; then
    echo "Metrics generated successfully. Output saved to $CSV_FILE with $(($LINE_COUNT-1)) classes."
  else
    echo "Metrics generation failed: No classes processed. Check Java files or javalang parsing errors."
    rm -rf "$TEMP_DIR"
    rm "$PYTHON_SCRIPT"
    deactivate
    exit 1
  fi
else
  echo "Failed to generate metrics. Python script exited with code $EXIT_CODE."
  rm -rf "$TEMP_DIR"
  rm "$PYTHON_SCRIPT"
  deactivate
  exit 1
fi

# Clean up
rm -rf "$TEMP_DIR"
rm "$PYTHON_SCRIPT"
deactivate

echo "Note: Metrics 'ca', 'ce', 'noc', 'mfa', 'cbm', and 'cam' are now calculated. 'ca' and 'ce' use import and instantiation analysis, 'noc' counts subclasses, 'mfa' measures inherited methods, 'cbm' counts intra-class method calls, and 'cam' measures method parameter similarity."