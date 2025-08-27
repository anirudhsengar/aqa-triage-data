# Semantic data collected (Running the Metrics Script)

To generate a dataset of software metrics for a Java project using the provided script, follow these steps:

---

## Prerequisites:

- Ensure git and Python 3 are installed on your system.
- The script requires the javalang Python library, which will be installed automatically in a virtual environment.

## Steps:

1. Run the script with a GitHub repository URL as an argument:
   ```bash
   bash extract_semantic_dataset.sh https://github.com/eclipse-openj9/openj9
   ```

The script will:
- Clone the repository.
- Set up a Python virtual environment and install javalang.
- Analyze all `.java` files to compute metrics (e.g., WMC, RFC, LOC, CBO, CA, CE, etc.).
- Generate a CSV file in the `metrics_output` directory named `<repository_name>_metrics.csv`.

## Output:

- The CSV file contains metrics for each Java class, including complexity, coupling, cohesion, inheritance, and bug counts derived from Git commit messages.
- Check the console output for success or error messages.
