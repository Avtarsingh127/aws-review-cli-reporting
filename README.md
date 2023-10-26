# AWS Report Tool

## Description

The AWS VPC Report Tool is a command-line utility designed to generate comprehensive reports on various AWS resources. The tool provides detailed insights into your AWS environment, facilitating better resource management, analysis, and troubleshooting. One of the main feature of this project is that you can get all the resources attached to the VPC with a single command.

## Features

- **Multiple AWS Services**: Fetches information from a variety of AWS services including EC2, VPC, RDS, Lambda, ELB, EKS, and more.
- **Flexible Output**: Supports different output formats (table, CSV) and levels of detail (short, medium, extended).
- **VPC Specific**: Capability to filter and generate reports based on specific VPCs.
- **Region Support**: Works across different AWS regions, defaulting to the AWS CLI configured region if not specified.

## Getting Started

### Prerequisites

- Python 3.x
- Boto3 (AWS SDK for Python)
- PrettyTable (for table-formatted output)

### Installation

```bash
# Clone the repository to your local machine
git clone https://github.com/yourusername/aws-vpc-report-tool.git

# Navigate to the project directory
cd aws-vpc-report-tool

# Install the required Python packages
pip install -r requirements.txt
```
## Usage

The tool supports a variety of command-line arguments to tailor the output to your specific needs:

- `--service`: (Required) Specifies the AWS service to generate a report for (options: `ec2`, `vpc`).
- `--region`: AWS region to query (defaults to AWS CLI configured region).
- `--output`: Determines the level of detail in the report (options: `s`, `s2`, `s3`).
- `--type`: Type of report when service is VPC (options include resource types like `ec2`, `sub`, `rds`, `elb`, `lambda`, etc. and `all` for all resource types).
- `--stopped`: (Flag) If set, shows only stopped EC2 instances.
- `--vpcid`: VPC ID to filter instances or show subnets.
- `--output_file`: File path to save the output. If not provided, output will be shown on the screen.
- `--format`: Output format (options: `table`, `csv`).

### Examples

```bash
# Generate a complete VPC report for a specific VPC and display it in the terminal
python3 showme.py --service vpc --type all --vpcid vpc-xxxx

# Generate a complete VPC report for a specific VPC in CSV format
python3 showme.py --service vpc --type all --vpcid vpc-xxxx --format csv

# Generate an EC2 report for a specific VPC in CSV format
python3 showme.py --service vpc --type ec2 --vpcid vpc-xxxx --format csv

# Save a complete VPC report for a specific VPC in CSV format to a file
python3 showme.py --service vpc --type all --vpcid vpc-xxxx --format csv --output_file /tmp/vpc_info_a1.csv

# Generate a client VPN endpoints report with short output
python3 showme.py --service vpc --type cvpn --output s
```
## Notes

1. **Initial Stage**: Please note that this project is currently in its initial development stages. As such, users may encounter bugs or features that are not fully implemented. Your understanding and patience are greatly appreciated.

2. **AWS CLI Configuration**: Ensure that your AWS CLI is properly configured with the necessary credentials and a default region to ensure seamless execution of the tool.

3. **Feedback and Reporting Issues**: Your feedback is invaluable to us. If you encounter any issues or have suggestions for improvements, please feel free to open an issue in the project's GitHub repository.

4. **Compatibility and Dependencies**: This tool is designed to work with Python 3 and makes use of the Boto3 library to interact with AWS services. Ensure that all dependencies are installed and up to date.

## Contributing

Contributions to improve the tool or fix issues are highly encouraged and welcomed. If you are interested in contributing, please follow these steps:

1. **Fork the Repository**: Click on the 'Fork' button at the top right corner of the [GitHub repository](https://github.com/your-repository-url). This will create a copy of the repository in your GitHub account.

2. **Clone Your Forked Repository**: Clone the forked repository to your local machine using the following command:
   ```bash
   git clone https://github.com/your-username/aws-vpc-report-tool.git

