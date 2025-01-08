"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2024-11-07
"""
"""
Check: ECR Repository Latest Image Vulnerability Scan
Description: Detects vulnerabilities in latest images of ECR repositories
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class ecr_repository_scan_vulnerabilities_in_latest_image(Check):
    def __init__(self, metadata=None):
        """Initialize check with severity threshold configuration"""
        super().__init__(metadata)
        self.severity_levels = {
            "CRITICAL": 3,
            "HIGH": 2,
            "MEDIUM": 1,
            "LOW": 0
        }
        self.severity_threshold = "MEDIUM"

    def evaluate_vulnerabilities(self, findings: dict) -> tuple:
        """
        Evaluate scan findings against severity threshold
        Args:
            findings: Vulnerability scan results
        Returns:
            tuple: (is_compliant, formatted_message)
        """
        if not findings:
            return True, "No vulnerabilities found"

        counts = findings.get('findingSeverityCounts', {})
        if not counts:
            return True, "No vulnerabilities found"

        # Check for critical vulnerabilities first
        if counts.get('CRITICAL', 0) > 0:
            return False, "Vulnerabilities detected"
        
        # Check for any other vulnerabilities
        if sum(counts.values()) > 0:
            return False, "Vulnerabilities detected"

        return True, "No vulnerabilities found"

    def get_latest_image_scan(self, ecr, repo_name: str) -> tuple:
        """
        Get scan results for latest image in repository
        Args:
            ecr: ECR client
            repo_name: Repository name
        Returns:
            tuple: (success, status_message, scan_findings)
        """
        try:
            images = ecr.list_images(
                repositoryName=repo_name,
                filter={'tagStatus': 'TAGGED'},
                maxResults=100
            ).get('imageIds', [])

            if not images:
                return False, "No images found", None

            latest_image = ecr.describe_images(
                repositoryName=repo_name,
                imageIds=[images[0]]
            ).get('imageDetails', [])[0]
            
            scan_result = ecr.describe_image_scan_findings(
                repositoryName=repo_name,
                imageId={'imageDigest': latest_image['imageDigest']}
            )
            
            scan_status = scan_result.get('imageScanStatus', {}).get('status')
            if scan_status != 'COMPLETE':
                return False, f"Scan status: {scan_status}", None

            return True, "Scan complete", scan_result.get('imageScanFindings', {})

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ScanNotFoundException':
                return False, "Scan not found", None
            return False, f"Error: {error_code}", None

    def execute(self, connection: boto3.Session) -> CheckReport:
        """Execute the vulnerability scan check"""
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            ecr = connection.client('ecr')
            repositories = ecr.describe_repositories().get('repositories', [])
            
            if not repositories:
                report.resource_ids_status["No ECR repositories found"] = True
                return report

            for repo in repositories:
                repo_name = repo['repositoryName']
                success, status, findings = self.get_latest_image_scan(ecr, repo_name)
                
                if not success:
                    report.resource_ids_status[f"{repo_name} : {status}"] = False
                    report.passed = False
                    continue

                is_compliant, message = self.evaluate_vulnerabilities(findings)
                report.resource_ids_status[f"{repo_name} : {message}"] = is_compliant
                if not is_compliant:
                    report.passed = False

        except ClientError as e:
            report.passed = False
            report.resource_ids_status[f"AWS Error: {e.response['Error']['Code']}"] = False
        except Exception as e:
            report.passed = False
            report.resource_ids_status[f"Unexpected Error: {str(e)}"] = False

        return report
