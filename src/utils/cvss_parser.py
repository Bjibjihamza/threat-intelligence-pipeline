#!/usr/bin/env python3
"""
CVSS Vector Parser - Extract all metrics from CVSS v2, v3.0, v3.1, v4.0 vectors
Supports parsing vectors like: AV:N/AC:L/Au:N/C:P/I:N/A:N
"""

import re
from typing import Dict, Optional


class CVSSVectorParser:
    """Parse CVSS vectors and extract individual metrics."""
    
    # CVSS v2.0 metrics (6 metrics)
    CVSS_V2_METRICS = {
        "AV": "Attack Vector",
        "AC": "Attack Complexity",
        "Au": "Authentication",
        "C": "Confidentiality",
        "I": "Integrity",
        "A": "Availability"
    }
    
    # CVSS v3.0 / v3.1 metrics (8 metrics)
    CVSS_V3_BASE_METRICS = {
        "AV": "Attack Vector",
        "AC": "Attack Complexity",
        "PR": "Privileges Required",
        "UI": "User Interaction",
        "S": "Scope",
        "C": "Confidentiality",
        "I": "Integrity",
        "A": "Availability"
    }
    
    CVSS_V3_TEMPORAL_METRICS = {
        "E": "Exploit Code Maturity",
        "RL": "Remediation Level",
        "RC": "Report Confidence"
    }
    
    CVSS_V3_ENVIRONMENTAL_METRICS = {
        "CR": "Confidentiality Requirement",
        "IR": "Integrity Requirement",
        "AR": "Availability Requirement",
        "MAV": "Modified Attack Vector",
        "MAC": "Modified Attack Complexity",
        "MPR": "Modified Privileges Required",
        "MUI": "Modified User Interaction",
        "MS": "Modified Scope",
        "MC": "Modified Confidentiality",
        "MI": "Modified Integrity",
        "MA": "Modified Availability"
    }
    
    # CVSS v4.0 metrics (all base + temporal + environmental)
    CVSS_V4_BASE_METRICS = {
        "AV": "Attack Vector",
        "AT": "Attack Complexity",  # Changed from AC in v4
        "AC": "Attack Complexity (Legacy)",
        "VC": "Vulnerable Component",  # New in v4
        "VI": "Vulnerable Component Integrity",  # New in v4
        "VA": "Vulnerable Component Availability",  # New in v4
        "SC": "Subsequent Component Impact",
        "SI": "Subsequent Component Integrity",
        "SA": "Subsequent Component Availability"
    }
    
    @staticmethod
    def parse_vector(vector: str, version: str) -> Dict[str, Optional[str]]:
        """
        Parse a CVSS vector string and extract all metrics.
        
        Args:
            vector: Vector string (e.g., 'AV:N/AC:L/Au:N/C:P/I:N/A:N')
            version: CVSS version ('v2', 'v3', 'v4')
            
        Returns:
            Dictionary mapping metric keys to values
        """
        if not vector or not isinstance(vector, str):
            return {}
        
        result = {}
        vector = vector.strip()
        
        if version == "v2":
            result = CVSSVectorParser._parse_v2(vector)
        elif version == "v3":
            result = CVSSVectorParser._parse_v3(vector)
        elif version == "v4":
            result = CVSSVectorParser._parse_v4(vector)
        
        return result
    
    @staticmethod
    def _parse_v2(vector: str) -> Dict[str, Optional[str]]:
        """Parse CVSS v2.0 vector."""
        metrics = {}
        pairs = vector.split("/")
        
        for pair in pairs:
            if ":" in pair:
                key, value = pair.split(":", 1)
                key = key.strip()
                value = value.strip()
                if key in CVSSVectorParser.CVSS_V2_METRICS:
                    metrics[f"cvss_v2_{key.lower()}"] = value
        
        # Fill missing with None
        for key in CVSSVectorParser.CVSS_V2_METRICS:
            metric_key = f"cvss_v2_{key.lower()}"
            if metric_key not in metrics:
                metrics[metric_key] = None
        
        return metrics
    
    @staticmethod
    def _parse_v3(vector: str) -> Dict[str, Optional[str]]:
        """Parse CVSS v3.0/v3.1 vector."""
        metrics = {}
        pairs = vector.split("/")
        
        for pair in pairs:
            if ":" in pair:
                key, value = pair.split(":", 1)
                key = key.strip()
                value = value.strip()
                
                # Base metrics
                if key in CVSSVectorParser.CVSS_V3_BASE_METRICS:
                    metrics[f"cvss_v3_base_{key.lower()}"] = value
                # Temporal metrics
                elif key in CVSSVectorParser.CVSS_V3_TEMPORAL_METRICS:
                    metrics[f"cvss_v3_temp_{key.lower()}"] = value
                # Environmental metrics
                elif key in CVSSVectorParser.CVSS_V3_ENVIRONMENTAL_METRICS:
                    metrics[f"cvss_v3_env_{key.lower()}"] = value
        
        # Fill missing base metrics with None
        for key in CVSSVectorParser.CVSS_V3_BASE_METRICS:
            metric_key = f"cvss_v3_base_{key.lower()}"
            if metric_key not in metrics:
                metrics[metric_key] = None
        
        return metrics
    
    @staticmethod
    def _parse_v4(vector: str) -> Dict[str, Optional[str]]:
        """Parse CVSS v4.0 vector."""
        metrics = {}
        pairs = vector.split("/")
        
        for pair in pairs:
            if ":" in pair:
                key, value = pair.split(":", 1)
                key = key.strip()
                value = value.strip()
                metrics[f"cvss_v4_{key.lower()}"] = value
        
        return metrics
    
    @staticmethod
    def get_all_column_names(version: str) -> list:
        """Get all possible column names for a CVSS version."""
        if version == "v2":
            return [f"cvss_v2_{k.lower()}" for k in CVSSVectorParser.CVSS_V2_METRICS.keys()]
        elif version == "v3":
            base = [f"cvss_v3_base_{k.lower()}" for k in CVSSVectorParser.CVSS_V3_BASE_METRICS.keys()]
            temp = [f"cvss_v3_temp_{k.lower()}" for k in CVSSVectorParser.CVSS_V3_TEMPORAL_METRICS.keys()]
            env = [f"cvss_v3_env_{k.lower()}" for k in CVSSVectorParser.CVSS_V3_ENVIRONMENTAL_METRICS.keys()]
            return base + temp + env
        elif version == "v4":
            return [f"cvss_v4_{k.lower()}" for k in CVSSVectorParser.CVSS_V4_BASE_METRICS.keys()]
        return []


# Example usage
if __name__ == "__main__":
    # Test v2
    v2_vector = "AV:N/AC:L/Au:N/C:P/I:N/A:N"
    print("CVSS v2.0 Vector:", v2_vector)
    v2_parsed = CVSSVectorParser.parse_vector(v2_vector, "v2")
    for k, v in v2_parsed.items():
        print(f"  {k}: {v}")
    
    # Test v3
    v3_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    print("\nCVSS v3.1 Vector:", v3_vector)
    v3_parsed = CVSSVectorParser.parse_vector(v3_vector, "v3")
    for k, v in sorted(v3_parsed.items()):
        print(f"  {k}: {v}")
    
    # Test v4
    v4_vector = "AV:N/AT:L/AC:L/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    print("\nCVSS v4.0 Vector:", v4_vector)
    v4_parsed = CVSSVectorParser.parse_vector(v4_vector, "v4")
    for k, v in v4_parsed.items():
        print(f"  {k}: {v}")