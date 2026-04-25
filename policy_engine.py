class PolicyEngine:
    def evaluate(self, risk_score):
        if risk_score < 30:
            return "Allow", "#2e7d32"
        elif risk_score <= 60:
            return "Require MFA", "#f57c00"
        else:
            return "Block", "#c62828"