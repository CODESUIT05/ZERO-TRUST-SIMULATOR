class RiskEngine:
    def calculate_score(self, device_trust, behavior_score, request_freq, resource_sensitivity):
        device_risk = (1.0 - device_trust) * 30
        behavior_risk = behavior_score * 25
        frequency_risk = request_freq * 20
        sensitivity_risk = resource_sensitivity * 25
        return max(0, min(100, int(device_risk + behavior_risk + frequency_risk + sensitivity_risk)))