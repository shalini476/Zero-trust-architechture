import csv
import random
import os

def generate_data(filepath, num_records=1200):
    """
    Generates synthetic security and behavior data for training the Zero Trust ML engine.
    Features:
    - login_hour (0-23)
    - failed_attempts_24h (0-10)
    - is_new_device (0 or 1)
    - is_unusual_time (0 or 1)
    - trust_score (0-100)
    - resource_access_frequency (0-30) (number of file accesses in session)
    - honeypot_accessed (0 or 1)
    - label (0: normal, 1: suspicious, 2: high_risk)
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    headers = [
        'login_hour', 
        'failed_attempts_24h', 
        'is_new_device', 
        'is_unusual_time', 
        'trust_score', 
        'resource_access_frequency', 
        'honeypot_accessed', 
        'label'
    ]
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for _ in range(num_records):
            # Roll for category to create realistic correlations
            roll = random.random()
            
            if roll < 0.65: # 65% Normal behavior
                login_hour = random.choice(list(range(8, 21))) # Working hours 8 AM - 8 PM
                failed_attempts = random.choice([0, 0, 0, 0, 1])
                is_new_device = 0
                is_unusual_time = 0
                trust_score = random.randint(85, 100)
                resource_access_frequency = random.randint(1, 5)
                honeypot_accessed = 0
                label = 0 # Normal
                
            elif roll < 0.88: # 23% Suspicious behavior
                # Unusual login hours or failed attempts
                login_hour = random.choice(list(range(0, 8)) + list(range(21, 24)))
                is_unusual_time = 1 if (login_hour < 8 or login_hour > 20) else 0
                failed_attempts = random.randint(1, 4)
                is_new_device = random.choice([0, 1, 1])
                trust_score = random.randint(50, 84)
                resource_access_frequency = random.randint(5, 12)
                honeypot_accessed = 0
                label = 1 # Suspicious
                
            else: # 12% High Risk / Threat behavior
                login_hour = random.randint(0, 23)
                is_unusual_time = 1 if (login_hour < 8 or login_hour > 20) else random.choice([0, 1])
                failed_attempts = random.randint(3, 10)
                is_new_device = random.choice([0, 1])
                trust_score = random.randint(10, 49)
                resource_access_frequency = random.randint(10, 30)
                honeypot_accessed = random.choice([0, 0, 1, 1]) # high probability of honeypot access
                
                # Force very low trust score if honeypot accessed
                if honeypot_accessed:
                    trust_score = max(0, trust_score - 40)
                    
                label = 2 # High Risk
                
            writer.writerow([
                login_hour, 
                failed_attempts, 
                is_new_device, 
                is_unusual_time, 
                trust_score, 
                resource_access_frequency, 
                honeypot_accessed, 
                label
            ])
            
    print(f"[DATA GENERATOR] Generated {num_records} synthetic records and saved to {filepath}")

if __name__ == '__main__':
    generate_data('C:/Users/shali/OneDrive/Dokumen/zero threat/data/sample_dataset.csv')
