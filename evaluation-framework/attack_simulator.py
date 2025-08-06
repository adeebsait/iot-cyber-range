import os
import json
import time
import random
import logging
import threading
import subprocess
from datetime import datetime
from kafka import KafkaProducer
from collections import deque

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttackSimulator:
    """Controlled attack simulation for evaluation"""

    def __init__(self):
        self.kafka_bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

        # Ground truth tracking
        self.producer = KafkaProducer(
            bootstrap_servers=[self.kafka_bootstrap_servers],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )

        # Attack scenarios
        self.attack_scenarios = [
            {'type': 'dos_flood', 'intensity': 'low', 'duration': 30},
            {'type': 'dos_flood', 'intensity': 'medium', 'duration': 45},
            {'type': 'dos_flood', 'intensity': 'high', 'duration': 60},
            {'type': 'malformed_packets', 'intensity': 'low', 'duration': 20},
            {'type': 'malformed_packets', 'intensity': 'medium', 'duration': 30},
            {'type': 'device_anomaly', 'intensity': 'low', 'duration': 120},
            {'type': 'device_anomaly', 'intensity': 'high', 'duration': 180},
            {'type': 'combined_attack', 'intensity': 'high', 'duration': 300}
        ]

        # Simulation state
        self.current_attack = None
        self.attack_log = deque(maxlen=100)

        logger.info("Attack Simulator initialized")

    def start_evaluation(self):
        """Start comprehensive evaluation"""
        logger.info("🎯 Starting Controlled Attack Simulation for Evaluation...")

        # Background normal operation
        normal_thread = threading.Thread(target=self._simulate_normal_operation)
        normal_thread.daemon = True
        normal_thread.start()

        # Run attack scenarios
        self._run_evaluation_scenarios()

    def _simulate_normal_operation(self):
        """Simulate normal IoT operation"""
        while True:
            try:
                # Inject normal device behavior variations
                time.sleep(300)  # Every 5 minutes
                self._inject_normal_variations()

            except Exception as e:
                logger.error(f"Normal simulation error: {e}")
                time.sleep(60)

    def _inject_normal_variations(self):
        """Inject normal but slightly unusual patterns"""
        variations = [
            'slight_vitals_increase',
            'network_congestion',
            'device_restart_pattern',
            'maintenance_window'
        ]

        variation = random.choice(variations)

        ground_truth = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'normal_variation',
            'variation_type': variation,
            'is_attack': False,
            'expected_detection': False,
            'description': f"Normal variation: {variation}"
        }

        self.producer.send('ground-truth', ground_truth)
        logger.info(f"📊 Normal variation injected: {variation}")

    def _run_evaluation_scenarios(self):
        """Run structured evaluation scenarios"""
        logger.info("Starting evaluation scenarios...")

        for i, scenario in enumerate(self.attack_scenarios):
            logger.info(f"🚨 Running scenario {i + 1}/{len(self.attack_scenarios)}: {scenario}")

            # Record ground truth
            attack_id = f"attack_{i + 1}_{int(time.time())}"
            ground_truth = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'attack_start',
                'attack_id': attack_id,
                'attack_type': scenario['type'],
                'intensity': scenario['intensity'],
                'duration': scenario['duration'],
                'is_attack': True,
                'expected_detection': True
            }

            self.producer.send('ground-truth', ground_truth)
            self.attack_log.append(ground_truth)

            # Execute attack
            self._execute_attack(scenario, attack_id)

            # Record attack end
            end_truth = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'attack_end',
                'attack_id': attack_id,
                'attack_type': scenario['type']
            }

            self.producer.send('ground-truth', end_truth)

            # Recovery period
            logger.info(f"⏳ Recovery period: 60 seconds...")
            time.sleep(60)

        logger.info("🏁 All evaluation scenarios completed!")

    def _execute_attack(self, scenario, attack_id):
        """Execute specific attack scenario"""
        attack_type = scenario['type']
        intensity = scenario['intensity']
        duration = scenario['duration']

        logger.info(f"Executing {attack_type} attack (intensity: {intensity}, duration: {duration}s)")

        if attack_type == 'dos_flood':
            self._execute_dos_attack(intensity, duration, attack_id)
        elif attack_type == 'malformed_packets':
            self._execute_malformed_attack(intensity, duration, attack_id)
        elif attack_type == 'device_anomaly':
            self._execute_device_anomaly(intensity, duration, attack_id)
        elif attack_type == 'combined_attack':
            self._execute_combined_attack(intensity, duration, attack_id)

    def _execute_dos_attack(self, intensity, duration, attack_id):
        """Execute DoS flood attack"""
        intensity_map = {'low': 5, 'medium': 15, 'high': 30}
        connections = intensity_map.get(intensity, 10)

        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                # Use docker-compose to run threat emulator
                cmd = [
                    "docker-compose", "run", "--rm", "threat-emulator",
                    "python", "dos_attack.py", str(connections)
                ]
                subprocess.run(cmd, check=True, capture_output=True, timeout=30)
                time.sleep(5)

            except Exception as e:
                logger.error(f"DoS attack execution error: {e}")
                time.sleep(1)

    def _execute_malformed_attack(self, intensity, duration, attack_id):
        """Execute malformed packet attack"""
        intensity_map = {'low': 3, 'medium': 8, 'high': 15}
        packets = intensity_map.get(intensity, 5)

        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                cmd = [
                    "docker-compose", "run", "--rm", "threat-emulator",
                    "python", "malformed_attack.py", str(packets)
                ]
                subprocess.run(cmd, check=True, capture_output=True, timeout=20)
                time.sleep(3)

            except Exception as e:
                logger.error(f"Malformed attack execution error: {e}")
                time.sleep(1)

    def _execute_device_anomaly(self, intensity, duration, attack_id):
        """Simulate device anomaly by injecting abnormal vitals"""
        anomaly_vitals = {
            'timestamp': datetime.now().isoformat(),
            'attack_id': attack_id,
            'anomaly_type': 'device_vitals',
            'intensity': intensity,
            'anomalies': []
        }

        # Define anomaly patterns based on intensity
        if intensity == 'low':
            anomalies = [
                {'heart_rate': random.randint(110, 130)},  # Slightly elevated
                {'spo2': random.uniform(88, 92)}  # Slightly low oxygen
            ]
        else:  # high intensity
            anomalies = [
                {'heart_rate': random.randint(150, 200)},  # Very high heart rate
                {'spo2': random.uniform(75, 85)},  # Dangerously low oxygen
                {'body_temp': random.uniform(39, 41)}  # High fever
            ]

        anomaly_vitals['anomalies'] = anomalies

        # Send anomaly indicators to metrics system
        self.producer.send('simulated-anomalies', anomaly_vitals)

        logger.info(f"Device anomaly injected: {intensity} intensity for {duration}s")
        time.sleep(duration)

    def _execute_combined_attack(self, intensity, duration, attack_id):
        """Execute combined multi-vector attack"""
        logger.info("Executing combined multi-vector attack...")

        # Phase 1: Network reconnaissance (malformed packets)
        self._execute_malformed_attack('low', duration // 4, f"{attack_id}_phase1")

        # Phase 2: DoS attack
        self._execute_dos_attack(intensity, duration // 2, f"{attack_id}_phase2")

        # Phase 3: Device compromise simulation
        self._execute_device_anomaly('high', duration // 4, f"{attack_id}_phase3")


if __name__ == "__main__":
    simulator = AttackSimulator()
    simulator.start_evaluation()
