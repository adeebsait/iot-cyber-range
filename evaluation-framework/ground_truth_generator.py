import json
import time
import random
import threading
from datetime import datetime, timedelta
from kafka import KafkaProducer
from dataclasses import dataclass
from typing import List, Dict, Optional
import uuid


@dataclass
class GroundTruthEvent:
    event_id: str
    timestamp: datetime
    event_type: str  # 'attack', 'normal', 'anomaly'
    attack_category: str  # 'dos', 'malformed', 'device_compromise', 'reconnaissance'
    severity: str  # 'high', 'medium', 'low'
    affected_devices: List[str]
    attack_duration: float
    attack_intensity: str
    expected_detections: int
    description: str


class GroundTruthGenerator:
    def __init__(self):
        self.producer = KafkaProducer(
            bootstrap_servers=['kafka:9092'],
            value_serializer=lambda x: json.dumps(x, default=str).encode('utf-8')
        )
        self.ground_truth_events = []
        self.attack_scenarios = self._define_attack_scenarios()

    def _define_attack_scenarios(self):
        return [
            {
                'type': 'dos_attack',
                'category': 'dos',
                'duration_range': (30, 300),
                'intensity_levels': ['low', 'medium', 'high'],
                'expected_detection_rate': 0.95,
                'device_targets': ['patient_monitor', 'network_gateway']
            },
            {
                'type': 'malformed_packets',
                'category': 'malformed',
                'duration_range': (15, 120),
                'intensity_levels': ['low', 'medium', 'high'],
                'expected_detection_rate': 0.87,
                'device_targets': ['network_infrastructure']
            },
            {
                'type': 'device_anomaly',
                'category': 'device_compromise',
                'duration_range': (60, 600),
                'intensity_levels': ['medium', 'high'],
                'expected_detection_rate': 0.92,
                'device_targets': ['patient_monitor', 'infusion_pump']
            },
            {
                'type': 'reconnaissance',
                'category': 'reconnaissance',
                'duration_range': (120, 900),
                'intensity_levels': ['low', 'medium'],
                'expected_detection_rate': 0.78,
                'device_targets': ['network_infrastructure']
            },
            {
                'type': 'multi_vector',
                'category': 'multi_vector',
                'duration_range': (300, 1800),
                'intensity_levels': ['high'],
                'expected_detection_rate': 0.89,
                'device_targets': ['patient_monitor', 'network_infrastructure', 'infusion_pump']
            }
        ]

    def generate_controlled_attack_sequence(self, total_duration_minutes=60, attack_frequency=5):
        """Generate a controlled sequence of attacks with known ground truth"""
        sequence_start = datetime.now()
        sequence_end = sequence_start + timedelta(minutes=total_duration_minutes)

        attack_schedule = []
        current_time = sequence_start

        while current_time < sequence_end:
            # Schedule normal periods and attack periods
            normal_duration = random.randint(3, 8)  # 3-8 minutes normal
            attack_duration = random.randint(1, 3)  # 1-3 minutes attack

            # Normal period
            normal_event = GroundTruthEvent(
                event_id=str(uuid.uuid4()),
                timestamp=current_time,
                event_type='normal',
                attack_category='none',
                severity='normal',
                affected_devices=[],
                attack_duration=normal_duration * 60,
                attack_intensity='none',
                expected_detections=0,
                description=f"Normal operation period - {normal_duration} minutes"
            )
            attack_schedule.append(normal_event)
            current_time += timedelta(minutes=normal_duration)

            # Attack period
            if current_time < sequence_end:
                scenario = random.choice(self.attack_scenarios)
                attack_event = self._create_attack_event(scenario, current_time, attack_duration)
                attack_schedule.append(attack_event)
                current_time += timedelta(minutes=attack_duration)

        return attack_schedule

    def _create_attack_event(self, scenario, start_time, duration_minutes):
        """Create a specific attack event with detailed parameters"""
        return GroundTruthEvent(
            event_id=str(uuid.uuid4()),
            timestamp=start_time,
            event_type='attack',
            attack_category=scenario['category'],
            severity=random.choice(['medium', 'high']),
            affected_devices=random.sample(scenario['device_targets'],
                                           min(2, len(scenario['device_targets']))),
            attack_duration=duration_minutes * 60,
            attack_intensity=random.choice(scenario['intensity_levels']),
            expected_detections=int(duration_minutes * scenario['expected_detection_rate']),
            description=f"{scenario['type']} attack - {duration_minutes}min duration"
        )

    def execute_attack_sequence(self, attack_schedule):
        """Execute the planned attack sequence and log ground truth"""
        for event in attack_schedule:
            self.ground_truth_events.append(event)

            # Publish ground truth event
            ground_truth_data = {
                'event_id': event.event_id,
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'attack_category': event.attack_category,
                'severity': event.severity,
                'affected_devices': event.affected_devices,
                'attack_duration': event.attack_duration,
                'attack_intensity': event.attack_intensity,
                'expected_detections': event.expected_detections,
                'description': event.description
            }

            self.producer.send('ground-truth', ground_truth_data)
            print(f"🎯 Ground Truth Event: {event.event_type} - {event.description}")

            if event.event_type == 'attack':
                self._simulate_attack(event)
            else:
                time.sleep(min(event.attack_duration, 60))  # Wait for normal period

    def _simulate_attack(self, event):
        """Simulate the actual attack based on the event type"""
        print(f"🚨 Executing {event.attack_category} attack for {event.attack_duration}s")

        if event.attack_category == 'dos':
            self._simulate_dos_attack(event)
        elif event.attack_category == 'device_compromise':
            self._simulate_device_anomaly(event)
        elif event.attack_category == 'malformed':
            self._simulate_malformed_packets(event)
        elif event.attack_category == 'reconnaissance':
            self._simulate_reconnaissance(event)
        elif event.attack_category == 'multi_vector':
            self._simulate_multi_vector_attack(event)

    def _simulate_dos_attack(self, event):
        """Simulate DoS attack by generating high network traffic"""
        # This would integrate with your existing attack simulators
        # For now, we'll simulate by injecting anomalous network patterns
        attack_data = {
            'attack_type': 'dos_flood',
            'intensity': event.attack_intensity,
            'duration': event.attack_duration,
            'target_devices': event.affected_devices,
            'timestamp': datetime.now().isoformat()
        }
        self.producer.send('simulated-attacks', attack_data)
        time.sleep(event.attack_duration)

    def _simulate_device_anomaly(self, event):
        """Simulate device compromise by injecting anomalous telemetry"""
        anomaly_data = {
            'device_id': random.choice(event.affected_devices),
            'anomaly_type': 'vital_signs_manipulation',
            'intensity': event.attack_intensity,
            'duration': event.attack_duration,
            'timestamp': datetime.now().isoformat()
        }
        self.producer.send('simulated-anomalies', anomaly_data)
        time.sleep(event.attack_duration)
