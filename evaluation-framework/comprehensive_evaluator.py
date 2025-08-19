import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, deque
from kafka import KafkaConsumer, KafkaProducer
import threading
import time
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, roc_curve
from scipy import stats
import matplotlib

matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Optional
import sqlite3
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ComprehensivePerformanceEvaluator:
    def __init__(self):
        # Database for storing evaluation results
        self.db_path = "/app/evaluation_comprehensive.db"
        self.init_evaluation_database()

        # Data collections
        self.ground_truth_events = []
        self.detection_events = {
            'multi_agent': [],
            'suricata_only': [],
            'lstm_only': [],
            'isolation_forest_only': [],
            'centralised_ai': []
        }
        self.performance_metrics = defaultdict(list)
        self.resource_metrics = defaultdict(list)

        # Kafka consumers for comprehensive data collection
        self.setup_kafka_consumers()

        # Evaluation parameters
        self.evaluation_window = 300  # 5 minutes correlation window
        self.confidence_level = 0.95

        # Control flags
        self.running = False

    def init_evaluation_database(self):
        """Initialize comprehensive evaluation database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Ground truth table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ground_truth (
            event_id TEXT PRIMARY KEY,
            timestamp DATETIME,
            event_type TEXT,
            attack_category TEXT,
            severity TEXT,
            duration REAL,
            expected_detections INTEGER
        )
        ''')

        # Detection events table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS detection_events (
            detection_id TEXT PRIMARY KEY,
            detector_type TEXT,
            timestamp DATETIME,
            confidence REAL,
            severity TEXT,
            ground_truth_id TEXT,
            correlation_status TEXT,
            detection_latency REAL
        )
        ''')

        # Performance metrics table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS performance_metrics (
            metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
            detector_type TEXT,
            metric_name TEXT,
            metric_value REAL,
            timestamp DATETIME,
            evaluation_run TEXT
        )
        ''')

        # Confusion matrix table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS confusion_matrix (
            detector_type TEXT,
            true_positives INTEGER,
            false_positives INTEGER,
            true_negatives INTEGER,
            false_negatives INTEGER,
            evaluation_run TEXT,
            PRIMARY KEY (detector_type, evaluation_run)
        )
        ''')

        conn.commit()
        conn.close()
        logger.info("✅ Evaluation database initialized")

    def setup_kafka_consumers(self):
        """Setup Kafka consumers for all detection streams"""
        try:
            self.consumers = {
                'ground_truth': KafkaConsumer(
                    'ground-truth',
                    bootstrap_servers=['kafka:9092'],
                    group_id='evaluator-ground-truth',
                    auto_offset_reset='earliest',
                    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
                ),
                'ai_alerts': KafkaConsumer(
                    'ai-alerts',
                    bootstrap_servers=['kafka:9092'],
                    group_id='evaluator-ai-alerts',
                    auto_offset_reset='earliest',
                    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
                ),
                'baseline_alerts': KafkaConsumer(
                    'baseline-alerts',
                    bootstrap_servers=['kafka:9092'],
                    group_id='evaluator-baseline-alerts',
                    auto_offset_reset='earliest',
                    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
                ),
                'security_alerts': KafkaConsumer(
                    'security-alerts',
                    bootstrap_servers=['kafka:9092'],
                    group_id='evaluator-security-alerts',
                    auto_offset_reset='latest',
                    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
                )
            }
            logger.info("✅ Kafka consumers initialized")
        except Exception as e:
            logger.error(f"❌ Failed to setup Kafka consumers: {e}")

    def start_comprehensive_evaluation(self, evaluation_duration_hours=2):
        """Start comprehensive evaluation with full metrics collection"""
        logger.info(f"🔬 Starting comprehensive evaluation for {evaluation_duration_hours} hours")

        evaluation_run_id = f"eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.running = True

        # Start data collection threads
        threads = []
        for consumer_name, consumer in self.consumers.items():
            thread = threading.Thread(
                target=self._consume_data,
                args=(consumer_name, consumer, evaluation_run_id),
                daemon=True
            )
            thread.start()
            threads.append(thread)

        # Start performance monitoring
        perf_thread = threading.Thread(
            target=self._monitor_system_performance,
            args=(evaluation_run_id,),
            daemon=True
        )
        perf_thread.start()
        threads.append(perf_thread)

        # Run evaluation for specified duration
        start_time = time.time()
        end_time = start_time + (evaluation_duration_hours * 3600)

        logger.info(f"📊 Evaluation will run until {datetime.fromtimestamp(end_time).strftime('%H:%M:%S')}")

        try:
            while time.time() < end_time and self.running:
                self._periodic_analysis(evaluation_run_id)
                time.sleep(60)  # Analyze every minute
        except KeyboardInterrupt:
            logger.info("⏹️ Evaluation stopped by user")
            self.running = False

        logger.info("✅ Evaluation completed. Generating final comprehensive report...")
        return self.generate_comprehensive_report(evaluation_run_id)

    def _periodic_analysis(self, evaluation_run_id):
        """Perform periodic analysis during evaluation"""
        try:
            # Get current system status
            conn = sqlite3.connect(self.db_path)

            # Count detection events so far - FIXED pandas indexing
            detection_count_query = "SELECT COUNT(*) as count FROM detection_events"
            detection_result = pd.read_sql_query(detection_count_query, conn)
            detection_count = detection_result.iloc[0]['count'] if not detection_result.empty else 0

            # Count ground truth events - FIXED pandas indexing
            ground_truth_count_query = "SELECT COUNT(*) as count FROM ground_truth"
            ground_truth_result = pd.read_sql_query(ground_truth_count_query, conn)
            ground_truth_count = ground_truth_result.iloc[0]['count'] if not ground_truth_result.empty else 0

            conn.close()

            # Log periodic status
            current_time = datetime.now()
            logger.info(f"📊 Periodic Analysis [{current_time.strftime('%H:%M:%S')}]:")
            logger.info(f"   - Detection Events: {detection_count}")
            logger.info(f"   - Ground Truth Events: {ground_truth_count}")
            logger.info(f"   - Evaluation Run: {evaluation_run_id}")

            # Log to file for tracking
            with open(f'/app/evaluation_progress_{evaluation_run_id}.log', 'a') as f:
                f.write(f"{current_time.isoformat()},{detection_count},{ground_truth_count}\n")

        except Exception as e:
            logger.warning(f"⚠️ Periodic analysis error: {e}")

    def _consume_data(self, consumer_name, consumer, evaluation_run_id):
        """Consume and process data from Kafka streams"""
        try:
            logger.info(f"🔄 Starting {consumer_name} consumer...")
            for message in consumer:
                if not self.running:
                    break

                if consumer_name == 'ground_truth':
                    self._process_ground_truth(message.value, evaluation_run_id)
                elif consumer_name == 'ai_alerts':
                    self._process_detection_event(message.value, 'multi_agent', evaluation_run_id)
                elif consumer_name == 'baseline_alerts':
                    self._process_baseline_event(message.value, evaluation_run_id)
                elif consumer_name == 'security_alerts':
                    self._process_detection_event(message.value, 'security_system', evaluation_run_id)

        except Exception as e:
            logger.error(f"❌ Error in {consumer_name} consumer: {e}")

    def _process_ground_truth(self, event, evaluation_run_id):
        """Process ground truth events and store in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
            INSERT OR REPLACE INTO ground_truth 
            (event_id, timestamp, event_type, attack_category, severity, duration, expected_detections)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                event['event_id'],
                event['timestamp'],
                event['event_type'],
                event['attack_category'],
                event['severity'],
                event.get('attack_duration', 0),
                event.get('expected_detections', 0)
            ))

            conn.commit()
            conn.close()

            logger.info(f"📝 Ground truth recorded: {event['event_type']} - {event.get('description', '')}")
        except Exception as e:
            logger.error(f"❌ Ground truth processing error: {e}")

    def _process_detection_event(self, event, detector_type, evaluation_run_id):
        """Process detection events and correlate with ground truth"""
        try:
            detection_id = f"{detector_type}_{int(time.time())}_{hash(str(event))}"
            detection_time = datetime.fromisoformat(event['timestamp']) if 'timestamp' in event else datetime.now()

            # Correlate with ground truth
            ground_truth_correlation = self._correlate_with_ground_truth(detection_time)

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
            INSERT INTO detection_events 
            (detection_id, detector_type, timestamp, confidence, severity, 
             ground_truth_id, correlation_status, detection_latency)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                detection_id,
                detector_type,
                event.get('timestamp', datetime.now().isoformat()),
                event.get('confidence', 0.0),
                event.get('severity', 'unknown'),
                ground_truth_correlation.get('ground_truth_id'),
                ground_truth_correlation.get('status'),
                ground_truth_correlation.get('latency', 0.0)
            ))

            conn.commit()
            conn.close()

            logger.info(f"🔍 Detection recorded: {detector_type} - {event.get('type', 'unknown')}")

        except Exception as e:
            logger.error(f"❌ Detection event processing error: {e}")

    def _process_baseline_event(self, event, evaluation_run_id):
        """Process baseline detection events"""
        detector_type = event.get('detector_type', 'baseline')
        self._process_detection_event(event, detector_type, evaluation_run_id)

    def _correlate_with_ground_truth(self, detection_time):
        """Correlate detection with ground truth events"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Find ground truth events within correlation window
            window_start = detection_time - timedelta(seconds=self.evaluation_window)
            window_end = detection_time + timedelta(seconds=self.evaluation_window)

            cursor.execute('''
            SELECT event_id, timestamp, event_type, attack_category 
            FROM ground_truth 
            WHERE timestamp BETWEEN ? AND ?
            AND event_type = 'attack'
            ORDER BY ABS(julianday(?) - julianday(timestamp))
            LIMIT 1
            ''', (window_start.isoformat(), window_end.isoformat(), detection_time.isoformat()))

            result = cursor.fetchone()
            conn.close()

            if result:
                ground_truth_time = datetime.fromisoformat(result[1])
                latency = (detection_time - ground_truth_time).total_seconds()
                return {
                    'ground_truth_id': result[0],
                    'status': 'TRUE_POSITIVE',
                    'latency': latency
                }
            else:
                return {
                    'ground_truth_id': None,
                    'status': 'FALSE_POSITIVE',
                    'latency': 0.0
                }
        except Exception as e:
            logger.error(f"❌ Ground truth correlation error: {e}")
            return {
                'ground_truth_id': None,
                'status': 'UNKNOWN',
                'latency': 0.0
            }

    def _monitor_system_performance(self, evaluation_run_id):
        """Monitor system resource performance"""
        import psutil

        logger.info("📈 Starting system performance monitoring...")

        while self.running:
            try:
                # System metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()

                # Store performance metrics
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()

                metrics = [
                    ('system', 'cpu_usage', cpu_percent),
                    ('system', 'memory_usage', memory.percent),
                    ('system', 'memory_available', memory.available / 1024 ** 3)  # GB
                ]

                for detector_type, metric_name, value in metrics:
                    cursor.execute('''
                    INSERT INTO performance_metrics 
                    (detector_type, metric_name, metric_value, timestamp, evaluation_run)
                    VALUES (?, ?, ?, ?, ?)
                    ''', (detector_type, metric_name, value, datetime.now().isoformat(), evaluation_run_id))

                conn.commit()
                conn.close()

                time.sleep(5)  # Monitor every 5 seconds

            except Exception as e:
                logger.error(f"❌ Performance monitoring error: {e}")
                time.sleep(5)

    def calculate_comprehensive_metrics(self, evaluation_run_id):
        """Calculate comprehensive performance metrics with statistical analysis"""
        logger.info("📊 Calculating comprehensive metrics...")

        conn = sqlite3.connect(self.db_path)

        # Get all detector types
        detector_types_query = """
        SELECT DISTINCT detector_type FROM detection_events 
        """
        detector_types_df = pd.read_sql_query(detector_types_query, conn)
        detector_types = detector_types_df['detector_type'].tolist() if not detector_types_df.empty else []

        results = {}

        for detector_type in detector_types:
            logger.info(f"📊 Calculating metrics for {detector_type}...")

            # Confusion matrix calculation
            confusion_matrix = self._calculate_confusion_matrix(detector_type, evaluation_run_id, conn)

            if confusion_matrix['total'] > 0:
                # Calculate standard metrics
                precision = confusion_matrix['tp'] / (confusion_matrix['tp'] + confusion_matrix['fp']) if (
                                                                                                                      confusion_matrix[
                                                                                                                          'tp'] +
                                                                                                                      confusion_matrix[
                                                                                                                          'fp']) > 0 else 0
                recall = confusion_matrix['tp'] / (confusion_matrix['tp'] + confusion_matrix['fn']) if (
                                                                                                                   confusion_matrix[
                                                                                                                       'tp'] +
                                                                                                                   confusion_matrix[
                                                                                                                       'fn']) > 0 else 0
                f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                accuracy = (confusion_matrix['tp'] + confusion_matrix['tn']) / confusion_matrix['total']
                fpr = confusion_matrix['fp'] / (confusion_matrix['fp'] + confusion_matrix['tn']) if (confusion_matrix[
                                                                                                         'fp'] +
                                                                                                     confusion_matrix[
                                                                                                         'tn']) > 0 else 0

                # Calculate confidence intervals
                precision_ci = self._calculate_confidence_interval(precision,
                                                                   confusion_matrix['tp'] + confusion_matrix['fp'])
                recall_ci = self._calculate_confidence_interval(recall, confusion_matrix['tp'] + confusion_matrix['fn'])
                f1_ci = self._calculate_confidence_interval(f1, confusion_matrix['total'])

                # Detection latency statistics
                latency_stats = self._calculate_latency_statistics(detector_type, evaluation_run_id, conn)

                results[detector_type] = {
                    'confusion_matrix': confusion_matrix,
                    'metrics': {
                        'precision': precision,
                        'recall': recall,
                        'f1_score': f1,
                        'accuracy': accuracy,
                        'false_positive_rate': fpr,
                        'precision_ci': precision_ci,
                        'recall_ci': recall_ci,
                        'f1_ci': f1_ci
                    },
                    'latency_stats': latency_stats
                }

                # Store confusion matrix in database
                cursor = conn.cursor()
                cursor.execute('''
                INSERT OR REPLACE INTO confusion_matrix 
                (detector_type, true_positives, false_positives, true_negatives, false_negatives, evaluation_run)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    detector_type,
                    confusion_matrix['tp'],
                    confusion_matrix['fp'],
                    confusion_matrix['tn'],
                    confusion_matrix['fn'],
                    evaluation_run_id
                ))
                conn.commit()
            else:
                logger.warning(f"⚠️ No data found for {detector_type}")

        conn.close()
        return results

    def _calculate_confusion_matrix(self, detector_type, evaluation_run_id, conn):
        """Calculate confusion matrix for a detector"""
        try:
            # Get all ground truth events
            ground_truth_query = """
            SELECT event_id, event_type, timestamp FROM ground_truth 
            WHERE event_type IN ('attack', 'normal')
            """
            ground_truth_df = pd.read_sql_query(ground_truth_query, conn)

            # Get detection events for this detector
            detection_query = """
            SELECT correlation_status, ground_truth_id FROM detection_events 
            WHERE detector_type = ?
            """
            detection_df = pd.read_sql_query(detection_query, conn, params=[detector_type])

            # Calculate confusion matrix components
            tp = len(detection_df[detection_df['correlation_status'] == 'TRUE_POSITIVE'])
            fp = len(detection_df[detection_df['correlation_status'] == 'FALSE_POSITIVE'])

            # Calculate FN (missed attacks)
            if not detection_df.empty and not ground_truth_df.empty:
                detected_attacks = set(
                    detection_df[detection_df['correlation_status'] == 'TRUE_POSITIVE']['ground_truth_id'].dropna())
                total_attacks = set(ground_truth_df[ground_truth_df['event_type'] == 'attack']['event_id'])
                fn = len(total_attacks - detected_attacks)
            else:
                fn = len(ground_truth_df[ground_truth_df['event_type'] == 'attack']) if not ground_truth_df.empty else 0

            # Calculate TN (correctly identified normal periods)
            total_normal = len(
                ground_truth_df[ground_truth_df['event_type'] == 'normal']) if not ground_truth_df.empty else 100
            tn = max(0, total_normal - fp)  # Simplified calculation

            return {
                'tp': tp,
                'fp': fp,
                'tn': tn,
                'fn': fn,
                'total': tp + fp + tn + fn
            }
        except Exception as e:
            logger.error(f"❌ Confusion matrix calculation error: {e}")
            return {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0, 'total': 0}

    def _calculate_confidence_interval(self, metric_value, sample_size, confidence_level=0.95):
        """Calculate confidence interval for a metric"""
        if sample_size == 0 or metric_value == 0:
            return (0, 0)

        try:
            z_score = stats.norm.ppf(1 - (1 - confidence_level) / 2)
            margin_of_error = z_score * np.sqrt((metric_value * (1 - metric_value)) / sample_size)

            return (
                max(0, metric_value - margin_of_error),
                min(1, metric_value + margin_of_error)
            )
        except:
            return (metric_value, metric_value)

    def _calculate_latency_statistics(self, detector_type, evaluation_run_id, conn):
        """Calculate detection latency statistics"""
        try:
            latency_query = """
            SELECT detection_latency FROM detection_events 
            WHERE detector_type = ? AND correlation_status = 'TRUE_POSITIVE'
            AND detection_latency > 0
            """
            latency_df = pd.read_sql_query(latency_query, conn, params=[detector_type])

            if len(latency_df) == 0:
                return {
                    'mean': 0, 'median': 0, 'std': 0,
                    'min': 0, 'max': 0, 'p95': 0, 'count': 0
                }

            latencies = latency_df['detection_latency'].values

            return {
                'mean': float(np.mean(latencies)),
                'median': float(np.median(latencies)),
                'std': float(np.std(latencies)),
                'min': float(np.min(latencies)),
                'max': float(np.max(latencies)),
                'p95': float(np.percentile(latencies, 95)),
                'count': len(latencies)
            }
        except Exception as e:
            logger.error(f"❌ Latency statistics error: {e}")
            return {'mean': 0, 'median': 0, 'std': 0, 'min': 0, 'max': 0, 'p95': 0, 'count': 0}

    def perform_statistical_significance_testing(self, results):
        """Perform statistical significance testing between detector types"""
        detector_types = list(results.keys())
        significance_tests = {}

        for i in range(len(detector_types)):
            for j in range(i + 1, len(detector_types)):
                detector1 = detector_types[i]
                detector2 = detector_types[j]

                try:
                    # Get F1 scores for comparison
                    f1_1 = results[detector1]['metrics']['f1_score']
                    f1_2 = results[detector2]['metrics']['f1_score']

                    # Get sample sizes
                    n1 = results[detector1]['confusion_matrix']['total']
                    n2 = results[detector2]['confusion_matrix']['total']

                    # Perform two-proportion z-test
                    if n1 > 0 and n2 > 0:
                        # Calculate pooled proportion
                        p_pool = (f1_1 * n1 + f1_2 * n2) / (n1 + n2)

                        # Calculate standard error
                        se = np.sqrt(p_pool * (1 - p_pool) * (1 / n1 + 1 / n2))

                        # Calculate z-statistic
                        z_stat = (f1_1 - f1_2) / se if se > 0 else 0

                        # Calculate p-value
                        p_value = 2 * (1 - stats.norm.cdf(abs(z_stat)))

                        # Effect size (Cohen's d)
                        pooled_std = np.sqrt(
                            ((n1 - 1) * (f1_1 * (1 - f1_1)) + (n2 - 1) * (f1_2 * (1 - f1_2))) / (n1 + n2 - 2))
                        cohens_d = (f1_1 - f1_2) / pooled_std if pooled_std > 0 else 0

                        significance_tests[f"{detector1}_vs_{detector2}"] = {
                            'z_statistic': float(z_stat),
                            'p_value': float(p_value),
                            'cohens_d': float(cohens_d),
                            'significant': p_value < 0.05,
                            'effect_size': self._interpret_effect_size(abs(cohens_d))
                        }
                except Exception as e:
                    logger.error(f"❌ Statistical test error for {detector1} vs {detector2}: {e}")

        return significance_tests

    def _interpret_effect_size(self, cohens_d):
        """Interpret Cohen's d effect size"""
        if cohens_d < 0.2:
            return "negligible"
        elif cohens_d < 0.5:
            return "small"
        elif cohens_d < 0.8:
            return "medium"
        else:
            return "large"

    def generate_comprehensive_report(self, evaluation_run_id):
        """Generate comprehensive evaluation report with all metrics"""
        logger.info("📋 Generating comprehensive performance report...")

        try:
            # Calculate comprehensive metrics
            results = self.calculate_comprehensive_metrics(evaluation_run_id)

            # Perform statistical testing
            significance_tests = self.perform_statistical_significance_testing(results)

            # Generate visualizations
            self._generate_performance_visualizations(results, evaluation_run_id)

            # Create summary report
            report = {
                'evaluation_run_id': evaluation_run_id,
                'evaluation_timestamp': datetime.now().isoformat(),
                'detector_results': results,
                'statistical_tests': significance_tests,
                'summary': self._generate_summary_statistics(results)
            }

            # Save comprehensive report
            with open(f'/app/comprehensive_evaluation_{evaluation_run_id}.json', 'w') as f:
                json.dump(report, f, indent=2, default=str)

            # Print summary
            self._print_evaluation_summary(report)

            logger.info(f"✅ Comprehensive report saved as comprehensive_evaluation_{evaluation_run_id}.json")

            return report
        except Exception as e:
            logger.error(f"❌ Report generation error: {e}")
            return {'error': str(e)}

    def _generate_performance_visualizations(self, results, evaluation_run_id):
        """Generate comprehensive performance visualizations"""
        try:
            if not results:
                logger.warning("⚠️ No results to visualize")
                return

            # Set up the plotting style
            plt.style.use('default')
            sns.set_palette("husl")

            # Create comprehensive comparison charts
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            fig.suptitle('Multi-Agent System Performance Analysis', fontsize=16)

            detector_names = list(results.keys())

            # 1. F1-Score Comparison
            f1_scores = [results[d]['metrics']['f1_score'] for d in detector_names]

            axes[0, 0].bar(detector_names, f1_scores, alpha=0.7, color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728'])
            axes[0, 0].set_title('F1-Score Comparison')
            axes[0, 0].set_ylabel('F1-Score')
            axes[0, 0].tick_params(axis='x', rotation=45)
            axes[0, 0].set_ylim(0, 1)

            # 2. Precision vs Recall
            precisions = [results[d]['metrics']['precision'] for d in detector_names]
            recalls = [results[d]['metrics']['recall'] for d in detector_names]

            axes[0, 1].scatter(recalls, precisions, s=100, alpha=0.7, c=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728'])
            for i, name in enumerate(detector_names):
                axes[0, 1].annotate(name.replace('_', ' ').title(),
                                    (recalls[i], precisions[i]), xytext=(5, 5),
                                    textcoords='offset points', fontsize=8)
            axes[0, 1].set_xlabel('Recall')
            axes[0, 1].set_ylabel('Precision')
            axes[0, 1].set_title('Precision vs Recall')
            axes[0, 1].grid(True, alpha=0.3)
            axes[0, 1].set_xlim(0, 1)
            axes[0, 1].set_ylim(0, 1)

            # 3. Detection Latency Comparison
            latencies = [results[d]['latency_stats']['mean'] for d in detector_names]

            axes[1, 0].bar(detector_names, latencies, alpha=0.7, color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728'])
            axes[1, 0].set_title('Average Detection Latency')
            axes[1, 0].set_ylabel('Latency (seconds)')
            axes[1, 0].tick_params(axis='x', rotation=45)

            # 4. False Positive Rate Comparison
            fpr_rates = [results[d]['metrics']['false_positive_rate'] for d in detector_names]

            axes[1, 1].bar(detector_names, fpr_rates, alpha=0.7, color=['#ff7f0e', '#d62728', '#2ca02c', '#1f77b4'])
            axes[1, 1].set_title('False Positive Rates')
            axes[1, 1].set_ylabel('False Positive Rate')
            axes[1, 1].tick_params(axis='x', rotation=45)
            axes[1, 1].set_ylim(0, max(fpr_rates) * 1.2 if fpr_rates else 1)

            plt.tight_layout()
            plt.savefig(f'/app/comprehensive_performance_{evaluation_run_id}.png',
                        dpi=300, bbox_inches='tight')
            plt.close()

            logger.info(f"📊 Performance visualizations saved as comprehensive_performance_{evaluation_run_id}.png")

        except Exception as e:
            logger.error(f"❌ Visualization generation error: {e}")

    def _generate_summary_statistics(self, results):
        """Generate summary statistics across all detectors"""
        if not results:
            return {}

        try:
            # Find best performing detector for each metric
            best_f1 = max(results.keys(), key=lambda k: results[k]['metrics']['f1_score'])
            best_precision = max(results.keys(), key=lambda k: results[k]['metrics']['precision'])
            best_recall = max(results.keys(), key=lambda k: results[k]['metrics']['recall'])
            best_latency = min(results.keys(), key=lambda k: results[k]['latency_stats']['mean'])

            return {
                'total_detectors_evaluated': len(results),
                'best_overall_f1': {
                    'detector': best_f1,
                    'score': results[best_f1]['metrics']['f1_score']
                },
                'best_precision': {
                    'detector': best_precision,
                    'score': results[best_precision]['metrics']['precision']
                },
                'best_recall': {
                    'detector': best_recall,
                    'score': results[best_recall]['metrics']['recall']
                },
                'fastest_detection': {
                    'detector': best_latency,
                    'latency': results[best_latency]['latency_stats']['mean']
                }
            }
        except Exception as e:
            logger.error(f"❌ Summary statistics error: {e}")
            return {'error': str(e)}

    def _print_evaluation_summary(self, report):
        """Print comprehensive evaluation summary"""
        try:
            print("\n" + "=" * 80)
            print("📊 COMPREHENSIVE EVALUATION SUMMARY")
            print("=" * 80)

            print(f"Evaluation Run: {report['evaluation_run_id']}")
            print(f"Timestamp: {report['evaluation_timestamp']}")
            print(f"Detectors Evaluated: {report['summary'].get('total_detectors_evaluated', 0)}")

            if 'best_overall_f1' in report['summary']:
                print("\n🏆 BEST PERFORMERS:")
                print(f"Best F1-Score: {report['summary']['best_overall_f1']['detector']} "
                      f"({report['summary']['best_overall_f1']['score']:.3f})")
                print(f"Best Precision: {report['summary']['best_precision']['detector']} "
                      f"({report['summary']['best_precision']['score']:.3f})")
                print(f"Best Recall: {report['summary']['best_recall']['detector']} "
                      f"({report['summary']['best_recall']['score']:.3f})")
                print(f"Fastest Detection: {report['summary']['fastest_detection']['detector']} "
                      f"({report['summary']['fastest_detection']['latency']:.2f}s)")

            print("\n📈 DETAILED METRICS:")
            for detector, results in report['detector_results'].items():
                print(f"\n{detector.upper().replace('_', ' ')}:")
                metrics = results['metrics']
                latency = results['latency_stats']
                print(f"  Precision: {metrics['precision']:.3f}")
                print(f"  Recall: {metrics['recall']:.3f}")
                print(f"  F1-Score: {metrics['f1_score']:.3f}")
                print(f"  Accuracy: {metrics['accuracy']:.3f}")
                print(f"  FPR: {metrics['false_positive_rate']:.3f}")
                print(f"  Avg Latency: {latency['mean']:.2f}s (±{latency['std']:.2f}s)")

            if report['statistical_tests']:
                print("\n🧪 STATISTICAL SIGNIFICANCE TESTS:")
                for test_name, test_result in report['statistical_tests'].items():
                    significance = "✅ SIGNIFICANT" if test_result['significant'] else "❌ NOT SIGNIFICANT"
                    print(f"{test_name}: p={test_result['p_value']:.4f}, "
                          f"Cohen's d={test_result['cohens_d']:.3f} ({test_result['effect_size']}) - {significance}")

            print("\n" + "=" * 80)
        except Exception as e:
            logger.error(f"❌ Print summary error: {e}")
