import time
import threading
from ground_truth_generator import GroundTruthGenerator
from comprehensive_evaluator import ComprehensivePerformanceEvaluator


def run_complete_evaluation():
    """Run complete evaluation with ground truth generation and comprehensive metrics"""

    print("🚀 Starting Complete Multi-Agent System Evaluation")
    print("=" * 60)

    # Initialize components
    ground_truth_gen = GroundTruthGenerator()
    evaluator = ComprehensivePerformanceEvaluator()

    # Generate attack sequence
    print("📋 Generating controlled attack sequence...")
    attack_schedule = ground_truth_gen.generate_controlled_attack_sequence(
        total_duration_minutes=120,  # 2 hours of testing
        attack_frequency=5
    )

    print(f"✅ Generated {len(attack_schedule)} events for evaluation")

    # Start evaluator
    print("🔬 Starting comprehensive evaluator...")
    eval_thread = threading.Thread(
        target=evaluator.start_comprehensive_evaluation,
        args=(2,)  # 2 hours evaluation
    )
    eval_thread.daemon = True
    eval_thread.start()

    # Wait for evaluator to initialize
    time.sleep(10)

    # Execute attack sequence with ground truth
    print("🎯 Executing attack sequence with ground truth generation...")
    ground_truth_gen.execute_attack_sequence(attack_schedule)

    # Wait for evaluation to complete
    eval_thread.join()

    print("✅ Complete evaluation finished!")
    print("📊 Check /app/ directory for comprehensive reports and visualizations")


if __name__ == "__main__":
    run_complete_evaluation()
