import time
import threading
from ground_truth_generator import GroundTruthGenerator
from comprehensive_evaluator import ComprehensivePerformanceEvaluator
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_complete_evaluation():
    """Run complete evaluation with ground truth generation and comprehensive metrics"""

    logger.info("🚀 Starting Complete Multi-Agent System Evaluation")
    logger.info("=" * 60)

    # Initialize components
    ground_truth_gen = GroundTruthGenerator()
    evaluator = ComprehensivePerformanceEvaluator()

    # Generate attack sequence
    logger.info("📋 Generating controlled attack sequence...")
    attack_schedule = ground_truth_gen.generate_controlled_attack_sequence(
        total_duration_minutes=120,  # 2 hours of testing
        attack_frequency=5
    )

    logger.info(f"✅ Generated {len(attack_schedule)} events for evaluation")

    # Start evaluator in background thread
    logger.info("🔬 Starting comprehensive evaluator...")
    eval_thread = threading.Thread(
        target=evaluator.start_comprehensive_evaluation,
        args=(2,),  # 2 hours evaluation
        daemon=True
    )
    eval_thread.start()

    # Wait for evaluator to initialize
    time.sleep(10)

    # Execute attack sequence with ground truth
    logger.info("🎯 Executing attack sequence with ground truth generation...")
    try:
        ground_truth_gen.execute_attack_sequence(attack_schedule)
    except Exception as e:
        logger.error(f"❌ Attack sequence execution error: {e}")

    # Wait for evaluation to complete
    logger.info("⏳ Waiting for evaluation to complete...")
    eval_thread.join(timeout=7200)  # 2 hour timeout

    logger.info("✅ Complete evaluation finished!")
    logger.info("📊 Check /app/ directory for comprehensive reports and visualizations")


if __name__ == "__main__":
    run_complete_evaluation()
