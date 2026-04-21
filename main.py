import argparse
import logging
from pathlib import Path
from core.parser import KibanaLogParser
from core.generator import PytestGenerator

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)


def main():
    """
    CLI Entrypoint for Secure Log2Test Engine.
  
    """
    parser = argparse.ArgumentParser(
        description="Deterministic AI-free API Test Generator for Enterprise environments.")
    parser.add_argument("--log", required=True, help="Path to the Kibana/Elasticsearch JSON log export.")
    parser.add_argument("--out", default="test_auto_generated.py",
                        help="Output filename for the generated pytest suite.")

    args = parser.parse_args()
    log_path = Path(args.log)

    if not log_path.exists():
        logger.error(f"Input file not found: {log_path}")
        return

    logger.info("Initializing Secure Log2Test Engine...")

    # 1. Parse deterministic footprint
    log_parser = KibanaLogParser(file_path=str(log_path))
    try:
        entries = log_parser.parse()
        if not entries:
            logger.warning("No valid entries parsed. Exiting.")
            return
    except Exception as e:
        logger.error(f"Parsing failed: {e}")
        return

    # 2. Generate pytest suite
    generator = PytestGenerator()
    try:
        output_file = generator.generate_suite(
            entries=entries,
            template_name="test_api.jinja2",
            output_filename=args.out
        )
        if output_file:
            logger.info(f"SUCCESS: Generated {len(entries)} test cases in {output_file}")
            logger.info(f"Run tests with: pytest {output_file} -v")
    except Exception as e:
        logger.error(f"Generation failed: {e}")


if __name__ == "__main__":
    main()
